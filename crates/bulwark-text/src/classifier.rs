//! Optional small text-classifier backstop.
//!
//! MINIMAL-AI MANDATE: the deterministic [`crate::engine::GroomingRuleEngine`]
//! is the primary detector and always runs. This classifier is an **opt-in
//! backstop only**, behind the `classifier` cargo feature (OFF by default). It
//! NEVER gates a verdict and is NEVER in the hot path: the analyzer computes the
//! rule verdict first, and the classifier may only *confirm* it by setting
//! [`bulwark_proto::GroomingSignal::classifier_backed`]. There is no LLM anywhere.
//!
//! The trait lets the analyzer stay agnostic: with the feature off, a
//! [`NoClassifier`] is used and `classifier_backed` is always false; with the
//! feature on, an [`OrtGroomingClassifier`] runs a tiny INT8 ONNX model
//! (DistilBERT / MiniLM class, see model-research.md) via `ort`.

use bulwark_proto::TextSpan;

/// A backstop text classifier. Pure CPU/in-memory and infallible at the trait
/// boundary (errors degrade to "no agreement" so it can never break a verdict).
pub trait TextClassifier: Send + Sync {
    /// Probability in 0.0–1.0 that `span` is grooming, per the small model.
    /// Implementations MUST be cheap and side-effect free.
    fn grooming_probability(&self, span: &TextSpan) -> f32;

    /// Whether the classifier *agrees* the span is grooming at its operating
    /// threshold. Used only to set `classifier_backed`; default = ≥0.5.
    fn agrees_grooming(&self, span: &TextSpan) -> bool {
        self.grooming_probability(span) >= 0.5
    }

    /// Stable id of the backing model for audit (`Evidence.model_id`).
    fn model_id(&self) -> &str;
}

/// The default, always-available implementation: no model, never agrees. With
/// the `classifier` feature off this is what the analyzer holds, so
/// `classifier_backed` is always false and the rule engine stands alone.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoClassifier;

impl TextClassifier for NoClassifier {
    fn grooming_probability(&self, _span: &TextSpan) -> f32 {
        0.0
    }
    fn agrees_grooming(&self, _span: &TextSpan) -> bool {
        false
    }
    fn model_id(&self) -> &str {
        "none"
    }
}

// ---------------------------------------------------------------------------
// ort-backed implementation — compiled ONLY under the `classifier` feature.
// ---------------------------------------------------------------------------
#[cfg(feature = "classifier")]
mod ort_impl {
    use super::TextClassifier;
    use crate::error::TextError;
    use bulwark_proto::TextSpan;
    use std::path::Path;
    use std::sync::Mutex;

    use ort::session::{builder::GraphOptimizationLevel, Session};
    use ort::value::Value;
    // Aliased so it doesn't collide with the `Tokenizer` trait above.
    use tokenizers::Tokenizer as HfTokenizer;

    /// A tiny INT8 grooming classifier (DistilBERT / MiniLM class) run via `ort`.
    ///
    /// NOT in the hot path: the analyzer only calls this to *confirm* a rule
    /// signal, and only when the `classifier` feature is enabled. The model is
    /// loaded once; inference is single-threaded and bounded.
    ///
    /// Tokenization is intentionally pluggable: production wires a real
    /// WordPiece/SentencePiece tokenizer matching the model. Here we keep the
    /// `ort` session wiring concrete and the tokenizer behind a small trait so
    /// the integration compiles and is testable without bundling a 268MB model.
    pub struct OrtGroomingClassifier {
        session: Mutex<Session>,
        tokenizer: Box<dyn Tokenizer>,
        model_id: String,
        threshold: f32,
    }

    /// Minimal tokenizer contract: text → (input_ids, attention_mask).
    pub trait Tokenizer: Send + Sync {
        fn encode(&self, text: &str) -> (Vec<i64>, Vec<i64>);
        fn max_len(&self) -> usize {
            128
        }
    }

    impl OrtGroomingClassifier {
        /// Load an INT8 ONNX model from `path` with the given tokenizer.
        ///
        /// `ort` selects the best available execution provider (CPU/oneDNN,
        /// DirectML, CoreML, NNAPI, CUDA) and falls back to CPU automatically,
        /// per model-research.md notes.
        pub fn load(
            path: impl AsRef<Path>,
            tokenizer: Box<dyn Tokenizer>,
            model_id: impl Into<String>,
        ) -> Result<Self, TextError> {
            let session = Session::builder()
                .map_err(|e| TextError::Classifier(e.to_string()))?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(|e| TextError::Classifier(e.to_string()))?
                .with_intra_threads(1)
                .map_err(|e| TextError::Classifier(e.to_string()))?
                .commit_from_file(path)
                .map_err(|e| TextError::Classifier(e.to_string()))?;
            Ok(Self {
                session: Mutex::new(session),
                tokenizer,
                model_id: model_id.into(),
                threshold: 0.5,
            })
        }

        /// Set the agreement threshold (default 0.5).
        pub fn with_threshold(mut self, t: f32) -> Self {
            self.threshold = t;
            self
        }

        /// Run the model and return the grooming-class probability, or an error.
        fn infer(&self, text: &str) -> Result<f32, TextError> {
            let (ids, mask) = self.tokenizer.encode(text);
            let len = ids.len();
            let id_arr = ([1_usize, len], ids);
            let mask_arr = ([1_usize, len], mask);

            let input_ids =
                Value::from_array(id_arr).map_err(|e| TextError::Classifier(e.to_string()))?;
            let attention_mask =
                Value::from_array(mask_arr).map_err(|e| TextError::Classifier(e.to_string()))?;

            let mut session = self
                .session
                .lock()
                .map_err(|_| TextError::Classifier("session lock poisoned".into()))?;

            let outputs = session
                .run(ort::inputs![
                    "input_ids" => input_ids,
                    "attention_mask" => attention_mask,
                ])
                .map_err(|e| TextError::Classifier(e.to_string()))?;

            // Expect a [1, 2] logits tensor: [not_grooming, grooming].
            let (_shape, logits) = outputs[0]
                .try_extract_tensor::<f32>()
                .map_err(|e| TextError::Classifier(e.to_string()))?;
            let p = softmax_grooming(logits);
            Ok(p)
        }
    }

    /// Softmax over the 2-class logits, returning P(grooming) = class 1.
    fn softmax_grooming(logits: &[f32]) -> f32 {
        if logits.len() < 2 {
            return 0.0;
        }
        let max = logits[0].max(logits[1]);
        let e0 = (logits[0] - max).exp();
        let e1 = (logits[1] - max).exp();
        e1 / (e0 + e1)
    }

    impl TextClassifier for OrtGroomingClassifier {
        fn grooming_probability(&self, span: &TextSpan) -> f32 {
            // Errors degrade to 0.0 (no agreement) so the classifier can never
            // break or block a rule-based verdict.
            self.infer(&span.text).unwrap_or(0.0)
        }

        fn agrees_grooming(&self, span: &TextSpan) -> bool {
            self.grooming_probability(span) >= self.threshold
        }

        fn model_id(&self) -> &str {
            &self.model_id
        }
    }

    // -----------------------------------------------------------------------
    // sklearn TF-IDF model — the "use now" classifier until DistilBERT lands.
    // -----------------------------------------------------------------------

    /// The full-corpus sklearn (TF-IDF + linear) grooming model, exported to ONNX
    /// with a STRING input (`"text"`) and a `[N, 2]` probability tensor
    /// (`[P(safe), P(grooming)]`). This is the live backstop until the DistilBERT
    /// ONNX is ready (which plugs into [`OrtGroomingClassifier`] above). Same
    /// confirm-only role: it sets `classifier_backed`, never gates a verdict.
    ///
    /// The model is bundled in the binary (`include_bytes!`) so there is no runtime
    /// file dependency. Input is formatted with the `[OTHER]` role marker the model
    /// was trained on (training joins segments as `[OTHER]/[SELF] … [SEP] …`).
    pub struct SklearnTfidfClassifier {
        session: Mutex<Session>,
        model_id: String,
        threshold: f32,
    }

    impl SklearnTfidfClassifier {
        /// Load the full-corpus model bundled in the binary (no external file).
        pub fn load_builtin() -> Result<Self, TextError> {
            const MODEL: &[u8] = include_bytes!("../models/grooming_detector.onnx");
            Self::from_bytes(MODEL, "sklearn-tfidf-grooming-fullcorpus-v1")
        }

        /// Load from raw ONNX bytes (string input → `[N,2]` probability tensor).
        pub fn from_bytes(bytes: &[u8], model_id: impl Into<String>) -> Result<Self, TextError> {
            let session = Session::builder()
                .map_err(|e| TextError::Classifier(e.to_string()))?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(|e| TextError::Classifier(e.to_string()))?
                .with_intra_threads(1)
                .map_err(|e| TextError::Classifier(e.to_string()))?
                .commit_from_memory(bytes)
                .map_err(|e| TextError::Classifier(e.to_string()))?;
            Ok(Self {
                session: Mutex::new(session),
                model_id: model_id.into(),
                threshold: 0.5,
            })
        }

        /// Set the agreement threshold (default 0.5).
        pub fn with_threshold(mut self, t: f32) -> Self {
            self.threshold = t;
            self
        }

        fn infer(&self, text: &str) -> Result<f32, TextError> {
            // Match the training text format (role-marked segments). A single span
            // is one [OTHER] segment; structured windows can join with " [SEP] ".
            let formatted = vec![format!("[OTHER] {text}")];
            let input = ort::value::Tensor::from_string_array(([1_usize, 1], formatted.as_slice()))
                .map_err(|e| TextError::Classifier(e.to_string()))?;

            let mut session = self
                .session
                .lock()
                .map_err(|_| TextError::Classifier("session lock poisoned".into()))?;

            let outputs = session
                .run(ort::inputs!["text" => input])
                .map_err(|e| TextError::Classifier(e.to_string()))?;

            // "probabilities": [1, 2] f32 = [P(safe), P(grooming)].
            let (_shape, probs) = outputs["probabilities"]
                .try_extract_tensor::<f32>()
                .map_err(|e| TextError::Classifier(e.to_string()))?;
            Ok(probs.get(1).copied().unwrap_or(0.0))
        }
    }

    impl TextClassifier for SklearnTfidfClassifier {
        fn grooming_probability(&self, span: &TextSpan) -> f32 {
            // Errors degrade to 0.0 (no agreement) so it can never break a verdict.
            self.infer(&span.text).unwrap_or(0.0)
        }
        fn agrees_grooming(&self, span: &TextSpan) -> bool {
            self.grooming_probability(span) >= self.threshold
        }
        fn model_id(&self) -> &str {
            &self.model_id
        }
    }

    // -----------------------------------------------------------------------
    // DistilBERT model — the higher-accuracy classifier (windowed AUC ~0.98).
    // -----------------------------------------------------------------------

    /// The fine-tuned DistilBERT grooming model (`grooming_detector_v2.onnx`), run
    /// via `ort` with a WordPiece tokenizer. The graph outputs a single
    /// `grooming_logit` → sigmoid → P(grooming). Trained on 20-message windows, so
    /// feed conversational context (the analyzer span), not a lone message.
    ///
    /// PATH-loaded: the model is ~268MB with an external-data sidecar
    /// (`grooming_detector_v2.onnx.data`, which MUST sit next to the `.onnx`), far
    /// too large to bundle. On-device inference is **batch=1** (the exported graph
    /// fixes the batch dim). Same confirm-only backstop role.
    pub struct DistilbertGroomingClassifier {
        session: Mutex<Session>,
        tokenizer: HfTokenizer,
        model_id: String,
        threshold: f32,
        max_len: usize,
    }

    impl DistilbertGroomingClassifier {
        /// Load `grooming_detector_v2.onnx` (its `.onnx.data` sidecar must be
        /// alongside it) and the WordPiece `tokenizer.json`.
        pub fn load(
            model_path: impl AsRef<Path>,
            tokenizer_json: impl AsRef<Path>,
            model_id: impl Into<String>,
        ) -> Result<Self, TextError> {
            let session = Session::builder()
                .map_err(|e| TextError::Classifier(e.to_string()))?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(|e| TextError::Classifier(e.to_string()))?
                .with_intra_threads(1)
                .map_err(|e| TextError::Classifier(e.to_string()))?
                .commit_from_file(model_path)
                .map_err(|e| TextError::Classifier(e.to_string()))?;
            let tokenizer = HfTokenizer::from_file(tokenizer_json)
                .map_err(|e| TextError::Classifier(e.to_string()))?;
            Ok(Self {
                session: Mutex::new(session),
                tokenizer,
                model_id: model_id.into(),
                threshold: 0.5,
                // Matches training MAX_SEQ_LENGTH (train_v2.py) — truncating shorter
                // would diverge from training on long windows.
                max_len: 256,
            })
        }

        /// Set the agreement threshold (default 0.5).
        pub fn with_threshold(mut self, t: f32) -> Self {
            self.threshold = t;
            self
        }

        fn infer(&self, text: &str) -> Result<f32, TextError> {
            // Feed the span verbatim (the caller supplies window-formatted context
            // matching training); `true` adds the [CLS]/[SEP] tokens the model pools.
            let enc = self
                .tokenizer
                .encode(text, true)
                .map_err(|e| TextError::Classifier(e.to_string()))?;
            let take = enc.get_ids().len().min(self.max_len);
            let ids: Vec<i64> = enc.get_ids()[..take].iter().map(|&x| x as i64).collect();
            let mask: Vec<i64> = enc.get_attention_mask()[..take]
                .iter()
                .map(|&x| x as i64)
                .collect();
            let len = ids.len();

            let input_ids = Value::from_array(([1_usize, len], ids))
                .map_err(|e| TextError::Classifier(e.to_string()))?;
            let attention_mask = Value::from_array(([1_usize, len], mask))
                .map_err(|e| TextError::Classifier(e.to_string()))?;

            let mut session = self
                .session
                .lock()
                .map_err(|_| TextError::Classifier("session lock poisoned".into()))?;
            let outputs = session
                .run(ort::inputs![
                    "input_ids" => input_ids,
                    "attention_mask" => attention_mask,
                ])
                .map_err(|e| TextError::Classifier(e.to_string()))?;

            // "grooming_logit": a single logit → sigmoid → P(grooming).
            let (_shape, logit) = outputs["grooming_logit"]
                .try_extract_tensor::<f32>()
                .map_err(|e| TextError::Classifier(e.to_string()))?;
            let z = logit.first().copied().unwrap_or(0.0);
            Ok(1.0 / (1.0 + (-z).exp()))
        }
    }

    impl TextClassifier for DistilbertGroomingClassifier {
        fn grooming_probability(&self, span: &TextSpan) -> f32 {
            self.infer(&span.text).unwrap_or(0.0)
        }
        fn agrees_grooming(&self, span: &TextSpan) -> bool {
            self.grooming_probability(span) >= self.threshold
        }
        fn model_id(&self) -> &str {
            &self.model_id
        }
    }
}

#[cfg(feature = "classifier")]
pub use ort_impl::{
    DistilbertGroomingClassifier, OrtGroomingClassifier, SklearnTfidfClassifier, Tokenizer,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_classifier_never_agrees() {
        let c = NoClassifier;
        let span = TextSpan {
            text: "send me a pic".into(),
            ..Default::default()
        };
        assert_eq!(c.grooming_probability(&span), 0.0);
        assert!(!c.agrees_grooming(&span));
        assert_eq!(c.model_id(), "none");
    }

    #[cfg(feature = "classifier")]
    #[test]
    fn sklearn_classifier_matches_python_reference() {
        // Layer 2 (parity) + Layer 3 (golden): the bundled ONNX, run via ort,
        // reproduces the Python onnxruntime reference probabilities, and known
        // grooming/benign cases land on the right side of the 0.5 threshold.
        let c = super::SklearnTfidfClassifier::load_builtin().expect("bundled model loads");
        let cases = [
            ("send me a pic of yourself", 0.7212_f32),
            ("did you finish the math homework", 0.0041),
            ("how old are you where do you live", 0.9336),
            ("want to play minecraft after school", 0.0891),
        ];
        for (text, want) in cases {
            let span = TextSpan {
                text: text.into(),
                ..Default::default()
            };
            let got = c.grooming_probability(&span);
            assert!(
                (got - want).abs() < 1e-3,
                "{text}: rust {got} vs python reference {want}"
            );
        }
        let pic = TextSpan {
            text: "send me a pic of yourself".into(),
            ..Default::default()
        };
        let hw = TextSpan {
            text: "did you finish the math homework".into(),
            ..Default::default()
        };
        assert!(c.agrees_grooming(&pic), "grooming should agree");
        assert!(!c.agrees_grooming(&hw), "benign should not agree");
        assert_eq!(c.model_id(), "sklearn-tfidf-grooming-fullcorpus-v1");
    }

    #[cfg(feature = "classifier")]
    #[test]
    fn distilbert_classifier_golden_when_model_present() {
        // Env-gated: the model is ~268MB so it isn't in CI. To run locally set:
        //   BULWARK_GROOMING_DISTILBERT=<...>/grooming_detector_v2.onnx  (sidecar alongside)
        //   BULWARK_GROOMING_TOKENIZER=<...>/tokenizer/tokenizer.json
        // (Python-side Layer-1 faithfulness is verified separately: windowed AUC 0.9837.)
        let (Ok(model), Ok(tok)) = (
            std::env::var("BULWARK_GROOMING_DISTILBERT"),
            std::env::var("BULWARK_GROOMING_TOKENIZER"),
        ) else {
            eprintln!("skipping distilbert golden test: model env vars not set");
            return;
        };
        let c = super::DistilbertGroomingClassifier::load(&model, &tok, "distilbert-test").unwrap();
        // PARITY: feed the EXACT window the Python onnxruntime reference scored and
        // assert Rust (ort + tokenizers) reproduces it within tolerance. This is the
        // faithful-inference check; windowed AUC 0.9837 is verified Python-side.
        let window = "[SELF] 6 or 7 [SEP] [OTHER] Yes [SEP] [SELF] o [SEP] [SELF] m [SEP] [OTHER] Ok [SEP] [SELF] g [SEP] [SELF] lol [SEP] [OTHER] I have to go work now [SEP] [SELF] kk [SEP] [SELF] byeeeeeee [SEP] [OTHER] I see you later [SEP] [SELF] k [SEP] [OTHER] Bye bye [SEP] [SELF] ye [SEP] [SELF] b [SEP] [SELF] bye";
        let span = TextSpan {
            text: window.into(),
            ..Default::default()
        };
        let p = c.grooming_probability(&span);
        eprintln!("distilbert parity P={p} (python reference 0.1345)");
        assert!(
            (p - 0.1345).abs() < 0.03,
            "rust {p} should match python reference 0.1345"
        );
    }
}
