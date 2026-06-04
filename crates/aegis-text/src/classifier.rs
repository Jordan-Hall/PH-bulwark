//! Optional small text-classifier backstop.
//!
//! MINIMAL-AI MANDATE: the deterministic [`crate::engine::GroomingRuleEngine`]
//! is the primary detector and always runs. This classifier is an **opt-in
//! backstop only**, behind the `classifier` cargo feature (OFF by default). It
//! NEVER gates a verdict and is NEVER in the hot path: the analyzer computes the
//! rule verdict first, and the classifier may only *confirm* it by setting
//! [`aegis_proto::GroomingSignal::classifier_backed`]. There is no LLM anywhere.
//!
//! The trait lets the analyzer stay agnostic: with the feature off, a
//! [`NoClassifier`] is used and `classifier_backed` is always false; with the
//! feature on, an [`OrtGroomingClassifier`] runs a tiny INT8 ONNX model
//! (DistilBERT / MiniLM class, see model-research.md) via `ort`.

use aegis_proto::TextSpan;

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
    use aegis_proto::TextSpan;
    use std::path::Path;
    use std::sync::Mutex;

    use ort::session::{builder::GraphOptimizationLevel, Session};
    use ort::value::Value;

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
}

#[cfg(feature = "classifier")]
pub use ort_impl::{OrtGroomingClassifier, Tokenizer};

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
}
