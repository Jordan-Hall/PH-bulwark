//! The local-execution seam.
//!
//! When the router decides [`Route::Local`](crate::Route::Local) it calls an
//! [`Analyzer`] — the *same* trait the server analyzers implement
//! (`docs/design/interfaces.md`), here used for the on-device **tiny first-pass
//! models**. This crate only ROUTES; it adds no models of its own beyond the
//! small dedicated ones (PLAN §0b: rules-first, small-model-second).
//!
//! Two concrete analyzers live here:
//! * [`NullAnalyzer`] — always available, no model runtime. Returns a
//!   conservative "needs offload / inconclusive" verdict so a build without the
//!   `onnx` feature still satisfies the trait and the router can fall back to
//!   the cluster. Used by the unit tests.
//! * [`OnnxAnalyzer`] — gated behind the **`onnx`** cargo feature; drives a
//!   small quantized ONNX model through [`ort`]: session creation (execution
//!   providers ordered from the `DeviceProfile`), shared bulwark-vision
//!   preprocessing, a real `session.run()`, and vision-convention score →
//!   Verdict mapping. Its unit tests self-skip when no model file is present.
//!
//! The router holds a `dyn Analyzer`, so a real first-pass model from
//! `bulwark-vision`/`-audio`/`-text` can be injected without changing the router.

use async_trait::async_trait;

use bulwark_core::Analyzer;
use bulwark_proto::v1::{AnalysisRequest, Category, MediaKind, Severity, Verdict};

use crate::error::Result;

/// Build the conservative "inconclusive — prefer offload" verdict. Used when no
/// real local model is available for a kind: a low-confidence SAFE verdict whose
/// `rationale` tells the caller to offload. Never fabricates a positive verdict.
fn inconclusive_verdict(req: &AnalysisRequest) -> Verdict {
    Verdict {
        request_id: req.request_id.clone(),
        category: Category::Safe as i32,
        action: bulwark_proto::v1::Action::Log as i32,
        severity: Severity::Info as i32,
        score: 0.0,
        rationale: "no local model for this media kind; offload to cluster".into(),
        evidence: None,
        grooming: None,
        worker_id: "local:null".into(),
        latency_ms: 0,
        ..Default::default()
    }
}

/// An always-available analyzer with no model runtime.
///
/// It declares it handles nothing heavy and returns an inconclusive verdict, so
/// a build without the `onnx` feature still satisfies the [`Analyzer`] trait and
/// the router transparently falls back to the cluster for media it cannot judge.
#[derive(Clone, Debug, Default)]
pub struct NullAnalyzer;

#[async_trait]
impl Analyzer for NullAnalyzer {
    fn handles(&self) -> &[MediaKind] {
        // Handles no heavy media: the router should offload instead.
        &[]
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        Ok(inconclusive_verdict(&req))
    }
}

// ---------------------------------------------------------------------------
// ONNX-backed local analyzer (feature = "onnx").
// ---------------------------------------------------------------------------

/// Real local inference via [`ort`], compiled only with `--features onnx`.
///
/// This is the integration seam for the small dedicated first-pass models. It
/// builds an `ort` session, ordering execution providers best-first from the
/// device's detected capability (`DeviceProfile.exec_providers`, produced by
/// `bulwark-core::detect_device_profile`). The model files themselves are owned
/// and checksum-pinned by the analyzer crates (`bulwark-vision`/`-audio`/`-text`)
/// — this crate only drives the runtime when policy says "local".
#[cfg(feature = "onnx")]
pub mod onnx {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use bulwark_proto::v1::{Action, DeviceProfile, Evidence, ExecutionProvider};
    use bulwark_vision::postprocess::{nsfw_probability, severity_for};
    use bulwark_vision::preprocess::{preprocess, Normalization};
    use ort::session::{builder::GraphOptimizationLevel, Session};
    use ort::value::Tensor as OrtTensor;

    /// Configuration for a local ONNX first-pass model.
    ///
    /// The seam is honest about its contract: it drives **image classifiers
    /// with the same conventions as the live bulwark-vision path** — an NCHW
    /// `f32` input `[1, 3, S, S]` and a 1-logit sigmoid or N-class softmax
    /// output head whose highest-indexed class is the flagged one. The spatial
    /// size `S` is read from the model's input metadata when static, else
    /// `fallback_input_size`. Anything it cannot judge returns the
    /// inconclusive verdict so the router offloads (never a fabricated one).
    #[derive(Clone, Debug)]
    pub struct OnnxConfig {
        /// Path to the quantized `.onnx` model file (checksum-pinned upstream).
        pub model_path: PathBuf,
        /// Stable model id recorded on the verdict for auditability.
        pub model_id: String,
        /// Media kinds this model judges (today: images only — other kinds
        /// return the inconclusive verdict so the router offloads them).
        pub handles: Vec<MediaKind>,
        /// Score at/above which the verdict flags (mirrors bulwark-vision's
        /// default of 0.7).
        pub flag_threshold: f32,
        /// Category emitted when the score crosses `flag_threshold`.
        pub flag_category: Category,
        /// Square input edge used when the model's input shape is dynamic.
        pub fallback_input_size: u32,
        /// Pixel normalization the model was trained with (the shipped ViT
        /// family uses `[-1, 1]` "half" scaling).
        pub norm: Normalization,
    }

    impl OnnxConfig {
        /// The standard first-pass NSFW image profile — same conventions as
        /// bulwark-vision's bundled model: 224 fallback edge, half
        /// normalization, threshold 0.7 → `AdultImage`.
        pub fn nsfw_image(model_path: impl Into<PathBuf>) -> Self {
            Self {
                model_path: model_path.into(),
                model_id: "local-onnx-nsfw".into(),
                handles: vec![MediaKind::Image],
                flag_threshold: 0.7,
                flag_category: Category::AdultImage,
                fallback_input_size: 224,
                norm: Normalization::half(),
            }
        }
    }

    /// An [`Analyzer`] backed by an `ort` session.
    pub struct OnnxAnalyzer {
        cfg: OnnxConfig,
        /// `Session::run` takes `&mut self`; `Analyzer::analyze` takes `&self`.
        /// Same wrap as bulwark-vision's scorer: inference is the bottleneck,
        /// not this lock.
        session: Mutex<Session>,
        /// Resolved square input edge: the model's static H/W when its input
        /// metadata declares one, else `cfg.fallback_input_size`.
        input_size: u32,
    }

    impl OnnxAnalyzer {
        /// Build a session for `cfg`, registering execution providers in the
        /// order the device advertises (`DeviceProfile.exec_providers`). `ort`
        /// silently falls back to CPU if a provider is unavailable, so an
        /// over-optimistic list is safe (see `bulwark-core::exec_providers_for`).
        pub fn new(cfg: OnnxConfig, profile: &DeviceProfile) -> Result<Self> {
            let providers = providers_from_profile(profile);
            let intra_threads = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);
            let session = Session::builder()
                .map_err(|e| ort_err(&cfg, "session builder", e))?
                .with_execution_providers(providers)
                .map_err(|e| ort_err(&cfg, "execution providers", e))?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(|e| ort_err(&cfg, "optimization level", e))?
                .with_intra_threads(intra_threads)
                .map_err(|e| ort_err(&cfg, "intra threads", e))?
                .commit_from_file(&cfg.model_path)
                .map_err(|e| ort_err(&cfg, "load model", e))?;
            let input_size = session
                .inputs()
                .first()
                .and_then(|input| match input.dtype() {
                    ort::value::ValueType::Tensor { shape, .. } => static_square_hw(shape),
                    _ => None,
                })
                .unwrap_or(cfg.fallback_input_size);
            Ok(Self {
                cfg,
                session: Mutex::new(session),
                input_size,
            })
        }

        /// Run one image through the session → flag probability in `[0, 1]`.
        /// Mirrors `bulwark-vision::onnx::OnnxScorer::infer`: shared
        /// preprocessing, bind by the model's actual first input name, first
        /// output as a flat `f32` head → `nsfw_probability`.
        fn infer(&self, image_bytes: &[u8]) -> anyhow::Result<f32> {
            let t = preprocess(image_bytes, self.input_size, self.cfg.norm)?;
            let input = OrtTensor::from_array((t.shape_i64(), t.data))
                .map_err(|e| anyhow::anyhow!("ort: build input tensor: {e}"))?;
            let mut session = self
                .session
                .lock()
                .map_err(|_| anyhow::anyhow!("onnx session mutex poisoned"))?;
            let input_name = session.inputs()[0].name().to_string();
            let outputs = session
                .run(ort::inputs![input_name => input])
                .map_err(|e| anyhow::anyhow!("ort: run: {e}"))?;
            let (_shape, logits) = outputs[0]
                .try_extract_tensor::<f32>()
                .map_err(|e| anyhow::anyhow!("ort: extract output: {e}"))?;
            Ok(nsfw_probability(logits))
        }
    }

    /// Shared `ort`-failure → crate-error mapping (keeps the original
    /// `InferError::Transport` classification).
    fn ort_err(cfg: &OnnxConfig, stage: &str, e: impl std::fmt::Display) -> bulwark_core::Error {
        bulwark_core::Error::from(crate::error::InferError::Transport(format!(
            "ort {stage} for {:?}: {e}",
            cfg.model_path
        )))
    }

    /// The static square spatial edge of a rank-4 NCHW input shape
    /// (`[N, C, S, S]`, `S > 0`), if the model declares one. Dynamic dims are
    /// `-1` in the session metadata → `None` → the configured fallback is used.
    fn static_square_hw(shape: &[i64]) -> Option<u32> {
        match shape {
            [_, _, h, w] if *h > 0 && h == w => Some(*h as u32),
            _ => None,
        }
    }

    /// Inline media bytes, if present. A `MediaRef` points at a side-channel
    /// blob the host resolves before calling a LOCAL analyzer; absent bytes →
    /// inconclusive (offload), never a fabricated verdict.
    fn inline_bytes(req: &AnalysisRequest) -> Option<&[u8]> {
        match req.media.as_ref()? {
            bulwark_proto::v1::analysis_request::Media::InlineMedia(m) => Some(&m.data),
            bulwark_proto::v1::analysis_request::Media::MediaRef(_) => None,
        }
    }

    fn sha256(bytes: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .to_vec()
    }

    /// Map the device's advertised execution providers onto `ort`'s provider
    /// dispatch list, best-first, always ending at CPU.
    fn providers_from_profile(profile: &DeviceProfile) -> Vec<ort::ep::ExecutionProviderDispatch> {
        use ort::ep;
        let mut out: Vec<ep::ExecutionProviderDispatch> = Vec::new();
        for raw in &profile.exec_providers {
            let provider = ExecutionProvider::try_from(*raw).unwrap_or(ExecutionProvider::Cpu);
            match provider {
                ExecutionProvider::Cuda => out.push(ep::CUDAExecutionProvider::default().build()),
                ExecutionProvider::Tensorrt => {
                    out.push(ep::TensorRTExecutionProvider::default().build())
                }
                ExecutionProvider::Directml => {
                    out.push(ep::DirectMLExecutionProvider::default().build())
                }
                ExecutionProvider::Coreml => {
                    out.push(ep::CoreMLExecutionProvider::default().build())
                }
                ExecutionProvider::Nnapi => out.push(ep::NNAPIExecutionProvider::default().build()),
                // QNN / unspecified fall through to the CPU floor below.
                _ => {}
            }
        }
        // CPU is always the final fallback.
        out.push(ep::CPUExecutionProvider::default().build());
        out
    }

    #[async_trait]
    impl Analyzer for OnnxAnalyzer {
        fn handles(&self) -> &[MediaKind] {
            &self.cfg.handles
        }

        async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
            // The seam currently judges IMAGES (bulwark-vision conventions).
            // Anything else is honestly inconclusive → the router offloads.
            if req.media_kind != MediaKind::Image as i32 {
                return Ok(super::inconclusive_verdict(&req));
            }
            let Some(bytes) = inline_bytes(&req) else {
                return Ok(super::inconclusive_verdict(&req));
            };
            let started = std::time::Instant::now();
            let score = match self.infer(bytes) {
                Ok(s) => s,
                Err(e) => {
                    // Conservative: a local failure is INCONCLUSIVE (offload to
                    // the cluster), never a fabricated Safe/positive verdict.
                    tracing::debug!(error = %e, "local onnx inference failed; offloading");
                    return Ok(super::inconclusive_verdict(&req));
                }
            };
            let flagged = score >= self.cfg.flag_threshold;
            // Hash-only evidence (privacy invariant: never raw media).
            let evidence = Evidence {
                sha256: sha256(bytes),
                model_id: self.cfg.model_id.clone(),
                ..Default::default()
            };
            Ok(Verdict {
                request_id: req.request_id,
                category: if flagged {
                    self.cfg.flag_category
                } else {
                    Category::Safe
                } as i32,
                // Blur rather than hard-drop (same as bulwark-vision) so
                // non-flagged context survives; policy remains the authority.
                action: if flagged { Action::Blur } else { Action::Allow } as i32,
                severity: if flagged {
                    severity_for(score)
                } else {
                    Severity::Info
                } as i32,
                score,
                rationale: format!(
                    "local first-pass score {score:.3} vs threshold {:.2}",
                    self.cfg.flag_threshold
                ),
                evidence: Some(evidence),
                worker_id: format!("local:onnx:{}", self.cfg.model_id),
                latency_ms: started.elapsed().as_millis() as u32,
                ..Default::default()
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn static_square_hw_reads_static_nchw_only() {
            assert_eq!(static_square_hw(&[1, 3, 224, 224]), Some(224));
            assert_eq!(static_square_hw(&[-1, 3, 384, 384]), Some(384));
            assert_eq!(static_square_hw(&[1, 3, -1, -1]), None); // dynamic
            assert_eq!(static_square_hw(&[1, 3, 224, 256]), None); // not square
            assert_eq!(static_square_hw(&[3, 224, 224]), None); // wrong rank
        }

        #[test]
        fn nsfw_image_profile_matches_vision_conventions() {
            let cfg = OnnxConfig::nsfw_image("model.onnx");
            assert_eq!(cfg.handles, vec![MediaKind::Image]);
            assert_eq!(cfg.flag_category, Category::AdultImage);
            assert!((cfg.flag_threshold - 0.7).abs() < f32::EPSILON);
            assert_eq!(cfg.fallback_input_size, 224);
        }

        /// Self-skipping live test (the bulwark-vision pattern): exercises the
        /// REAL `session.run()` end to end ONLY when `BULWARK_NSFW_MODEL`
        /// points at an existing file; otherwise it returns early so CI with
        /// no model (and no ONNX Runtime library) still passes.
        #[tokio::test]
        async fn live_model_analyzes_when_present() {
            let Some(path) = std::env::var("BULWARK_NSFW_MODEL")
                .ok()
                .filter(|s| !s.is_empty())
            else {
                eprintln!("skipping: BULWARK_NSFW_MODEL not set");
                return;
            };
            if !std::path::Path::new(&path).is_file() {
                eprintln!("skipping: BULWARK_NSFW_MODEL -> {path} is not a file");
                return;
            }
            let analyzer = match OnnxAnalyzer::new(
                OnnxConfig::nsfw_image(path.as_str()),
                &DeviceProfile::default(),
            ) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("skipping: could not load ONNX Runtime / model: {e}");
                    return;
                }
            };

            // Tiny synthetic PNG → decode → preprocess → run, end to end.
            let mut img = image::RgbImage::new(16, 16);
            for px in img.pixels_mut() {
                *px = image::Rgb([10, 120, 200]);
            }
            let mut png: Vec<u8> = Vec::new();
            {
                use image::ImageEncoder;
                image::codecs::png::PngEncoder::new(&mut png)
                    .write_image(img.as_raw(), 16, 16, image::ExtendedColorType::Rgb8)
                    .expect("encode");
            }
            let req = AnalysisRequest {
                request_id: "req-onnx-live".into(),
                media_kind: MediaKind::Image as i32,
                media: Some(bulwark_proto::v1::analysis_request::Media::InlineMedia(
                    bulwark_proto::v1::InlineMedia {
                        data: png,
                        mime_type: "image/png".into(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            };

            let v = analyzer.analyze(req).await.expect("analyze");
            assert!((0.0..=1.0).contains(&v.score), "score in range: {}", v.score);
            assert!(v.worker_id.starts_with("local:onnx:"), "{}", v.worker_id);
            let ev = v.evidence.expect("hash-only evidence");
            assert_eq!(ev.sha256.len(), 32);
            assert!(ev.safe_thumbnail.is_empty(), "never raw media in evidence");

            // Non-image kinds stay inconclusive → the router offloads them.
            let text = AnalysisRequest {
                request_id: "req-text".into(),
                media_kind: MediaKind::Text as i32,
                ..Default::default()
            };
            let v = analyzer.analyze(text).await.expect("analyze");
            assert!(v.rationale.contains("offload"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::AnalysisBatch;

    fn text_request() -> AnalysisRequest {
        AnalysisRequest {
            request_id: "req-1".into(),
            media_kind: MediaKind::Text as i32,
            source_channel: bulwark_proto::v1::SourceChannel::Web as i32,
            device_id: "dev-1".into(),
            ts: 0,
            text_span: None,
            media: None,
            deadline_ms: 0,
        }
    }

    #[tokio::test]
    async fn null_analyzer_returns_inconclusive_safe_verdict() {
        let a = NullAnalyzer;
        assert!(a.handles().is_empty());
        let v = a.analyze(text_request()).await.unwrap();
        assert_eq!(v.category, Category::Safe as i32);
        assert_eq!(v.score, 0.0);
        assert!(v.rationale.contains("offload"));
        assert!(v.evidence.is_none());
    }

    #[tokio::test]
    async fn null_analyzer_batch_is_sequential() {
        let a = NullAnalyzer;
        let batch = AnalysisBatch {
            requests: vec![text_request(), text_request()],
        };
        let out = a.analyze_batch(batch).await.unwrap();
        assert_eq!(out.verdicts.len(), 2);
    }
}
