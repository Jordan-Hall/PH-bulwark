//! aegis-vision — small dedicated NSFW image/frame classifier.
//!
//! Implements the `Analyzer` contract (interfaces.md) for `MediaKind::IMAGE`.
//! The model is a small single-purpose NSFW classifier (e.g. Falconsai's
//! `nsfw_image_detection` exported to ONNX, or NudeNet — see
//! docs/research/model-research.md), run via the `ort` crate (ONNX Runtime)
//! behind the optional `onnx` feature.
//!
//! ## Default build (no `ort`)
//! The default build does NOT depend on ONNX Runtime. It uses [`StubScorer`],
//! which fails **OPEN** (score 0.0 → SAFE/Allow) so the workspace links and the
//! tests run with no model artifact and no `onnxruntime.dll`. This is deliberate:
//! the build host enforces Smart App Control, which can block loading the ONNX
//! Runtime native library (the same environmental block that affected SQLite).
//!
//! ## Real classification (`--features onnx`)
//! Enabling the `onnx` feature compiles [`onnx::OnnxScorer`], which loads an
//! ONNX model from a path and runs it on the CPU execution provider,
//! deterministically. See the crate `README.md` for where to drop a model and
//! the environment variable to point at it.
//!
//! Evidence carries the content SHA-256 only — NEVER the raw image. No LLM.
#![forbid(unsafe_code)]

use aegis_core::{Analyzer, Result};
use aegis_proto::v1::{
    analysis_request::Media, Action, AnalysisRequest, Category, Evidence, MediaKind, Severity,
    Verdict,
};
use async_trait::async_trait;

pub mod preprocess;

/// Environment variable holding the filesystem path to the ONNX NSFW model.
/// Consulted by [`VisionAnalyzer::from_env`] (and [`onnx::OnnxScorer::from_env`]).
pub const MODEL_PATH_ENV: &str = "AEGIS_NSFW_MODEL";

/// Scores image bytes → NSFW probability in `[0, 1]`.
pub trait Scorer: Send + Sync {
    fn score(&self, image_bytes: &[u8]) -> f32;
    fn model_id(&self) -> &str;
}

/// So a `Box<dyn Scorer>` (used by [`VisionAnalyzer::from_env`]) is itself a
/// `Scorer` and can fill the analyzer's generic slot.
impl Scorer for Box<dyn Scorer> {
    fn score(&self, image_bytes: &[u8]) -> f32 {
        (**self).score(image_bytes)
    }
    fn model_id(&self) -> &str {
        (**self).model_id()
    }
}

/// Default scorer: fails open (0.0). Real scoring needs `--features onnx`.
pub struct StubScorer;
impl Scorer for StubScorer {
    fn score(&self, _image_bytes: &[u8]) -> f32 {
        0.0
    }
    fn model_id(&self) -> &str {
        "stub-noop"
    }
}

#[derive(Debug, Clone)]
pub struct VisionConfig {
    /// NSFW score at/above which we act. Tuned per deployment.
    pub nsfw_threshold: f32,
    /// Optional path to the ONNX model. When `None`, [`MODEL_PATH_ENV`] is
    /// consulted by the env constructors. Ignored unless the `onnx` feature is
    /// enabled (the stub scorer never loads a model).
    pub model_path: Option<String>,
    /// Square edge (pixels) the input image is resized to before inference.
    /// 224 matches the common ViT/MobileNet NSFW model cards.
    pub input_size: u32,
}
impl Default for VisionConfig {
    fn default() -> Self {
        Self {
            nsfw_threshold: 0.7,
            model_path: None,
            input_size: 224,
        }
    }
}

pub struct VisionAnalyzer<S: Scorer = StubScorer> {
    cfg: VisionConfig,
    scorer: S,
}

impl VisionAnalyzer<StubScorer> {
    pub fn new() -> Self {
        Self {
            cfg: VisionConfig::default(),
            scorer: StubScorer,
        }
    }
}
impl Default for VisionAnalyzer<StubScorer> {
    fn default() -> Self {
        Self::new()
    }
}
impl<S: Scorer> VisionAnalyzer<S> {
    pub fn with_scorer(cfg: VisionConfig, scorer: S) -> Self {
        Self { cfg, scorer }
    }
}

impl VisionAnalyzer<Box<dyn Scorer>> {
    /// Build an analyzer using the best scorer available for this build:
    ///
    /// * With the `onnx` feature **and** a model configured (via
    ///   `cfg.model_path` or the [`MODEL_PATH_ENV`] env var) that loads
    ///   successfully → a real [`onnx::OnnxScorer`].
    /// * Otherwise → the deterministic [`StubScorer`] that fails OPEN. A single
    ///   warning is logged the first time we fall back, so default builds and
    ///   tests need no model and stay quiet.
    ///
    /// This never returns an error: an unloadable/missing model degrades to the
    /// safe stub rather than failing the analyzer construction.
    pub fn from_env(mut cfg: VisionConfig) -> Self {
        if cfg.model_path.is_none() {
            cfg.model_path = std::env::var(MODEL_PATH_ENV).ok().filter(|s| !s.is_empty());
        }
        let scorer = build_scorer(&cfg);
        Self { cfg, scorer }
    }
}

/// Selects the scorer for the current build/config, logging the fallback once.
fn build_scorer(cfg: &VisionConfig) -> Box<dyn Scorer> {
    #[cfg(feature = "onnx")]
    {
        if let Some(path) = cfg.model_path.as_deref() {
            match onnx::OnnxScorer::load(path, cfg.input_size) {
                Ok(s) => {
                    tracing::info!(model = %path, "aegis-vision: loaded ONNX NSFW model");
                    return Box::new(s);
                }
                Err(e) => {
                    log_fallback_once(&format!(
                        "failed to load ONNX model from {path}: {e}; failing OPEN (stub)"
                    ));
                    return Box::new(StubScorer);
                }
            }
        }
        log_fallback_once(&format!(
            "no NSFW model configured ({MODEL_PATH_ENV} unset / model_path None); failing OPEN (stub)"
        ));
    }
    #[cfg(not(feature = "onnx"))]
    {
        let _ = cfg;
        log_fallback_once(
            "built without the `onnx` feature; NSFW scoring fails OPEN (stub). \
             Rebuild with --features onnx and set AEGIS_NSFW_MODEL for real scoring.",
        );
    }
    Box::new(StubScorer)
}

fn log_fallback_once(msg: &str) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| tracing::warn!("aegis-vision: {msg}"));
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn extract_bytes(req: &AnalysisRequest) -> Option<&[u8]> {
    match req.media.as_ref()? {
        Media::InlineMedia(m) => Some(&m.data),
        // MediaRef points at a side-channel blob; the server resolves it before
        // calling the analyzer in a full deployment.
        Media::MediaRef(_) => None,
    }
}

fn severity_for(score: f32) -> Severity {
    if score >= 0.9 {
        Severity::High
    } else if score >= 0.7 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[async_trait]
impl<S: Scorer> Analyzer for VisionAnalyzer<S> {
    fn handles(&self) -> &[MediaKind] {
        const K: [MediaKind; 1] = [MediaKind::Image];
        &K
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        let Some(bytes) = extract_bytes(&req) else {
            return Ok(Verdict {
                request_id: req.request_id,
                category: Category::Safe as i32,
                action: Action::Allow as i32,
                severity: Severity::Info as i32,
                score: 0.0,
                rationale: "no inline image (MediaRef resolved server-side)".into(),
                ..Default::default()
            });
        };
        let score = self.scorer.score(bytes);
        let nsfw = score >= self.cfg.nsfw_threshold;
        let evidence = Evidence {
            sha256: sha256(bytes),
            model_id: self.scorer.model_id().to_string(),
            ..Default::default()
        };
        Ok(Verdict {
            request_id: req.request_id,
            category: if nsfw { Category::AdultImage } else { Category::Safe } as i32,
            // Blur the frame rather than hard-drop, so non-flagged context survives.
            action: if nsfw { Action::Blur } else { Action::Allow } as i32,
            severity: if nsfw { severity_for(score) } else { Severity::Info } as i32,
            score,
            rationale: format!("nsfw score {score:.3} vs threshold {:.2}", self.cfg.nsfw_threshold),
            evidence: Some(evidence),
            ..Default::default()
        })
    }
}

#[cfg(feature = "onnx")]
pub mod onnx;

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::v1::InlineMedia;

    struct AlwaysNsfw;
    impl Scorer for AlwaysNsfw {
        fn score(&self, _: &[u8]) -> f32 {
            0.95
        }
        fn model_id(&self) -> &str {
            "test"
        }
    }

    fn img_req(bytes: Vec<u8>) -> AnalysisRequest {
        AnalysisRequest {
            request_id: "r1".into(),
            media_kind: MediaKind::Image as i32,
            media: Some(Media::InlineMedia(InlineMedia {
                data: bytes,
                mime_type: "image/jpeg".into(),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn flags_nsfw_and_blurs_with_hash_only() {
        let a = VisionAnalyzer::with_scorer(VisionConfig::default(), AlwaysNsfw);
        let v = a.analyze(img_req(vec![1, 2, 3])).await.unwrap();
        assert_eq!(v.category, Category::AdultImage as i32);
        assert_eq!(v.action, Action::Blur as i32);
        let ev = v.evidence.unwrap();
        assert_eq!(ev.sha256.len(), 32, "sha256 present");
        assert!(ev.safe_thumbnail.is_empty(), "never raw image in evidence");
    }

    #[tokio::test]
    async fn stub_fails_open_safe() {
        let a = VisionAnalyzer::new();
        let v = a.analyze(img_req(vec![9, 9])).await.unwrap();
        assert_eq!(v.category, Category::Safe as i32);
        assert_eq!(v.action, Action::Allow as i32);
    }

    #[tokio::test]
    async fn from_env_without_model_fails_open() {
        // No `onnx` feature and/or no model → stub → SAFE/Allow.
        let a = VisionAnalyzer::from_env(VisionConfig::default());
        let v = a.analyze(img_req(vec![4, 5, 6])).await.unwrap();
        assert_eq!(v.category, Category::Safe as i32);
        assert_eq!(v.action, Action::Allow as i32);
    }
}
