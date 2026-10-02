//! bulwark-vision — small dedicated NSFW image/frame classifier.
//!
//! Implements the `Analyzer` contract for `MediaKind::IMAGE`. Production ONNX
//! scoring is fail-closed: a missing model, absent inline image, decoder failure,
//! inference error, or non-finite score is `Category::Unspecified` + BLOCK, never
//! a false SAFE verdict. Evidence is hash-only; raw images are never attached.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bulwark_core::{Analyzer, Result};
use bulwark_proto::v1::{
    analysis_request::Media, Action, AnalysisRequest, Category, Evidence, MediaKind, Severity,
    Verdict,
};
use std::path::PathBuf;

pub mod postprocess;
pub mod preprocess;

/// Environment variable holding the filesystem path to the ONNX NSFW model.
pub const MODEL_PATH_ENV: &str = "BULWARK_NSFW_MODEL";
/// Optional per-install model path configuration file.
pub const MODEL_PATH_CONFIG_FILE: &str = "nsfw_model.txt";

/// Scores image bytes to an NSFW probability. Non-finite values mean coverage
/// failed and are handled conservatively by [`VisionAnalyzer`].
pub trait Scorer: Send + Sync {
    fn score(&self, image_bytes: &[u8]) -> f32;
    fn model_id(&self) -> &str;
}

impl Scorer for Box<dyn Scorer> {
    fn score(&self, image_bytes: &[u8]) -> f32 {
        (**self).score(image_bytes)
    }
    fn model_id(&self) -> &str {
        (**self).model_id()
    }
}

/// No-model sentinel. The analyzer recognizes this id and emits an uncovered
/// blocking verdict rather than trusting the numeric zero.
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
    /// NSFW score at/above which content is acted on.
    pub nsfw_threshold: f32,
    /// Optional ONNX model path.
    pub model_path: Option<String>,
    /// Square input size expected by the model.
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
    /// Build the best configured scorer. If a real scorer cannot be constructed,
    /// the stub remains explicit and analysis fail-closes at verdict time.
    pub fn from_env(mut cfg: VisionConfig) -> Self {
        if cfg.model_path.is_none() {
            cfg.model_path = model_path_from_env_or_config();
        }
        let scorer = build_scorer(&cfg);
        Self { cfg, scorer }
    }
}

/// Resolve the configured NSFW model path from env or per-install config.
pub fn model_path_from_env_or_config() -> Option<String> {
    std::env::var(MODEL_PATH_ENV)
        .ok()
        .and_then(non_empty)
        .or_else(|| read_config_value(MODEL_PATH_CONFIG_FILE))
}

fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn read_config_value(file_name: &str) -> Option<String> {
    let path = bulwark_config_dir()?.join(file_name);
    let value = std::fs::read_to_string(path).ok()?;
    non_empty(value)
}

fn bulwark_config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|base| base.join("Bulwark"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|base| base.join("bulwark"))
    }
}

#[cfg(feature = "onnx")]
const BUNDLED_NSFW_MODEL: &[u8] = include_bytes!("../models/nsfw_detector.onnx");
#[cfg(feature = "onnx")]
const BUNDLED_NSFW_INPUT_SIZE: u32 = 384;

fn build_scorer(cfg: &VisionConfig) -> Box<dyn Scorer> {
    #[cfg(feature = "onnx")]
    {
        if let Some(path) = cfg.model_path.as_deref() {
            match onnx::OnnxScorer::from_path_env(path, cfg.input_size) {
                Ok(scorer) => {
                    tracing::info!(model = %path, "loaded configured ONNX NSFW model");
                    return Box::new(scorer);
                }
                Err(error) => log_fallback_once(&format!(
                    "failed to load ONNX model from {path}: {error}; trying bundled model"
                )),
            }
        }
        match onnx::OnnxScorer::load_from_bytes(
            BUNDLED_NSFW_MODEL,
            BUNDLED_NSFW_INPUT_SIZE,
            crate::preprocess::Normalization::half(),
        ) {
            Ok(scorer) => {
                tracing::info!("loaded bundled NSFW model");
                return Box::new(scorer);
            }
            Err(error) => log_fallback_once(&format!(
                "bundled NSFW model could not load: {error}; image coverage will fail closed"
            )),
        }
    }
    #[cfg(not(feature = "onnx"))]
    {
        let _ = cfg;
        log_fallback_once("built without ONNX image scoring; image coverage will fail closed");
    }
    Box::new(StubScorer)
}

fn log_fallback_once(message: &str) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| tracing::warn!("bulwark-vision: {message}"));
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn extract_bytes(req: &AnalysisRequest) -> Option<&[u8]> {
    match req.media.as_ref()? {
        Media::InlineMedia(media) => Some(&media.data),
        Media::MediaRef(_) => None,
    }
}

fn uncovered(request_id: String, rationale: impl Into<String>) -> Verdict {
    Verdict {
        request_id,
        category: Category::Unspecified as i32,
        action: Action::Block as i32,
        severity: Severity::Medium as i32,
        score: 0.0,
        rationale: rationale.into(),
        ..Default::default()
    }
}

#[async_trait]
impl<S: Scorer> Analyzer for VisionAnalyzer<S> {
    fn handles(&self) -> &[MediaKind] {
        const KINDS: [MediaKind; 1] = [MediaKind::Image];
        &KINDS
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        if self.scorer.model_id() == "stub-noop" {
            return Ok(uncovered(
                req.request_id,
                "no real image model is loaded; content was not scored",
            ));
        }
        let Some(bytes) = extract_bytes(&req) else {
            return Ok(uncovered(
                req.request_id,
                "image payload was not available inline to the analyzer",
            ));
        };
        if bytes.is_empty() {
            return Ok(uncovered(req.request_id, "image payload was empty"));
        }

        let score = self.scorer.score(bytes);
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Ok(uncovered(
                req.request_id,
                "image decode or model inference failed; content was not scored",
            ));
        }

        let nsfw = score >= self.cfg.nsfw_threshold;
        let evidence = Evidence {
            sha256: sha256(bytes),
            model_id: self.scorer.model_id().to_string(),
            ..Default::default()
        };
        Ok(Verdict {
            request_id: req.request_id,
            category: if nsfw {
                Category::AdultImage
            } else {
                Category::Safe
            } as i32,
            action: if nsfw { Action::Blur } else { Action::Allow } as i32,
            severity: if nsfw {
                postprocess::severity_for(score)
            } else {
                Severity::Info
            } as i32,
            score,
            rationale: format!(
                "nsfw score {score:.3} vs threshold {:.2}",
                self.cfg.nsfw_threshold
            ),
            evidence: Some(evidence),
            ..Default::default()
        })
    }
}

#[cfg(feature = "onnx")]
#[path = "onnx_safe.rs"]
pub mod onnx;

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::InlineMedia;

    struct AlwaysNsfw;
    impl Scorer for AlwaysNsfw {
        fn score(&self, _: &[u8]) -> f32 {
            0.95
        }
        fn model_id(&self) -> &str {
            "test"
        }
    }

    struct BrokenScorer;
    impl Scorer for BrokenScorer {
        fn score(&self, _: &[u8]) -> f32 {
            f32::NAN
        }
        fn model_id(&self) -> &str {
            "broken"
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
    async fn flags_nsfw_and_keeps_hash_only_evidence() {
        let analyzer = VisionAnalyzer::with_scorer(VisionConfig::default(), AlwaysNsfw);
        let verdict = analyzer.analyze(img_req(vec![1, 2, 3])).await.unwrap();
        assert_eq!(verdict.category, Category::AdultImage as i32);
        assert_eq!(verdict.action, Action::Blur as i32);
        let evidence = verdict.evidence.unwrap();
        assert_eq!(evidence.sha256.len(), 32);
        assert!(evidence.safe_thumbnail.is_empty());
    }

    #[tokio::test]
    async fn stub_and_model_errors_are_never_safe() {
        let stub = VisionAnalyzer::new();
        let verdict = stub.analyze(img_req(vec![9, 9])).await.unwrap();
        assert_eq!(verdict.category(), Category::Unspecified);
        assert_eq!(verdict.action(), Action::Block);

        let broken = VisionAnalyzer::with_scorer(VisionConfig::default(), BrokenScorer);
        let verdict = broken.analyze(img_req(vec![1])).await.unwrap();
        assert_eq!(verdict.category(), Category::Unspecified);
        assert_eq!(verdict.action(), Action::Block);
    }

    #[tokio::test]
    async fn missing_inline_image_is_never_safe() {
        let analyzer = VisionAnalyzer::with_scorer(VisionConfig::default(), AlwaysNsfw);
        let verdict = analyzer
            .analyze(AnalysisRequest {
                request_id: "missing".into(),
                media_kind: MediaKind::Image as i32,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(verdict.category(), Category::Unspecified);
        assert_eq!(verdict.action(), Action::Block);
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn bundled_model_loads_and_scores_a_real_image() {
        use image::Rgb;
        let buffer = image::ImageBuffer::from_pixel(48, 48, Rgb([130u8, 110, 90]));
        let mut png = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(buffer)
            .write_to(&mut png, image::ImageFormat::Png)
            .unwrap();
        let scorer = onnx::OnnxScorer::load_from_bytes(
            BUNDLED_NSFW_MODEL,
            BUNDLED_NSFW_INPUT_SIZE,
            crate::preprocess::Normalization::half(),
        )
        .expect("bundled model must load");
        let score = scorer.score(&png.into_inner());
        assert!((0.0..=1.0).contains(&score), "score out of range: {score}");
    }
}
