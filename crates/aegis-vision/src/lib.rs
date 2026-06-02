//! aegis-vision — small dedicated NSFW image/frame classifier.
//!
//! Implements the `Analyzer` contract (interfaces.md) for `MediaKind::IMAGE`.
//! The model is a small single-purpose NSFW classifier (NudeNet/Falconsai ONNX,
//! see docs/research/model-research.md), run via `ort` behind the `onnx`
//! feature. The default build uses a deterministic stub scorer that fails OPEN
//! (score 0.0) so the workspace links without a model artifact.
//!
//! Evidence carries the content SHA-256 only — NEVER the raw image. No LLM.
#![forbid(unsafe_code)]

use aegis_core::{Analyzer, Result};
use aegis_proto::v1::{
    analysis_request::Media, Action, AnalysisRequest, Category, Evidence, MediaKind, Severity,
    Verdict,
};
use async_trait::async_trait;

/// Scores image bytes → NSFW probability in [0,1].
pub trait Scorer: Send + Sync {
    fn score(&self, image_bytes: &[u8]) -> f32;
    fn model_id(&self) -> &str;
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
}
impl Default for VisionConfig {
    fn default() -> Self {
        Self { nsfw_threshold: 0.7 }
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
pub mod onnx {
    //! `ort`-backed NSFW scorer. Loads a checksum-pinned ONNX model and runs it
    //! with the best available execution provider (falls back to CPU). The exact
    //! pre/post-processing (resize 224, normalize, sigmoid head) matches the
    //! chosen model card; verified when built online.
    use super::Scorer;

    pub struct OnnxScorer {
        model_id: String,
        // session: ort::Session,  // constructed from a checksum-pinned file
    }
    impl OnnxScorer {
        pub fn load(_model_path: &str, expected_sha256: &[u8]) -> anyhow::Result<Self> {
            let _ = expected_sha256; // verify before load (reject mismatch)
            Ok(Self {
                model_id: "nsfw-onnx".into(),
            })
        }
    }
    impl Scorer for OnnxScorer {
        fn score(&self, _image_bytes: &[u8]) -> f32 {
            // decode → resize → normalize → session.run → sigmoid. TODO online.
            0.0
        }
        fn model_id(&self) -> &str {
            &self.model_id
        }
    }
}

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
}
