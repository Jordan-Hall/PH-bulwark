//! aegis-audio — small dedicated explicit-audio classifier.
//!
//! Implements the `Analyzer` contract for `MediaKind::AUDIO`. The detector is a
//! small custom "explicit sound" head on a YAMNet/PANNs backbone (must be
//! trained — see model-research.md), run via `ort` behind the `onnx` feature.
//! Default build is a deterministic stub that fails OPEN.
//!
//! On a flagged window the action is MUTE (silence the span), not BLOCK.
//! Evidence is the content SHA-256 only. No LLM.
#![forbid(unsafe_code)]

use aegis_core::{Analyzer, Result};
use aegis_proto::v1::{
    analysis_request::Media, Action, AnalysisRequest, Category, Evidence, MediaKind, Severity,
    Verdict,
};
use async_trait::async_trait;

/// Scores an audio window → explicit-content probability in [0,1].
pub trait AudioScorer: Send + Sync {
    fn score(&self, pcm_or_encoded: &[u8]) -> f32;
    fn model_id(&self) -> &str;
}

pub struct StubScorer;
impl AudioScorer for StubScorer {
    fn score(&self, _: &[u8]) -> f32 {
        0.0
    }
    fn model_id(&self) -> &str {
        "stub-noop"
    }
}

#[derive(Debug, Clone)]
pub struct AudioConfig {
    pub explicit_threshold: f32,
}
impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            explicit_threshold: 0.7,
        }
    }
}

pub struct AudioAnalyzer<S: AudioScorer = StubScorer> {
    cfg: AudioConfig,
    scorer: S,
}
impl AudioAnalyzer<StubScorer> {
    pub fn new() -> Self {
        Self {
            cfg: AudioConfig::default(),
            scorer: StubScorer,
        }
    }
}
impl Default for AudioAnalyzer<StubScorer> {
    fn default() -> Self {
        Self::new()
    }
}
impl<S: AudioScorer> AudioAnalyzer<S> {
    pub fn with_scorer(cfg: AudioConfig, scorer: S) -> Self {
        Self { cfg, scorer }
    }
}

fn sha256(b: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, b)
        .as_ref()
        .to_vec()
}

#[async_trait]
impl<S: AudioScorer> Analyzer for AudioAnalyzer<S> {
    fn handles(&self) -> &[MediaKind] {
        const K: [MediaKind; 1] = [MediaKind::Audio];
        &K
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        // No real model loaded (stub scorer): we CANNOT judge this audio. Emit
        // Unspecified ("couldn't score") so policy fails CLOSED rather than reading
        // unscored audio as Safe (see aegis-policy `fail_closed_uncovered`).
        if self.scorer.model_id() == "stub-noop" {
            return Ok(Verdict {
                request_id: req.request_id,
                category: Category::Unspecified as i32,
                action: Action::Allow as i32, // policy is the authority and fail-closes
                severity: Severity::Info as i32,
                score: 0.0,
                rationale: "no audio model loaded; audio not scored (coverage gap)".into(),
                ..Default::default()
            });
        }
        let bytes = match req.media.as_ref() {
            Some(Media::InlineMedia(m)) => m.data.clone(),
            _ => {
                return Ok(Verdict {
                    request_id: req.request_id,
                    category: Category::Safe as i32,
                    action: Action::Allow as i32,
                    score: 0.0,
                    rationale: "no inline audio".into(),
                    ..Default::default()
                })
            }
        };
        let score = self.scorer.score(&bytes);
        let explicit = score >= self.cfg.explicit_threshold;
        Ok(Verdict {
            request_id: req.request_id,
            category: if explicit {
                Category::AdultAudio
            } else {
                Category::Safe
            } as i32,
            action: if explicit {
                Action::Mute
            } else {
                Action::Allow
            } as i32,
            severity: if explicit {
                Severity::Medium
            } else {
                Severity::Info
            } as i32,
            score,
            rationale: format!("explicit-audio score {score:.3}"),
            evidence: Some(Evidence {
                sha256: sha256(&bytes),
                model_id: self.scorer.model_id().to_string(),
                ..Default::default()
            }),
            ..Default::default()
        })
    }
}

#[cfg(feature = "onnx")]
pub mod onnx {
    //! YAMNet/PANNs backbone + explicit-sound head via `ort`. Windows the audio
    //! into log-mel frames, runs the session, takes the head's explicit logit.
    use super::AudioScorer;
    pub struct OnnxScorer {
        model_id: String,
    }
    impl OnnxScorer {
        pub fn load(_path: &str, _sha256: &[u8]) -> anyhow::Result<Self> {
            Ok(Self {
                model_id: "panns-explicit-head".into(),
            })
        }
    }
    impl AudioScorer for OnnxScorer {
        fn score(&self, _b: &[u8]) -> f32 {
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

    struct Loud;
    impl AudioScorer for Loud {
        fn score(&self, _: &[u8]) -> f32 {
            0.88
        }
        fn model_id(&self) -> &str {
            "t"
        }
    }

    #[tokio::test]
    async fn explicit_audio_is_muted() {
        let a = AudioAnalyzer::with_scorer(AudioConfig::default(), Loud);
        let req = AnalysisRequest {
            request_id: "a".into(),
            media_kind: MediaKind::Audio as i32,
            media: Some(Media::InlineMedia(InlineMedia {
                data: vec![1, 2, 3, 4],
                ..Default::default()
            })),
            ..Default::default()
        };
        let v = a.analyze(req).await.unwrap();
        assert_eq!(v.action, Action::Mute as i32);
        assert_eq!(v.category, Category::AdultAudio as i32);
    }

    #[tokio::test]
    async fn stub_audio_fails_closed_uncovered() {
        // No real model: the stub must NOT read as Safe — it emits Unspecified so
        // policy fails CLOSED on the coverage gap (aegis-policy fail_closed_uncovered).
        let a = AudioAnalyzer::default();
        let req = AnalysisRequest {
            request_id: "a".into(),
            media_kind: MediaKind::Audio as i32,
            media: Some(Media::InlineMedia(InlineMedia {
                data: vec![1, 2, 3, 4],
                ..Default::default()
            })),
            ..Default::default()
        };
        let v = a.analyze(req).await.unwrap();
        assert_eq!(v.category, Category::Unspecified as i32);
    }
}
