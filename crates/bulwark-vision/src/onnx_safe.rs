//! Fail-closed, bounded-concurrent public ONNX scorer.
//!
//! Each ONNX Runtime session still has its own internal mutex, but independent
//! requests are distributed over a small session pool instead of serializing all
//! image decisions through one process-wide lock. Decode/inference failures remain
//! explicit coverage gaps (NaN to the caller), never a false zero-risk score.

#[path = "onnx.rs"]
mod inner;

pub use inner::ExecProviderMode;

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::preprocess::Normalization;
use crate::Scorer;

const MAX_SESSION_POOL: usize = 4;

/// Error-aware ONNX NSFW scorer with bounded request concurrency.
pub struct OnnxScorer {
    scorers: Vec<inner::OnnxScorer>,
    next: AtomicUsize,
}

impl OnnxScorer {
    fn pool_size() -> usize {
        std::env::var("BULWARK_NSFW_SESSIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|value| if value.get() >= 4 { 2 } else { 1 })
                    .unwrap_or(1)
            })
            .clamp(1, MAX_SESSION_POOL)
    }

    fn build_pool(
        mut build: impl FnMut() -> anyhow::Result<inner::OnnxScorer>,
    ) -> anyhow::Result<Self> {
        let first = build()?;
        let target = Self::pool_size();
        let mut scorers = Vec::with_capacity(target);
        scorers.push(first);
        while scorers.len() < target {
            match build() {
                Ok(scorer) => scorers.push(scorer),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        requested = target,
                        active = scorers.len(),
                        "could not create another ONNX session; continuing with smaller pool"
                    );
                    break;
                }
            }
        }
        tracing::info!(sessions = scorers.len(), "ONNX image session pool ready");
        Ok(Self {
            scorers,
            next: AtomicUsize::new(0),
        })
    }

    fn selected(&self) -> &inner::OnnxScorer {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.scorers.len();
        &self.scorers[index]
    }

    /// Load an ONNX model using ImageNet normalization.
    pub fn load(model_path: &str, input_size: u32) -> anyhow::Result<Self> {
        Self::build_pool(|| inner::OnnxScorer::load(model_path, input_size))
    }

    /// Load an ONNX model with explicit normalization.
    pub fn load_with(
        model_path: &str,
        input_size: u32,
        norm: Normalization,
    ) -> anyhow::Result<Self> {
        Self::build_pool(|| inner::OnnxScorer::load_with(model_path, input_size, norm))
    }

    /// Load an ONNX model with an explicit execution-provider mode.
    pub fn load_with_ep(
        model_path: &str,
        input_size: u32,
        norm: Normalization,
        mode: ExecProviderMode,
    ) -> anyhow::Result<Self> {
        Self::build_pool(|| inner::OnnxScorer::load_with_ep(model_path, input_size, norm, mode))
    }

    /// Load an embedded/in-memory ONNX model.
    pub fn load_from_bytes(
        bytes: &[u8],
        input_size: u32,
        norm: Normalization,
    ) -> anyhow::Result<Self> {
        Self::build_pool(|| inner::OnnxScorer::load_from_bytes(bytes, input_size, norm))
    }

    /// Load from the configured model path/environment.
    pub fn from_env(input_size: u32) -> anyhow::Result<Self> {
        Self::build_pool(|| inner::OnnxScorer::from_env(input_size))
    }

    /// Load from an already-resolved model path using environment tuning.
    pub fn from_path_env(model_path: &str, default_input_size: u32) -> anyhow::Result<Self> {
        Self::build_pool(|| inner::OnnxScorer::from_path_env(model_path, default_input_size))
    }

    /// Score while preserving decode/inference errors.
    pub fn try_score(&self, image_bytes: &[u8]) -> anyhow::Result<f32> {
        self.selected().try_score(image_bytes)
    }
}

impl Scorer for OnnxScorer {
    fn score(&self, image_bytes: &[u8]) -> f32 {
        match self.try_score(image_bytes) {
            Ok(score) if score.is_finite() => score,
            Ok(_) => {
                tracing::warn!(
                    "ONNX image scorer returned a non-finite score; treating as uncovered"
                );
                f32::NAN
            }
            Err(error) => {
                tracing::debug!(%error, "ONNX image decode/inference failed; treating as uncovered");
                f32::NAN
            }
        }
    }

    fn model_id(&self) -> &str {
        self.scorers
            .first()
            .expect("ONNX scorer pool always contains at least one session")
            .model_id()
    }
}
