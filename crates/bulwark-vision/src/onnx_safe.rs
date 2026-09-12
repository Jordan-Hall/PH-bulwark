//! Fail-closed public ONNX scorer wrapper.
//!
//! The legacy implementation is kept as the session/runtime engine, but its
//! `Scorer::score` compatibility path maps decode/inference errors to `0.0`.
//! This wrapper uses the engine's error-aware `try_score` API and returns NaN on
//! failure. Every Bulwark policy-facing caller treats a non-finite score as an
//! explicit coverage gap, never as a safe image.

#[path = "onnx.rs"]
mod inner;

pub use inner::ExecProviderMode;

use crate::preprocess::Normalization;
use crate::Scorer;

/// Error-aware ONNX NSFW scorer.
pub struct OnnxScorer(inner::OnnxScorer);

impl OnnxScorer {
    /// Load an ONNX model using ImageNet normalization.
    pub fn load(model_path: &str, input_size: u32) -> anyhow::Result<Self> {
        inner::OnnxScorer::load(model_path, input_size).map(Self)
    }

    /// Load an ONNX model with explicit normalization.
    pub fn load_with(
        model_path: &str,
        input_size: u32,
        norm: Normalization,
    ) -> anyhow::Result<Self> {
        inner::OnnxScorer::load_with(model_path, input_size, norm).map(Self)
    }

    /// Load an ONNX model with an explicit execution-provider mode.
    pub fn load_with_ep(
        model_path: &str,
        input_size: u32,
        norm: Normalization,
        mode: ExecProviderMode,
    ) -> anyhow::Result<Self> {
        inner::OnnxScorer::load_with_ep(model_path, input_size, norm, mode).map(Self)
    }

    /// Load an embedded/in-memory ONNX model.
    pub fn load_from_bytes(
        bytes: &[u8],
        input_size: u32,
        norm: Normalization,
    ) -> anyhow::Result<Self> {
        inner::OnnxScorer::load_from_bytes(bytes, input_size, norm).map(Self)
    }

    /// Load from the configured model path/environment.
    pub fn from_env(input_size: u32) -> anyhow::Result<Self> {
        inner::OnnxScorer::from_env(input_size).map(Self)
    }

    /// Load from an already-resolved model path using environment tuning.
    pub fn from_path_env(model_path: &str, default_input_size: u32) -> anyhow::Result<Self> {
        inner::OnnxScorer::from_path_env(model_path, default_input_size).map(Self)
    }

    /// Score while preserving decode/inference errors.
    pub fn try_score(&self, image_bytes: &[u8]) -> anyhow::Result<f32> {
        self.0.try_score(image_bytes)
    }
}

impl Scorer for OnnxScorer {
    fn score(&self, image_bytes: &[u8]) -> f32 {
        match self.0.try_score(image_bytes) {
            Ok(score) if score.is_finite() => score,
            Ok(_) => {
                tracing::warn!("ONNX image scorer returned a non-finite score; treating as uncovered");
                f32::NAN
            }
            Err(error) => {
                tracing::debug!(%error, "ONNX image decode/inference failed; treating as uncovered");
                f32::NAN
            }
        }
    }

    fn model_id(&self) -> &str {
        self.0.model_id()
    }
}
