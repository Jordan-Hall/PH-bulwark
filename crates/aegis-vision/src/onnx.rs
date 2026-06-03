//! `ort`-backed NSFW scorer (ONNX Runtime).
//!
//! Compiled only with `--features onnx`. Loads a single-purpose NSFW ONNX
//! classifier from a filesystem path and runs it on the **CPU** execution
//! provider with **multi-threaded** intra-op parallelism (scaled to the
//! machine's cores) so the live in-flight image filter scores fast. Strict
//! deterministic compute is intentionally NOT set — it would serialize ops and
//! cost throughput, and threshold scoring needs speed, not bit-reproducibility.
//! The model must accept an NCHW `f32` input of shape `[1, 3, size, size]`.
//!
//! Output postprocessing auto-adapts to the two common NSFW heads:
//! * **1 logit**  → `sigmoid(logit)` is the NSFW probability.
//! * **2 classes** → `softmax(...)`; we take the NSFW class. We assume the
//!   higher-indexed class is "nsfw" (matches Falconsai `nsfw_image_detection`:
//!   index 0 = "normal", index 1 = "nsfw").
//!
//! `ort` is configured with `load-dynamic` in the workspace, so the ONNX
//! Runtime shared library is resolved at runtime. On hosts where Smart App
//! Control blocks loading `onnxruntime.dll`, [`OnnxScorer::load`] returns an
//! error and the caller falls back to the safe stub (it does not panic).

use std::sync::Mutex;

use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::Tensor as OrtTensor;

use crate::preprocess::{preprocess, Normalization};
use crate::Scorer;

pub struct OnnxScorer {
    model_id: String,
    input_size: u32,
    norm: Normalization,
    // `Session::run` takes `&mut self`; `Scorer::score` is `&self`. Wrap the
    // session so the analyzer can stay `Send + Sync` and shared. ONNX Runtime
    // CPU inference is the bottleneck, not this lock.
    session: Mutex<Session>,
}

impl OnnxScorer {
    /// Load an ONNX model from `model_path` and run it at `input_size`×`input_size`.
    /// Uses ImageNet normalization (see [`Normalization`]); override with
    /// [`OnnxScorer::load_with`] for a `[0,1]`-scaled model.
    pub fn load(model_path: &str, input_size: u32) -> anyhow::Result<Self> {
        Self::load_with(model_path, input_size, Normalization::imagenet())
    }

    /// Like [`OnnxScorer::load`] but with explicit input normalization.
    pub fn load_with(
        model_path: &str,
        input_size: u32,
        norm: Normalization,
    ) -> anyhow::Result<Self> {
        // CPU EP, MULTI-THREADED. No execution provider is registered → ort uses
        // the built-in CPU provider. `commit_from_file` is the ort 2.x loader.
        //
        // Speed matters here (the live MITM image filter must score in-flight),
        // so we run intra-op parallelism across the machine's cores instead of a
        // single thread. We also drop the strict `with_deterministic_compute`
        // flag: it serializes ops to make results bit-reproducible, which fights
        // multi-thread throughput — and NSFW scoring only needs to clear a
        // threshold, not be bit-identical run-to-run.
        //
        // `ort::Error<R>` carries the failed builder `R` (which is not
        // `Send + Sync`), so it cannot be `?`-converted straight into
        // `anyhow::Error`. Stringify each step to drop that payload.
        let intra_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let session = Session::builder()
            .map_err(|e| anyhow::anyhow!("ort: session builder: {e}"))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| anyhow::anyhow!("ort: optimization level: {e}"))?
            .with_intra_threads(intra_threads)
            .map_err(|e| anyhow::anyhow!("ort: intra threads: {e}"))?
            .commit_from_file(model_path)
            .map_err(|e| anyhow::anyhow!("ort: load model {model_path}: {e}"))?;

        Ok(Self {
            model_id: format!("nsfw-onnx:{model_path}"),
            input_size,
            norm,
            session: Mutex::new(session),
        })
    }

    /// Construct from the `AEGIS_NSFW_MODEL` env var, erroring if unset/empty.
    pub fn from_env(input_size: u32) -> anyhow::Result<Self> {
        let path = std::env::var(crate::MODEL_PATH_ENV)
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("{} is not set", crate::MODEL_PATH_ENV))?;
        // Pixel normalization, selectable via AEGIS_NSFW_NORM (half | imagenet | unit).
        // Default = `half` ([-1,1], mean/std 0.5): the Falconsai / onnx-community
        // nsfw_image_detection ViT we ship needs this; ImageNet would skew its scores.
        let norm = match std::env::var("AEGIS_NSFW_NORM").ok().as_deref() {
            Some("imagenet") => Normalization::imagenet(),
            Some("unit") => Normalization::unit(),
            _ => Normalization::half(),
        };
        Self::load_with(&path, input_size, norm)
    }

    /// Run inference and return the NSFW probability in `[0, 1]`.
    /// Returns an error on decode/inference failure so the caller can decide
    /// (the public [`Scorer::score`] impl fails OPEN → 0.0).
    fn infer(&self, image_bytes: &[u8]) -> anyhow::Result<f32> {
        let t = preprocess(image_bytes, self.input_size, self.norm)?;
        let input = OrtTensor::from_array((t.shape_i64(), t.data))
            .map_err(|e| anyhow::anyhow!("ort: build input tensor: {e}"))?;

        let mut session = self
            .session
            .lock()
            .map_err(|_| anyhow::anyhow!("onnx session mutex poisoned"))?;

        // Bind by the model's actual first input name so we don't depend on a
        // hardcoded "input"/"pixel_values" convention.
        let input_name = session.inputs()[0].name().to_string();
        let outputs = session
            .run(ort::inputs![input_name => input])
            .map_err(|e| anyhow::anyhow!("ort: run: {e}"))?;

        // First output, as a flat f32 slice.
        let (_shape, logits) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow::anyhow!("ort: extract output: {e}"))?;
        Ok(nsfw_probability(logits))
    }
}

/// Map raw model output logits/probabilities to an NSFW probability.
///
/// * len 1            → `sigmoid(x[0])`.
/// * len 2            → `softmax`, take the higher-indexed (nsfw) class.
/// * already in [0,1] → if a single value is already a probability we still
///   pass it through sigmoid/softmax above; callers wanting raw probabilities
///   should export a sigmoid head.
fn nsfw_probability(logits: &[f32]) -> f32 {
    match logits.len() {
        0 => 0.0,
        1 => sigmoid(logits[0]),
        _ => {
            let probs = softmax(logits);
            // Convention: last class is "nsfw" (Falconsai: 0=normal, 1=nsfw).
            *probs.last().unwrap_or(&0.0)
        }
    }
    .clamp(0.0, 1.0)
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

fn softmax(xs: &[f32]) -> Vec<f32> {
    let max = xs.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = xs.iter().map(|&x| (x - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    if sum == 0.0 {
        return vec![0.0; xs.len()];
    }
    exps.into_iter().map(|e| e / sum).collect()
}

impl Scorer for OnnxScorer {
    fn score(&self, image_bytes: &[u8]) -> f32 {
        match self.infer(image_bytes) {
            Ok(p) => p,
            Err(e) => {
                // Fail OPEN on a per-image error (corrupt frame, etc.).
                tracing::debug!("aegis-vision onnx: inference failed, scoring 0.0: {e}");
                0.0
            }
        }
    }
    fn model_id(&self) -> &str {
        &self.model_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigmoid_and_softmax_math() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-6);
        assert!(sigmoid(20.0) > 0.99);
        assert!(sigmoid(-20.0) < 0.01);

        let p = softmax(&[1.0, 1.0]);
        assert!((p[0] - 0.5).abs() < 1e-6 && (p[1] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn postprocess_heads() {
        // 1-logit sigmoid head.
        assert!((nsfw_probability(&[0.0]) - 0.5).abs() < 1e-6);
        // 2-class softmax head; class 1 ("nsfw") dominant.
        let p = nsfw_probability(&[0.0, 10.0]);
        assert!(p > 0.99, "nsfw class dominant → ~1.0, got {p}");
        let p = nsfw_probability(&[10.0, 0.0]);
        assert!(p < 0.01, "normal class dominant → ~0.0, got {p}");
        assert_eq!(nsfw_probability(&[]), 0.0);
    }

    /// Self-skipping live model test. Runs the real ONNX Runtime ONLY when
    /// `AEGIS_NSFW_MODEL` points at an existing file; otherwise it returns
    /// early so CI without a model (and without onnxruntime.dll) still passes.
    #[test]
    fn live_model_scores_when_present() {
        let Some(path) = std::env::var(crate::MODEL_PATH_ENV)
            .ok()
            .filter(|s| !s.is_empty())
        else {
            eprintln!("skipping: {} not set", crate::MODEL_PATH_ENV);
            return;
        };
        if !std::path::Path::new(&path).is_file() {
            eprintln!("skipping: {} -> {path} is not a file", crate::MODEL_PATH_ENV);
            return;
        }

        let scorer = match OnnxScorer::load(&path, 224) {
            Ok(s) => s,
            Err(e) => {
                // Smart App Control / missing onnxruntime.dll → don't fail CI.
                eprintln!("skipping: could not load ONNX Runtime / model: {e}");
                return;
            }
        };

        // Tiny synthetic image so we exercise decode→preprocess→run end to end.
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

        let p = scorer.score(&png);
        assert!((0.0..=1.0).contains(&p), "probability in range, got {p}");
        eprintln!("live model {} scored {p:.4}", scorer.model_id());
    }
}
