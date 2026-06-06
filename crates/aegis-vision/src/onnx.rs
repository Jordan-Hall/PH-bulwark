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

use crate::preprocess::{preprocess, ModelClass, Normalization};
use crate::Scorer;

/// Execution-provider strategy for the NSFW session.
///
/// `auto` (default) builds a GPU-preferring session AND a CPU session, times a
/// warmup inference on each, and KEEPS WHICHEVER IS FASTER — so a machine whose
/// GPU is slower than its CPU (common on low-end mobile/integrated GPUs) silently
/// runs on CPU. `gpu` forces the GPU-preferring dispatch (still CPU-backed by
/// ort if the GPU EP is unavailable at runtime); `cpu` forces CPU only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecProviderMode {
    /// Benchmark GPU vs CPU at load, keep the faster.
    Auto,
    /// CPU execution provider only.
    Cpu,
    /// GPU-preferring dispatch (platform EP first, CPU fallback).
    Gpu,
}

impl ExecProviderMode {
    /// Select from `AEGIS_NSFW_EP` (`auto` | `cpu` | `gpu`). Default `Auto`.
    pub fn from_env() -> Self {
        match std::env::var("AEGIS_NSFW_EP").ok().as_deref() {
            Some("cpu") => Self::Cpu,
            Some("gpu") => Self::Gpu,
            _ => Self::Auto,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
        }
    }
}

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

    /// Like [`OnnxScorer::load`] but with explicit input normalization. CPU only
    /// (back-compat); use [`OnnxScorer::load_with_ep`] to opt into GPU selection.
    pub fn load_with(
        model_path: &str,
        input_size: u32,
        norm: Normalization,
    ) -> anyhow::Result<Self> {
        Self::load_with_ep(model_path, input_size, norm, ExecProviderMode::Cpu)
    }

    /// Load with an explicit execution-provider [`ExecProviderMode`]: `Cpu`,
    /// `Gpu` (platform EP first, CPU fallback), or `Auto` (benchmark GPU vs CPU at
    /// load and keep the faster — the "fall back to CPU even on mobile if the GPU
    /// is slower" path).
    pub fn load_with_ep(
        model_path: &str,
        input_size: u32,
        norm: Normalization,
        mode: ExecProviderMode,
    ) -> anyhow::Result<Self> {
        let session = match mode {
            ExecProviderMode::Cpu => build_session(model_path, cpu_only())?,
            ExecProviderMode::Gpu => build_session(model_path, gpu_then_cpu())?,
            ExecProviderMode::Auto => auto_select_session(model_path, input_size)?,
        };
        Ok(Self {
            model_id: format!("nsfw-onnx:{model_path}:{}", mode.label()),
            input_size,
            norm,
            session: Mutex::new(session),
        })
    }

    /// Construct from `AEGIS_NSFW_MODEL`, picking the model class
    /// (`AEGIS_NSFW_MODEL_CLASS`), normalization (`AEGIS_NSFW_NORM` override), and
    /// execution provider (`AEGIS_NSFW_EP`) from the environment. If the env var
    /// is unset, falls back to the per-install `nsfw_model.txt` config file.
    pub fn from_env(input_size: u32) -> anyhow::Result<Self> {
        let path = crate::model_path_from_env_or_config()
            .ok_or_else(|| anyhow::anyhow!("{} is not set", crate::MODEL_PATH_ENV))?;
        Self::from_path_env(&path, input_size)
    }

    /// Like [`OnnxScorer::from_env`] but for an already-resolved `model_path`
    /// (so an explicit `VisionConfig.model_path` is honoured). Reads the model
    /// class + normalization + EP mode from the environment.
    pub fn from_path_env(model_path: &str, default_input_size: u32) -> anyhow::Result<Self> {
        let class = ModelClass::from_env();
        let input_size = if std::env::var("AEGIS_NSFW_MODEL_CLASS").is_ok() {
            class.input_size()
        } else {
            default_input_size
        };
        let norm = norm_from_env(class);
        let mode = ExecProviderMode::from_env();
        Self::load_with_ep(model_path, input_size, norm, mode)
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

/// Build an `ort` session for `model_path` with the given execution-provider
/// dispatch list. Multi-threaded intra-op parallelism (live image filter must
/// score in-flight); `ort::Error<R>` carries a non-`Send` builder payload so we
/// stringify each step before `?`-converting into `anyhow`.
fn build_session(
    model_path: &str,
    providers: Vec<ort::ep::ExecutionProviderDispatch>,
) -> anyhow::Result<Session> {
    let intra_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    Session::builder()
        .map_err(|e| anyhow::anyhow!("ort: session builder: {e}"))?
        .with_execution_providers(providers)
        .map_err(|e| anyhow::anyhow!("ort: execution providers: {e}"))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|e| anyhow::anyhow!("ort: optimization level: {e}"))?
        .with_intra_threads(intra_threads)
        .map_err(|e| anyhow::anyhow!("ort: intra threads: {e}"))?
        .commit_from_file(model_path)
        .map_err(|e| anyhow::anyhow!("ort: load model {model_path}: {e}"))
}

/// CPU-only dispatch.
fn cpu_only() -> Vec<ort::ep::ExecutionProviderDispatch> {
    use ort::ep;
    vec![ep::CPUExecutionProvider::default().build()]
}

/// GPU-preferring dispatch: the platform's best GPU EP(s) first, CPU last. `ort`
/// silently uses CPU if a GPU EP isn't available at runtime, so this is always
/// safe to register.
fn gpu_then_cpu() -> Vec<ort::ep::ExecutionProviderDispatch> {
    let mut out = platform_gpu_providers();
    out.extend(cpu_only());
    out
}

/// The platform's best-first GPU execution providers (empty where none apply).
/// Mirrors `aegis-infer`'s provider mapping.
fn platform_gpu_providers() -> Vec<ort::ep::ExecutionProviderDispatch> {
    use ort::ep;
    #[cfg(target_os = "windows")]
    {
        vec![ep::DirectMLExecutionProvider::default().build()]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            ep::CUDAExecutionProvider::default().build(),
            ep::TensorRTExecutionProvider::default().build(),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![ep::CoreMLExecutionProvider::default().build()]
    }
    #[cfg(target_os = "android")]
    {
        vec![ep::NNAPIExecutionProvider::default().build()]
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "android"
    )))]
    {
        Vec::new()
    }
}

/// `Auto` mode: build a GPU-preferring session and a CPU session, time a warmup
/// inference on each, and keep whichever is faster. If there's no platform GPU
/// EP, or the GPU session fails to build, we just use CPU. The slower session is
/// dropped.
fn auto_select_session(model_path: &str, input_size: u32) -> anyhow::Result<Session> {
    // No GPU EP on this platform → straight to CPU.
    if platform_gpu_providers().is_empty() {
        return build_session(model_path, cpu_only());
    }

    let mut cpu = build_session(model_path, cpu_only())?;
    let mut gpu = match build_session(model_path, gpu_then_cpu()) {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(error = %e, "aegis-vision: GPU session unavailable, using CPU");
            return Ok(cpu);
        }
    };

    let cpu_ms = time_warmup(&mut cpu, input_size);
    let gpu_ms = time_warmup(&mut gpu, input_size);

    match (gpu_ms, cpu_ms) {
        (Some(g), Some(c)) if g <= c => {
            tracing::info!(gpu_ms = g, cpu_ms = c, "aegis-vision: GPU faster → GPU");
            Ok(gpu)
        }
        (Some(g), Some(c)) => {
            tracing::info!(gpu_ms = g, cpu_ms = c, "aegis-vision: CPU faster → CPU");
            Ok(cpu)
        }
        // If either benchmark couldn't run, prefer the CPU session (always valid).
        _ => Ok(cpu),
    }
}

/// Time one inference of a zero-filled `[1,3,size,size]` input (after one warm
/// run). Returns milliseconds, or `None` if the dummy run failed.
fn time_warmup(session: &mut Session, input_size: u32) -> Option<f32> {
    let make_input = || {
        let n = (input_size as usize) * (input_size as usize) * 3;
        OrtTensor::from_array((
            vec![1i64, 3, input_size as i64, input_size as i64],
            vec![0f32; n],
        ))
        .ok()
    };
    let name = session.inputs().first()?.name().to_string();
    // Warm (JIT / EP graph compile) — not timed. A FAILED run means this EP can't
    // actually execute the model (e.g. a GPU EP that builds but can't run it), so
    // return None → auto-select treats it as unusable and keeps the CPU session.
    // (Without this, a failed run is ~instant and would look "fastest".)
    session
        .run(ort::inputs![name.clone() => make_input()?])
        .ok()?;
    let start = std::time::Instant::now();
    session.run(ort::inputs![name => make_input()?]).ok()?;
    Some(start.elapsed().as_secs_f32() * 1000.0)
}

/// Normalization for a build: an explicit `AEGIS_NSFW_NORM` wins; otherwise the
/// model class default (ViT → half `[-1,1]`, MobileNet → ImageNet).
fn norm_from_env(class: ModelClass) -> Normalization {
    match std::env::var("AEGIS_NSFW_NORM").ok().as_deref() {
        Some("imagenet") => Normalization::imagenet(),
        Some("unit") => Normalization::unit(),
        Some("half") => Normalization::half(),
        _ => class.normalization(),
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
            eprintln!(
                "skipping: {} -> {path} is not a file",
                crate::MODEL_PATH_ENV
            );
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
