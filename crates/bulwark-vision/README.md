# bulwark-vision

Small dedicated NSFW image/frame classifier. Implements the `Analyzer`
contract for `MediaKind::IMAGE`. No large LLM — a single-purpose ONNX model
runs via ONNX Runtime (`ort`). Evidence carries the content SHA-256 only,
never the raw image.

## Two build modes

### Default build (no model, fails OPEN)

```sh
cargo build -p bulwark-vision
cargo test  -p bulwark-vision
```

The default build does **not** depend on ONNX Runtime. It uses `StubScorer`,
which scores every image `0.0` → `SAFE` / `Allow`. A single warning is logged
the first time the analyzer falls back. This keeps the workspace linking and
the test suite green on hosts that have no model and/or cannot load the ONNX
Runtime native library (e.g. Windows Smart App Control).

### Real classification (`onnx` feature)

```sh
# Point at a model on disk, then build/run with the feature on:
$env:BULWARK_NSFW_MODEL = "C:\models\nsfw.onnx"      # PowerShell
export BULWARK_NSFW_MODEL=/opt/bulwark/models/nsfw.onnx # bash

cargo build -p bulwark-vision --features onnx
cargo test  -p bulwark-vision --features onnx
```

`ort` is an **optional** dependency behind the `onnx` cargo feature (default
OFF). All ONNX Runtime code is gated on `#[cfg(feature = "onnx")]`.

`ort` is configured with `load-dynamic`, so the ONNX Runtime shared library is
resolved **at runtime** when a session is first created — there is no native
download or link step during `cargo build`. If a host blocks loading
`onnxruntime.dll` (Smart App Control / `os error 4551`), `OnnxScorer::load`
returns an error and the analyzer falls back to the safe stub; it does not
panic and the build still succeeds.

## Getting a model

Drop any single-input image classifier exported to ONNX at the path you point
`BULWARK_NSFW_MODEL` at. Known-good options:

* **Falconsai/nsfw_image_detection** — ViT-based; export the HF model to ONNX.
  Two output classes, index `0` = `normal`, index `1` = `nsfw`. Input is a
  `224×224` RGB tensor normalized with ImageNet mean/std (the default here).
* **NudeNet** — also distributed as ONNX.

The model must accept an NCHW `f32` input of shape `[1, 3, size, size]`
(`size` defaults to `224`, configurable via `VisionConfig::input_size`).

### Output heads handled automatically

* **1 logit** → `sigmoid(logit)` is the NSFW probability.
* **2 classes** → `softmax`, the higher-indexed class is taken as `nsfw`.

### Normalization

Defaults to ImageNet mean/std (`Normalization::imagenet()`), matching common
ViT/MobileNet exports. For a model trained on plain `[0,1]`-scaled pixels, load
via `OnnxScorer::load_with(path, size, Normalization::unit())`.

## Wiring it up

```rust
use bulwark_vision::{VisionAnalyzer, VisionConfig};

// Picks OnnxScorer when `--features onnx` is on AND a loadable model is
// configured (via cfg.model_path or BULWARK_NSFW_MODEL); otherwise the safe stub.
let analyzer = VisionAnalyzer::from_env(VisionConfig::default());
```

## Layout

* `src/preprocess.rs` — decode → resize → normalize → NCHW `f32` tensor.
  Always compiled (no `ort`), so its unit tests run on the default build.
* `src/onnx.rs` — `ort`-backed `OnnxScorer` (CPU EP, deterministic). Compiled
  only with `--features onnx`. Includes a self-skipping live-model test that
  runs only when `BULWARK_NSFW_MODEL` points at an existing file.
* `src/lib.rs` — `Scorer` trait, `StubScorer`, `VisionConfig`, `VisionAnalyzer`.

## ort version

`ort 2.0.0-rc.12` (pinned in the workspace, `features = ["load-dynamic"]`).
API used: `Session::builder()?.with_optimization_level(...)?.with_intra_threads(1)?
.with_deterministic_compute(true)?.commit_from_file(path)?`, then
`session.run(ort::inputs![name => Tensor::from_array((shape, data))?])?` and
`outputs[0].try_extract_tensor::<f32>()?`.
