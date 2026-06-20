//! C ABI for the Child Safety ROM NSFW safety gate — see `../include/bulwark_safety.h`.
//!
//! `bulwarkd` (screen path) and the `Camera3OutputStream` hook (camera path) link this
//! and call [`bw_score_nsfw`]. The scorer is `crates/bulwark-vision`'s, so detection
//! NEVER drifts from the shipping engine (same model, 384x384, [-1,1] norm, softmax,
//! threshold 0.7).
//!
//! **Fail-CLOSED:** any error — no model, bad pointer, decode/score failure, panic —
//! returns `BW_VERDICT_FAIL_CLOSED`, which the caller MUST treat as "block the frame".
//! Never fails open. Scoring is in-memory only; the frame is never persisted.
//!
//! The real `ort` scorer is behind the `onnx` feature (CI / Android via cargo-ndk,
//! linking libonnxruntime.so). Without `onnx` (dev-host default), every score fails
//! closed — so the ABI compiles + verifies on any host while the model path is CI/Android.
//!
//! NOT built here against AOSP; the Rust core builds via cargo / cargo-ndk.

use std::os::raw::{c_char, c_int, c_uchar};
use std::panic::catch_unwind;

// --- ABI constants — MUST match include/bulwark_safety.h ---
#[allow(dead_code)] // referenced only in the `onnx` build (engine::init)
const BW_OK: c_int = 0;
const BW_ERR_NO_MODEL: c_int = 1;
#[allow(dead_code)] // referenced only in the `onnx` build (engine::init)
const BW_ALREADY_INIT: c_int = 2;

const BW_VERDICT_SAFE: c_int = 0;
const BW_VERDICT_NSFW: c_int = 1;
const BW_VERDICT_FAIL_CLOSED: c_int = 2;

const BW_FMT_RGBA8888: c_int = 0;
// BW_FMT_NV21 = 1, BW_FMT_NV12 = 2 — YUV->RGB conversion is a TODO; until then those
// formats fail CLOSED (block) rather than pass an unscored frame.

#[allow(dead_code)] // referenced only in the `onnx` build (OnnxScorer::load)
const INPUT_SIZE: u32 = 384;
const NSFW_THRESHOLD: f32 = 0.7;

#[cfg(feature = "onnx")]
mod engine {
    use bulwark_vision::onnx::OnnxScorer;
    use std::os::raw::c_char;
    use std::sync::{Mutex, OnceLock};

    static SCORER: OnceLock<Mutex<Option<OnnxScorer>>> = OnceLock::new();

    pub fn init(model_path: &str) -> i32 {
        let cell = SCORER.get_or_init(|| Mutex::new(None));
        let Ok(mut guard) = cell.lock() else {
            return super::BW_ERR_NO_MODEL;
        };
        if guard.is_some() {
            return super::BW_ALREADY_INIT;
        }
        match OnnxScorer::load(model_path, super::INPUT_SIZE) {
            Ok(s) => {
                *guard = Some(s);
                log::info!("bulwark-safety: NSFW model loaded ({model_path})");
                super::BW_OK
            }
            Err(e) => {
                log::error!("bulwark-safety: NSFW model load failed: {e}");
                super::BW_ERR_NO_MODEL
            }
        }
    }

    /// Score already-encoded image bytes via the engine's exact scorer. `None` when no
    /// model is loaded OR inference errors -> caller fails CLOSED. We use
    /// `OnnxScorer::try_score` (NOT `Scorer::score`, which fails OPEN → 0.0 for the
    /// streaming path): an unscorable frame here must BLOCK, never pass as "safe".
    pub fn score_encoded(bytes: &[u8]) -> Option<f32> {
        let cell = SCORER.get()?;
        let guard = cell.lock().ok()?;
        let scorer = guard.as_ref()?;
        scorer.try_score(bytes).ok()
    }

    /// Content-free build identifier (safe to log) — reflects whether a model is
    /// loaded, never a path or score. `'static` C string.
    pub fn model_id_cstr() -> *const c_char {
        let loaded = SCORER
            .get()
            .and_then(|c| c.lock().ok().map(|g| g.is_some()))
            .unwrap_or(false);
        if loaded {
            c"nsfw-onnx".as_ptr()
        } else {
            c"stub-noop".as_ptr()
        }
    }
}

#[cfg(not(feature = "onnx"))]
mod engine {
    // No ONNX in this build (dev host) -> no scorer -> everything fails CLOSED. This is
    // what lets the crate + ABI compile + verify on any host without onnxruntime.
    pub fn init(_model_path: &str) -> i32 {
        super::BW_ERR_NO_MODEL
    }
    pub fn score_encoded(_bytes: &[u8]) -> Option<f32> {
        None
    }
    /// No scorer in this build -> always the stub id. `'static` C string.
    pub fn model_id_cstr() -> *const std::os::raw::c_char {
        c"stub-noop".as_ptr()
    }
}

/// Encode raw RGBA8888 into PNG in memory so the engine's `Scorer` (which takes encoded
/// bytes) decodes + preprocesses it exactly as everywhere else — no detection drift.
/// Per-frame encode is a known cost; a raw-pixel scoring entry on bulwark-vision is the
/// planned optimisation, and the hot path throttles/samples (see camera-gate INTEGRATION).
fn rgba_to_png(rgba: &[u8], w: u32, h: u32) -> Option<Vec<u8>> {
    let expected = (w as usize).checked_mul(h as usize)?.checked_mul(4)?;
    if rgba.len() < expected {
        return None;
    }
    let buf = image::RgbaImage::from_raw(w, h, rgba[..expected].to_vec())?;
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(buf)
        .write_to(&mut out, image::ImageFormat::Png)
        .ok()?;
    Some(out.into_inner())
}

/// `bw_init_once` — load + warm the NSFW model. Idempotent. See the header.
///
/// # Safety
/// `model_path` must be NULL or a NUL-terminated C string valid for the call.
#[no_mangle]
pub unsafe extern "C" fn bw_init_once(model_path: *const c_char) -> c_int {
    catch_unwind(|| {
        if model_path.is_null() {
            return BW_ERR_NO_MODEL;
        }
        // SAFETY: caller contract — NUL-terminated C string.
        let cstr = unsafe { std::ffi::CStr::from_ptr(model_path) };
        let Ok(path) = cstr.to_str() else {
            return BW_ERR_NO_MODEL;
        };
        engine::init(path)
    })
    .unwrap_or(BW_ERR_NO_MODEL)
}

/// `bw_score_nsfw` — score one frame; FAILS CLOSED on any error. See the header.
///
/// # Safety
/// `pixels` must be NULL or point to at least `width*height*4` bytes (RGBA8888).
/// `score_out` must be NULL or point to a writable `f32`.
#[no_mangle]
pub unsafe extern "C" fn bw_score_nsfw(
    pixels: *const c_uchar,
    width: c_int,
    height: c_int,
    format: c_int,
    score_out: *mut f32,
) -> c_int {
    catch_unwind(|| {
        if pixels.is_null() || width < 1 || height < 1 {
            return BW_VERDICT_FAIL_CLOSED;
        }
        if format != BW_FMT_RGBA8888 {
            // YUV (NV21/NV12) not yet supported -> fail CLOSED (block), never pass.
            return BW_VERDICT_FAIL_CLOSED;
        }
        let (w, h) = (width as u32, height as u32);
        let Some(len) = (w as usize)
            .checked_mul(h as usize)
            .and_then(|n| n.checked_mul(4))
        else {
            return BW_VERDICT_FAIL_CLOSED;
        };
        // SAFETY: caller contract — `pixels` points to width*height*4 bytes (RGBA8888).
        let rgba = unsafe { std::slice::from_raw_parts(pixels, len) };
        let Some(png) = rgba_to_png(rgba, w, h) else {
            return BW_VERDICT_FAIL_CLOSED;
        };
        let Some(score) = engine::score_encoded(&png) else {
            return BW_VERDICT_FAIL_CLOSED;
        };
        if !score.is_finite() {
            return BW_VERDICT_FAIL_CLOSED;
        }
        if !score_out.is_null() {
            // SAFETY: caller contract — non-NULL `score_out` is a writable f32.
            unsafe { *score_out = score };
        }
        if score >= NSFW_THRESHOLD {
            BW_VERDICT_NSFW
        } else {
            BW_VERDICT_SAFE
        }
    })
    .unwrap_or(BW_VERDICT_FAIL_CLOSED)
}

mod text {
    use bulwark_proto::{Action, TextSpan};
    use bulwark_text::{NoClassifier, TextAnalyzer};
    use std::sync::OnceLock;

    // Rules-first grooming/adult-text detector (no ML classifier → no model file,
    // matches the engine's "rules-first minimal AI" invariant). Built once.
    static ANALYZER: OnceLock<Option<TextAnalyzer<NoClassifier>>> = OnceLock::new();

    fn analyzer() -> Option<&'static TextAnalyzer<NoClassifier>> {
        ANALYZER.get_or_init(|| TextAnalyzer::new().ok()).as_ref()
    }

    /// Score one snapshot of on-screen text → BwVerdict. Stateless per call
    /// (a fixed thread id); cross-message thread escalation is a future enhancement
    /// once the ROM supplies a stable per-conversation id.
    pub fn score(s: &str) -> i32 {
        let Some(a) = analyzer() else {
            return super::BW_VERDICT_FAIL_CLOSED;
        };
        let span = TextSpan {
            text: s.to_string(),
            thread_id: "rom-screen".to_string(),
            ..Default::default()
        };
        let verdict = a.analyze_span("rom-scan", &span, 0);
        match verdict.action {
            x if x == Action::Unspecified as i32 => super::BW_VERDICT_FAIL_CLOSED,
            x if x == Action::Allow as i32 => super::BW_VERDICT_SAFE,
            _ => super::BW_VERDICT_NSFW, // BLOCK / BLUR / MUTE / WARN / LOG → flagged
        }
    }
}

/// `bw_score_text` — score a snapshot of on-screen text for grooming / adult content
/// (bulwarkd's screen path). Here `BW_VERDICT_NSFW` means "flagged"; fail-CLOSED on any
/// error. Uses the exact shipping `bulwark-text` detector (no drift).
///
/// # Safety
/// `utf8` must be NULL or point to `len` bytes of UTF-8 text.
#[no_mangle]
pub unsafe extern "C" fn bw_score_text(utf8: *const c_uchar, len: usize) -> c_int {
    catch_unwind(|| {
        if utf8.is_null() || len == 0 {
            return BW_VERDICT_FAIL_CLOSED;
        }
        // SAFETY: caller contract — `utf8` points to `len` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(utf8, len) };
        let Ok(s) = std::str::from_utf8(bytes) else {
            return BW_VERDICT_FAIL_CLOSED;
        };
        text::score(s)
    })
    .unwrap_or(BW_VERDICT_FAIL_CLOSED)
}

/// `bw_model_id` — content-free identifier of the active scorer build (safe to log):
/// "nsfw-onnx" once a model is loaded, else "stub-noop". The returned pointer is a
/// `'static` NUL-terminated C string, valid for the process lifetime. See the header.
#[no_mangle]
pub extern "C" fn bw_model_id() -> *const c_char {
    engine::model_id_cstr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_and_bad_inputs_fail_closed() {
        // No model loaded + NULL/short inputs must all block, never pass.
        // SAFETY: NULL pointers and a correctly-sized buffer per each fn's contract.
        unsafe {
            assert_eq!(bw_init_once(std::ptr::null()), BW_ERR_NO_MODEL);
            assert_eq!(
                bw_score_nsfw(
                    std::ptr::null(),
                    8,
                    8,
                    BW_FMT_RGBA8888,
                    std::ptr::null_mut()
                ),
                BW_VERDICT_FAIL_CLOSED,
            );
            // Valid RGBA buffer but no model loaded (or non-onnx build) -> fail closed.
            let px = [0u8; 4 * 4 * 4];
            assert_eq!(
                bw_score_nsfw(px.as_ptr(), 4, 4, BW_FMT_RGBA8888, std::ptr::null_mut()),
                BW_VERDICT_FAIL_CLOSED,
            );
            // Unsupported pixel format fails closed.
            assert_eq!(
                bw_score_nsfw(px.as_ptr(), 4, 4, 1 /* NV21 */, std::ptr::null_mut()),
                BW_VERDICT_FAIL_CLOSED,
            );
        }
    }

    #[test]
    fn text_path_flags_adult_passes_benign() {
        // SAFETY: each pointer/len is valid (or deliberately NULL/0 to test fail-closed).
        unsafe {
            // Null / empty → fail closed.
            assert_eq!(bw_score_text(std::ptr::null(), 4), BW_VERDICT_FAIL_CLOSED);
            assert_eq!(bw_score_text(b"x".as_ptr(), 0), BW_VERDICT_FAIL_CLOSED);
            // Plainly benign → safe.
            let benign = b"hello, how was school today?";
            assert_eq!(
                bw_score_text(benign.as_ptr(), benign.len()),
                BW_VERDICT_SAFE
            );
            // Plainly adult → flagged (the rules engine detects it, never SAFE).
            let flagged = "wanna watch some porn together".as_bytes();
            assert_eq!(
                bw_score_text(flagged.as_ptr(), flagged.len()),
                BW_VERDICT_NSFW
            );
        }
    }

    #[test]
    fn model_id_is_content_free() {
        // Safe fn (no pointer args). Before init / in the no-onnx build it's the stub.
        let p = bw_model_id();
        assert!(!p.is_null());
        // SAFETY: the returned pointer is a 'static NUL-terminated C string.
        let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_str().unwrap();
        assert!(s == "stub-noop" || s == "nsfw-onnx", "unexpected id: {s}");
    }

    /// RUNTIME smoke for the REAL onnx scorer — only with `--features onnx` and the
    /// bundled Apache-2.0 NSFW model present. This actually EXECUTES the full path the
    /// build-only check never does: load the model, decode+preprocess+infer a real
    /// frame, threshold it. A benign solid frame must score finite and below 0.7 → SAFE,
    /// and `bw_model_id` must report the loaded model. Self-skips if the model is absent
    /// (e.g. CI's no-onnx job) so it never blocks a build.
    #[cfg(feature = "onnx")]
    #[test]
    fn onnx_runtime_smoke_benign_passes() {
        use std::ffi::{CStr, CString};
        let model = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../crates/bulwark-vision/models/nsfw_detector.onnx"
        );
        if !std::path::Path::new(model).exists() {
            eprintln!("onnx_runtime_smoke: bundled model absent — skipping");
            return;
        }
        let c = CString::new(model).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path for the call.
        let rc = unsafe { bw_init_once(c.as_ptr()) };
        assert_eq!(rc, BW_OK, "bundled NSFW model must load (rc={rc})");

        // Benign solid-grey 384x384 RGBA frame → real inference → finite score < 0.7 → SAFE.
        let (w, h) = (384u32, 384u32);
        let rgba = vec![128u8; (w * h * 4) as usize];
        let mut score = -1.0f32;
        // SAFETY: `rgba` is exactly w*h*4 bytes; `score` is a writable f32.
        let v = unsafe {
            bw_score_nsfw(
                rgba.as_ptr(),
                w as c_int,
                h as c_int,
                BW_FMT_RGBA8888,
                &mut score,
            )
        };
        assert_eq!(
            v, BW_VERDICT_SAFE,
            "benign grey frame must pass (score={score})"
        );
        assert!(
            score.is_finite() && (0.0..NSFW_THRESHOLD).contains(&score),
            "score must be a real probability below threshold: {score}"
        );
        // Model is loaded now → content-free id reflects it.
        // SAFETY: 'static NUL-terminated C string.
        let id = unsafe { CStr::from_ptr(bw_model_id()) }.to_str().unwrap();
        assert_eq!(id, "nsfw-onnx");
    }
}
