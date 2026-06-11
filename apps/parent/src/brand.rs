//! The Bulwark Shield brand mark, embedded into the binary so the desktop
//! webview always has it (no asset server / index.html needed — the app injects
//! its stylesheet through `style { {CSS} }`).
//!
//! `branding/logo.jpg` is the full lockup (the two-figure shield over the
//! "BULWARK SHIELD" wordmark) on a WHITE field. Pair it with
//! `mix-blend-mode: multiply` on light surfaces (the white drops out), or sit it
//! inside a light chip on dark surfaces (the white reads as an intentional
//! badge).

use crate::media::base64_encode;

/// The brand logo as a `data:` URI (JPEG). Decoded once per call; callers cache
/// it in a `use_signal`/`use_memo` if they render it repeatedly.
pub fn logo_data_uri() -> String {
    // Path is relative to THIS source file (apps/parent/src/brand.rs):
    // ../../../ climbs src → apps/parent → apps → repo root.
    const BYTES: &[u8] = include_bytes!("../../../branding/logo.jpg");
    format!("data:image/jpeg;base64,{}", base64_encode(BYTES))
}
