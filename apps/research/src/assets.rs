//! Embedded brand asset + a tiny base64 encoder, so the wasm bundle carries the
//! official mark with no asset-server round-trip (mirrors apps/parent's brand.rs).
//!
//! `branding/logo.jpg` is the official lockup on a WHITE field. This site is
//! dark, so the JPG is only ever shown inside a light "chip" (the footer
//! credential), where the white field reads as an intentional badge. The
//! nav/hero use the bespoke inline-SVG `shield` glyph from `icons.rs` instead,
//! which we can tint to the dark palette precisely.

/// The official Predator Hunters wordmark (red/white distressed lockup with the
/// rifle crossbar) as a transparent-background `data:` URI (PNG). It is the org
/// brand mark, shown in the nav + footer; on the dark stage the white letter
/// fill reads cleanly, in light mode it sits on a small dark plate (see CSS).
/// Decoded on call; cache in a `use_memo` if rendered repeatedly.
pub fn ph_logo_data_uri() -> String {
    // Relative to THIS file (apps/research/src/assets.rs): ../../../ climbs
    // src → apps/research → apps → repo root.
    const BYTES: &[u8] = include_bytes!("../../../branding/ph-logo.png");
    format!("data:image/png;base64,{}", base64_encode(BYTES))
}

/// Minimal standard-alphabet base64 encoder (RFC 4648, `=` padded). Hand-rolled
/// so the site needs no extra dependency for the data URI.
pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}
