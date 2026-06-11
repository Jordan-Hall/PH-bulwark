//! Media + encoding helpers: pairing setup payload (v2 JSON -> QR SVG), segment
//! disk loads, data-URI assembly, and MIME sniffing for evidence previews.

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

use crate::config::segments_dir;
use crate::servers::{
    cluster_ca_path_for_endpoint, cluster_endpoint, saved_choice, selected_server_id,
};

/// Build the **setup payload v2** the child device consumes by QR scan or paste:
/// routing (active region id + endpoint), the freshly minted short-lived pair
/// code + its expiry, the child's name, and — when this console has a CA pinned
/// for the active server — that CA PEM (base64), so the child device can make
/// its FIRST secure call against a self-hosted/private-CA server. The CA is
/// public certificate material, not a secret; the single-use pair code stays the
/// only credential. `include_ca: false` builds the same payload without the CA
/// (the QR fallback when a large pinned CA won't fit in a scannable code).
pub fn setup_payload_v2(
    child_name: &str,
    pair_code: &str,
    expires_ts: i64,
    include_ca: bool,
) -> Option<String> {
    let endpoint = cluster_endpoint();
    let region = selected_server_id(&saved_choice());
    let ca_b64 = if include_ca {
        pinned_ca_b64(&endpoint)
    } else {
        None
    };
    build_setup_payload_v2(
        &region,
        &endpoint,
        pair_code,
        expires_ts,
        child_name,
        ca_b64.as_deref(),
    )
}

/// base64 of the pinned cluster CA PEM for `endpoint`, or `None` when no CA is
/// pinned for that server (plain http / public-cert self-hosted) or the file
/// isn't certificate PEM. Best-effort by design: a missing or malformed CA file
/// never blocks pairing — the payload simply omits the field.
fn pinned_ca_b64(endpoint: &str) -> Option<String> {
    let bytes = std::fs::read(cluster_ca_path_for_endpoint(endpoint)).ok()?;
    if !String::from_utf8_lossy(&bytes).contains("BEGIN CERTIFICATE") {
        return None;
    }
    Some(base64_encode(&bytes))
}

/// Pure payload-v2 assembly (see [`setup_payload_v2`]), split out so tests can
/// exercise the wire shape without touching disk. `cluster_ca_pem_b64` is
/// omitted entirely when no CA is pinned. This shape is the FIXED v2 contract
/// the child app's scan + paste paths parse.
pub fn build_setup_payload_v2(
    server_region: &str,
    server_endpoint: &str,
    pair_code: &str,
    expires_ts: i64,
    child_name: &str,
    cluster_ca_pem_b64: Option<&str>,
) -> Option<String> {
    let mut payload = serde_json::json!({
        "v": 2,
        "server_region": server_region.trim(),
        "server_endpoint": server_endpoint.trim(),
        "pair_code": pair_code.trim(),
        "expires_ts": expires_ts,
        "child_name": child_name.trim(),
    });
    if let (Some(map), Some(ca)) = (payload.as_object_mut(), cluster_ca_pem_b64) {
        map.insert(
            "cluster_ca_pem_b64".to_string(),
            serde_json::Value::String(ca.to_string()),
        );
    }
    serde_json::to_string(&payload).ok()
}

/// Render `payload` as a self-contained SVG QR string for inline display via
/// `dangerous_inner_html` (the SVG is produced locally from a controlled payload).
/// Colours match the console's calm dark theme. Tries medium error correction
/// first, then low — a v2 payload carrying a pinned CA can be dense. `None` if
/// the payload still can't be encoded, so the caller falls back gracefully.
pub fn pair_qr_svg(payload: &str) -> Option<String> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .or_else(|_| QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::L))
        .ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(180, 180)
            .quiet_zone(true)
            .dark_color(svg::Color("#10110f"))
            .light_color(svg::Color("#eceee8"))
            .build(),
    )
}

/// Resolve a `blob://<sha256>` URI to the per-user segment store path and read
/// the bytes. `Ok(None)` = missing/purged; `Err` = malformed URI or read error.
pub fn load_segment_from_disk(uri: &str) -> Result<Option<Vec<u8>>, String> {
    let sha = uri
        .strip_prefix("blob://")
        .ok_or_else(|| "not a blob:// URI".to_string())?;
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("malformed segment id".to_string());
    }
    let path = segments_dir().join(format!("{sha}.blob"));
    match std::fs::read(&path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Inline image preview helpers (no heavy deps — hand-rolled base64 + sniff)
// ---------------------------------------------------------------------------

/// Build a `data:` URI for inline `<img src=...>` rendering from raw image
/// bytes, sniffing the format from magic bytes (JPEG default).
pub fn image_data_uri(bytes: &[u8]) -> String {
    let mime = sniff_image_mime(bytes);
    format!("data:{};base64,{}", mime, base64_encode(bytes))
}

/// Best-effort image MIME sniff from leading magic bytes. Defaults to
/// `image/jpeg` (the common safe-thumbnail format) when nothing matches.
pub fn sniff_image_mime(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 8 && bytes[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        "image/png"
    } else if bytes.len() >= 6 && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a") {
        "image/gif"
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        // JPEG (FF D8 FF) and everything else default to jpeg.
        "image/jpeg"
    }
}

/// Best-effort video-container MIME sniff for a stored review clip. The segment
/// store keeps bytes as-is, so a clip may be MP4/fMP4, DASH `.m4s`, HLS `.ts`, or
/// WebM. Defaults to `video/mp4` (the common case) when nothing matches.
pub fn sniff_video_mime(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 8 && (&bytes[4..8] == b"ftyp" || &bytes[4..8] == b"styp") {
        // ISO-BMFF: MP4, fragmented MP4, and DASH `.m4s` all carry a ftyp/styp box.
        "video/mp4"
    } else if bytes.len() >= 4 && bytes[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        // EBML header → WebM / Matroska.
        "video/webm"
    } else if bytes.len() >= 4 && &bytes[..4] == b"OggS" {
        "video/ogg"
    } else if bytes.len() > 188 && bytes[0] == 0x47 && bytes[188] == 0x47 {
        // MPEG-TS (HLS `.ts`): 188-byte packets, each starting with the 0x47 sync.
        "video/mp2t"
    } else {
        "video/mp4"
    }
}

/// Minimal standard-alphabet base64 encoder (RFC 4648, with `=` padding).
/// Hand-rolled so the console needs no extra dependency for the data URI.
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

/// Copy `text` to the OS clipboard (the "copy recovery code" button). Best-effort:
/// returns an error string the caller may ignore — the code is also shown as
/// selectable text, so a clipboard failure is never blocking.
pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text(text.to_string()).map_err(|e| e.to_string())
}
