//! Deterministic flow classification — **no AI/ML** (PLAN §0b).
//!
//! Given the head + body-peek of a [`CapturedFlow`](crate::CapturedFlow), decide:
//!   * the [`MediaKind`] (TEXT / IMAGE / AUDIO / VIDEO), and
//!   * the [`SourceChannel`] (WEB / VIDEO_STREAM / LIVE_STREAM / …),
//!
//! using, in priority order: explicit `Content-Type`, manifest/body sniffing
//! (HLS `.m3u8`, DASH `.mpd`), magic bytes, then URL extension. The result also
//! says whether the unit must be **buffered** (streaming media) and, for live,
//! the **delay budget** to apply.
//!
//! The full signal table lives in this module's doc-comments and the unit tests;
//! see also the crate README in `lib.rs`.

use bytes::Bytes;

use aegis_proto::v1::{MediaKind, SourceChannel};

use crate::flow::{CapturedFlow, FlowPayload, HttpHead};

/// The outcome of classifying one flow: what it is, where it came from, and how
/// the buffer/delay layer should treat it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classification {
    /// The detected media kind.
    pub media_kind: MediaKind,
    /// The (possibly refined) source channel.
    pub source_channel: SourceChannel,
    /// How the streaming/buffering layer should treat this flow.
    pub disposition: Disposition,
    /// A short, human-readable reason citing the winning signal (auditable).
    pub reason: &'static str,
}

/// What the buffer/delay layer should do with a classified flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Emit a unit immediately; no buffering (text, single image, audio span).
    PassThrough,
    /// A streaming **manifest** (HLS `.m3u8` / DASH `.mpd`). It carries no media
    /// bytes itself; it tells the demuxer which segments to expect. Forwarded
    /// immediately but tags the host so subsequent segments are buffered.
    Manifest { live: bool },
    /// A media **segment** (progressive `mp4`, HLS `.ts`, DASH `.m4s`) that must
    /// be held in the ring buffer for the analysis-delay window before release.
    /// `live` selects the bounded live deadline vs. the relaxed VOD budget.
    BufferSegment { live: bool },
    /// Not classifiable / not in scope (e.g. WebRTC, opaque binary, pinned/E2E):
    /// pass through unchanged. WebRTC detection is `aegis-net`'s job; we only
    /// fall through to here when no media signal matched.
    Other,
}

/// Default broadcast-delay window for **live** segments (ms). Within the
/// architecture.md §4 "delay window 2–5 s" budget; the buffer keeps play-out at
/// least this far behind live so a verdict can return before release.
pub const LIVE_DELAY_MS: u32 = 3_000;

/// Default delay budget for **VOD** segments (ms). VOD has no hard live deadline
/// (the buffer hides the latency), so `deadline_ms` is reported as 0; this value
/// only sizes how long the buffer is willing to hold before shedding.
pub const VOD_DELAY_MS: u32 = 250;

/// Pure flow classifier. Holds no model and no mutable state — it is a set of
/// deterministic predicates over headers, magic bytes, and URLs.
#[derive(Clone, Copy, Debug, Default)]
pub struct Classifier;

impl Classifier {
    /// Build the (stateless) classifier.
    pub fn new() -> Self {
        Classifier
    }

    /// Classify a captured flow. Never fails: an unrecognised flow classifies as
    /// [`Disposition::Other`] (pass-through), honouring fail-safe-forward for
    /// content we cannot inspect (the *block* fail-safe is policy's job, applied
    /// only to content we did classify and could not get a verdict for).
    pub fn classify(&self, flow: &CapturedFlow) -> Classification {
        // Pinned / E2E flows are not readable here — they go to OCR, not us.
        if !flow.readable {
            return Classification {
                media_kind: MediaKind::Unspecified,
                source_channel: flow.source_channel,
                disposition: Disposition::Other,
                reason: "flow not readable (pinned/E2E) → OCR fallback",
            };
        }

        match &flow.payload {
            FlowPayload::Http(head) => self.classify_http(flow.source_channel, head),
            FlowPayload::StreamChunk {
                data,
                mime_type,
                url,
            } => self.classify_chunk(
                flow.source_channel,
                data,
                mime_type.as_deref(),
                url.as_deref(),
            ),
        }
    }

    /// Classify an HTTP request/response by its head + body peek.
    fn classify_http(&self, channel: SourceChannel, head: &HttpHead) -> Classification {
        let ct = head.content_type();
        let path = head.path.as_deref().unwrap_or("");

        // 1. Body manifest sniffing FIRST. An HLS/DASH manifest body is the
        //    authoritative signal for both the streaming family AND liveness
        //    (#EXT-X-ENDLIST / PLAYLIST-TYPE / MPD type=dynamic) — which the
        //    content-type header cannot convey — and servers routinely mislabel
        //    the content-type (e.g. text/plain for an .m3u8). So the body wins
        //    over the header for manifests.
        if let Some(c) = sniff_manifest(&head.body_peek, channel) {
            return c;
        }

        // 2. Explicit Content-Type is the next strongest signal.
        if let Some(ct) = ct.as_deref() {
            if let Some(c) = classify_content_type(ct, channel) {
                return c;
            }
        }

        // 3. Magic bytes on the body peek (image/audio/video containers).
        if let Some(c) = sniff_magic(&head.body_peek, channel) {
            return c;
        }

        // 4. URL extension as a last structural hint.
        if let Some(c) = classify_extension(path, channel) {
            return c;
        }

        // 5. Default for an HTTP page with no media signal: treat readable text.
        //    A successful HTML/text response with a body becomes a TEXT unit;
        //    anything else (opaque binary, no body) passes through.
        if ct.as_deref().map(is_textual_ct).unwrap_or(false) || looks_like_html(&head.body_peek) {
            return text_web("text/html-like body → web text");
        }

        Classification {
            media_kind: MediaKind::Unspecified,
            source_channel: channel,
            disposition: Disposition::Other,
            reason: "no media signal (content-type/manifest/magic/extension) → pass-through",
        }
    }

    /// Classify a raw demuxed stream chunk (a single media segment).
    fn classify_chunk(
        &self,
        channel: SourceChannel,
        data: &Bytes,
        mime_type: Option<&str>,
        url: Option<&str>,
    ) -> Classification {
        let live = is_live(channel);

        // A declared segment MIME wins.
        if let Some(mt) = mime_type {
            let mt = strip_ct_params(mt);
            if mt.starts_with("video/") || mt == "video/mp2t" {
                return buffered_video(channel, live, "stream chunk content-type video/*");
            }
            if mt.starts_with("audio/") {
                return audio(channel, "stream chunk content-type audio/*");
            }
        }

        // Else fall back to extension / magic on the chunk.
        if let Some(url) = url {
            if let Some(c) = classify_extension(url, channel) {
                return c;
            }
        }
        if let Some(c) = sniff_magic(data, channel) {
            return c;
        }

        // Unknown chunk on a known streaming channel: buffer it as video, since
        // it arrived on a VIDEO/LIVE channel and is opaque bytes — fail toward
        // analysis, not toward bypass.
        buffered_video(
            channel,
            live,
            "opaque chunk on streaming channel → buffer as video",
        )
    }
}

// ---------------------------------------------------------------------------
// Signal helpers (the classification table, encoded as functions)
// ---------------------------------------------------------------------------

/// Is this channel a low-latency live channel (bounded delay budget)?
fn is_live(channel: SourceChannel) -> bool {
    channel == SourceChannel::LiveStream
}

/// Strip `; charset=…` parameters and lowercase a content-type.
fn strip_ct_params(ct: &str) -> String {
    ct.split(';')
        .next()
        .unwrap_or(ct)
        .trim()
        .to_ascii_lowercase()
}

/// Textual content-types that become a TEXT unit (page text / web chat JSON).
fn is_textual_ct(ct: &str) -> bool {
    matches!(
        ct,
        "text/html" | "text/plain" | "application/xhtml+xml" | "application/json" | "text/json"
    ) || ct.starts_with("text/")
}

/// Cheap HTML/text sniff on a body peek (no full parse).
fn looks_like_html(peek: &Bytes) -> bool {
    let n = peek.len().min(512);
    let head = &peek[..n];
    // Skip a possible UTF-8 BOM / leading whitespace.
    let trimmed: &[u8] = {
        let mut s = head;
        if s.starts_with(&[0xEF, 0xBB, 0xBF]) {
            s = &s[3..];
        }
        while let [first, rest @ ..] = s {
            if first.is_ascii_whitespace() {
                s = rest;
            } else {
                break;
            }
        }
        s
    };
    let lower: Vec<u8> = trimmed
        .iter()
        .take(64)
        .map(|b| b.to_ascii_lowercase())
        .collect();
    starts_with_any(
        &lower,
        &[b"<!doctype html", b"<html", b"<?xml", b"<head", b"<body"],
    )
}

fn starts_with_any(hay: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|n| hay.starts_with(n))
}

/// Map an explicit `Content-Type` to a classification, or `None` if it carries
/// no media signal (caller then falls back to sniffing / extension).
fn classify_content_type(ct: &str, channel: SourceChannel) -> Option<Classification> {
    // --- streaming manifests (highest-specificity content-types) ---
    if ct == "application/vnd.apple.mpegurl"
        || ct == "application/x-mpegurl"
        || ct == "audio/mpegurl"
    {
        // HLS manifest. Liveness is decided from body (#EXT-X-PLAYLIST-TYPE /
        // absence of #EXT-X-ENDLIST); content-type alone keeps the channel hint.
        let live = is_live(channel);
        return Some(manifest(
            promote_video(channel),
            live,
            "content-type HLS manifest",
        ));
    }
    if ct == "application/dash+xml" {
        let live = is_live(channel);
        return Some(manifest(
            promote_video(channel),
            live,
            "content-type DASH manifest",
        ));
    }

    // --- transport-stream / segment content-types → buffered video ---
    if ct == "video/mp2t" {
        let live = is_live(channel);
        return Some(buffered_video(
            promote_video(channel),
            live,
            "content-type video/mp2t (HLS .ts)",
        ));
    }
    if ct.starts_with("video/") || ct == "application/mp4" {
        let live = is_live(channel);
        return Some(buffered_video(
            promote_video(channel),
            live,
            "content-type video/*",
        ));
    }

    // --- audio ---
    if ct.starts_with("audio/") {
        return Some(audio(channel, "content-type audio/*"));
    }

    // --- images ---
    if ct.starts_with("image/") {
        return Some(image(channel, "content-type image/*"));
    }

    // --- text ---
    if is_textual_ct(ct) {
        return Some(text_web("content-type textual"));
    }

    None
}

/// Sniff an HLS or DASH **manifest** out of a body peek, regardless of the
/// declared content-type (servers routinely mislabel these).
fn sniff_manifest(peek: &Bytes, channel: SourceChannel) -> Option<Classification> {
    if peek.is_empty() {
        return None;
    }
    let n = peek.len().min(4096);
    let text = String::from_utf8_lossy(&peek[..n]);
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();

    // HLS: an Extended M3U playlist begins with #EXTM3U.
    if trimmed.starts_with("#EXTM3U") {
        // Live vs VOD: VOD playlists carry #EXT-X-ENDLIST (or PLAYLIST-TYPE:VOD).
        let has_endlist = text.contains("#EXT-X-ENDLIST");
        let vod_typed = text.contains("#EXT-X-PLAYLIST-TYPE:VOD");
        let event_typed = text.contains("#EXT-X-PLAYLIST-TYPE:EVENT");
        let live = !has_endlist && !vod_typed || event_typed;
        return Some(manifest(
            promote_live_or_video(channel, live),
            live,
            if live {
                "HLS #EXTM3U without #EXT-X-ENDLIST → live"
            } else {
                "HLS #EXTM3U with #EXT-X-ENDLIST → VOD"
            },
        ));
    }

    // DASH: an MPD XML document. Liveness is type="dynamic" (vs "static").
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("<mpd")
        && (lower.contains("urn:mpeg:dash:schema:mpd") || lower.contains("dash"))
    {
        let live = lower.contains("type=\"dynamic\"") || lower.contains("type='dynamic'");
        return Some(manifest(
            promote_live_or_video(channel, live),
            live,
            if live {
                "DASH MPD type=dynamic → live"
            } else {
                "DASH MPD (static) → VOD"
            },
        ));
    }

    None
}

/// Sniff container/codec **magic bytes** on a body peek.
fn sniff_magic(peek: &Bytes, channel: SourceChannel) -> Option<Classification> {
    if peek.len() < 4 {
        return None;
    }
    let b = &peek[..];

    // --- images ---
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(image(channel, "magic JPEG (FF D8 FF)"));
    }
    if b.starts_with(&[0x89, b'P', b'N', b'G']) {
        return Some(image(channel, "magic PNG (89 50 4E 47)"));
    }
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return Some(image(channel, "magic GIF"));
    }
    if b.starts_with(b"BM") {
        return Some(image(channel, "magic BMP"));
    }
    if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        return Some(image(channel, "magic WEBP (RIFF…WEBP)"));
    }
    // RIFF…WAVE → audio.
    if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WAVE" {
        return Some(audio(channel, "magic WAV (RIFF…WAVE)"));
    }

    // --- ISO-BMFF (mp4/m4a/m4v/m4s): bytes 4..8 == "ftyp" (or styp for segments) ---
    if b.len() >= 8 {
        let box_type = &b[4..8];
        if box_type == b"ftyp" || box_type == b"styp" || box_type == b"moof" || box_type == b"moov"
        {
            let brand = if b.len() >= 12 { &b[8..12] } else { &b[4..8] };
            let live = is_live(channel);
            // Audio-only MP4 brands (M4A ) → audio; everything else → video.
            if brand == b"M4A " || brand == b"M4B " {
                return Some(audio(channel, "magic ISO-BMFF audio brand (M4A)"));
            }
            return Some(buffered_video(
                promote_video(channel),
                live,
                "magic ISO-BMFF (ftyp/styp/moof) → mp4 video",
            ));
        }
    }

    // --- MPEG-TS: 0x47 sync byte every 188 bytes (HLS .ts) ---
    if b[0] == 0x47 && (b.len() < 189 || b[188] == 0x47) {
        let live = is_live(channel);
        return Some(buffered_video(
            promote_video(channel),
            live,
            "magic MPEG-TS sync (0x47) → .ts video",
        ));
    }

    // --- WebM / Matroska (EBML): 1A 45 DF A3 ---
    if b.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        let live = is_live(channel);
        return Some(buffered_video(
            promote_video(channel),
            live,
            "magic EBML (WebM/MKV)",
        ));
    }

    // --- audio: ID3 (mp3), MPEG audio frame, OggS, fLaC ---
    if b.starts_with(b"ID3") {
        return Some(audio(channel, "magic ID3 (mp3)"));
    }
    if b[0] == 0xFF && (b[1] & 0xE0) == 0xE0 {
        return Some(audio(channel, "magic MPEG audio frame sync"));
    }
    if b.starts_with(b"OggS") {
        return Some(audio(channel, "magic Ogg"));
    }
    if b.starts_with(b"fLaC") {
        return Some(audio(channel, "magic FLAC"));
    }

    None
}

/// Classify by URL/path extension (last structural fallback).
fn classify_extension(path: &str, channel: SourceChannel) -> Option<Classification> {
    let ext = extension_of(path)?;
    let live = is_live(channel);
    match ext.as_str() {
        // streaming manifests
        "m3u8" => Some(manifest(
            promote_video(channel),
            live,
            "extension .m3u8 (HLS manifest)",
        )),
        "mpd" => Some(manifest(
            promote_video(channel),
            live,
            "extension .mpd (DASH manifest)",
        )),
        // streaming segments → buffered video
        "ts" => Some(buffered_video(
            promote_video(channel),
            live,
            "extension .ts (HLS segment)",
        )),
        "m4s" => Some(buffered_video(
            promote_video(channel),
            live,
            "extension .m4s (DASH segment)",
        )),
        "mp4" | "m4v" | "mov" | "webm" | "mkv" => Some(buffered_video(
            promote_video(channel),
            live,
            "extension progressive video",
        )),
        // audio
        "mp3" | "aac" | "m4a" | "ogg" | "oga" | "opus" | "flac" | "wav" => {
            Some(audio(channel, "extension audio"))
        }
        // images
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "avif" | "tiff" | "tif" => {
            Some(image(channel, "extension image"))
        }
        // text-ish
        "html" | "htm" | "xhtml" | "txt" | "json" => Some(text_web("extension textual")),
        _ => None,
    }
}

/// Lowercased file extension of a URL/path, ignoring any query string / fragment.
fn extension_of(path: &str) -> Option<String> {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let last = path.rsplit('/').next().unwrap_or(path);
    let dot = last.rfind('.')?;
    let ext = &last[dot + 1..];
    if ext.is_empty() {
        None
    } else {
        Some(ext.to_ascii_lowercase())
    }
}

// ---------------------------------------------------------------------------
// Channel refinement: the classifier may PROMOTE a WEB flow to a streaming
// channel once it sees streaming content, but never DEMOTES LIVE → VOD/WEB.
// ---------------------------------------------------------------------------

/// Promote a generic channel to `VIDEO_STREAM` when we know it carries video,
/// preserving an already-`LIVE_STREAM` channel.
fn promote_video(channel: SourceChannel) -> SourceChannel {
    match channel {
        SourceChannel::LiveStream => SourceChannel::LiveStream,
        _ => SourceChannel::VideoStream,
    }
}

/// Promote based on detected liveness: a live manifest/segment makes the channel
/// `LIVE_STREAM`; a VOD one makes it `VIDEO_STREAM`. Never demotes an existing
/// `LIVE_STREAM`.
fn promote_live_or_video(channel: SourceChannel, live: bool) -> SourceChannel {
    if channel == SourceChannel::LiveStream || live {
        SourceChannel::LiveStream
    } else {
        SourceChannel::VideoStream
    }
}

// ---------------------------------------------------------------------------
// Classification constructors
// ---------------------------------------------------------------------------

fn text_web(reason: &'static str) -> Classification {
    Classification {
        media_kind: MediaKind::Text,
        source_channel: SourceChannel::Web,
        disposition: Disposition::PassThrough,
        reason,
    }
}

fn image(channel: SourceChannel, reason: &'static str) -> Classification {
    Classification {
        media_kind: MediaKind::Image,
        // An image inside a video/live stream is still served on that channel,
        // but a still image is analysed immediately (no buffering).
        source_channel: channel,
        disposition: Disposition::PassThrough,
        reason,
    }
}

fn audio(channel: SourceChannel, reason: &'static str) -> Classification {
    Classification {
        media_kind: MediaKind::Audio,
        source_channel: channel,
        disposition: Disposition::PassThrough,
        reason,
    }
}

fn buffered_video(channel: SourceChannel, live: bool, reason: &'static str) -> Classification {
    Classification {
        media_kind: MediaKind::Video,
        source_channel: channel,
        disposition: Disposition::BufferSegment { live },
        reason,
    }
}

fn manifest(channel: SourceChannel, live: bool, reason: &'static str) -> Classification {
    Classification {
        // A manifest itself carries no media bytes; it is text we forward as-is,
        // but its disposition tells the demuxer to buffer subsequent segments.
        media_kind: MediaKind::Unspecified,
        source_channel: channel,
        disposition: Disposition::Manifest { live },
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Header, HttpHead};

    fn http_with(ct: Option<&str>, path: Option<&str>, body: &[u8]) -> CapturedFlow {
        let mut headers = Vec::new();
        if let Some(ct) = ct {
            headers.push(Header {
                name: "content-type".into(),
                value: ct.into(),
            });
        }
        CapturedFlow::http(
            1,
            "example.com",
            HttpHead {
                method: Some("GET".into()),
                path: path.map(|p| p.into()),
                status: Some(200),
                headers,
                body_peek: Bytes::copy_from_slice(body),
            },
        )
    }

    #[test]
    fn html_content_type_is_text_web() {
        let c = Classifier::new().classify(&http_with(Some("text/html; charset=utf-8"), None, b""));
        assert_eq!(c.media_kind, MediaKind::Text);
        assert_eq!(c.source_channel, SourceChannel::Web);
        assert_eq!(c.disposition, Disposition::PassThrough);
    }

    #[test]
    fn jpeg_content_type_is_image() {
        let c = Classifier::new().classify(&http_with(Some("image/jpeg"), None, b""));
        assert_eq!(c.media_kind, MediaKind::Image);
        assert_eq!(c.disposition, Disposition::PassThrough);
    }

    #[test]
    fn jpeg_magic_bytes_is_image_even_without_content_type() {
        let c = Classifier::new().classify(&http_with(None, None, &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0]));
        assert_eq!(c.media_kind, MediaKind::Image);
        assert!(c.reason.contains("JPEG"));
    }

    #[test]
    fn png_magic_bytes_is_image() {
        let c = Classifier::new().classify(&http_with(None, None, b"\x89PNG\r\n\x1a\n"));
        assert_eq!(c.media_kind, MediaKind::Image);
    }

    #[test]
    fn mp3_id3_magic_is_audio() {
        let c = Classifier::new().classify(&http_with(None, None, b"ID3\x03\x00\x00\x00"));
        assert_eq!(c.media_kind, MediaKind::Audio);
    }

    #[test]
    fn progressive_mp4_content_type_buffers_as_video() {
        let c = Classifier::new().classify(&http_with(Some("video/mp4"), None, b""));
        assert_eq!(c.media_kind, MediaKind::Video);
        assert_eq!(c.source_channel, SourceChannel::VideoStream);
        assert_eq!(c.disposition, Disposition::BufferSegment { live: false });
    }

    #[test]
    fn mp4_ftyp_magic_buffers_as_video() {
        // size(4) + "ftyp" + "isom" brand
        let body = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00";
        let c = Classifier::new().classify(&http_with(None, None, body));
        assert_eq!(c.media_kind, MediaKind::Video);
        assert_eq!(c.disposition, Disposition::BufferSegment { live: false });
    }

    #[test]
    fn hls_manifest_vod_is_video_stream() {
        let manifest = b"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-PLAYLIST-TYPE:VOD\n\
                         #EXTINF:6.0,\nseg0.ts\n#EXTINF:6.0,\nseg1.ts\n#EXT-X-ENDLIST\n";
        // Served (as is common) with the wrong content-type to prove sniffing wins.
        let c = Classifier::new().classify(&http_with(
            Some("text/plain"),
            Some("/master.m3u8"),
            manifest,
        ));
        assert_eq!(c.source_channel, SourceChannel::VideoStream);
        assert_eq!(c.disposition, Disposition::Manifest { live: false });
        assert!(c.reason.contains("ENDLIST"));
    }

    #[test]
    fn hls_manifest_live_is_live_stream() {
        // No #EXT-X-ENDLIST, no PLAYLIST-TYPE → live.
        let manifest = b"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:2\n\
                         #EXT-X-MEDIA-SEQUENCE:120\n#EXTINF:2.0,\nseg120.ts\n#EXTINF:2.0,\nseg121.ts\n";
        let c = Classifier::new().classify(&http_with(
            Some("application/vnd.apple.mpegurl"),
            Some("/live.m3u8"),
            manifest,
        ));
        assert_eq!(c.source_channel, SourceChannel::LiveStream);
        assert_eq!(c.disposition, Disposition::Manifest { live: true });
    }

    #[test]
    fn dash_manifest_static_is_vod() {
        let mpd = br#"<?xml version="1.0"?>
            <MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static" minBufferTime="PT2S">
              <Period><AdaptationSet mimeType="video/mp4"></AdaptationSet></Period>
            </MPD>"#;
        let c = Classifier::new().classify(&http_with(
            Some("application/dash+xml"),
            Some("/manifest.mpd"),
            mpd,
        ));
        assert_eq!(c.source_channel, SourceChannel::VideoStream);
        assert_eq!(c.disposition, Disposition::Manifest { live: false });
    }

    #[test]
    fn dash_manifest_dynamic_is_live() {
        let mpd = br#"<?xml version="1.0"?>
            <MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="dynamic" minBufferTime="PT2S">
              <Period><AdaptationSet mimeType="video/mp4"></AdaptationSet></Period>
            </MPD>"#;
        // Wrong content-type again → sniffing must still win.
        let c = Classifier::new().classify(&http_with(
            Some("application/octet-stream"),
            Some("/live.mpd"),
            mpd,
        ));
        assert_eq!(c.source_channel, SourceChannel::LiveStream);
        assert_eq!(c.disposition, Disposition::Manifest { live: true });
    }

    #[test]
    fn ts_segment_extension_buffers_as_video() {
        let c =
            Classifier::new().classify(&http_with(Some("video/mp2t"), Some("/hls/seg42.ts"), b""));
        assert_eq!(c.media_kind, MediaKind::Video);
        assert_eq!(c.disposition, Disposition::BufferSegment { live: false });
    }

    #[test]
    fn m4s_segment_extension_buffers_as_video() {
        let c = Classifier::new().classify(&http_with(None, Some("/dash/chunk-7.m4s"), b""));
        assert_eq!(c.media_kind, MediaKind::Video);
        assert_eq!(c.disposition, Disposition::BufferSegment { live: false });
    }

    #[test]
    fn live_channel_keeps_live_for_ts_segment() {
        let mut flow = http_with(Some("video/mp2t"), Some("/seg.ts"), b"");
        flow.source_channel = SourceChannel::LiveStream;
        let c = Classifier::new().classify(&flow);
        assert_eq!(c.source_channel, SourceChannel::LiveStream);
        assert_eq!(c.disposition, Disposition::BufferSegment { live: true });
    }

    #[test]
    fn unreadable_flow_is_other() {
        let mut flow = http_with(Some("text/html"), None, b"");
        flow.readable = false;
        let c = Classifier::new().classify(&flow);
        assert_eq!(c.disposition, Disposition::Other);
    }

    #[test]
    fn opaque_binary_passes_through_as_other() {
        let c = Classifier::new().classify(&http_with(
            Some("application/octet-stream"),
            Some("/blob"),
            &[0x00, 0x01, 0x02, 0x03],
        ));
        assert_eq!(c.disposition, Disposition::Other);
        assert_eq!(c.media_kind, MediaKind::Unspecified);
    }

    #[test]
    fn html_body_sniff_without_content_type() {
        let c =
            Classifier::new().classify(&http_with(None, Some("/page"), b"<!DOCTYPE html><html>"));
        assert_eq!(c.media_kind, MediaKind::Text);
    }

    #[test]
    fn extension_parsing_ignores_query_and_fragment() {
        assert_eq!(extension_of("/a/b/seg.ts?token=xyz"), Some("ts".into()));
        assert_eq!(extension_of("/v.mp4#t=10"), Some("mp4".into()));
        assert_eq!(extension_of("/no-extension"), None);
        assert_eq!(extension_of("/dir.with.dots/file"), None);
    }

    #[test]
    fn stream_chunk_video_buffers() {
        let flow = CapturedFlow {
            flow_id: 9,
            source_channel: SourceChannel::LiveStream,
            app_or_host: "live.example".into(),
            readable: true,
            payload: FlowPayload::StreamChunk {
                data: Bytes::from_static(&[0x47, 0, 0, 0]),
                mime_type: Some("video/mp2t".into()),
                url: Some("/seg9.ts".into()),
            },
        };
        let c = Classifier::new().classify(&flow);
        assert_eq!(c.media_kind, MediaKind::Video);
        assert_eq!(c.disposition, Disposition::BufferSegment { live: true });
    }
}
