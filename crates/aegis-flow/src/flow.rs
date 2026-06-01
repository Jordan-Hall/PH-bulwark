//! The in-process flow vocabulary shared with `aegis-net` (the [`Interceptor`])
//! and the analyzer layer.
//!
//! These types are **not** part of the `aegis.v1` wire contract — they are the
//! Rust hand-off shapes named in docs/design/interfaces.md (`CapturedFlow`,
//! `FlowPayload`, `AnalysisUnit`). `aegis-net` produces a [`CapturedFlow`];
//! `aegis-flow` turns it into zero or more [`AnalysisUnit`]s. They live here (not
//! in `aegis-proto`) because they carry transient bytes/handles that never cross
//! a process or network boundary; each [`AnalysisUnit`] maps 1:1 onto an
//! `AnalysisRequest` once the router fills `device_id`/`ts`/`request_id`.
//!
//! `bytes::Bytes` is used for payload/segment handles so the ring buffer can
//! hold and clone segments cheaply (ref-counted, no copy).

use bytes::Bytes;

use aegis_proto::v1::{InlineMedia, SourceChannel, TextSpan};

/// One header line from the request or response head of a captured flow.
///
/// We keep names lowercased for case-insensitive lookup (HTTP header names are
/// case-insensitive); values are kept verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Lowercased header name (e.g. `"content-type"`).
    pub name: String,
    /// Header value, verbatim.
    pub value: String,
}

/// The parsed HTTP head (request line + headers, response status + headers) plus
/// a bounded **peek** of the body. The classifier reads only the head and the
/// peek; it never buffers the full body (that is the ring buffer's job, and only
/// for streaming media).
#[derive(Clone, Debug, Default)]
pub struct HttpHead {
    /// Request method, if this is (or was triggered by) a request we saw.
    pub method: Option<String>,
    /// Request path / full URL, used for extension-based detection
    /// (`.m3u8`, `.mpd`, `.ts`, `.m4s`, `.mp4`, `.jpg`, …).
    pub path: Option<String>,
    /// Response status code, if known.
    pub status: Option<u16>,
    /// Response (or request) headers, names lowercased.
    pub headers: Vec<Header>,
    /// A bounded prefix of the body for magic-byte sniffing / manifest peeking.
    /// MUST be small (the interceptor caps this); never the whole body.
    pub body_peek: Bytes,
}

impl HttpHead {
    /// Case-insensitive header lookup (name must already be lowercased).
    pub fn header(&self, lower_name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name == lower_name)
            .map(|h| h.value.as_str())
    }

    /// The `Content-Type` value with any `; charset=…`/`; boundary=…` parameters
    /// stripped and lowercased (e.g. `"text/html; charset=utf-8"` → `"text/html"`).
    pub fn content_type(&self) -> Option<String> {
        self.header("content-type").map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or(ct)
                .trim()
                .to_ascii_lowercase()
        })
    }
}

/// The payload of a captured flow. Either a (mostly) complete HTTP exchange we
/// can classify head-first, or a raw byte stream chunk for non-HTTP / already
/// demuxed transport.
#[derive(Clone, Debug)]
pub enum FlowPayload {
    /// An HTTP request/response with a parsed head and a body peek.
    Http(HttpHead),
    /// A raw transport stream chunk (e.g. a single HLS `.ts` / DASH `.m4s`
    /// segment already pulled by the interceptor), with an optional declared
    /// MIME type and the URL it came from.
    StreamChunk {
        /// The chunk bytes (a single media segment).
        data: Bytes,
        /// Declared MIME type, if the transport carried one.
        mime_type: Option<String>,
        /// Source URL / path of the chunk, used for extension detection.
        url: Option<String>,
    },
}

/// A captured, MITM-decrypted (or marked-unreadable) network unit handed up from
/// `aegis-net` for classification. Mirrors `CapturedFlow` in interfaces.md.
#[derive(Clone, Debug)]
pub struct CapturedFlow {
    /// Stable per-flow id assigned by the interceptor; echoed back on `apply`.
    pub flow_id: u64,
    /// The channel the interceptor believes this came from. The classifier may
    /// **refine** it (e.g. a `WEB` flow whose body is an HLS manifest becomes
    /// `VIDEO_STREAM`); it never widens a `LIVE_STREAM` back to `WEB`.
    pub source_channel: SourceChannel,
    /// App or host the flow belongs to (`"example.com"`, `"messenger"`).
    pub app_or_host: String,
    /// `false` = pinned / E2E → not readable here; route to the OCR fallback.
    pub readable: bool,
    /// The payload: bytes + protocol metadata.
    pub payload: FlowPayload,
}

impl CapturedFlow {
    /// Convenience constructor for an HTTP flow.
    pub fn http(flow_id: u64, app_or_host: impl Into<String>, head: HttpHead) -> Self {
        CapturedFlow {
            flow_id,
            source_channel: SourceChannel::Web,
            app_or_host: app_or_host.into(),
            readable: true,
            payload: FlowPayload::Http(head),
        }
    }
}

/// One analysis-ready unit produced from a flow. Maps 1:1 onto an
/// `AnalysisRequest` (the router fills `device_id`/`ts`/`request_id`). Mirrors
/// `AnalysisUnit` in interfaces.md.
#[derive(Clone, Debug)]
pub enum AnalysisUnit {
    /// Page / chat / extracted text → `MediaKind::TEXT`.
    Text(TextSpan),
    /// A still image (by content-type or magic bytes) → `MediaKind::IMAGE`.
    Image(InlineMedia),
    /// An audio span / stream → `MediaKind::AUDIO`.
    Audio(InlineMedia),
    /// A buffered video segment → `MediaKind::VIDEO`. `deadline_ms` is the soft
    /// live deadline (0 for VOD where the buffer hides the latency); it becomes
    /// `AnalysisRequest.deadline_ms` so a worker can fast-path / shed.
    VideoSegment {
        /// The segment bytes + container metadata.
        media: InlineMedia,
        /// Soft deadline for live budgets; 0 = VOD (delay acceptable).
        deadline_ms: u32,
        /// The buffer ticket this segment was admitted under, so the verdict's
        /// `Action` can be applied back to the held bytes. `None` for a
        /// pass-through (un-buffered) unit.
        segment_id: Option<u64>,
    },
}

impl AnalysisUnit {
    /// The `SourceChannel`-agnostic media kind this unit represents, for logging
    /// and for the analyzer-dispatch hint.
    pub fn kind_name(&self) -> &'static str {
        match self {
            AnalysisUnit::Text(_) => "text",
            AnalysisUnit::Image(_) => "image",
            AnalysisUnit::Audio(_) => "audio",
            AnalysisUnit::VideoSegment { .. } => "video",
        }
    }
}
