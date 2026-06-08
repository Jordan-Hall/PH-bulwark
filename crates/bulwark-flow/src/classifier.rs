//! The [`FlowClassifier`] trait (docs/design/interfaces.md) and its default
//! implementation, [`DefaultFlowClassifier`], which wires the pure
//! [`Classifier`](crate::classify::Classifier) to the broadcast-delay
//! [`DelayBuffer`](crate::buffer::DelayBuffer).
//!
//! interfaces.md declares `FlowClassifier` in terms of `bulwark_core::Result`;
//! this crate depends on `bulwark-core`, so we use that `Result` directly (the
//! authentic contract). Names, arguments, and ownership match interfaces.md
//! exactly; the only addition is helper accessors on the concrete type, not on
//! the trait (workflow hand-off rule #1: do not widen the trait).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use bulwark_core::Result;
use bulwark_proto::v1::{Action, InlineMedia, MediaKind, SourceChannel, TextSpan};

use crate::buffer::{Admission, BufferConfig, DelayBuffer, OverdueSegment, Released};
use crate::classify::{Classification, Classifier, Disposition, LIVE_DELAY_MS};
use crate::error::FlowError;
use crate::flow::{AnalysisUnit, CapturedFlow, FlowPayload, HttpHead};

/// Classify + demux a captured flow into analysis-ready units, driving the
/// broadcast-delay buffer for streaming media. Mirrors interfaces.md verbatim.
#[async_trait]
pub trait FlowClassifier: Send + Sync {
    /// Classify + demux a captured flow into zero or more analysis units. For
    /// streaming media this drives the buffer; units are released as the delay
    /// window permits.
    async fn classify(&self, flow: CapturedFlow) -> Result<Vec<AnalysisUnit>>;

    /// How far behind live the play-out buffer currently sits (live budget).
    fn current_delay_ms(&self) -> u32;
}

/// The default `FlowClassifier`: stateless content classification + a shared
/// broadcast-delay ring buffer for video/live segments.
///
/// Cheap to clone — the buffer is behind an `Arc`, so the same play-out buffer is
/// shared across clones (one logical buffer per device).
#[derive(Clone)]
pub struct DefaultFlowClassifier {
    classifier: Classifier,
    buffer: Arc<DelayBuffer>,
    /// Monotonic counter so each emitted unit gets a stable per-classifier id
    /// (the router replaces this with the real `request_id`).
    seq: Arc<AtomicU64>,
}

impl DefaultFlowClassifier {
    /// Build with explicit buffer configuration.
    pub fn new(config: BufferConfig) -> Self {
        DefaultFlowClassifier {
            classifier: Classifier::new(),
            buffer: Arc::new(DelayBuffer::new(config)),
            seq: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Build with default buffer configuration.
    pub fn with_defaults() -> Self {
        DefaultFlowClassifier::new(BufferConfig::default())
    }

    /// Access the underlying delay buffer (to `apply` verdicts, poll
    /// `due_segments`, observe back-pressure). The orchestrator (`bulwark-client`)
    /// applies the returned `Action` here after the analyzer responds.
    pub fn buffer(&self) -> &DelayBuffer {
        &self.buffer
    }

    /// Apply a verdict `Action` to a buffered segment (forward / drop / hold).
    /// Convenience wrapper over [`DelayBuffer::apply`].
    pub fn apply(
        &self,
        segment_id: u64,
        action: Action,
        rewritten: Option<Bytes>,
    ) -> Result<Released> {
        Ok(self.buffer.apply(segment_id, action, rewritten)?)
    }

    /// Segments whose deadline elapsed with no verdict — the caller applies the
    /// fail-safe default and then `apply`s the chosen action. Convenience wrapper
    /// over [`DelayBuffer::due_segments`].
    pub fn due_segments(&self) -> Vec<OverdueSegment> {
        self.buffer.due_segments()
    }

    /// The pure classification of a flow (no buffering side-effects), exposed for
    /// callers that only want the routing decision.
    pub fn classification(&self, flow: &CapturedFlow) -> Classification {
        self.classifier.classify(flow)
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Turn a classified flow into zero or more analysis units, admitting
    /// streaming segments to the delay buffer first.
    fn build_units(
        &self,
        flow: &CapturedFlow,
        class: &Classification,
    ) -> Result<Vec<AnalysisUnit>> {
        let body = body_bytes(&flow.payload);

        match class.disposition {
            // A manifest carries no media bytes — nothing to analyse yet; the
            // demuxer will see the segments it points to as their own flows.
            Disposition::Manifest { .. } => {
                tracing::trace!(
                    flow = flow.flow_id,
                    reason = class.reason,
                    "manifest forwarded"
                );
                Ok(Vec::new())
            }

            // Not in scope (WebRTC handled by bulwark-net, opaque binary, E2E) →
            // pass through with no unit.
            Disposition::Other => {
                tracing::trace!(
                    flow = flow.flow_id,
                    reason = class.reason,
                    "flow passed through"
                );
                Ok(Vec::new())
            }

            Disposition::PassThrough => match class.media_kind {
                MediaKind::Text => Ok(vec![AnalysisUnit::Text(self.text_span(flow))]),
                MediaKind::Image => Ok(vec![AnalysisUnit::Image(inline(
                    body,
                    mime_of(&flow.payload),
                ))]),
                MediaKind::Audio => Ok(vec![AnalysisUnit::Audio(inline(
                    body,
                    mime_of(&flow.payload),
                ))]),
                // A video kind with a pass-through disposition shouldn't happen
                // (video always buffers); be safe and admit it anyway.
                MediaKind::Video => self.buffer_video(flow, class, body, false),
                MediaKind::Unspecified => Ok(Vec::new()),
            },

            // Streaming segment → hold in the delay buffer, then emit a
            // VideoSegment unit carrying its ticket + live deadline.
            Disposition::BufferSegment { live } => self.buffer_video(flow, class, body, live),
        }
    }

    /// Admit a video segment to the delay buffer and produce its analysis unit.
    fn buffer_video(
        &self,
        flow: &CapturedFlow,
        class: &Classification,
        body: Bytes,
        live: bool,
    ) -> Result<Vec<AnalysisUnit>> {
        if body.is_empty() {
            // A header-only video flow (e.g. a HEAD/redirect) has nothing to
            // buffer; treat as pass-through.
            return Ok(Vec::new());
        }

        let deadline_ms = if live { LIVE_DELAY_MS } else { 0 };

        match self.buffer.admit(body.clone(), live) {
            Admission::Admitted(segment_id) => {
                tracing::trace!(
                    flow = flow.flow_id,
                    segment_id,
                    live,
                    reason = class.reason,
                    "video segment buffered",
                );
                Ok(vec![AnalysisUnit::VideoSegment {
                    media: inline(body, mime_of(&flow.payload)),
                    deadline_ms,
                    segment_id: Some(segment_id),
                }])
            }
            Admission::BackPressure => {
                // Buffer full: surface back-pressure so the orchestrator slows
                // the source. We do not silently drop or bypass analysis.
                Err(FlowError::BufferFull(format!(
                    "flow {} segment ({} bytes) refused; {} pending, {} bytes held",
                    flow.flow_id,
                    body.len(),
                    self.buffer.pending(),
                    self.buffer.held_bytes(),
                ))
                .into())
            }
        }
    }

    /// Build a `TextSpan` from a flow's textual body (page text / web chat).
    /// We carry the host as `app` and the flow id (stringified) as a thread hint;
    /// the text analyzer's own thread correlation refines this. No raw secrets —
    /// this is page/chat text the MITM layer already decrypted.
    fn text_span(&self, flow: &CapturedFlow) -> TextSpan {
        let text = match &flow.payload {
            FlowPayload::Http(head) => String::from_utf8_lossy(&head.body_peek).into_owned(),
            FlowPayload::StreamChunk { data, .. } => String::from_utf8_lossy(data).into_owned(),
        };
        TextSpan {
            text,
            lang: String::new(),
            app: flow.app_or_host.clone(),
            thread_id: format!("flow-{}", flow.flow_id),
            from_minor: false,
            prior_excerpts: Vec::new(),
        }
    }
}

#[async_trait]
impl FlowClassifier for DefaultFlowClassifier {
    async fn classify(&self, flow: CapturedFlow) -> Result<Vec<AnalysisUnit>> {
        let _ = self.next_seq(); // reserve a sequence position for tracing/correlation
        let class = self.classifier.classify(&flow);
        tracing::debug!(
            flow = flow.flow_id,
            host = %flow.app_or_host,
            kind = ?class.media_kind,
            channel = ?class.source_channel,
            disposition = ?class.disposition,
            reason = class.reason,
            "flow classified",
        );
        self.build_units(&flow, &class)
    }

    fn current_delay_ms(&self) -> u32 {
        self.buffer.current_delay_ms()
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Extract the body bytes from a payload (the peek for HTTP, the chunk for a
/// stream). For real video buffering the interceptor supplies the full segment
/// as the body/chunk; the *peek* is only used for classification.
fn body_bytes(payload: &FlowPayload) -> Bytes {
    match payload {
        FlowPayload::Http(HttpHead { body_peek, .. }) => body_peek.clone(),
        FlowPayload::StreamChunk { data, .. } => data.clone(),
    }
}

/// Best-effort MIME for an `InlineMedia` from the payload metadata.
fn mime_of(payload: &FlowPayload) -> String {
    match payload {
        FlowPayload::Http(head) => head.content_type().unwrap_or_default(),
        FlowPayload::StreamChunk { mime_type, .. } => mime_type.clone().unwrap_or_default(),
    }
}

/// Build an `InlineMedia` carrier (width/height/duration left 0 — the analyzer
/// or ffmpeg fills them; we never decode here).
fn inline(data: Bytes, mime_type: String) -> InlineMedia {
    InlineMedia {
        data: data.to_vec(),
        mime_type,
        width: 0,
        height: 0,
        duration_ms: 0,
    }
}

/// The `SourceChannel` is preserved on each unit via the classification; callers
/// that need it read it from [`DefaultFlowClassifier::classification`]. This tiny
/// helper documents the mapping for the record.
pub fn channel_for_unit(unit: &AnalysisUnit, fallback: SourceChannel) -> SourceChannel {
    match unit {
        AnalysisUnit::Text(_) => SourceChannel::Web,
        AnalysisUnit::VideoSegment { deadline_ms, .. } if *deadline_ms > 0 => {
            SourceChannel::LiveStream
        }
        AnalysisUnit::VideoSegment { .. } => SourceChannel::VideoStream,
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::Header;

    fn http(ct: Option<&str>, path: Option<&str>, body: &[u8], live: bool) -> CapturedFlow {
        let mut headers = Vec::new();
        if let Some(ct) = ct {
            headers.push(Header {
                name: "content-type".into(),
                value: ct.into(),
            });
        }
        let mut flow = CapturedFlow::http(
            7,
            "example.com",
            HttpHead {
                method: Some("GET".into()),
                path: path.map(|p| p.into()),
                status: Some(200),
                headers,
                body_peek: Bytes::copy_from_slice(body),
            },
        );
        if live {
            flow.source_channel = SourceChannel::LiveStream;
        }
        flow
    }

    #[tokio::test]
    async fn html_flow_yields_one_text_unit() {
        let fc = DefaultFlowClassifier::with_defaults();
        let units = fc
            .classify(http(
                Some("text/html"),
                Some("/p"),
                b"<html>hello</html>",
                false,
            ))
            .await
            .unwrap();
        assert_eq!(units.len(), 1);
        assert!(matches!(units[0], AnalysisUnit::Text(_)));
    }

    #[tokio::test]
    async fn image_flow_yields_one_image_unit() {
        let fc = DefaultFlowClassifier::with_defaults();
        let units = fc
            .classify(http(
                Some("image/png"),
                Some("/i.png"),
                b"\x89PNG\r\n\x1a\n",
                false,
            ))
            .await
            .unwrap();
        assert_eq!(units.len(), 1);
        assert!(matches!(units[0], AnalysisUnit::Image(_)));
    }

    #[tokio::test]
    async fn vod_video_segment_is_buffered_with_zero_deadline() {
        let fc = DefaultFlowClassifier::with_defaults();
        let units = fc
            .classify(http(
                Some("video/mp4"),
                Some("/v.mp4"),
                b"\x00\x00\x00\x18ftypisom....",
                false,
            ))
            .await
            .unwrap();
        assert_eq!(units.len(), 1);
        match &units[0] {
            AnalysisUnit::VideoSegment {
                deadline_ms,
                segment_id,
                ..
            } => {
                assert_eq!(*deadline_ms, 0, "VOD has no hard live deadline");
                assert!(segment_id.is_some());
            }
            other => panic!("expected VideoSegment, got {other:?}"),
        }
        assert_eq!(fc.buffer().pending(), 1);
    }

    #[tokio::test]
    async fn live_video_segment_carries_live_deadline_then_releases_on_allow() {
        let fc = DefaultFlowClassifier::with_defaults();
        let units = fc
            .classify(http(
                Some("video/mp2t"),
                Some("/live/seg.ts"),
                &[0x47u8; 16],
                true,
            ))
            .await
            .unwrap();
        let (deadline, seg_id) = match &units[0] {
            AnalysisUnit::VideoSegment {
                deadline_ms,
                segment_id,
                ..
            } => (*deadline_ms, segment_id.unwrap()),
            other => panic!("expected VideoSegment, got {other:?}"),
        };
        assert_eq!(
            deadline, LIVE_DELAY_MS,
            "live segment carries the live deadline"
        );
        assert_eq!(fc.buffer().pending(), 1);

        // Verdict comes back ALLOW → segment released (forwarded), buffer drains.
        let released = fc.apply(seg_id, Action::Allow, None).unwrap();
        assert!(matches!(released, Released::Forward(_)));
        assert_eq!(fc.buffer().pending(), 0);
    }

    #[tokio::test]
    async fn manifest_flow_yields_no_units_but_is_forwarded() {
        let fc = DefaultFlowClassifier::with_defaults();
        let m = b"#EXTM3U\n#EXT-X-ENDLIST\n";
        let units = fc
            .classify(http(
                Some("application/vnd.apple.mpegurl"),
                Some("/m.m3u8"),
                m,
                false,
            ))
            .await
            .unwrap();
        assert!(units.is_empty(), "a manifest carries no media to analyse");
    }

    #[tokio::test]
    async fn current_delay_ms_reflects_buffer() {
        let fc = DefaultFlowClassifier::with_defaults();
        assert_eq!(fc.current_delay_ms(), 0);
        fc.classify(http(
            Some("video/mp4"),
            Some("/v.mp4"),
            b"\x00\x00\x00\x18ftypisomXXXX",
            false,
        ))
        .await
        .unwrap();
        // Just admitted, so the delay is ~0 but the segment is held.
        assert_eq!(fc.buffer().pending(), 1);
    }
}
