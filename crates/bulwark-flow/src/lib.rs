//! # bulwark-flow — flow classification, stream demux, and the broadcast-delay buffer.
//!
//! `bulwark-flow` is the client data-plane stage between `bulwark-net` (the
//! [`Interceptor`]) and the analyzer/offload layer. It takes a decrypted
//! [`CapturedFlow`], decides **what** it is and **where** it came from, and turns
//! it into zero or more analysis-ready [`AnalysisUnit`]s — buffering video/live
//! segments behind a configurable broadcast delay so real-time filtering is
//! possible.
//!
//! It implements the [`FlowClassifier`] trait from `docs/design/interfaces.md`.
//!
//! ## Minimal-AI, no telemetry
//! `#![forbid(unsafe_code)]`. There is **no AI/ML** here (PLAN §0b): every
//! decision is a deterministic predicate over content-types, magic bytes, URL
//! extensions, and manifest text. Nothing reports off-device (PLAN §3).
//!
//! ## Classification table (signal → MediaKind / SourceChannel / disposition)
//!
//! Signals are tried in priority order: **Content-Type → manifest sniff → magic
//! bytes → URL extension → HTML body sniff**. The first match wins.
//!
//! | Signal | MediaKind | SourceChannel | Disposition |
//! |---|---|---|---|
//! | `text/html`, `text/plain`, `application/json`, `text/*`; `<!doctype html`/`<html` body | TEXT | WEB | pass-through |
//! | `image/*`; JPEG `FF D8 FF`, PNG `89 50 4E 47`, GIF, BMP, `RIFF…WEBP`; `.jpg/.png/.gif/.webp/…` | IMAGE | (flow channel) | pass-through |
//! | `audio/*`; `ID3`/MPEG-frame/`OggS`/`fLaC`/`RIFF…WAVE`/`M4A ` brand; `.mp3/.aac/.m4a/.ogg/.flac/.wav` | AUDIO | (flow channel) | pass-through |
//! | `video/mp4`, `application/mp4`; ISO-BMFF `ftyp/styp/moof`; WebM EBML; `.mp4/.m4v/.mov/.webm/.mkv` | VIDEO | VIDEO_STREAM* | **buffer segment** |
//! | `video/mp2t`; MPEG-TS `0x47` sync; `.ts` | VIDEO | VIDEO_STREAM* | **buffer segment** |
//! | `.m4s` (DASH segment) | VIDEO | VIDEO_STREAM* | **buffer segment** |
//! | HLS `#EXTM3U` body / `application/vnd.apple.mpegurl` / `.m3u8` | — | VIDEO_STREAM or LIVE_STREAM | **manifest** |
//! | DASH `<MPD …>` body / `application/dash+xml` / `.mpd` | — | VIDEO_STREAM or LIVE_STREAM | **manifest** |
//! | anything else (opaque binary, WebRTC, pinned/E2E unreadable) | UNSPECIFIED | (flow channel) | pass-through (Other) |
//!
//! \* The channel is **promoted** to `LIVE_STREAM` when liveness is detected
//! (HLS without `#EXT-X-ENDLIST`/with `PLAYLIST-TYPE:EVENT`; DASH `type="dynamic"`),
//! otherwise `VIDEO_STREAM`. An existing `LIVE_STREAM` is never demoted.
//!
//! ## Live vs VOD
//! * **VOD** (`#EXT-X-ENDLIST`, `PLAYLIST-TYPE:VOD`, DASH `static`): delay is
//!   acceptable; segments buffer with a relaxed budget and `deadline_ms == 0`.
//! * **Live** (no end-list, DASH `dynamic`): a bounded broadcast delay
//!   ([`classify::LIVE_DELAY_MS`], within architecture.md §4's 2–5 s window) keeps
//!   play-out behind live; each `VideoSegment` unit carries that `deadline_ms` so
//!   a worker can fast-path / shed under the live budget.
//!
//! ## The broadcast-delay buffer
//! Video/live segments are admitted to a bounded [`DelayBuffer`]: it holds them
//! for the delay window, exerts **back-pressure** ([`Admission::BackPressure`])
//! when full (by count or bytes), surfaces **overdue** segments for the fail-safe
//! shed path ([`DelayBuffer::due_segments`]), and applies the verdict's
//! [`Action`](bulwark_proto::v1::Action) back onto the held bytes
//! ([`DelayBuffer::apply`]): `ALLOW`/`WARN`/`LOG` → forward, `BLUR`/`MUTE` →
//! forward rewritten bytes, `BLOCK` → drop. This is the mechanism that makes
//! real-time video filtering possible (PLAN §0a, architecture.md §3c/§3d).

#![forbid(unsafe_code)]

pub mod buffer;
pub mod classifier;
pub mod classify;
pub mod error;
pub mod flow;

// --- Public API re-exports -------------------------------------------------

pub use buffer::{Admission, BufferConfig, DelayBuffer, OverdueSegment, Released};
pub use classifier::{channel_for_unit, DefaultFlowClassifier, FlowClassifier};
pub use classify::{Classification, Classifier, Disposition, LIVE_DELAY_MS, VOD_DELAY_MS};
pub use error::{FlowError, Result};
pub use flow::{AnalysisUnit, CapturedFlow, FlowPayload, Header, HttpHead};

// --- End-to-end integration tests ------------------------------------------

#[cfg(test)]
mod integration_tests {
    use super::*;
    use bulwark_proto::v1::{Action, MediaKind, SourceChannel};
    use bytes::Bytes;

    fn flow(
        flow_id: u64,
        ct: Option<&str>,
        path: &str,
        body: &[u8],
        channel: SourceChannel,
    ) -> CapturedFlow {
        let mut headers = Vec::new();
        if let Some(ct) = ct {
            headers.push(Header {
                name: "content-type".into(),
                value: ct.into(),
            });
        }
        CapturedFlow {
            flow_id,
            source_channel: channel,
            app_or_host: "cdn.example.com".into(),
            readable: true,
            payload: FlowPayload::Http(HttpHead {
                method: Some("GET".into()),
                path: Some(path.into()),
                status: Some(200),
                headers,
                body_peek: Bytes::copy_from_slice(body),
            }),
        }
    }

    /// Sample content-types classify to the right MediaKind / SourceChannel.
    #[tokio::test]
    async fn sample_content_types_classify_correctly() {
        let fc = DefaultFlowClassifier::with_defaults();

        let cases: &[(&str, &str, MediaKind, SourceChannel)] = &[
            (
                "text/html",
                "/index.html",
                MediaKind::Text,
                SourceChannel::Web,
            ),
            (
                "application/json",
                "/api/chat",
                MediaKind::Text,
                SourceChannel::Web,
            ),
            ("image/jpeg", "/a.jpg", MediaKind::Image, SourceChannel::Web),
            (
                "image/webp",
                "/a.webp",
                MediaKind::Image,
                SourceChannel::Web,
            ),
            ("audio/mpeg", "/a.mp3", MediaKind::Audio, SourceChannel::Web),
            (
                "video/mp4",
                "/a.mp4",
                MediaKind::Video,
                SourceChannel::VideoStream,
            ),
            (
                "video/mp2t",
                "/seg.ts",
                MediaKind::Video,
                SourceChannel::VideoStream,
            ),
        ];

        for (ct, path, kind, channel) in cases {
            let c = fc.classification(&flow(1, Some(ct), path, b"", SourceChannel::Web));
            assert_eq!(c.media_kind, *kind, "content-type {ct} media_kind");
            assert_eq!(c.source_channel, *channel, "content-type {ct} channel");
        }
    }

    /// An HLS manifest (live, mislabeled content-type) classifies as a LIVE_STREAM
    /// manifest and yields no analysis unit (it carries no media bytes).
    #[tokio::test]
    async fn hls_live_manifest_is_live_stream_manifest() {
        let fc = DefaultFlowClassifier::with_defaults();
        let manifest = b"#EXTM3U\n#EXT-X-VERSION:6\n#EXT-X-TARGETDURATION:2\n\
                         #EXT-X-MEDIA-SEQUENCE:330\n#EXTINF:2.0,\nseg330.ts\n#EXTINF:2.0,\nseg331.ts\n";
        let f = flow(
            10,
            Some("text/plain"),
            "/live/master.m3u8",
            manifest,
            SourceChannel::Web,
        );

        let c = fc.classification(&f);
        assert_eq!(c.source_channel, SourceChannel::LiveStream);
        assert_eq!(c.disposition, Disposition::Manifest { live: true });

        let units = fc.classify(f).await.unwrap();
        assert!(units.is_empty());
    }

    /// A DASH manifest (static/VOD) classifies as a VIDEO_STREAM manifest.
    #[tokio::test]
    async fn dash_vod_manifest_is_video_stream_manifest() {
        let fc = DefaultFlowClassifier::with_defaults();
        let mpd = br#"<?xml version="1.0" encoding="UTF-8"?>
            <MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
                 mediaPresentationDuration="PT10M" minBufferTime="PT2S">
              <Period><AdaptationSet mimeType="video/mp4">
                <Representation id="1" bandwidth="800000"></Representation>
              </AdaptationSet></Period>
            </MPD>"#;
        let f = flow(
            11,
            Some("application/dash+xml"),
            "/vod/manifest.mpd",
            mpd,
            SourceChannel::Web,
        );

        let c = fc.classification(&f);
        assert_eq!(c.source_channel, SourceChannel::VideoStream);
        assert_eq!(c.disposition, Disposition::Manifest { live: false });

        let units = fc.classify(f).await.unwrap();
        assert!(units.is_empty());
    }

    /// The delay buffer HOLDS a segment, then RELEASES it (forward) on ALLOW.
    #[tokio::test]
    async fn delay_buffer_holds_then_releases_on_allow() {
        let fc = DefaultFlowClassifier::with_defaults();
        // A progressive mp4 chunk (ftyp box) on a VOD video channel.
        let seg = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2 video-payload-here";
        let units = fc
            .classify(flow(
                20,
                Some("video/mp4"),
                "/vod/chunk0.mp4",
                seg,
                SourceChannel::VideoStream,
            ))
            .await
            .unwrap();

        // The segment is HELD in the buffer, surfaced as a VideoSegment unit.
        assert_eq!(units.len(), 1);
        let seg_id = match &units[0] {
            AnalysisUnit::VideoSegment { segment_id, .. } => segment_id.unwrap(),
            other => panic!("expected VideoSegment, got {other:?}"),
        };
        assert_eq!(
            fc.buffer().pending(),
            1,
            "segment is held pending a verdict"
        );

        // Verdict returns ALLOW → the segment is RELEASED (forwarded) and the
        // buffer drains.
        let released = fc.apply(seg_id, Action::Allow, None).unwrap();
        match released {
            Released::Forward(bytes) => assert_eq!(&bytes[..], &seg[..]),
            other => panic!("expected Forward, got {other:?}"),
        }
        assert_eq!(fc.buffer().pending(), 0, "buffer drains after release");
    }

    /// The delay buffer DROPS a segment on BLOCK — it never forwards downstream.
    #[tokio::test]
    async fn delay_buffer_drops_on_block() {
        let fc = DefaultFlowClassifier::with_defaults();
        // A live .ts segment (MPEG-TS sync byte) on a live channel.
        let seg = [0x47u8; 376]; // two TS packets
        let units = fc
            .classify(flow(
                21,
                Some("video/mp2t"),
                "/live/seg42.ts",
                &seg,
                SourceChannel::LiveStream,
            ))
            .await
            .unwrap();

        let (seg_id, deadline) = match &units[0] {
            AnalysisUnit::VideoSegment {
                segment_id,
                deadline_ms,
                ..
            } => (segment_id.unwrap(), *deadline_ms),
            other => panic!("expected VideoSegment, got {other:?}"),
        };
        assert_eq!(
            deadline, LIVE_DELAY_MS,
            "live segment carries the broadcast-delay deadline"
        );
        assert_eq!(fc.buffer().pending(), 1);

        // Verdict returns BLOCK → the segment is DROPPED, not forwarded.
        let released = fc.apply(seg_id, Action::Block, None).unwrap();
        assert_eq!(released, Released::Dropped);
        assert_eq!(fc.buffer().pending(), 0);
        // And it is truly gone — re-applying is a not-found.
        assert!(fc.apply(seg_id, Action::Allow, None).is_err());
    }

    /// Back-pressure: a saturated buffer refuses new segments (the orchestrator
    /// must slow the source) rather than growing unbounded or bypassing analysis.
    #[tokio::test]
    async fn buffer_exerts_back_pressure_when_saturated() {
        let fc = DefaultFlowClassifier::new(BufferConfig {
            max_segments: 1,
            max_bytes: 1024,
            ..BufferConfig::default()
        });
        let seg = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00payload";

        // First segment admitted.
        let units = fc
            .classify(flow(
                30,
                Some("video/mp4"),
                "/a.mp4",
                seg,
                SourceChannel::VideoStream,
            ))
            .await
            .unwrap();
        assert_eq!(units.len(), 1);

        // Second segment: buffer full → classify surfaces a BufferFull error.
        let err = fc
            .classify(flow(
                31,
                Some("video/mp4"),
                "/b.mp4",
                seg,
                SourceChannel::VideoStream,
            ))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ipc") || err.to_string().contains("back-pressure"));
    }
}
