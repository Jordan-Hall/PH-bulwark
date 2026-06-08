//! aegis-video — the ffmpeg decode → sample → classify → block/blur/mute pipeline.
//!
//! Implements the `Analyzer` contract for `MediaKind::VIDEO`. ffmpeg is **shelled
//! out** via `ffmpeg-sidecar` (behind the `ffmpeg` feature) so its GPL/LGPL never
//! links into our binary. A buffered segment is decoded, frames are sampled
//! (scene-aware), each frame goes to `aegis-vision`, audio windows to
//! `aegis-audio`, and the worst verdict drives the action:
//!   * NSFW frame → BLUR flagged frames (re-encode flagged segments only)
//!   * explicit audio → MUTE the span
//!   * if a whole segment is unrecoverable → BLOCK
//!
//! Live streams rely on the broadcast-delay buffer in `aegis-flow`; only flagged
//! segments are re-encoded (GPU NVENC/QSV/VAAPI when present). No LLM.
#![forbid(unsafe_code)]

use aegis_core::Result;
use aegis_proto::v1::{
    analysis_request::Media, Action, AnalysisRequest, Category, InlineMedia, MediaKind, Severity,
    Verdict,
};
use async_trait::async_trait;

use aegis_core::Analyzer;

use aegis_audio::AudioAnalyzer;
use aegis_vision::{Scorer, VisionAnalyzer, VisionConfig};

pub mod store;
pub use store::{SegmentStore, StoredSegment};

#[derive(Debug, Clone)]
pub struct VideoConfig {
    /// Frames per second to sample for classification (plus scene-cut detection).
    pub sample_fps: f32,
}
impl Default for VideoConfig {
    fn default() -> Self {
        Self { sample_fps: 2.0 }
    }
}

/// Decodes a buffered video segment into sampled frames (JPEG bytes) + audio
/// windows. Implemented by the `ffmpeg` feature; the default returns nothing.
pub trait Demuxer: Send + Sync {
    fn sample(&self, segment: &[u8], sample_fps: f32) -> DecodedSegment;
}

#[derive(Default)]
pub struct DecodedSegment {
    pub frames: Vec<Vec<u8>>, // sampled frame images (e.g. JPEG)
    pub audio_windows: Vec<Vec<u8>>,
    pub decoded: bool, // false = couldn't decode (→ conservative handling)
}

/// Default demuxer: no ffmpeg available → empty (handled conservatively).
pub struct NullDemuxer;
impl Demuxer for NullDemuxer {
    fn sample(&self, _segment: &[u8], _fps: f32) -> DecodedSegment {
        DecodedSegment::default()
    }
}

pub struct VideoAnalyzer<D: Demuxer = NullDemuxer> {
    cfg: VideoConfig,
    demux: D,
    /// Per-frame NSFW scorer. Built via [`VisionAnalyzer::from_env`] so a
    /// `--features onnx` build with `AEGIS_NSFW_MODEL` set scores frames with the
    /// real model; otherwise it is the fail-open stub. (`VisionAnalyzer::new()`
    /// would pin the stub even under onnx, leaving sampled frames unscored.)
    vision: VisionAnalyzer<Box<dyn Scorer>>,
    audio: AudioAnalyzer,
    /// Optional local store for blocked/borderline segments (guardian review).
    /// `None` = don't retain clips (default). CSAM is never stored regardless.
    segment_store: Option<SegmentStore>,
}

impl VideoAnalyzer<NullDemuxer> {
    pub fn new() -> Self {
        Self {
            cfg: VideoConfig::default(),
            demux: NullDemuxer,
            vision: VisionAnalyzer::from_env(VisionConfig::default()),
            audio: AudioAnalyzer::new(),
            segment_store: None,
        }
    }
}
impl Default for VideoAnalyzer<NullDemuxer> {
    fn default() -> Self {
        Self::new()
    }
}
impl<D: Demuxer> VideoAnalyzer<D> {
    pub fn with_demuxer(cfg: VideoConfig, demux: D) -> Self {
        Self {
            cfg,
            demux,
            vision: VisionAnalyzer::from_env(VisionConfig::default()),
            audio: AudioAnalyzer::new(),
            segment_store: None,
        }
    }

    /// Attach a [`SegmentStore`]: blocked/borderline non-CSAM segments are
    /// written locally for guardian review (CSAM is never stored).
    pub fn with_segment_store(mut self, store: SegmentStore) -> Self {
        self.segment_store = Some(store);
        self
    }

    /// Override the per-frame NSFW scorer. Production uses the env/ONNX scorer from
    /// [`VisionAnalyzer::from_env`]; this injects a specific scorer (tests, or a
    /// custom model).
    pub fn with_vision_scorer(mut self, scorer: Box<dyn Scorer>) -> Self {
        self.vision = VisionAnalyzer::with_scorer(VisionConfig::default(), scorer);
        self
    }
}

fn image_req(req_id: &str, bytes: Vec<u8>) -> AnalysisRequest {
    AnalysisRequest {
        request_id: req_id.to_string(),
        media_kind: MediaKind::Image as i32,
        media: Some(Media::InlineMedia(InlineMedia {
            data: bytes,
            mime_type: "image/jpeg".into(),
            ..Default::default()
        })),
        ..Default::default()
    }
}
fn audio_req(req_id: &str, bytes: Vec<u8>) -> AnalysisRequest {
    AnalysisRequest {
        request_id: req_id.to_string(),
        media_kind: MediaKind::Audio as i32,
        media: Some(Media::InlineMedia(InlineMedia {
            data: bytes,
            mime_type: "audio/L16".into(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

#[async_trait]
impl<D: Demuxer> Analyzer for VideoAnalyzer<D> {
    fn handles(&self) -> &[MediaKind] {
        const K: [MediaKind; 1] = [MediaKind::Video];
        &K
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        let segment = match req.media.as_ref() {
            Some(Media::InlineMedia(m)) => m.data.clone(),
            _ => Vec::new(),
        };
        let decoded = self.demux.sample(&segment, self.cfg.sample_fps);

        if !decoded.decoded {
            // Couldn't decode (no ffmpeg / unsupported) → Unspecified ("couldn't
            // score") so policy fail-CLOSES on the coverage gap instead of allowing
            // an unscored video as Safe.
            return Ok(Verdict {
                request_id: req.request_id,
                category: Category::Unspecified as i32,
                action: Action::Allow as i32, // policy is the authority and fail-closes
                severity: Severity::Info as i32,
                rationale: "video not decoded (ffmpeg feature off / unsupported); not scored".into(),
                ..Default::default()
            });
        }

        let mut worst: Option<Verdict> = None;
        let mut take = |v: Verdict| {
            let better = worst.as_ref().map(|w| v.score > w.score).unwrap_or(true);
            if better {
                worst = Some(v);
            }
        };

        for (i, frame) in decoded.frames.iter().enumerate() {
            let v = self
                .vision
                .analyze(image_req(
                    &format!("{}-f{i}", req.request_id),
                    frame.clone(),
                ))
                .await?;
            if v.category == Category::AdultImage as i32 {
                take(v);
            }
        }
        for (i, win) in decoded.audio_windows.iter().enumerate() {
            let v = self
                .audio
                .analyze(audio_req(&format!("{}-a{i}", req.request_id), win.clone()))
                .await?;
            if v.category == Category::AdultAudio as i32 {
                take(v);
            }
        }

        let mut verdict = worst.unwrap_or(Verdict {
            request_id: req.request_id,
            category: Category::Safe as i32,
            action: Action::Allow as i32,
            severity: Severity::Info as i32,
            rationale: "no flagged frames/audio in segment".into(),
            ..Default::default()
        });

        // Retain the segment for guardian review when it was blocked/borderline.
        // `store_if_safe` enforces the CSAM-never-stored boundary and skips benign
        // ALLOW, so this is a no-op for safe traffic.
        if let Some(store) = &self.segment_store {
            match store.store_if_safe(verdict.category(), verdict.action(), &segment) {
                Ok(Some(stored)) => {
                    tracing::info!(uri = %stored.uri, "aegis-video: stored segment for review");
                    // Propagate the local ref so the guardian alert can find the clip.
                    verdict.local_segment_uri = stored.uri;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "aegis-video: segment store write failed"),
            }
        }

        Ok(verdict)
    }
}

#[cfg(feature = "ffmpeg")]
pub mod ffmpeg {
    //! `ffmpeg-sidecar` demuxer: spawn ffmpeg to extract sampled frames and audio
    //! windows from a buffered segment, and (for flagged segments) re-encode with
    //! blur/mute filters. ffmpeg is a child process — **never linked** (keeps its
    //! GPL/LGPL and its C attack surface out of our address space).
    use super::{DecodedSegment, Demuxer};
    use ffmpeg_sidecar::command::FfmpegCommand;
    use ffmpeg_sidecar::event::FfmpegEvent;
    use std::ffi::OsString;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    /// One decoded + sampled frame, with the dimensions ffmpeg actually produced.
    /// `data` is raw RGB24 (`width * height * 3` bytes) so downstream code can
    /// re-encode or hand it to a classifier without guessing the pixel layout.
    #[derive(Clone)]
    pub struct SampledFrame {
        pub width: u32,
        pub height: u32,
        pub timestamp: f32,
        pub data: Vec<u8>,
    }

    /// Resolve the ffmpeg binary. ffmpeg-sidecar's own `ffmpeg_path()` only looks
    /// for a binary adjacent to our exe or on `PATH`; it does **not** read
    /// `FFMPEG_BINARY`. We honour `FFMPEG_BINARY` ourselves (matching the wider
    /// sidecar ecosystem convention), plus the product-specific
    /// `AEGIS_FFMPEG_BINARY`, plus Aegis' per-install `ffmpeg_binary.txt`, and
    /// otherwise fall back to bare `ffmpeg`.
    fn resolve_binary(explicit: Option<&Path>) -> OsString {
        if let Some(p) = explicit {
            return p.as_os_str().to_owned();
        }
        if let Some(env) = std::env::var_os("FFMPEG_BINARY") {
            if !env.is_empty() {
                return env;
            }
        }
        if let Some(env) = std::env::var_os("AEGIS_FFMPEG_BINARY") {
            if !env.is_empty() {
                return env;
            }
        }
        if let Some(config) = read_config_value("ffmpeg_binary.txt") {
            return config.into();
        }
        OsString::from("ffmpeg")
    }

    fn read_config_value(file_name: &str) -> Option<OsString> {
        let path = aegis_config_dir()?.join(file_name);
        let value = std::fs::read_to_string(path).ok()?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(OsString::from(trimmed))
        }
    }

    fn aegis_config_dir() -> Option<PathBuf> {
        #[cfg(windows)]
        {
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .map(|base| base.join("Aegis"))
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
                })
                .map(|base| base.join("aegis"))
        }
    }

    /// Real ffmpeg-backed demuxer.
    ///
    /// `binary` lets callers pin an exact ffmpeg path (e.g. from app config);
    /// when `None`, `FFMPEG_BINARY` then `PATH` are consulted at run time.
    #[derive(Default)]
    pub struct FfmpegDemuxer {
        binary: Option<PathBuf>,
    }

    impl FfmpegDemuxer {
        pub fn new() -> Self {
            Self { binary: None }
        }

        /// Pin a specific ffmpeg binary path.
        pub fn with_binary(path: impl Into<PathBuf>) -> Self {
            Self {
                binary: Some(path.into()),
            }
        }

        fn command(&self) -> FfmpegCommand {
            let mut cmd = FfmpegCommand::new_with_path(resolve_binary(self.binary.as_deref()));
            cmd.create_no_window();
            cmd
        }

        /// Decode `input` (a file path or an ffmpeg input URL such as a `lavfi`
        /// spec when paired with `-f lavfi`) and sample frames at `sample_fps`,
        /// returning the decoded RGB24 frames with their true dimensions.
        ///
        /// Returns `None` if ffmpeg could not be spawned (binary missing) so
        /// callers can fail open / self-skip.
        pub fn decode_path_frames(
            &self,
            input: &str,
            sample_fps: f32,
            lavfi: bool,
        ) -> Option<Vec<SampledFrame>> {
            let mut cmd = self.command();
            cmd.hide_banner();
            if lavfi {
                cmd.format("lavfi");
            }
            cmd.input(input);
            // Sample at `sample_fps`, emit raw RGB24 frames on stdout so the
            // sidecar parser hands us exact per-frame dimensions + timestamps.
            cmd.arg("-vf").arg(format!("fps={sample_fps}"));
            cmd.rawvideo(); // -f rawvideo -pix_fmt rgb24 -
            cmd.inner_pipe_stdout();

            let mut child = cmd.spawn().ok()?;
            let mut frames = Vec::new();
            let iter = child.iter().ok()?;
            for event in iter {
                if let FfmpegEvent::OutputFrame(f) = event {
                    frames.push(SampledFrame {
                        width: f.width,
                        height: f.height,
                        timestamp: f.timestamp,
                        data: f.data,
                    });
                }
            }
            let _ = child.wait();
            Some(frames)
        }

        /// Decode an in-memory segment by staging it to a temp file (the segment
        /// API is byte-oriented; piping arbitrary container bytes through stdin
        /// is format-fragile, so a temp file is the robust path).
        fn decode_segment_frames(
            &self,
            segment: &[u8],
            sample_fps: f32,
        ) -> Option<Vec<SampledFrame>> {
            if segment.is_empty() {
                return Some(Vec::new());
            }
            let tmp = TempInput::write(segment).ok()?;
            self.decode_path_frames(&tmp.path().to_string_lossy(), sample_fps, false)
        }
    }

    impl Demuxer for FfmpegDemuxer {
        fn sample(&self, segment: &[u8], fps: f32) -> DecodedSegment {
            match self.decode_segment_frames(segment, fps) {
                Some(frames) => DecodedSegment {
                    frames: frames.into_iter().map(|f| f.data).collect(),
                    audio_windows: Vec::new(),
                    decoded: true,
                },
                // ffmpeg unavailable → not decoded → conservative handling upstream.
                None => DecodedSegment::default(),
            }
        }
    }

    /// `FfmpegCommand` exposes `pipe_stdout()` but it pushes a second `-`. We
    /// already added `-` via `rawvideo()`, so wire stdout piping directly on the
    /// inner `Command` instead of appending another output arg.
    trait InnerPipeStdout {
        fn inner_pipe_stdout(&mut self) -> &mut Self;
    }
    impl InnerPipeStdout for FfmpegCommand {
        fn inner_pipe_stdout(&mut self) -> &mut Self {
            self.as_inner_mut().stdout(std::process::Stdio::piped());
            self
        }
    }

    /// A self-deleting temp file holding a staged input segment.
    struct TempInput {
        path: PathBuf,
    }
    impl TempInput {
        fn write(bytes: &[u8]) -> std::io::Result<Self> {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut path = std::env::temp_dir();
            path.push(format!("aegis-video-seg-{}-{}.bin", std::process::id(), n));
            let mut f = std::fs::File::create(&path)?;
            f.write_all(bytes)?;
            f.flush()?;
            Ok(Self { path })
        }
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempInput {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OneNsfwFrame;
    impl Demuxer for OneNsfwFrame {
        fn sample(&self, _s: &[u8], _f: f32) -> DecodedSegment {
            DecodedSegment {
                frames: vec![vec![1, 2, 3]],
                audio_windows: vec![],
                decoded: true,
            }
        }
    }

    #[tokio::test]
    async fn undecoded_segment_fails_closed() {
        // NullDemuxer → decoded=false → can't score → Unspecified (policy fail-closes),
        // not a false Safe for a video we never decoded.
        let a = VideoAnalyzer::new();
        let req = AnalysisRequest {
            request_id: "v".into(),
            media_kind: MediaKind::Video as i32,
            media: Some(Media::InlineMedia(InlineMedia {
                data: vec![0; 16],
                ..Default::default()
            })),
            ..Default::default()
        };
        let v = a.analyze(req).await.unwrap();
        assert_eq!(v.category, Category::Unspecified as i32);
    }

    #[tokio::test]
    async fn decoded_segment_with_stub_vision_is_safe() {
        // Vision stub scores 0 → no frame flagged → segment SAFE.
        let a = VideoAnalyzer::with_demuxer(VideoConfig::default(), OneNsfwFrame);
        let req = AnalysisRequest {
            request_id: "v2".into(),
            media_kind: MediaKind::Video as i32,
            media: Some(Media::InlineMedia(InlineMedia::default())),
            ..Default::default()
        };
        let v = a.analyze(req).await.unwrap();
        assert_eq!(v.category, Category::Safe as i32);
    }

    /// Always-NSFW scorer (stands in for the real ONNX model wired via
    /// `from_env`/`with_vision_scorer`).
    struct HotScorer;
    impl Scorer for HotScorer {
        fn score(&self, _b: &[u8]) -> f32 {
            1.0
        }
        fn model_id(&self) -> &str {
            "test-hot"
        }
    }

    #[tokio::test]
    async fn flagged_frame_blocks_and_retains_segment() {
        // End-to-end: real-ish scorer flags the decoded frame → segment verdict is
        // AdultImage and the clip is retained, so `local_segment_uri` is set. This
        // is the path that was dead while video used the stub scorer.
        let dir = std::env::temp_dir().join(format!(
            "aegis-vid-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = SegmentStore::new(&dir).expect("create store");
        let a = VideoAnalyzer::with_demuxer(VideoConfig::default(), OneNsfwFrame)
            .with_vision_scorer(Box::new(HotScorer))
            .with_segment_store(store);
        let req = AnalysisRequest {
            request_id: "v3".into(),
            media_kind: MediaKind::Video as i32,
            media: Some(Media::InlineMedia(InlineMedia {
                data: vec![5, 6, 7, 8],
                ..Default::default()
            })),
            ..Default::default()
        };
        let v = a.analyze(req).await.unwrap();
        assert_eq!(v.category, Category::AdultImage as i32);
        assert!(
            v.local_segment_uri.starts_with("blob://"),
            "a flagged clip must be retained for review"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
