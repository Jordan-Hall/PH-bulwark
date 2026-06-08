//! bulwark-video — the ffmpeg decode → sample → classify → block/blur/mute pipeline.
//!
//! Implements the `Analyzer` contract for `MediaKind::VIDEO`. ffmpeg is **shelled
//! out** via `ffmpeg-sidecar` (behind the `ffmpeg` feature) so its GPL/LGPL never
//! links into our binary. A buffered segment is decoded, frames are sampled
//! (scene-aware), each frame goes to `bulwark-vision`, audio windows to
//! `bulwark-audio`, and the worst verdict drives the action:
//!   * NSFW frame → BLUR flagged frames (re-encode flagged segments only)
//!   * explicit audio → MUTE the span
//!   * if a whole segment is unrecoverable → BLOCK
//!
//! Live streams rely on the broadcast-delay buffer in `bulwark-flow`; only flagged
//! segments are re-encoded (GPU NVENC/QSV/VAAPI when present). No LLM.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bulwark_core::Result;
use bulwark_proto::v1::{
    analysis_request::Media, Action, AnalysisRequest, Category, InlineMedia, MediaKind, Severity,
    Verdict,
};

use bulwark_core::Analyzer;

use bulwark_audio::{AudioAnalyzer, StubTranscriber, Transcriber};
use bulwark_vision::{Scorer, VisionAnalyzer, VisionConfig};

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
    /// `--features onnx` build with `BULWARK_NSFW_MODEL` set scores frames with the
    /// real model; otherwise it is the fail-open stub. (`VisionAnalyzer::new()`
    /// would pin the stub even under onnx, leaving sampled frames unscored.)
    vision: VisionAnalyzer<Box<dyn Scorer>>,
    /// Audio path: transcribe windows → bulwark-text. Boxed so the server can inject
    /// whisper (default = StubTranscriber, which fail-CLOSES with no model).
    audio: AudioAnalyzer<Box<dyn Transcriber>>,
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
            audio: AudioAnalyzer::with_transcriber(Box::new(StubTranscriber) as Box<dyn Transcriber>),
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
            audio: AudioAnalyzer::with_transcriber(Box::new(StubTranscriber) as Box<dyn Transcriber>),
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

    /// Inject the audio transcriber (e.g. whisper) for the video's speech windows.
    /// Default is the StubTranscriber (fail-CLOSED); the server swaps in whisper.
    pub fn with_audio_transcriber(mut self, transcriber: Box<dyn Transcriber>) -> Self {
        self.audio = AudioAnalyzer::with_transcriber(transcriber);
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
                rationale: "video not decoded (ffmpeg feature off / unsupported); not scored"
                    .into(),
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
            // Flag the clip on adult OR grooming speech in any window.
            if v.category == Category::AdultAudio as i32 || v.category == Category::Grooming as i32 {
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
                    tracing::info!(uri = %stored.uri, "bulwark-video: stored segment for review");
                    // Propagate the local ref so the guardian alert can find the clip.
                    verdict.local_segment_uri = stored.uri;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "bulwark-video: segment store write failed"),
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
    /// `BULWARK_FFMPEG_BINARY`, plus Bulwark' per-install `ffmpeg_binary.txt`, and
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
        if let Some(env) = std::env::var_os("BULWARK_FFMPEG_BINARY") {
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
        let path = bulwark_config_dir()?.join(file_name);
        let value = std::fs::read_to_string(path).ok()?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(OsString::from(trimmed))
        }
    }

    fn bulwark_config_dir() -> Option<PathBuf> {
        #[cfg(windows)]
        {
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .map(|base| base.join("Bulwark"))
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
                })
                .map(|base| base.join("bulwark"))
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

        /// Extract the segment's audio as a single 16 kHz-mono PCM WAV (the format
        /// whisper wants). `None` if there's no audio / ffmpeg is unavailable.
        fn decode_segment_audio(&self, segment: &[u8]) -> Option<Vec<u8>> {
            if segment.is_empty() {
                return None;
            }
            let input = TempInput::write(segment).ok()?;
            let output = TempInput::reserve("wav");
            let in_path = input.path().to_string_lossy().into_owned();
            let out_path = output.path().to_string_lossy().into_owned();
            let mut cmd = self.command();
            cmd.hide_banner();
            cmd.input(&in_path);
            // Strip video, downmix to mono, resample to 16 kHz, 16-bit PCM.
            cmd.arg("-vn")
                .arg("-ac")
                .arg("1")
                .arg("-ar")
                .arg("16000")
                .arg("-c:a")
                .arg("pcm_s16le");
            cmd.arg("-y").arg(&out_path);
            let mut child = cmd.spawn().ok()?;
            if let Ok(iter) = child.iter() {
                for _ in iter {} // drain so ffmpeg runs to completion
            }
            let _ = child.wait();
            std::fs::read(output.path()).ok().filter(|b| !b.is_empty())
        }
    }

    impl Demuxer for FfmpegDemuxer {
        fn sample(&self, segment: &[u8], fps: f32) -> DecodedSegment {
            match self.decode_segment_frames(segment, fps) {
                Some(frames) => DecodedSegment {
                    // Re-encode each raw RGB24 frame to JPEG so bulwark-vision (which
                    // decodes via the `image` crate) can actually score it.
                    frames: frames
                        .into_iter()
                        .filter_map(|f| rgb24_to_jpeg(f.width, f.height, &f.data))
                        .collect(),
                    // Extract + window the audio track so speech gets transcribed.
                    audio_windows: self
                        .decode_segment_audio(segment)
                        .map(|wav| window_wav(&wav, AUDIO_WINDOW_SECS))
                        .unwrap_or_default(),
                    decoded: true,
                },
                // ffmpeg unavailable → not decoded → conservative handling upstream.
                None => DecodedSegment::default(),
            }
        }
    }

    /// Encode a raw RGB24 frame (as ffmpeg emits via `-pix_fmt rgb24`) to JPEG so
    /// bulwark-vision's image-crate decoder can read it. `None` if the buffer size
    /// doesn't match `width*height*3` (e.g. a truncated frame at EOF).
    fn rgb24_to_jpeg(width: u32, height: u32, rgb: &[u8]) -> Option<Vec<u8>> {
        let img = image::RgbImage::from_raw(width, height, rgb.to_vec())?;
        let mut jpeg = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut jpeg, image::ImageFormat::Jpeg)
            .ok()?;
        Some(jpeg.into_inner())
    }

    /// Audio is windowed into chunks this many seconds long; each window is scored
    /// independently so a flagged window maps to a precise mute timecode.
    const AUDIO_WINDOW_SECS: u32 = 15;

    /// Split a 16 kHz-mono PCM WAV into `window_secs`-long WAV windows. Window `i`
    /// covers `[i*window_secs, (i+1)*window_secs)` — its timecode for remediation.
    fn window_wav(wav: &[u8], window_secs: u32) -> Vec<Vec<u8>> {
        let reader = match hound::WavReader::new(std::io::Cursor::new(wav)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let spec = reader.spec();
        let samples: Vec<i16> = reader.into_samples::<i16>().filter_map(Result::ok).collect();
        let per_window = spec.sample_rate as usize * window_secs as usize * spec.channels as usize;
        if per_window == 0 {
            return Vec::new();
        }
        samples
            .chunks(per_window)
            .filter_map(|chunk| {
                let mut buf = std::io::Cursor::new(Vec::new());
                let mut writer = hound::WavWriter::new(&mut buf, spec).ok()?;
                for &s in chunk {
                    writer.write_sample(s).ok()?;
                }
                writer.finalize().ok()?;
                Some(buf.into_inner())
            })
            .collect()
    }

    // ---- remediation: soften flagged timecodes instead of blocking the whole clip ----

    /// `between(t,a,b)+between(t,c,d)…` for ffmpeg's `enable=` (None if no ranges).
    fn enable_expr(ranges: &[(f32, f32)]) -> Option<String> {
        if ranges.is_empty() {
            return None;
        }
        Some(
            ranges
                .iter()
                .map(|(a, b)| format!("between(t,{a:.3},{b:.3})"))
                .collect::<Vec<_>>()
                .join("+"),
        )
    }

    /// Blur the video only where a frame was flagged NSFW.
    fn blur_filter(ranges: &[(f32, f32)]) -> Option<String> {
        enable_expr(ranges).map(|e| format!("boxblur=20:enable='{e}'"))
    }

    /// Mute the audio only where speech was flagged adult/grooming.
    fn mute_filter(ranges: &[(f32, f32)]) -> Option<String> {
        enable_expr(ranges).map(|e| format!("volume=0:enable='{e}'"))
    }

    impl FfmpegDemuxer {
        /// Re-encode `segment`, blurring the video during `blur_ranges` and muting the
        /// audio during `mute_ranges` (seconds). Returns the remediated bytes, or
        /// `None` if there is nothing to do or ffmpeg is unavailable. Softens the
        /// offending timecodes rather than dropping the whole clip.
        pub fn remediate(
            &self,
            segment: &[u8],
            blur_ranges: &[(f32, f32)],
            mute_ranges: &[(f32, f32)],
        ) -> Option<Vec<u8>> {
            if segment.is_empty() || (blur_ranges.is_empty() && mute_ranges.is_empty()) {
                return None;
            }
            let input = TempInput::write(segment).ok()?;
            let output = TempInput::reserve("mp4");
            let in_path = input.path().to_string_lossy().into_owned();
            let out_path = output.path().to_string_lossy().into_owned();
            let mut cmd = self.command();
            cmd.hide_banner();
            cmd.input(&in_path);
            if let Some(vf) = blur_filter(blur_ranges) {
                cmd.arg("-vf").arg(vf);
            }
            if let Some(af) = mute_filter(mute_ranges) {
                cmd.arg("-af").arg(af);
            }
            cmd.arg("-y").arg(&out_path); // overwrite the reserved output path
            let mut child = cmd.spawn().ok()?;
            if let Ok(iter) = child.iter() {
                for _ in iter {} // drain events so ffmpeg runs to completion
            }
            let _ = child.wait();
            let bytes = std::fs::read(output.path()).ok()?;
            (!bytes.is_empty()).then_some(bytes)
        }
    }

    #[cfg(test)]
    mod ffmpeg_tests {
        use super::{blur_filter, mute_filter, rgb24_to_jpeg, window_wav};

        #[test]
        fn rgb24_converts_to_decodable_jpeg() {
            // 2x2 RGB24 (12 bytes) → JPEG that the image crate can re-decode.
            let rgb = vec![255u8, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255];
            let jpeg = rgb24_to_jpeg(2, 2, &rgb).expect("convert");
            let decoded = image::load_from_memory(&jpeg).expect("re-decode jpeg");
            assert_eq!(decoded.width(), 2);
            assert_eq!(decoded.height(), 2);
        }

        #[test]
        fn wrong_size_buffer_is_rejected() {
            assert!(rgb24_to_jpeg(2, 2, &[0u8; 5]).is_none());
        }

        #[test]
        fn filters_build_enable_expressions() {
            let blur = blur_filter(&[(1.0, 2.0), (5.0, 6.0)]).expect("blur");
            assert!(blur.starts_with("boxblur="));
            assert!(blur.contains("between(t,1.000,2.000)+between(t,5.000,6.000)"));
            let mute = mute_filter(&[(3.0, 4.0)]).expect("mute");
            assert!(mute.contains("volume=0"));
            assert!(mute.contains("between(t,3.000,4.000)"));
        }

        #[test]
        fn empty_ranges_yield_no_filter() {
            assert!(blur_filter(&[]).is_none());
            assert!(mute_filter(&[]).is_none());
        }

        #[test]
        fn audio_splits_into_timecoded_windows() {
            // 32 s of 16 kHz mono → 15 s windows → [0,15),[15,30),[30,32) = 3 windows.
            let spec = hound::WavSpec {
                channels: 1,
                sample_rate: 16_000,
                bits_per_sample: 16,
                sample_format: hound::SampleFormat::Int,
            };
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut w = hound::WavWriter::new(&mut buf, spec).unwrap();
                for _ in 0..(16_000 * 32) {
                    w.write_sample(0i16).unwrap();
                }
                w.finalize().unwrap();
            }
            let windows = window_wav(&buf.into_inner(), 15);
            assert_eq!(windows.len(), 3);
            for win in &windows {
                assert!(hound::WavReader::new(std::io::Cursor::new(win)).is_ok());
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
            path.push(format!(
                "bulwark-video-seg-{}-{}.bin",
                std::process::id(),
                n
            ));
            let mut f = std::fs::File::create(&path)?;
            f.write_all(bytes)?;
            f.flush()?;
            Ok(Self { path })
        }
        /// Reserve a temp path (no file written) for ffmpeg to write its output to;
        /// self-deletes on drop like a staged input.
        fn reserve(ext: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "bulwark-video-out-{}-{}.{ext}",
                std::process::id(),
                n
            ));
            Self { path }
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
            "bulwark-vid-test-{}",
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
