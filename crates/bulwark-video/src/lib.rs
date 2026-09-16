//! Bounded video decode → sample → classify → remediate pipeline.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use async_trait::async_trait;
use bulwark_audio::{AudioAnalyzer, StubTranscriber, Transcriber};
use bulwark_core::{Analyzer, Result};
use bulwark_proto::v1::{
    analysis_request::Media, Action, AnalysisRequest, Category, InlineMedia, MediaKind, Severity,
    Verdict,
};
use bulwark_vision::{Scorer, VisionAnalyzer, VisionConfig};

pub mod store;
pub use store::{RetentionMode, SegmentOwner, SegmentStore, StoredSegment};

const MAX_INLINE_VIDEO_BYTES: usize = 32 * 1024 * 1024;
const MAX_SAMPLED_FRAMES: usize = 16;
const MAX_AUDIO_WINDOWS: usize = 8;
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// Video-analysis sampling configuration.
#[derive(Debug, Clone)]
pub struct VideoConfig {
    /// Target frame samples per second. One sample/second is the production
    /// latency/coverage default for short HLS/DASH chunks.
    pub sample_fps: f32,
}

impl Default for VideoConfig {
    fn default() -> Self {
        Self { sample_fps: 1.0 }
    }
}

/// Synchronous container decode/remediation seam.
pub trait Demuxer: Send + Sync {
    /// Decode bounded representative frame/audio samples.
    fn sample(&self, segment: &[u8], sample_fps: f32) -> DecodedSegment;

    /// Produce a cleaned replacement for flagged time ranges.
    fn remediate(
        &self,
        _segment: &[u8],
        _blur_ranges: &[(f32, f32)],
        _mute_ranges: &[(f32, f32)],
    ) -> Option<Vec<u8>> {
        None
    }
}

/// Bounded decoded samples from one media segment.
#[derive(Default)]
pub struct DecodedSegment {
    /// JPEG frame samples.
    pub frames: Vec<Vec<u8>>,
    /// WAV speech windows.
    pub audio_windows: Vec<Vec<u8>>,
    /// Seconds represented by one audio window.
    pub audio_window_secs: f32,
    /// False when the container could not be decoded reliably.
    pub decoded: bool,
}

/// Decoder used when ffmpeg support is unavailable.
pub struct NullDemuxer;

impl Demuxer for NullDemuxer {
    fn sample(&self, _segment: &[u8], _sample_fps: f32) -> DecodedSegment {
        DecodedSegment::default()
    }
}

/// Buffered-video analyzer.
pub struct VideoAnalyzer<D: Demuxer = NullDemuxer> {
    cfg: VideoConfig,
    demux: D,
    vision: VisionAnalyzer<Box<dyn Scorer>>,
    audio: AudioAnalyzer<Box<dyn Transcriber>>,
    segment_store: Option<SegmentStore>,
}

impl VideoAnalyzer<NullDemuxer> {
    /// Build without an external decoder.
    pub fn new() -> Self {
        Self {
            cfg: VideoConfig::default(),
            demux: NullDemuxer,
            vision: VisionAnalyzer::from_env(VisionConfig::default()),
            audio: AudioAnalyzer::with_transcriber(
                Box::new(StubTranscriber) as Box<dyn Transcriber>
            ),
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
    /// Build with a concrete bounded demuxer.
    pub fn with_demuxer(cfg: VideoConfig, demux: D) -> Self {
        Self {
            cfg,
            demux,
            vision: VisionAnalyzer::from_env(VisionConfig::default()),
            audio: AudioAnalyzer::with_transcriber(
                Box::new(StubTranscriber) as Box<dyn Transcriber>
            ),
            segment_store: None,
        }
    }

    /// Enable explicitly configured local guardian-review retention.
    pub fn with_segment_store(mut self, store: SegmentStore) -> Self {
        self.segment_store = Some(store);
        self
    }

    /// Override the frame scorer.
    pub fn with_vision_scorer(mut self, scorer: Box<dyn Scorer>) -> Self {
        self.vision = VisionAnalyzer::with_scorer(VisionConfig::default(), scorer);
        self
    }

    /// Override the audio transcriber.
    pub fn with_audio_transcriber(mut self, transcriber: Box<dyn Transcriber>) -> Self {
        self.audio = AudioAnalyzer::with_transcriber(transcriber);
        self
    }
}

fn image_req(parent: &AnalysisRequest, request_id: String, bytes: Vec<u8>) -> AnalysisRequest {
    AnalysisRequest {
        request_id,
        media_kind: MediaKind::Image as i32,
        source_channel: parent.source_channel,
        device_id: parent.device_id.clone(),
        ts: parent.ts,
        deadline_ms: parent.deadline_ms,
        media: Some(Media::InlineMedia(InlineMedia {
            data: bytes,
            mime_type: "image/jpeg".into(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn audio_req(parent: &AnalysisRequest, request_id: String, bytes: Vec<u8>) -> AnalysisRequest {
    AnalysisRequest {
        request_id,
        media_kind: MediaKind::Audio as i32,
        source_channel: parent.source_channel,
        device_id: parent.device_id.clone(),
        ts: parent.ts,
        deadline_ms: parent.deadline_ms,
        media: Some(Media::InlineMedia(InlineMedia {
            data: bytes,
            mime_type: "audio/wav".into(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn rank(verdict: &Verdict) -> (i32, i32, i32) {
    let category = match verdict.category() {
        Category::CsamSuspected => 100,
        Category::Grooming => 80,
        Category::AdultImage | Category::AdultAudio | Category::AdultText => 60,
        Category::Unspecified => 50,
        Category::Safe => 0,
        _ => 40,
    };
    (
        verdict.severity,
        category,
        (verdict.score.clamp(0.0, 1.0) * 10_000.0) as i32,
    )
}

fn consider(worst: &mut Option<Verdict>, verdict: Verdict) {
    if worst
        .as_ref()
        .map(|current| rank(&verdict) > rank(current))
        .unwrap_or(true)
    {
        *worst = Some(verdict);
    }
}

fn uncovered(request_id: String, rationale: impl Into<String>) -> Verdict {
    Verdict {
        request_id,
        category: Category::Unspecified as i32,
        action: Action::Block as i32,
        severity: Severity::Medium as i32,
        score: 0.0,
        rationale: rationale.into(),
        ..Default::default()
    }
}

fn over_deadline(started: Instant, deadline_ms: u32) -> bool {
    deadline_ms > 0 && started.elapsed() >= Duration::from_millis(u64::from(deadline_ms))
}

#[async_trait]
impl<D: Demuxer> Analyzer for VideoAnalyzer<D> {
    fn handles(&self) -> &[MediaKind] {
        const KINDS: [MediaKind; 1] = [MediaKind::Video];
        &KINDS
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        let started = Instant::now();
        let segment = match req.media.as_ref() {
            Some(Media::InlineMedia(media)) => media.data.clone(),
            _ => {
                return Ok(uncovered(
                    req.request_id,
                    "video payload is not available inline on this analyzer",
                ))
            }
        };
        if segment.is_empty() {
            return Ok(uncovered(req.request_id, "empty video segment"));
        }
        if segment.len() > MAX_INLINE_VIDEO_BYTES {
            return Ok(uncovered(
                req.request_id,
                "video segment exceeds bounded analysis limit",
            ));
        }

        let decoded = self.demux.sample(&segment, self.cfg.sample_fps);
        if over_deadline(started, req.deadline_ms) {
            return Ok(uncovered(
                req.request_id,
                "video decode exceeded the requested protection deadline",
            ));
        }
        if !decoded.decoded {
            return Ok(uncovered(
                req.request_id,
                "video decoder unavailable, timed out, or rejected the container",
            ));
        }
        if decoded.frames.is_empty() && decoded.audio_windows.is_empty() {
            return Ok(uncovered(
                req.request_id,
                "video decoded but produced no analyzable samples",
            ));
        }

        let fps = self.cfg.sample_fps.max(0.1);
        let window_secs = decoded.audio_window_secs.max(0.001);
        let mut worst = None;
        let mut blur_ranges = Vec::new();
        let mut mute_ranges = Vec::new();
        let mut incomplete = decoded.frames.len() > MAX_SAMPLED_FRAMES
            || decoded.audio_windows.len() > MAX_AUDIO_WINDOWS;

        for (index, frame) in decoded.frames.iter().take(MAX_SAMPLED_FRAMES).enumerate() {
            if over_deadline(started, req.deadline_ms) {
                incomplete = true;
                break;
            }
            if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
                incomplete = true;
                continue;
            }
            let verdict = self
                .vision
                .analyze(image_req(
                    &req,
                    format!("{}-f{index}", req.request_id),
                    frame.clone(),
                ))
                .await?;
            match verdict.category() {
                Category::Unspecified => incomplete = true,
                Category::AdultImage => {
                    let start = index as f32 / fps;
                    blur_ranges.push((start, start + 1.0 / fps));
                }
                _ => {}
            }
            let terminal = verdict.category() == Category::CsamSuspected;
            consider(&mut worst, verdict);
            if terminal {
                break;
            }
        }

        // Once the frame path already found a terminal block, audio cannot weaken
        // the decision, so skip STT work and return sooner.
        let terminal = worst
            .as_ref()
            .is_some_and(|verdict| verdict.category() == Category::CsamSuspected);
        if !terminal {
            for (index, window) in decoded
                .audio_windows
                .iter()
                .take(MAX_AUDIO_WINDOWS)
                .enumerate()
            {
                if over_deadline(started, req.deadline_ms) {
                    incomplete = true;
                    break;
                }
                let verdict = self
                    .audio
                    .analyze(audio_req(
                        &req,
                        format!("{}-a{index}", req.request_id),
                        window.clone(),
                    ))
                    .await?;
                match verdict.category() {
                    Category::Unspecified => incomplete = true,
                    Category::AdultAudio | Category::Grooming => {
                        let start = index as f32 * window_secs;
                        mute_ranges.push((start, start + window_secs));
                    }
                    _ => {}
                }
                consider(&mut worst, verdict);
            }
        }

        let mut verdict = worst.unwrap_or_else(|| Verdict {
            request_id: req.request_id.clone(),
            category: Category::Safe as i32,
            action: Action::Allow as i32,
            severity: Severity::Info as i32,
            score: 0.0,
            rationale: "all bounded video samples were scored with no safety signal".into(),
            ..Default::default()
        });
        verdict.request_id = req.request_id.clone();

        if incomplete {
            if verdict.category() == Category::Safe {
                verdict = uncovered(
                    req.request_id.clone(),
                    "video protection deadline elapsed before complete bounded coverage",
                );
            } else {
                verdict.action = Action::Block as i32;
                verdict
                    .rationale
                    .push_str("; additional samples were not fully scored before deadline");
            }
        }

        if verdict.category() == Category::CsamSuspected {
            verdict.action = Action::Block as i32;
            verdict.remediated_media.clear();
        } else if !blur_ranges.is_empty() || !mute_ranges.is_empty() {
            // Remediation is optional only after the unsafe classification is
            // known. If there is no time budget left, blocking is safer and faster.
            if over_deadline(started, req.deadline_ms) {
                verdict.action = Action::Block as i32;
                verdict
                    .rationale
                    .push_str("; deadline exhausted before safe remediation");
            } else {
                match self.demux.remediate(&segment, &blur_ranges, &mute_ranges) {
                    Some(cleaned) if !cleaned.is_empty() => verdict.remediated_media = cleaned,
                    _ => {
                        verdict.action = Action::Block as i32;
                        verdict
                            .rationale
                            .push_str("; remediation unavailable, blocking original");
                    }
                }
            }
        }

        if let Some(store) = &self.segment_store {
            match store.store_if_safe(verdict.category(), verdict.action(), &segment) {
                Ok(Some(stored)) => verdict.local_segment_uri = stored.uri,
                Ok(None) => {}
                Err(error) => tracing::warn!(%error, "video review retention failed"),
            }
        }
        verdict.latency_ms = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
        Ok(verdict)
    }
}

#[cfg(feature = "ffmpeg")]
pub mod ffmpeg {
    use super::{DecodedSegment, Demuxer, MAX_SAMPLED_FRAMES};
    use std::ffi::OsString;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime};

    const AUDIO_WINDOW_SECS: u32 = 10;
    const FFMPEG_TIMEOUT: Duration = Duration::from_millis(850);
    const FRAME_EDGE: u32 = 384;

    /// Sidecar ffmpeg decoder. ffmpeg remains out-of-process.
    #[derive(Default)]
    pub struct FfmpegDemuxer {
        binary: Option<PathBuf>,
    }

    impl FfmpegDemuxer {
        /// Build using env/PATH ffmpeg discovery.
        pub fn new() -> Self {
            Self { binary: None }
        }

        /// Pin an explicit ffmpeg binary.
        pub fn with_binary(path: impl Into<PathBuf>) -> Self {
            Self {
                binary: Some(path.into()),
            }
        }

        fn binary(&self) -> OsString {
            self.binary
                .as_ref()
                .map(|path| path.as_os_str().to_owned())
                .or_else(|| std::env::var_os("BULWARK_FFMPEG_BINARY").filter(|v| !v.is_empty()))
                .or_else(|| std::env::var_os("FFMPEG_BINARY").filter(|v| !v.is_empty()))
                .unwrap_or_else(|| OsString::from("ffmpeg"))
        }

        fn command(&self) -> Command {
            let mut command = Command::new(self.binary());
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        }

        fn run_bounded(&self, command: &mut Command) -> bool {
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(_) => return false,
            };
            let started = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return status.success(),
                    Ok(None) if started.elapsed() < FFMPEG_TIMEOUT => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) | Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return false;
                    }
                }
            }
        }

        fn decode_frames(
            &self,
            workspace: &TempWorkspace,
            sample_fps: f32,
        ) -> Option<Vec<Vec<u8>>> {
            let pattern = workspace.dir.join("frame-%04d.jpg");
            let mut command = self.command();
            command
                .arg("-hide_banner")
                .arg("-loglevel")
                .arg("error")
                .arg("-threads")
                .arg("2")
                .arg("-i")
                .arg(&workspace.input)
                .arg("-vf")
                .arg(format!(
                    "fps={},scale='min({},iw)':-2",
                    sample_fps.clamp(0.25, 2.0),
                    FRAME_EDGE
                ))
                .arg("-frames:v")
                .arg(MAX_SAMPLED_FRAMES.to_string())
                .arg("-q:v")
                .arg("8")
                .arg("-y")
                .arg(pattern);
            if !self.run_bounded(&mut command) {
                return None;
            }

            let mut paths = std::fs::read_dir(&workspace.dir)
                .ok()?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("jpg"))
                .collect::<Vec<_>>();
            paths.sort();
            Some(
                paths
                    .into_iter()
                    .take(MAX_SAMPLED_FRAMES)
                    .filter_map(|path| std::fs::read(path).ok())
                    .collect(),
            )
        }

        fn decode_audio(&self, workspace: &TempWorkspace) -> Option<Vec<Vec<u8>>> {
            let output = workspace.dir.join("audio.wav");
            let mut command = self.command();
            command
                .arg("-hide_banner")
                .arg("-loglevel")
                .arg("error")
                .arg("-threads")
                .arg("1")
                .arg("-i")
                .arg(&workspace.input)
                .arg("-vn")
                .arg("-ac")
                .arg("1")
                .arg("-ar")
                .arg("16000")
                .arg("-c:a")
                .arg("pcm_s16le")
                .arg("-y")
                .arg(&output);
            if !self.run_bounded(&mut command) {
                return Some(Vec::new());
            }
            let wav = std::fs::read(output).ok()?;
            Some(window_wav(&wav, AUDIO_WINDOW_SECS))
        }

        fn remediate_impl(
            &self,
            segment: &[u8],
            blur_ranges: &[(f32, f32)],
            mute_ranges: &[(f32, f32)],
        ) -> Option<Vec<u8>> {
            if segment.is_empty() || (blur_ranges.is_empty() && mute_ranges.is_empty()) {
                return None;
            }
            let workspace = TempWorkspace::new(segment, output_ext(segment)).ok()?;
            let output = workspace
                .dir
                .join(format!("cleaned.{}", output_ext(segment)));
            let mut command = self.command();
            command
                .arg("-hide_banner")
                .arg("-loglevel")
                .arg("error")
                .arg("-threads")
                .arg("2")
                .arg("-i")
                .arg(&workspace.input)
                .arg("-copyts");
            if let Some(filter) = filter_expr("boxblur=16", blur_ranges) {
                command.arg("-vf").arg(filter);
            } else {
                command.arg("-c:v").arg("copy");
            }
            if let Some(filter) = filter_expr("volume=0", mute_ranges) {
                command.arg("-af").arg(filter);
            } else {
                command.arg("-c:a").arg("copy");
            }
            command.arg("-y").arg(&output);
            if !self.run_bounded(&mut command) {
                return None;
            }
            std::fs::read(output).ok().filter(|bytes| !bytes.is_empty())
        }
    }

    impl Demuxer for FfmpegDemuxer {
        fn sample(&self, segment: &[u8], sample_fps: f32) -> DecodedSegment {
            let workspace = match TempWorkspace::new(segment, output_ext(segment)) {
                Ok(workspace) => workspace,
                Err(_) => return DecodedSegment::default(),
            };

            // Video decode and audio extraction are independent; doing them in
            // parallel removes an entire sidecar duration from the gate latency.
            let (frames, audio_windows) = std::thread::scope(|scope| {
                let frame_job = scope.spawn(|| self.decode_frames(&workspace, sample_fps));
                let audio_job = scope.spawn(|| self.decode_audio(&workspace));
                (
                    frame_job.join().ok().flatten(),
                    audio_job.join().ok().flatten().unwrap_or_default(),
                )
            });

            DecodedSegment {
                decoded: frames.is_some(),
                frames: frames.unwrap_or_default(),
                audio_windows,
                audio_window_secs: AUDIO_WINDOW_SECS as f32,
            }
        }

        fn remediate(
            &self,
            segment: &[u8],
            blur_ranges: &[(f32, f32)],
            mute_ranges: &[(f32, f32)],
        ) -> Option<Vec<u8>> {
            self.remediate_impl(segment, blur_ranges, mute_ranges)
        }
    }

    fn filter_expr(filter: &str, ranges: &[(f32, f32)]) -> Option<String> {
        if ranges.is_empty() {
            return None;
        }
        let enable = ranges
            .iter()
            .map(|(start, end)| format!("between(t,{start:.3},{end:.3})"))
            .collect::<Vec<_>>()
            .join("+");
        Some(format!("{filter}:enable='{enable}'"))
    }

    fn window_wav(wav: &[u8], window_secs: u32) -> Vec<Vec<u8>> {
        let reader = match hound::WavReader::new(std::io::Cursor::new(wav)) {
            Ok(reader) => reader,
            Err(_) => return Vec::new(),
        };
        let spec = reader.spec();
        let samples = reader
            .into_samples::<i16>()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        let per_window = spec.sample_rate as usize * window_secs as usize * spec.channels as usize;
        if per_window == 0 {
            return Vec::new();
        }
        samples
            .chunks(per_window)
            .filter_map(|chunk| {
                let mut buffer = std::io::Cursor::new(Vec::new());
                let mut writer = hound::WavWriter::new(&mut buffer, spec).ok()?;
                for sample in chunk {
                    writer.write_sample(*sample).ok()?;
                }
                writer.finalize().ok()?;
                Some(buffer.into_inner())
            })
            .collect()
    }

    fn output_ext(bytes: &[u8]) -> &'static str {
        if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
            "mp4"
        } else if bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]) {
            "webm"
        } else if bytes.first() == Some(&0x47) {
            "ts"
        } else if bytes.starts_with(b"FLV") {
            "flv"
        } else {
            "mp4"
        }
    }

    struct TempWorkspace {
        dir: PathBuf,
        input: PathBuf,
    }

    impl TempWorkspace {
        fn new(segment: &[u8], ext: &str) -> std::io::Result<Self> {
            cleanup_stale_workspaces();
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "bulwark-video-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
            let input = dir.join(format!("input.{ext}"));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&input)?;
            file.write_all(segment)?;
            file.sync_all()?;
            Ok(Self { dir, input })
        }
    }

    impl Drop for TempWorkspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn cleanup_stale_workspaces() {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        let cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(60 * 60))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with("bulwark-video-") {
                continue;
            }
            let path = entry.path();
            let old = std::fs::metadata(&path)
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .is_some_and(|modified| modified < cutoff);
            if old {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EmptyDecoded;
    impl Demuxer for EmptyDecoded {
        fn sample(&self, _: &[u8], _: f32) -> DecodedSegment {
            DecodedSegment {
                decoded: true,
                ..Default::default()
            }
        }
    }

    #[tokio::test]
    async fn decoded_without_samples_is_not_safe() {
        let analyzer = VideoAnalyzer::with_demuxer(VideoConfig::default(), EmptyDecoded);
        let verdict = analyzer
            .analyze(AnalysisRequest {
                request_id: "v".into(),
                media_kind: MediaKind::Video as i32,
                media: Some(Media::InlineMedia(InlineMedia {
                    data: vec![1, 2, 3],
                    ..Default::default()
                })),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(verdict.category(), Category::Unspecified);
        assert_eq!(verdict.action(), Action::Block);
    }

    #[test]
    fn production_sampling_is_latency_bounded() {
        assert!(VideoConfig::default().sample_fps <= 1.0);
        const {
            assert!(MAX_SAMPLED_FRAMES <= 16);
            assert!(MAX_AUDIO_WINDOWS <= 8);
        }
    }
}
