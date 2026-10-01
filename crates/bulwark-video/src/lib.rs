//! Bounded video decode → sample → classify → remediate pipeline.
#![forbid(unsafe_code)]

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
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

/// One shared deadline and cancellation signal for the entire video operation.
#[derive(Clone)]
pub struct AnalysisBudget {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl AnalysisBudget {
    /// A zero request deadline uses 850 ms; explicit deadlines are capped at 5 s.
    pub fn new(deadline_ms: u32) -> Self {
        Self {
            deadline: Instant::now()
                + Duration::from_millis(u64::from(if deadline_ms == 0 {
                    850
                } else {
                    deadline_ms.min(5000)
                })),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn expired(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }

    fn remaining_ms(&self) -> u32 {
        self.deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u128::from(u32::MAX)) as u32
    }
}

struct CancelOnDrop(AnalysisBudget);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Relaxed);
    }
}

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
    fn sample(&self, segment: &[u8], sample_fps: f32, budget: &AnalysisBudget) -> DecodedSegment;

    /// Produce a cleaned replacement for flagged time ranges.
    fn remediate(
        &self,
        _segment: &[u8],
        _blur_ranges: &[(f32, f32)],
        _mute_ranges: &[(f32, f32)],
        _budget: &AnalysisBudget,
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
    fn sample(
        &self,
        _segment: &[u8],
        _sample_fps: f32,
        _budget: &AnalysisBudget,
    ) -> DecodedSegment {
        DecodedSegment::default()
    }
}

/// Buffered-video analyzer.
pub struct VideoAnalyzer<D: Demuxer = NullDemuxer> {
    cfg: VideoConfig,
    demux: Arc<D>,
    vision: Arc<VisionAnalyzer<Box<dyn Scorer>>>,
    audio: Arc<AudioAnalyzer<Box<dyn Transcriber>>>,
    segment_store: Option<SegmentStore>,
}

impl VideoAnalyzer<NullDemuxer> {
    /// Build without an external decoder.
    pub fn new() -> Self {
        Self {
            cfg: VideoConfig::default(),
            demux: Arc::new(NullDemuxer),
            vision: Arc::new(VisionAnalyzer::from_env(VisionConfig::default())),
            audio: Arc::new(AudioAnalyzer::with_transcriber(
                Box::new(StubTranscriber) as Box<dyn Transcriber>
            )),
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
            demux: Arc::new(demux),
            vision: Arc::new(VisionAnalyzer::from_env(VisionConfig::default())),
            audio: Arc::new(AudioAnalyzer::with_transcriber(
                Box::new(StubTranscriber) as Box<dyn Transcriber>
            )),
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
        self.vision = Arc::new(VisionAnalyzer::with_scorer(VisionConfig::default(), scorer));
        self
    }

    /// Override the audio transcriber.
    pub fn with_audio_transcriber(mut self, transcriber: Box<dyn Transcriber>) -> Self {
        self.audio = Arc::new(AudioAnalyzer::with_transcriber(transcriber));
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

#[async_trait]
impl<D: Demuxer + 'static> Analyzer for VideoAnalyzer<D> {
    fn handles(&self) -> &[MediaKind] {
        const KINDS: [MediaKind; 1] = [MediaKind::Video];
        &KINDS
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        static WORKERS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
            std::sync::OnceLock::new();
        let budget = AnalysisBudget::new(req.deadline_ms);
        let _cancel = CancelOnDrop(budget.clone());
        let permit = match WORKERS
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4)))
            .clone()
            .try_acquire_owned()
        {
            Ok(permit) => permit,
            Err(_) => {
                return Ok(uncovered(
                    req.request_id,
                    "video workers saturated; coverage unavailable",
                ))
            }
        };
        let worker = Self {
            cfg: self.cfg.clone(),
            demux: self.demux.clone(),
            vision: self.vision.clone(),
            audio: self.audio.clone(),
            segment_store: self.segment_store.clone(),
        };
        let request_id = req.request_id.clone();
        let deadline = tokio::time::Instant::from_std(budget.deadline);
        let job = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| bulwark_core::Error::Other(error.into()))?;
            runtime.block_on(worker.analyze_bounded(req, budget))
        });
        match tokio::time::timeout_at(deadline, job).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Ok(uncovered(
                request_id,
                "video worker failed; coverage unavailable",
            )),
            Err(_) => Ok(uncovered(request_id, "video protection deadline elapsed")),
        }
    }
}

impl<D: Demuxer> VideoAnalyzer<D> {
    async fn analyze_bounded(
        &self,
        mut req: AnalysisRequest,
        budget: AnalysisBudget,
    ) -> Result<Verdict> {
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

        let decoded = self.demux.sample(&segment, self.cfg.sample_fps, &budget);
        if budget.expired() {
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
            if budget.expired() {
                incomplete = true;
                break;
            }
            if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
                incomplete = true;
                continue;
            }
            req.deadline_ms = budget.remaining_ms().max(1);
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
                if budget.expired() {
                    incomplete = true;
                    break;
                }
                req.deadline_ms = budget.remaining_ms().max(1);
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

        incomplete |= budget.expired();
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

        if incomplete && verdict.category() != Category::CsamSuspected {
            return Ok(uncovered(
                req.request_id,
                "video coverage incomplete or deadline exhausted",
            ));
        }

        if verdict.category() == Category::CsamSuspected {
            verdict.action = Action::Block as i32;
            verdict.remediated_media.clear();
        } else if !blur_ranges.is_empty() || !mute_ranges.is_empty() {
            // Remediation is optional only after the unsafe classification is
            // known. If there is no time budget left, blocking is safer and faster.
            if budget.expired() {
                verdict.action = Action::Block as i32;
                verdict
                    .rationale
                    .push_str("; deadline exhausted before safe remediation");
            } else {
                match self
                    .demux
                    .remediate(&segment, &blur_ranges, &mute_ranges, &budget)
                {
                    Some(cleaned) if !cleaned.is_empty() && !budget.expired() => {
                        verdict.remediated_media = cleaned
                    }
                    _ => {
                        verdict.action = Action::Block as i32;
                        verdict
                            .rationale
                            .push_str("; remediation unavailable, blocking original");
                    }
                }
            }
        }

        if budget.expired() && verdict.category() != Category::CsamSuspected {
            return Ok(uncovered(
                req.request_id,
                "video deadline exhausted during remediation",
            ));
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
    use super::{
        AnalysisBudget, DecodedSegment, Demuxer, MAX_AUDIO_WINDOWS, MAX_FRAME_BYTES,
        MAX_INLINE_VIDEO_BYTES, MAX_SAMPLED_FRAMES,
    };
    use std::ffi::OsString;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime};

    const AUDIO_WINDOW_SECS: u32 = 10;
    const FRAME_EDGE: u32 = 384;

    /// Sidecar ffmpeg decoder. ffmpeg remains out-of-process.
    #[derive(Default)]
    pub struct FfmpegDemuxer {
        binary: Option<PathBuf>,
    }

    enum AudioStream {
        Absent,
        Samples(Vec<Vec<u8>>),
        Incomplete,
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

        fn run_bounded(&self, command: &mut Command, budget: &AnalysisBudget) -> bool {
            if budget.expired() {
                return false;
            }
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(_) => return false,
            };
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return status.success(),
                    Ok(None) if !budget.expired() => {
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
            budget: &AnalysisBudget,
        ) -> Option<Vec<Vec<u8>>> {
            let pattern = workspace.dir.join("frame-%04d.jpg");
            let mut command = self.command();
            command
                .arg("-hide_banner")
                .arg("-loglevel")
                .arg("error")
                .arg("-xerror")
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
                .arg((MAX_SAMPLED_FRAMES + 1).to_string())
                .arg("-q:v")
                .arg("8")
                .arg("-y")
                .arg(pattern);
            if !self.run_bounded(&mut command, budget) {
                return None;
            }

            read_frames(workspace)
        }

        fn decode_audio(
            &self,
            workspace: &TempWorkspace,
            present: bool,
            budget: &AnalysisBudget,
        ) -> AudioStream {
            if !present {
                return AudioStream::Absent;
            }
            match self.extract_audio(workspace, budget) {
                Some(windows) => AudioStream::Samples(windows),
                None => AudioStream::Incomplete,
            }
        }

        fn extract_audio(
            &self,
            workspace: &TempWorkspace,
            budget: &AnalysisBudget,
        ) -> Option<Vec<Vec<u8>>> {
            let output = workspace.dir.join("audio.wav");
            let mut command = self.command();
            command
                .args([
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-xerror",
                    "-threads",
                    "1",
                    "-i",
                ])
                .arg(&workspace.input)
                .args([
                    "-map",
                    "0:a:0",
                    "-vn",
                    "-ac",
                    "1",
                    "-ar",
                    "16000",
                    "-c:a",
                    "pcm_s16le",
                    "-t",
                ])
                .arg((AUDIO_WINDOW_SECS as usize * (MAX_AUDIO_WINDOWS + 1)).to_string())
                .arg("-fs")
                .arg(MAX_WAV_BYTES.to_string())
                .arg("-y")
                .arg(&output);
            if !self.run_bounded(&mut command, budget) {
                return None;
            }
            let file = std::fs::File::open(output).ok()?;
            if file.metadata().ok()?.len() > MAX_WAV_BYTES {
                return None;
            }
            window_wav(file, AUDIO_WINDOW_SECS, budget)
        }

        fn probe_audio(&self, workspace: &TempWorkspace, budget: &AnalysisBudget) -> Option<bool> {
            let probe = self.binary();
            let probe = PathBuf::from(probe).with_file_name(if cfg!(windows) {
                "ffprobe.exe"
            } else {
                "ffprobe"
            });
            let output = workspace.dir.join("streams.json");
            let file = std::fs::File::create(&output).ok()?;
            let mut command = Command::new(probe);
            command
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .stdout(file)
                .args([
                    "-v",
                    "error",
                    "-select_streams",
                    "a",
                    "-show_entries",
                    "stream=index",
                    "-of",
                    "json",
                ])
                .arg(&workspace.input);
            if !self.run_bounded(&mut command, budget) {
                return None;
            }
            if std::fs::metadata(&output).ok()?.len() > 64 * 1024 {
                return None;
            }
            let data: serde_json::Value =
                serde_json::from_reader(std::fs::File::open(output).ok()?).ok()?;
            Some(!data.get("streams")?.as_array()?.is_empty())
        }

        fn remediate_impl(
            &self,
            segment: &[u8],
            blur_ranges: &[(f32, f32)],
            mute_ranges: &[(f32, f32)],
            budget: &AnalysisBudget,
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
                .arg("-xerror")
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
            command
                .arg("-fs")
                .arg((MAX_INLINE_VIDEO_BYTES + 1).to_string())
                .arg("-y")
                .arg(&output);
            if !self.run_bounded(&mut command, budget) {
                return None;
            }
            if std::fs::metadata(&output).ok()?.len() > MAX_INLINE_VIDEO_BYTES as u64 {
                return None;
            }
            std::fs::read(output).ok().filter(|bytes| !bytes.is_empty())
        }
    }

    impl Demuxer for FfmpegDemuxer {
        fn sample(
            &self,
            segment: &[u8],
            sample_fps: f32,
            budget: &AnalysisBudget,
        ) -> DecodedSegment {
            let workspace = match TempWorkspace::new(segment, output_ext(segment)) {
                Ok(workspace) => workspace,
                Err(_) => return DecodedSegment::default(),
            };

            let Some(audio_present) = self.probe_audio(&workspace, budget) else {
                return DecodedSegment::default();
            };

            // Video decode and audio extraction are independent; doing them in
            // parallel removes an entire sidecar duration from the gate latency.
            let (frames, audio_stream) = std::thread::scope(|scope| {
                let frame_job = scope.spawn(|| self.decode_frames(&workspace, sample_fps, budget));
                let audio_job =
                    scope.spawn(|| self.decode_audio(&workspace, audio_present, budget));
                (
                    frame_job.join().ok().flatten(),
                    audio_job.join().unwrap_or(AudioStream::Incomplete),
                )
            });

            let audio_windows = match audio_stream {
                AudioStream::Absent => Some(Vec::new()),
                AudioStream::Samples(windows) => Some(windows),
                AudioStream::Incomplete => None,
            };
            DecodedSegment {
                decoded: frames.is_some() && audio_windows.is_some() && !budget.expired(),
                frames: frames.unwrap_or_default(),
                audio_windows: audio_windows.unwrap_or_default(),
                audio_window_secs: AUDIO_WINDOW_SECS as f32,
            }
        }

        fn remediate(
            &self,
            segment: &[u8],
            blur_ranges: &[(f32, f32)],
            mute_ranges: &[(f32, f32)],
            budget: &AnalysisBudget,
        ) -> Option<Vec<u8>> {
            self.remediate_impl(segment, blur_ranges, mute_ranges, budget)
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

    fn read_frames(workspace: &TempWorkspace) -> Option<Vec<Vec<u8>>> {
        let entries = std::fs::read_dir(&workspace.dir)
            .ok()?
            .collect::<std::io::Result<Vec<_>>>()
            .ok()?;
        let mut paths = entries
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("jpg"))
            .collect::<Vec<_>>();
        paths.sort();
        paths
            .into_iter()
            .take(MAX_SAMPLED_FRAMES + 1)
            .map(|path| {
                if std::fs::metadata(&path)?.len() > MAX_FRAME_BYTES as u64 {
                    return Err(std::io::Error::other("frame exceeds byte limit"));
                }
                std::fs::read(path)
            })
            .collect::<std::io::Result<Vec<_>>>()
            .ok()
    }

    const MAX_WAV_BYTES: u64 =
        16000 * 2 * AUDIO_WINDOW_SECS as u64 * (MAX_AUDIO_WINDOWS as u64 + 1) + 4096;

    fn window_wav(
        file: std::fs::File,
        window_secs: u32,
        budget: &AnalysisBudget,
    ) -> Option<Vec<Vec<u8>>> {
        let mut reader = hound::WavReader::new(std::io::BufReader::new(file)).ok()?;
        let spec = reader.spec();
        if spec.sample_rate != 16000
            || spec.channels != 1
            || spec.bits_per_sample != 16
            || spec.sample_format != hound::SampleFormat::Int
        {
            return None;
        }
        let per_window = spec.sample_rate as usize * window_secs as usize;
        let expected = reader.len() as usize;
        if expected == 0 {
            return None;
        }
        let mut samples = reader.samples::<i16>();
        let mut windows = Vec::new();
        let mut count = 0;
        while count < expected && windows.len() <= MAX_AUDIO_WINDOWS {
            if budget.expired() {
                return None;
            }
            let mut buffer = std::io::Cursor::new(Vec::new());
            let mut writer = hound::WavWriter::new(&mut buffer, spec).ok()?;
            for _ in 0..per_window.min(expected - count) {
                writer.write_sample(samples.next()?.ok()?).ok()?;
                count += 1;
            }
            writer.finalize().ok()?;
            windows.push(buffer.into_inner());
        }
        (!budget.expired()).then_some(windows)
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
            let workspace = Self {
                input: dir.join(format!("input.{ext}")),
                dir: dir.clone(),
            };
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
            Ok(workspace)
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
    #[cfg(test)]
    mod decode_tests {
        use super::*;
        #[test]
        #[ignore = "subprocess fixture, invoked by the cancellation test"]
        fn waiting_child() {
            if let Some(path) = std::env::var_os("BULWARK_TEST_CHILD_READY") {
                std::fs::write(path, b"ready").unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }
        }

        #[test]
        fn cancellation_kills_child_and_cleans_workspace() {
            let workspace = TempWorkspace::new(&[], "mp4").unwrap();
            let dir = workspace.dir.clone();
            let marker = workspace.dir.join("ready");
            let budget = AnalysisBudget::new(5000);
            let watcher_budget = budget.clone();
            let watcher_marker = marker.clone();
            let watcher = std::thread::spawn(move || {
                while !watcher_marker.exists() && !watcher_budget.expired() {
                    std::thread::sleep(Duration::from_millis(2));
                }
                watcher_budget
                    .cancelled
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            });
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--ignored",
                    "--exact",
                    "ffmpeg::decode_tests::waiting_child",
                ])
                .env("BULWARK_TEST_CHILD_READY", &marker)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            assert!(!FfmpegDemuxer::new().run_bounded(&mut command, &budget));
            watcher.join().unwrap();
            assert!(marker.exists(), "child must begin work before cancellation");
            drop(workspace);
            assert!(
                !dir.exists(),
                "cancelled work must release its temporary files"
            );
        }

        #[test]
        fn wav_errors_and_overflow_keep_incomplete_coverage() {
            let workspace = TempWorkspace::new(&[], "mp4").unwrap();
            let bad_frame = workspace.dir.join("frame-0001.jpg");
            std::fs::create_dir(&bad_frame).unwrap();
            assert!(read_frames(&workspace).is_none());
            std::fs::remove_dir(&bad_frame).unwrap();
            for index in 0..MAX_SAMPLED_FRAMES + 1 {
                std::fs::write(workspace.dir.join(format!("frame-{index:04}.jpg")), [1]).unwrap();
            }
            assert_eq!(
                read_frames(&workspace).unwrap().len(),
                MAX_SAMPLED_FRAMES + 1
            );
            let path = workspace.dir.join("test.wav");
            std::fs::write(&path, b"not a WAV").unwrap();
            assert!(window_wav(
                std::fs::File::open(&path).unwrap(),
                1,
                &AnalysisBudget::new(5000)
            )
            .is_none());
            let spec = hound::WavSpec {
                channels: 1,
                sample_rate: 16000,
                bits_per_sample: 16,
                sample_format: hound::SampleFormat::Int,
            };
            let mut writer = hound::WavWriter::create(&path, spec).unwrap();
            for _ in 0..16000 * (MAX_AUDIO_WINDOWS + 2) {
                writer.write_sample(0i16).unwrap();
            }
            writer.finalize().unwrap();
            assert_eq!(
                window_wav(
                    std::fs::File::open(&path).unwrap(),
                    1,
                    &AnalysisBudget::new(5000)
                )
                .unwrap()
                .len(),
                MAX_AUDIO_WINDOWS + 1
            );
            let mut writer = hound::WavWriter::create(&path, spec).unwrap();
            for _ in 0..16000 {
                writer.write_sample(0i16).unwrap();
            }
            writer.finalize().unwrap();
            assert_eq!(
                window_wav(
                    std::fs::File::open(&path).unwrap(),
                    1,
                    &AnalysisBudget::new(5000)
                )
                .unwrap()
                .len(),
                1
            );
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(64)
                .unwrap();
            assert!(window_wav(
                std::fs::File::open(&path).unwrap(),
                1,
                &AnalysisBudget::new(5000)
            )
            .is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EmptyDecoded;
    impl Demuxer for EmptyDecoded {
        fn sample(&self, _: &[u8], _: f32, _: &AnalysisBudget) -> DecodedSegment {
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

    struct Samples {
        frames: usize,
        audio: bool,
        decoded: bool,
        remediation_delay: bool,
    }
    impl Demuxer for Samples {
        fn sample(&self, _: &[u8], _: f32, _: &AnalysisBudget) -> DecodedSegment {
            DecodedSegment {
                frames: vec![vec![1]; self.frames],
                audio_windows: if self.audio { vec![vec![1]] } else { vec![] },
                decoded: self.decoded,
                audio_window_secs: 10.0,
            }
        }
        fn remediate(
            &self,
            _: &[u8],
            _: &[(f32, f32)],
            _: &[(f32, f32)],
            _: &AnalysisBudget,
        ) -> Option<Vec<u8>> {
            if self.remediation_delay {
                std::thread::sleep(Duration::from_millis(80));
            }
            Some(vec![1])
        }
    }
    struct Score {
        delay: bool,
        unsafe_frame: bool,
    }
    impl Scorer for Score {
        fn score(&self, _: &[u8]) -> f32 {
            if self.delay {
                std::thread::sleep(Duration::from_millis(80));
            }
            if self.unsafe_frame {
                0.9
            } else {
                0.0
            }
        }
        fn model_id(&self) -> &str {
            "test-real-scorer"
        }
    }
    struct SlowAudio;
    impl Transcriber for SlowAudio {
        fn transcribe(&self, _: &[u8]) -> Option<String> {
            std::thread::sleep(Duration::from_millis(80));
            Some("hello".into())
        }
        fn engine_id(&self) -> &str {
            "test-real-transcriber"
        }
    }
    struct WaitForCancellation {
        started: Arc<AtomicBool>,
        finished: Arc<AtomicBool>,
    }
    impl Demuxer for WaitForCancellation {
        fn sample(&self, _: &[u8], _: f32, budget: &AnalysisBudget) -> DecodedSegment {
            self.started.store(true, Ordering::SeqCst);
            while !budget.expired() {
                std::thread::sleep(Duration::from_millis(2));
            }
            self.finished.store(true, Ordering::SeqCst);
            DecodedSegment::default()
        }
    }
    fn request(deadline_ms: u32) -> AnalysisRequest {
        AnalysisRequest {
            request_id: "regression".into(),
            media_kind: MediaKind::Video as i32,
            deadline_ms,
            media: Some(Media::InlineMedia(InlineMedia {
                data: vec![1],
                ..Default::default()
            })),
            ..Default::default()
        }
    }
    #[tokio::test]
    async fn incomplete_and_late_samples_never_allow_or_rewrite() {
        for (
            frames,
            audio,
            decoded,
            slow_score,
            unsafe_frame,
            slow_remediation,
            deadline,
            expected,
        ) in [
            (1, false, true, false, false, false, 1000, Category::Safe),
            (16, false, true, false, false, false, 1000, Category::Safe),
            (
                17,
                false,
                true,
                false,
                false,
                false,
                1000,
                Category::Unspecified,
            ),
            (
                1,
                false,
                false,
                false,
                false,
                false,
                1000,
                Category::Unspecified,
            ),
            (
                1,
                false,
                true,
                true,
                false,
                false,
                30,
                Category::Unspecified,
            ),
            (
                0,
                true,
                true,
                false,
                false,
                false,
                30,
                Category::Unspecified,
            ),
            (1, false, true, false, true, true, 30, Category::Unspecified),
        ] {
            let analyzer = VideoAnalyzer::with_demuxer(
                VideoConfig::default(),
                Samples {
                    frames,
                    audio,
                    decoded,
                    remediation_delay: slow_remediation,
                },
            )
            .with_vision_scorer(Box::new(Score {
                delay: slow_score,
                unsafe_frame,
            }))
            .with_audio_transcriber(Box::new(SlowAudio));
            let verdict = analyzer.analyze(request(deadline)).await.unwrap();
            assert_eq!(verdict.category(), expected);
            if expected == Category::Unspecified {
                assert_eq!(verdict.action(), Action::Block);
                assert!(verdict.remediated_media.is_empty());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let analyzer = VideoAnalyzer::with_demuxer(
            VideoConfig::default(),
            WaitForCancellation {
                started: started.clone(),
                finished: finished.clone(),
            },
        );
        let task = tokio::spawn(async move { analyzer.analyze(request(5000)).await });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !started.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !finished.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("cancelled decode must stop and release its worker");
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
