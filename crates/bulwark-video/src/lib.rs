//! Bounded video decode → sample → classify → remediate pipeline.
#![forbid(unsafe_code)]

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
const MAX_SAMPLED_FRAMES: usize = 120;
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct VideoConfig {
    pub sample_fps: f32,
}

impl Default for VideoConfig {
    fn default() -> Self {
        Self { sample_fps: 2.0 }
    }
}

pub trait Demuxer: Send + Sync {
    fn sample(&self, segment: &[u8], sample_fps: f32) -> DecodedSegment;

    fn remediate(
        &self,
        _segment: &[u8],
        _blur_ranges: &[(f32, f32)],
        _mute_ranges: &[(f32, f32)],
    ) -> Option<Vec<u8>> {
        None
    }
}

#[derive(Default)]
pub struct DecodedSegment {
    pub frames: Vec<Vec<u8>>,
    pub audio_windows: Vec<Vec<u8>>,
    pub audio_window_secs: f32,
    pub decoded: bool,
}

pub struct NullDemuxer;
impl Demuxer for NullDemuxer {
    fn sample(&self, _segment: &[u8], _sample_fps: f32) -> DecodedSegment {
        DecodedSegment::default()
    }
}

pub struct VideoAnalyzer<D: Demuxer = NullDemuxer> {
    cfg: VideoConfig,
    demux: D,
    vision: VisionAnalyzer<Box<dyn Scorer>>,
    audio: AudioAnalyzer<Box<dyn Transcriber>>,
    segment_store: Option<SegmentStore>,
}

impl VideoAnalyzer<NullDemuxer> {
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

    pub fn with_segment_store(mut self, store: SegmentStore) -> Self {
        self.segment_store = Some(store);
        self
    }

    pub fn with_vision_scorer(mut self, scorer: Box<dyn Scorer>) -> Self {
        self.vision = VisionAnalyzer::with_scorer(VisionConfig::default(), scorer);
        self
    }

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
        media: Some(Media::InlineMedia(InlineMedia {
            data: bytes,
            mime_type: "audio/wav".into(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn severity_rank(verdict: &Verdict) -> (i32, i32, i32) {
    let category = verdict.category();
    let category_rank = match category {
        Category::CsamSuspected => 100,
        Category::Grooming => 80,
        Category::AdultImage | Category::AdultAudio | Category::AdultText => 60,
        Category::Unspecified => 50,
        Category::Safe => 0,
        _ => 40,
    };
    (verdict.severity, category_rank, (verdict.score * 10_000.0) as i32)
}

fn consider(worst: &mut Option<Verdict>, verdict: Verdict) {
    let replace = worst
        .as_ref()
        .map(|current| severity_rank(&verdict) > severity_rank(current))
        .unwrap_or(true);
    if replace {
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
impl<D: Demuxer> Analyzer for VideoAnalyzer<D> {
    fn handles(&self) -> &[MediaKind] {
        const KINDS: [MediaKind; 1] = [MediaKind::Video];
        &KINDS
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
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
                format!(
                    "video segment exceeds bounded inline analysis limit of {} bytes",
                    MAX_INLINE_VIDEO_BYTES
                ),
            ));
        }

        let decoded = self.demux.sample(&segment, self.cfg.sample_fps);
        if !decoded.decoded {
            return Ok(uncovered(
                req.request_id,
                "video decoder unavailable, timed out, or rejected the container",
            ));
        }
        if decoded.frames.is_empty() && decoded.audio_windows.is_empty() {
            return Ok(uncovered(
                req.request_id,
                "video decoded but produced no analyzable frame or audio samples",
            ));
        }

        let fps = self.cfg.sample_fps.max(0.001);
        let window_secs = decoded.audio_window_secs.max(0.001);
        let mut worst: Option<Verdict> = None;
        let mut blur_ranges = Vec::new();
        let mut mute_ranges = Vec::new();
        let mut coverage_incomplete = false;

        for (index, frame) in decoded.frames.iter().take(MAX_SAMPLED_FRAMES).enumerate() {
            if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
                coverage_incomplete = true;
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
                Category::Safe => {}
                Category::Unspecified => coverage_incomplete = true,
                Category::AdultImage => {
                    let start = index as f32 / fps;
                    blur_ranges.push((start, start + 1.0 / fps));
                }
                Category::CsamSuspected => {}
                _ => {}
            }
            consider(&mut worst, verdict);
        }

        for (index, window) in decoded.audio_windows.iter().enumerate() {
            let verdict = self
                .audio
                .analyze(audio_req(
                    &req,
                    format!("{}-a{index}", req.request_id),
                    window.clone(),
                ))
                .await?;
            match verdict.category() {
                Category::Safe => {}
                Category::Unspecified => coverage_incomplete = true,
                Category::AdultAudio | Category::Grooming => {
                    let start = index as f32 * window_secs;
                    mute_ranges.push((start, start + window_secs));
                }
                Category::CsamSuspected => {}
                _ => {}
            }
            consider(&mut worst, verdict);
        }

        if decoded.frames.len() > MAX_SAMPLED_FRAMES {
            coverage_incomplete = true;
        }

        let mut verdict = worst.unwrap_or_else(|| Verdict {
            request_id: req.request_id.clone(),
            category: Category::Safe as i32,
            action: Action::Allow as i32,
            severity: Severity::Info as i32,
            score: 0.0,
            rationale: "all decoded video samples were analyzed with no safety signal".into(),
            ..Default::default()
        });
        verdict.request_id = req.request_id.clone();

        // Any unknown child result prevents a clean Safe conclusion. If another
        // known signal exists we retain that category but force conservative block
        // and annotate incomplete coverage; otherwise return explicit Unspecified.
        if coverage_incomplete {
            if verdict.category() == Category::Safe {
                verdict = uncovered(
                    req.request_id.clone(),
                    "video analysis coverage incomplete; at least one sample was not scored",
                );
            } else {
                verdict.action = Action::Block as i32;
                verdict.rationale.push_str("; additional video samples were not fully scored");
            }
        }

        if verdict.category() == Category::CsamSuspected {
            verdict.action = Action::Block as i32;
            verdict.remediated_media.clear();
        } else if !blur_ranges.is_empty() || !mute_ranges.is_empty() {
            match self.demux.remediate(&segment, &blur_ranges, &mute_ranges) {
                Some(cleaned) if !cleaned.is_empty() => verdict.remediated_media = cleaned,
                _ => {
                    // We know the original is unsafe but could not reliably produce
                    // the promised redaction. Drop rather than forward raw content.
                    verdict.action = Action::Block as i32;
                    verdict.rationale.push_str("; remediation unavailable, blocking original");
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

    const AUDIO_WINDOW_SECS: u32 = 15;
    const FFMPEG_TIMEOUT: Duration = Duration::from_secs(20);

    #[derive(Default)]
    pub struct FfmpegDemuxer {
        binary: Option<PathBuf>,
    }

    impl FfmpegDemuxer {
        pub fn new() -> Self {
            Self { binary: None }
        }

        pub fn with_binary(path: impl Into<PathBuf>) -> Self {
            Self {
                binary: Some(path.into()),
            }
        }

        fn binary(&self) -> OsString {
            if let Some(path) = &self.binary {
                return path.as_os_str().to_owned();
            }
            std::env::var_os("BULWARK_FFMPEG_BINARY")
                .filter(|value| !value.is_empty())
                .or_else(|| std::env::var_os("FFMPEG_BINARY").filter(|value| !value.is_empty()))
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
                        std::thread::sleep(Duration::from_millis(25));
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
            let pattern = workspace.dir.join("frame-%06d.jpg");
            let mut command = self.command();
            command
                .arg("-hide_banner")
                .arg("-loglevel")
                .arg("error")
                .arg("-i")
                .arg(&workspace.input)
                .arg("-vf")
                .arg(format!("fps={}", sample_fps.max(0.1)))
                .arg("-frames:v")
                .arg(MAX_SAMPLED_FRAMES.to_string())
                .arg("-q:v")
                .arg("5")
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
            let output = workspace.dir.join(format!("cleaned.{}", output_ext(segment)));
            let mut command = self.command();
            command
                .arg("-hide_banner")
                .arg("-loglevel")
                .arg("error")
                .arg("-i")
                .arg(&workspace.input)
                .arg("-copyts");
            if let Some(filter) = filter_expr("boxblur=20", blur_ranges) {
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
            let frames = self.decode_frames(&workspace, sample_fps);
            let audio_windows = self.decode_audio(&workspace).unwrap_or_default();
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
        let per_window = spec.sample_rate as usize
            * window_secs as usize
            * spec.channels as usize;
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
        } else if bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
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
                .map(|modified| modified < cutoff)
                .unwrap_or(false);
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
}
