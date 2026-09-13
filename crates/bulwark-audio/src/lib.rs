//! bulwark-audio — transcript-first audio safety analysis.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bulwark_core::{Analyzer, Result};
use bulwark_proto::v1::{
    analysis_request::Media, Action, AnalysisRequest, Category, Evidence, MediaKind, Severity,
    TextSpan, Verdict,
};
use bulwark_text::TextAnalyzer;

const MAX_AUDIO_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_NORMALIZED_WAV_BYTES: usize = 32 * 1024 * 1024;
const FFMPEG_NORMALIZE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(600);

pub trait Transcriber: Send + Sync {
    fn transcribe(&self, audio: &[u8]) -> Option<String>;
    fn engine_id(&self) -> &str;
}

pub struct StubTranscriber;
impl Transcriber for StubTranscriber {
    fn transcribe(&self, _audio: &[u8]) -> Option<String> {
        None
    }
    fn engine_id(&self) -> &str {
        "stub-none"
    }
}

impl Transcriber for Box<dyn Transcriber> {
    fn transcribe(&self, audio: &[u8]) -> Option<String> {
        (**self).transcribe(audio)
    }
    fn engine_id(&self) -> &str {
        (**self).engine_id()
    }
}

/// Normalizes compressed/container audio to 16 kHz mono PCM WAV with a bounded
/// ffmpeg sidecar before delegating to the underlying transcriber. WAV input is
/// passed straight through, so video-extracted speech windows pay no extra process
/// startup cost.
pub struct FfmpegTranscriber<T: Transcriber> {
    inner: T,
    id: String,
}

impl<T: Transcriber> FfmpegTranscriber<T> {
    pub fn new(inner: T) -> Self {
        let id = format!("ffmpeg-normalize+{}", inner.engine_id());
        Self { inner, id }
    }

    fn normalize(&self, audio: &[u8]) -> Option<Vec<u8>> {
        if is_wav(audio) {
            return Some(audio.to_vec());
        }
        if audio.is_empty() || audio.len() > MAX_AUDIO_INPUT_BYTES {
            return None;
        }

        let workspace = AudioWorkspace::new(audio).ok()?;
        let binary = std::env::var_os("BULWARK_FFMPEG_BINARY")
            .filter(|value| !value.is_empty())
            .or_else(|| std::env::var_os("FFMPEG_BINARY").filter(|value| !value.is_empty()))
            .unwrap_or_else(|| "ffmpeg".into());
        let mut command = std::process::Command::new(binary);
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .arg("-nostdin")
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
            .arg("-fs")
            .arg(MAX_NORMALIZED_WAV_BYTES.to_string())
            .arg("-f")
            .arg("wav")
            .arg("-y")
            .arg(&workspace.output);

        if !run_command_bounded(&mut command, FFMPEG_NORMALIZE_TIMEOUT) {
            return None;
        }
        let normalized = std::fs::read(&workspace.output).ok()?;
        if normalized.is_empty()
            || normalized.len() > MAX_NORMALIZED_WAV_BYTES
            || !is_wav(&normalized)
        {
            return None;
        }
        Some(normalized)
    }
}

impl<T: Transcriber> Transcriber for FfmpegTranscriber<T> {
    fn transcribe(&self, audio: &[u8]) -> Option<String> {
        let normalized = self.normalize(audio)?;
        self.inner.transcribe(&normalized)
    }

    fn engine_id(&self) -> &str {
        &self.id
    }
}

fn is_wav(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE"
}

fn run_command_bounded(command: &mut std::process::Command, timeout: std::time::Duration) -> bool {
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return false,
    };
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

struct AudioWorkspace {
    dir: std::path::PathBuf,
    input: std::path::PathBuf,
    output: std::path::PathBuf,
}

impl AudioWorkspace {
    fn new(audio: &[u8]) -> std::io::Result<Self> {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};

        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bulwark-audio-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let input = dir.join("input.media");
        let output = dir.join("normalized.wav");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&input)?;
        file.write_all(audio)?;
        file.sync_all()?;
        Ok(Self { dir, input, output })
    }
}

impl Drop for AudioWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run_blocking<R>(work: impl FnOnce() -> R) -> R {
    let multithread = tokio::runtime::Handle::try_current()
        .map(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
        .unwrap_or(false);
    if multithread {
        tokio::task::block_in_place(work)
    } else {
        work()
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

pub struct AudioAnalyzer<T: Transcriber = StubTranscriber> {
    transcriber: T,
    text: TextAnalyzer,
}

impl AudioAnalyzer<StubTranscriber> {
    pub fn new() -> Self {
        Self::with_transcriber(StubTranscriber)
    }
}

impl Default for AudioAnalyzer<StubTranscriber> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Transcriber> AudioAnalyzer<T> {
    pub fn with_transcriber(transcriber: T) -> Self {
        Self {
            transcriber,
            text: TextAnalyzer::new().expect("bulwark-text built-in lexicon must load"),
        }
    }
}

#[async_trait]
impl<T: Transcriber> Analyzer for AudioAnalyzer<T> {
    fn handles(&self) -> &[MediaKind] {
        const KINDS: [MediaKind; 1] = [MediaKind::Audio];
        &KINDS
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        let bytes = match req.media.as_ref() {
            Some(Media::InlineMedia(media)) if !media.data.is_empty() => media.data.clone(),
            _ => return Ok(uncovered(req.request_id, "no inline audio payload")),
        };
        if bytes.len() > MAX_AUDIO_INPUT_BYTES {
            return Ok(uncovered(
                req.request_id,
                "audio payload exceeds bounded analysis limit",
            ));
        }
        let Some(transcript) = run_blocking(|| self.transcriber.transcribe(&bytes)) else {
            return Ok(uncovered(
                req.request_id,
                "audio transcription unavailable, timed out, or failed; content not scored",
            ));
        };
        if transcript.trim().is_empty() {
            return Ok(safe(
                req.request_id,
                "transcription completed; no speech detected",
            ));
        }

        let span = TextSpan {
            text: transcript,
            app: "audio".into(),
            thread_id: format!("{}\u{1f}audio\u{1f}{}", req.device_id, req.request_id),
            ..Default::default()
        };
        let mut verdict = self.text.analyze_span(&req.request_id, &span, req.ts);
        if verdict.category == Category::AdultText as i32 {
            verdict.category = Category::AdultAudio as i32;
        }
        if verdict.category != Category::Safe as i32
            && verdict.category != Category::Grooming as i32
        {
            verdict.action = Action::Mute as i32;
        }
        let evidence = verdict.evidence.get_or_insert_with(Evidence::default);
        evidence.sha256 = sha256(&bytes);
        evidence.model_id = format!("{}+{}", evidence.model_id, self.transcriber.engine_id());
        Ok(verdict)
    }
}

fn uncovered(request_id: String, why: &str) -> Verdict {
    Verdict {
        request_id,
        category: Category::Unspecified as i32,
        action: Action::Block as i32,
        severity: Severity::Medium as i32,
        score: 0.0,
        rationale: why.into(),
        ..Default::default()
    }
}

fn safe(request_id: String, why: &str) -> Verdict {
    Verdict {
        request_id,
        category: Category::Safe as i32,
        action: Action::Allow as i32,
        severity: Severity::Info as i32,
        score: 0.0,
        rationale: why.into(),
        ..Default::default()
    }
}

#[cfg(feature = "whisper")]
pub mod whisper {
    use super::Transcriber;
    use whisper_rs::{
        convert_integer_to_float_audio, convert_stereo_to_mono_audio, FullParams, SamplingStrategy,
        WhisperContext, WhisperContextParameters,
    };

    pub struct WhisperTranscriber {
        ctx: WhisperContext,
        id: String,
    }

    impl WhisperTranscriber {
        pub const MODEL_ENV: &'static str = "BULWARK_WHISPER_MODEL";

        pub fn from_env() -> Option<Self> {
            let path = std::env::var(Self::MODEL_ENV)
                .ok()
                .filter(|path| !path.trim().is_empty())?;
            match Self::load(&path) {
                Ok(transcriber) => Some(transcriber),
                Err(error) => {
                    tracing::warn!(model = %path, %error, "whisper load failed; audio remains uncovered");
                    None
                }
            }
        }

        pub fn load(model_path: &str) -> anyhow::Result<Self> {
            let ctx =
                WhisperContext::new_with_params(model_path, WhisperContextParameters::default())
                    .map_err(|error| anyhow::anyhow!("whisper: load {model_path}: {error}"))?;
            Ok(Self {
                ctx,
                id: format!("whisper:{model_path}"),
            })
        }

        fn pcm_16k_mono(audio: &[u8]) -> anyhow::Result<Vec<f32>> {
            let reader = hound::WavReader::new(std::io::Cursor::new(audio))?;
            let spec = reader.spec();
            let samples: Vec<f32> = match spec.sample_format {
                hound::SampleFormat::Float => reader
                    .into_samples::<f32>()
                    .filter_map(Result::ok)
                    .collect(),
                hound::SampleFormat::Int => {
                    let ints: Vec<i16> = reader
                        .into_samples::<i16>()
                        .filter_map(Result::ok)
                        .collect();
                    let mut floats = vec![0.0f32; ints.len()];
                    convert_integer_to_float_audio(&ints, &mut floats)
                        .map_err(|error| anyhow::anyhow!("whisper: int->float: {error}"))?;
                    floats
                }
            };
            let mono = if spec.channels >= 2 {
                convert_stereo_to_mono_audio(&samples)
                    .map_err(|error| anyhow::anyhow!("whisper: stereo->mono: {error}"))?
            } else {
                samples
            };
            Ok(resample_16k(&mono, spec.sample_rate))
        }
    }

    fn resample_16k(input: &[f32], src_sr: u32) -> Vec<f32> {
        if src_sr == 16_000 || input.is_empty() {
            return input.to_vec();
        }
        let ratio = 16_000.0 / src_sr as f32;
        let out_len = (input.len() as f32 * ratio) as usize;
        (0..out_len)
            .map(|index| {
                let position = index as f32 / ratio;
                let base = position as usize;
                let frac = position - base as f32;
                let a = input[base.min(input.len() - 1)];
                let b = input[(base + 1).min(input.len() - 1)];
                a + (b - a) * frac
            })
            .collect()
    }

    impl Transcriber for WhisperTranscriber {
        fn transcribe(&self, audio: &[u8]) -> Option<String> {
            let pcm = Self::pcm_16k_mono(audio).ok()?;
            if pcm.is_empty() {
                return Some(String::new());
            }
            let mut state = self.ctx.create_state().ok()?;
            let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
            params.set_language(Some("en"));
            params.set_print_special(false);
            params.set_print_progress(false);
            params.set_print_realtime(false);
            params.set_print_timestamps(false);
            state.full(params, &pcm).ok()?;
            let count = state.full_n_segments().ok()?;
            let mut text = String::new();
            for index in 0..count {
                if let Ok(segment) = state.full_get_segment_text(index) {
                    text.push_str(&segment);
                }
            }
            Some(text.trim().to_string())
        }

        fn engine_id(&self) -> &str {
            &self.id
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::InlineMedia;

    fn request() -> AnalysisRequest {
        AnalysisRequest {
            request_id: "audio-1".into(),
            device_id: "device-1".into(),
            media_kind: MediaKind::Audio as i32,
            media: Some(Media::InlineMedia(InlineMedia {
                data: vec![1, 2, 3],
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn missing_stt_is_not_safe() {
        let verdict = AudioAnalyzer::new().analyze(request()).await.unwrap();
        assert_eq!(verdict.category(), Category::Unspecified);
        assert_eq!(verdict.action(), Action::Block);
    }

    struct EchoTranscriber;
    impl Transcriber for EchoTranscriber {
        fn transcribe(&self, audio: &[u8]) -> Option<String> {
            is_wav(audio).then(|| "hello".to_string())
        }
        fn engine_id(&self) -> &str {
            "echo"
        }
    }

    #[test]
    fn wav_bypasses_ffmpeg_normalization() {
        let transcriber = FfmpegTranscriber::new(EchoTranscriber);
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&[0u8; 4]);
        wav.extend_from_slice(b"WAVE");
        assert_eq!(transcriber.transcribe(&wav).as_deref(), Some("hello"));
    }
}
