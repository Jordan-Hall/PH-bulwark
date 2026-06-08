//! bulwark-audio — explicit / grooming audio detection via TRANSCRIPTION.
//!
//! Instead of a heavy dedicated audio-NSFW model, we transcribe speech to text and
//! run the transcript through the proven [`bulwark_text`] engine (grooming + adult
//! rules). Lighter, on-device-friendly, and reuses one detection brain. A flagged
//! span recommends **MUTE** (silence that timecode); evidence is the SHA-256 only.
//!
//! Transcription is pluggable via [`Transcriber`]. The default [`StubTranscriber`]
//! produces nothing (no STT model present) so the analyzer **fail-CLOSES** — never a
//! false "safe". A real whisper STT is injected via [`AudioAnalyzer::with_transcriber`]
//! (the `whisper` feature, landing next).
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bulwark_core::{Analyzer, Result};
use bulwark_proto::v1::{
    analysis_request::Media, Action, AnalysisRequest, Category, Evidence, MediaKind, Severity,
    TextSpan, Verdict,
};
use bulwark_text::TextAnalyzer;

/// Turns audio bytes into a transcript. `None` => transcription unavailable (no
/// model, or decode failure) => the analyzer fail-CLOSES (never a false "safe").
pub trait Transcriber: Send + Sync {
    fn transcribe(&self, audio: &[u8]) -> Option<String>;
    fn engine_id(&self) -> &str;
}

/// No STT model present: transcribes nothing → the analyzer fail-CLOSES.
pub struct StubTranscriber;
impl Transcriber for StubTranscriber {
    fn transcribe(&self, _audio: &[u8]) -> Option<String> {
        None
    }
    fn engine_id(&self) -> &str {
        "stub-none"
    }
}

fn sha256(b: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, b)
        .as_ref()
        .to_vec()
}

/// Audio analyzer: transcribe → judge the transcript with `bulwark-text`.
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
    /// Inject a transcription engine (e.g. whisper). The grooming/adult-text brain
    /// is always `bulwark-text`.
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
        const K: [MediaKind; 1] = [MediaKind::Audio];
        &K
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        let bytes = match req.media.as_ref() {
            Some(Media::InlineMedia(m)) => m.data.clone(),
            // No inline audio (a ref resolved elsewhere): can't transcribe here.
            _ => return Ok(uncovered(req.request_id, "no inline audio")),
        };

        let Some(transcript) = self.transcriber.transcribe(&bytes) else {
            // Couldn't transcribe (no STT model / decode failed) → fail CLOSED.
            return Ok(uncovered(
                req.request_id,
                "audio not transcribed (no STT model); not scored",
            ));
        };
        if transcript.trim().is_empty() {
            // Transcribed fine, but there is no speech → genuinely safe.
            return Ok(safe(req.request_id, "no speech detected in audio"));
        }

        // Reuse the proven grooming/adult-text engine on the transcript.
        let span = TextSpan {
            text: transcript,
            app: "audio".into(),
            ..Default::default()
        };
        let mut v = self.text.analyze_span(&req.request_id, &span, req.ts);
        // Recast adult TEXT as adult AUDIO for the media context, and recommend MUTE
        // (silence the offending timecode) rather than a hard block. GROOMING keeps
        // its category (policy alerts/escalates it).
        if v.category == Category::AdultText as i32 {
            v.category = Category::AdultAudio as i32;
        }
        if v.category != Category::Safe as i32 && v.category != Category::Grooming as i32 {
            v.action = Action::Mute as i32;
        }
        v.evidence.get_or_insert_with(Evidence::default).sha256 = sha256(&bytes);
        Ok(v)
    }
}

/// "Couldn't score" → Unspecified, so policy fail-CLOSES (never a false safe).
fn uncovered(request_id: String, why: &str) -> Verdict {
    Verdict {
        request_id,
        category: Category::Unspecified as i32,
        action: Action::Allow as i32, // policy is the authority and fail-closes
        severity: Severity::Info as i32,
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

/// whisper.cpp-backed transcription (open-source, MIT). Loads a ggml model from
/// `BULWARK_WHISPER_MODEL` (e.g. ggml-tiny.en-q5_1.bin, ~30 MB, provisioned at
/// deploy) and transcribes 16 kHz-mono WAV via whisper-rs:
/// `AudioAnalyzer::with_transcriber(WhisperTranscriber::from_env().unwrap())`.
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
        /// Env var holding the ggml model path (provisioned at deploy).
        pub const MODEL_ENV: &'static str = "BULWARK_WHISPER_MODEL";

        /// Load from `BULWARK_WHISPER_MODEL`. `None` when unset/missing/unloadable —
        /// the analyzer then keeps the StubTranscriber and fail-CLOSES.
        pub fn from_env() -> Option<Self> {
            let path = std::env::var(Self::MODEL_ENV)
                .ok()
                .filter(|p| !p.trim().is_empty())?;
            match Self::load(&path) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::warn!(model = %path, "whisper load failed: {e}; audio fail-closes");
                    None
                }
            }
        }

        pub fn load(model_path: &str) -> anyhow::Result<Self> {
            let ctx =
                WhisperContext::new_with_params(model_path, WhisperContextParameters::default())
                    .map_err(|e| anyhow::anyhow!("whisper: load {model_path}: {e}"))?;
            Ok(Self {
                ctx,
                id: format!("whisper:{model_path}"),
            })
        }

        /// WAV bytes (any rate/channels) → 16 kHz-mono `f32` PCM for whisper.
        fn pcm_16k_mono(audio: &[u8]) -> anyhow::Result<Vec<f32>> {
            let reader = hound::WavReader::new(std::io::Cursor::new(audio))?;
            let spec = reader.spec();
            let samples: Vec<f32> = match spec.sample_format {
                hound::SampleFormat::Float => {
                    reader.into_samples::<f32>().filter_map(Result::ok).collect()
                }
                hound::SampleFormat::Int => {
                    let ints: Vec<i16> =
                        reader.into_samples::<i16>().filter_map(Result::ok).collect();
                    let mut floats = vec![0.0f32; ints.len()];
                    convert_integer_to_float_audio(&ints, &mut floats)
                        .map_err(|e| anyhow::anyhow!("whisper: int->float: {e}"))?;
                    floats
                }
            };
            let mono = if spec.channels >= 2 {
                convert_stereo_to_mono_audio(&samples)
                    .map_err(|e| anyhow::anyhow!("whisper: stereo->mono: {e}"))?
            } else {
                samples
            };
            Ok(resample_16k(&mono, spec.sample_rate))
        }
    }

    /// Linear resample to 16 kHz (whisper is robust; keeps it dependency-free).
    fn resample_16k(input: &[f32], src_sr: u32) -> Vec<f32> {
        if src_sr == 16_000 || input.is_empty() {
            return input.to_vec();
        }
        let ratio = 16_000.0 / src_sr as f32;
        let out_len = (input.len() as f32 * ratio) as usize;
        (0..out_len)
            .map(|i| {
                let pos = i as f32 / ratio;
                let idx = pos as usize;
                let frac = pos - idx as f32;
                let a = input[idx.min(input.len() - 1)];
                let b = input[(idx + 1).min(input.len() - 1)];
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
            let mut p = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
            p.set_language(Some("en"));
            p.set_print_special(false);
            p.set_print_progress(false);
            p.set_print_realtime(false);
            p.set_print_timestamps(false);
            state.full(p, &pcm).ok()?;
            let n = state.full_n_segments().ok()?;
            let mut text = String::new();
            for i in 0..n {
                if let Ok(seg) = state.full_get_segment_text(i) {
                    text.push_str(&seg);
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

    fn audio_req(data: Vec<u8>) -> AnalysisRequest {
        AnalysisRequest {
            request_id: "a".into(),
            media_kind: MediaKind::Audio as i32,
            media: Some(Media::InlineMedia(InlineMedia {
                data,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// Stands in for whisper: returns a fixed transcript.
    struct Fake(&'static str);
    impl Transcriber for Fake {
        fn transcribe(&self, _: &[u8]) -> Option<String> {
            Some(self.0.to_string())
        }
        fn engine_id(&self) -> &str {
            "fake"
        }
    }

    #[tokio::test]
    async fn no_stt_model_fails_closed() {
        let a = AudioAnalyzer::new(); // StubTranscriber → None
        let v = a.analyze(audio_req(vec![1, 2, 3, 4])).await.unwrap();
        assert_eq!(v.category, Category::Unspecified as i32);
    }

    #[tokio::test]
    async fn empty_transcript_is_safe() {
        let a = AudioAnalyzer::with_transcriber(Fake("   "));
        let v = a.analyze(audio_req(vec![1, 2, 3, 4])).await.unwrap();
        assert_eq!(v.category, Category::Safe as i32);
    }

    #[tokio::test]
    async fn benign_speech_runs_through_text_engine_and_is_safe() {
        // Proves the transcribe → bulwark-text wiring end-to-end (no real STT needed):
        // a benign transcript scores Safe via the text engine.
        let a = AudioAnalyzer::with_transcriber(Fake("hello, lovely day at the park today"));
        let v = a.analyze(audio_req(vec![1, 2, 3, 4])).await.unwrap();
        assert_eq!(v.category, Category::Safe as i32);
    }
}
