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
