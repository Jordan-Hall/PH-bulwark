//! # aegis-text — deterministic grooming rules + lexicon engine (PRIMARY), plus
//! adult-text detection, behind the `Analyzer` contract.
//!
//! ## Minimal-AI design
//! Aegis is **rules-first** (PLAN.md §0b). This crate's real detector is the
//! deterministic [`GroomingRuleEngine`]: eight indicator categories, per-category
//! weights, cross-message context multipliers, normalized scoring and severity
//! thresholds straight from `docs/research/model-research.md §grooming`. It needs
//! no GPU, is explainable (every verdict cites the rules that fired), and is
//! always in the hot path.
//!
//! A small text classifier ([`TextClassifier`]) is an **opt-in backstop only**,
//! behind the `classifier` cargo feature (OFF by default). It can only *confirm*
//! a rule signal (sets [`aegis_proto::GroomingSignal::classifier_backed`]); it
//! never gates a verdict and never runs in the hot path. **There is no LLM.**
//!
//! ## Pipeline
//! [`TextAnalyzer`] implements the [`Analyzer`] trait (interfaces.md): a
//! [`TextSpan`](aegis_proto::TextSpan) → [`Verdict`](aegis_proto::Verdict) with a
//! populated [`GroomingSignal`](aegis_proto::GroomingSignal). Conversation state
//! ([`ThreadState`]) is keyed by `thread_id`, so multipliers like
//! secrecy×platform-switch and rapid escalation work across messages, and a
//! single image request escalates the thread to **CRITICAL** /
//! `Category::CsamSuspected`.
//!
//! ## Privacy
//! `#![forbid(unsafe_code)]`. Evidence and thread state carry only category
//! names, timestamps and **redacted excerpts** — never raw message text. No
//! telemetry.

#![forbid(unsafe_code)]

pub mod analyzer;
pub mod classifier;
pub mod engine;
pub mod error;
pub mod lexicon;
pub mod redact;
pub mod state;
pub mod traits;

#[cfg(test)]
mod test_util;

// --- Public API re-exports ------------------------------------------------

pub use aegis_core::Analyzer;
pub use analyzer::TextAnalyzer;
pub use classifier::{NoClassifier, TextClassifier};
pub use engine::{weight, GroomingRuleEngine, RuleOutcome};
pub use error::{Result, TextError};
pub use lexicon::{LanguageLexicon, Lexicon};
pub use state::{ThreadState, ESCALATION_WINDOW_MS};
pub use traits::GroomingRules;

#[cfg(feature = "classifier")]
pub use classifier::{
    DistilbertGroomingClassifier, OrtGroomingClassifier, SklearnTfidfClassifier, Tokenizer,
};

// --- End-to-end integration tests ----------------------------------------

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::test_util::text_span;
    use aegis_proto::{Action, Category, GroomingRule, Severity};

    /// Layer 4: with the sklearn model wired as the confirm-only backstop, a
    /// grooming span (image-request rule fires AND the model agrees) is
    /// `classifier_backed`; a benign span is not. The classifier never gates.
    #[cfg(feature = "classifier")]
    #[test]
    fn sklearn_backstop_confirms_grooming_not_benign() {
        let a = TextAnalyzer::with_builtin_grooming_model().unwrap();
        let v = a.analyze_span("m1", &text_span("t", "send me a pic of you"), 0);
        let g = v.grooming.as_ref().expect("grooming signal");
        assert!(
            g.classifier_backed,
            "grooming span should be classifier-backed"
        );

        let v2 = a.analyze_span(
            "m2",
            &text_span("t2", "did you finish the math homework"),
            0,
        );
        assert!(
            v2.grooming
                .as_ref()
                .map(|g| !g.classifier_backed)
                .unwrap_or(true),
            "benign span should not be classifier-backed"
        );
    }

    /// THE headline flow: secrecy → platform-switch → image-request, across
    /// three messages in one thread, escalates to a CRITICAL / CSAM-suspected
    /// verdict that recommends BLOCK. Demonstrates cross-message thread state.
    #[test]
    fn secrecy_then_switch_then_image_request_reaches_critical() {
        let a = TextAnalyzer::new().unwrap();
        let thread = "groomer-thread-1";

        // Day 0, message 1 — secrecy. On its own this is below the log
        // threshold (weight 0.5 / 10 = 0.05), so it just records state.
        let v1 = a.analyze_span(
            "m1",
            // Soft secrecy only ("our little secret") — a single low-weight signal.
            // (Guardian-isolation phrases like "don't tell your parents" are
            // intentionally NOT low on their own; that's covered in engine.rs tests.)
            &text_span(thread, "hey this is our little secret ok"),
            0,
        );
        assert_eq!(v1.category, Category::Grooming as i32);
        let g1 = v1.grooming.as_ref().unwrap();
        assert!(g1.fired_categories.iter().any(|c| c == "secrecy"));
        assert!(g1.score < 0.3, "soft secrecy alone stays low: {}", g1.score);

        // Day 1, message 2 — platform switch. Thread memory pulls in the
        // secrecy×platform-switch +2.0 bonus and the rapid-escalation ×1.5,
        // pushing the score into the flag/log band.
        let one_day = 24 * 60 * 60 * 1000;
        let v2 = a.analyze_span(
            "m2",
            &text_span(thread, "lets move to telegram so we can talk there"),
            one_day,
        );
        assert_eq!(v2.category, Category::Grooming as i32);
        let g2 = v2.grooming.as_ref().unwrap();
        assert!(g2
            .fired_categories
            .iter()
            .any(|c| c == "platform_switching"));
        assert!(
            g2.score > g1.score,
            "escalation raises score: {} !> {}",
            g2.score,
            g1.score
        );
        assert!(v2.rationale.contains("secrecy × platform-switch"));

        // Day 2, message 3 — image request. CSAM-risk: hard-escalates the whole
        // thread to CRITICAL with a BLOCK recommendation, regardless of the
        // numeric score (which here maxes at 1.0 anyway).
        let two_days = 2 * one_day;
        let v3 = a.analyze_span(
            "m3",
            &text_span(thread, "now send me a pic of you in your room"),
            two_days,
        );
        assert_eq!(v3.category, Category::CsamSuspected as i32);
        assert_eq!(v3.severity, Severity::Critical as i32);
        assert_eq!(v3.action, Action::Block as i32);
        assert_eq!(v3.score, 1.0);

        let g3 = v3.grooming.as_ref().unwrap();
        assert!(g3.fired_categories.iter().any(|c| c == "image_request"));
        // Evidence is a redacted excerpt only — never the raw message.
        let ev = v3.evidence.as_ref().unwrap();
        assert!(ev.text_snippet.starts_with("[redacted"));
        assert!(!ev.text_snippet.contains("send me a pic"));

        // Thread state remembers the full escalation arc.
        let snap = a.thread_snapshot(thread).unwrap();
        assert!(snap.has_seen(GroomingRule::Secrecy));
        assert!(snap.has_seen(GroomingRule::PlatformSwitching));
        assert!(snap.image_request_seen());
        assert_eq!(snap.flagged_messages, 3);
    }

    /// A realistic BENIGN conversation must produce zero false positives:
    /// every message is SAFE/ALLOW with no grooming signal.
    #[test]
    fn benign_conversation_has_no_false_positives() {
        let a = TextAnalyzer::new().unwrap();
        let thread = "friends-thread";
        let benign = [
            "hey did you do the science homework?",
            "yeah it was so long lol",
            "wanna play fortnite later with the squad?",
            "i cant my mum says i have to walk the dog first",
            "haha ok add me when youre on",
            "did you watch the match last night? what a goal",
            "see you at school tomorrow",
        ];
        for (i, msg) in benign.iter().enumerate() {
            let v = a.analyze_span(&format!("b{i}"), &text_span(thread, msg), i as i64 * 1000);
            assert_eq!(
                v.category,
                Category::Safe as i32,
                "benign msg flagged: {msg:?} → {}",
                v.rationale
            );
            assert_eq!(v.action, Action::Allow as i32);
            assert!(v.grooming.is_none());
        }
        // No thread state should have been recorded for a clean conversation.
        assert!(a.thread_snapshot(thread).is_none());
    }

    /// "add me when youre on" (benign) must NOT trip platform_switching, which
    /// requires an explicit app name. Guards a plausible false positive.
    #[test]
    fn casual_add_me_is_not_platform_switching() {
        let a = TextAnalyzer::new().unwrap();
        let v = a.analyze_span("x", &text_span("t", "add me when youre online later"), 0);
        assert_eq!(v.category, Category::Safe as i32);
    }

    /// Distinct threads do not bleed state into each other.
    #[test]
    fn thread_state_is_isolated_per_thread() {
        let a = TextAnalyzer::new().unwrap();
        // Secrecy in thread A.
        a.analyze_span("a1", &text_span("A", "our little secret"), 0);
        // Platform switch in thread B should NOT see thread A's secrecy, so no
        // cross-message bonus fires there.
        let vb = a.analyze_span("b1", &text_span("B", "lets move to discord"), 0);
        assert!(!vb.rationale.contains("secrecy × platform-switch"));
    }

    /// Adult explicit text with no grooming context → Category::ADULT_TEXT.
    #[test]
    fn explicit_adult_text_is_adult_text_category() {
        let a = TextAnalyzer::new().unwrap();
        let v = a.analyze_span("p1", &text_span("t", "wanna watch some porn together"), 0);
        assert_eq!(v.category, Category::AdultText as i32);
        assert_eq!(v.action, Action::Warn as i32);
        assert!(v.grooming.is_none());
    }

    /// The streaming path yields one verdict per request, preserving thread
    /// escalation in order.
    #[tokio::test]
    async fn analyze_stream_yields_one_verdict_per_request() {
        use aegis_proto::{AnalysisRequest, MediaKind};
        use futures_util::StreamExt;

        let a = TextAnalyzer::new().unwrap();
        let mk = |id: &str, text: &str, ts: i64| AnalysisRequest {
            request_id: id.to_string(),
            media_kind: MediaKind::Text as i32,
            source_channel: 0,
            device_id: "dev".into(),
            ts,
            text_span: Some(text_span("s", text)),
            media: None,
            deadline_ms: 0,
        };
        let reqs = vec![
            mk("s1", "our little secret", 0),
            mk("s2", "lets move to snapchat", 1000),
            mk("s3", "send me a selfie", 2000),
        ];
        let stream = futures_util::stream::iter(reqs).boxed();
        let out = a.analyze_stream(stream).await.unwrap();
        let verdicts: Vec<_> = out.collect().await;
        assert_eq!(verdicts.len(), 3);
        let last = verdicts[2].as_ref().unwrap();
        assert_eq!(last.category, Category::CsamSuspected as i32);
        assert_eq!(last.severity, Severity::Critical as i32);
    }
}
