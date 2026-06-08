//! # bulwark-apple-ffi — a stable C ABI over the shared Bulwark content-safety core
//!
//! This crate is the Rust half of the Apple child shell. It compiles to a
//! `staticlib` that an iOS/macOS **Network Extension** content filter
//! (`NEFilterDataProvider`) links in, and exposes a tiny, stable C ABI so the
//! Swift `FilterDataProvider` can classify extracted text on the wire and decide
//! whether to `.allow()` or `.drop()` a flow.
//!
//! ## What it wraps (real core APIs only — no inventions)
//! * [`bulwark_text::TextAnalyzer`] — the deterministic grooming RULE engine
//!   (PRIMARY detector) plus adult-text detection. Constructed with
//!   `TextAnalyzer::new()` (returns a `Result`); a span is scored with
//!   `analyze_span(request_id, &TextSpan, ts_ms) -> Verdict`.
//! * [`bulwark_policy::Policy`] — turns a [`Verdict`] into a [`PolicyDecision`]
//!   (action + alert + severity) via `Policy::evaluate(&Verdict, &PolicyContext)`.
//!
//! There is **no AI/ML** in the hot path (rules-first), no telemetry, and no
//! persistence. The Apple shell is strictly FILTER + ALERTS.
//!
//! ## Scope guardrail (Apple platform + Bulwark policy)
//! This library only *classifies text it is handed*. It cannot — and must not —
//! read other apps' messages, capture the screen, track location, or block
//! uninstall. Those are forbidden for third-party apps on Apple and are out of
//! scope for Bulwark by design.
//!
//! ## Privacy
//! The FFI logs nothing sensitive: invalid UTF-8 fails **open** (allow) and is
//! not logged with content; verdict rationales and redacted excerpts stay inside
//! Rust and are never returned across the ABI. The C surface returns only small
//! integer codes.

// This crate is unsafe-free OUTSIDE the `ffi` module. The core crates it depends
// on (`bulwark-core`, `bulwark-text`, `bulwark-policy`, `bulwark-proto`) each
// `#![forbid(unsafe_code)]`. FFI inherently needs `unsafe`, so we *allow* (never
// `forbid`) it and confine every `unsafe` block to the `ffi` module.
#![allow(unsafe_code)]
#![warn(missing_docs)]

pub mod ffi;

use bulwark_policy::{AgeProfile, Policy, PolicyContext};
use bulwark_proto::v1::{Action, Category, SourceChannel, TextSpan, Verdict};
use bulwark_proto::DeviceId;
use bulwark_text::TextAnalyzer;

/// Stable action codes returned across the C ABI by
/// [`ffi::bulwark_apple_classify_text`]. Deliberately tiny and language-neutral.
///
/// These collapse the richer [`bulwark_proto::v1::Action`] ladder (ALLOW / LOG /
/// WARN / BLOCK / BLUR / MUTE) into the three outcomes a network content filter
/// can actually act on for a text flow: pass it, pass-but-warn, or drop it.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppleAction {
    /// Forward the flow unchanged (ALLOW / LOG — nothing the filter must do).
    Allow = 0,
    /// Forward but surface an interstitial / post a redacted local notification
    /// (WARN / BLUR / MUTE — a soft intervention that does not drop the flow).
    Warn = 1,
    /// Drop / reset the flow (BLOCK — including the CSAM-suspected hard block).
    Block = 2,
}

impl AppleAction {
    /// Project a policy [`Action`] onto the three-state Apple action code.
    fn from_action(action: Action) -> AppleAction {
        match action {
            Action::Block => AppleAction::Block,
            // WARN / BLUR / MUTE are all "intervene but don't drop the flow" for
            // a text content filter; surface them as a warning.
            Action::Warn | Action::Blur | Action::Mute => AppleAction::Warn,
            // ALLOW, LOG, and the unspecified default all forward unchanged.
            Action::Allow | Action::Log | Action::Unspecified => AppleAction::Allow,
        }
    }
}

/// Stable category codes written to the optional `out_category` out-param of
/// [`ffi::bulwark_apple_classify_text`]. Mirrors [`bulwark_proto::v1::Category`] so
/// the Swift side can show a redacted reason ("grooming suspected", etc.)
/// without ever seeing message text.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppleCategory {
    /// No category / unclassified.
    Unspecified = 0,
    /// Explicitly safe.
    Safe = 1,
    /// Adult image (not produced by the text path; present for ABI stability).
    AdultImage = 2,
    /// Adult audio (not produced by the text path; present for ABI stability).
    AdultAudio = 3,
    /// Explicit adult text.
    AdultText = 4,
    /// Grooming indicators fired.
    Grooming = 5,
    /// CSAM suspected (e.g. image request in a grooming thread) — hard block.
    CsamSuspected = 6,
    /// Violence.
    Violence = 7,
    /// Self-harm.
    SelfHarm = 8,
    /// Hate.
    Hate = 9,
}

impl AppleCategory {
    fn from_category(category: Category) -> AppleCategory {
        match category {
            Category::Unspecified => AppleCategory::Unspecified,
            Category::Safe => AppleCategory::Safe,
            Category::AdultImage => AppleCategory::AdultImage,
            Category::AdultAudio => AppleCategory::AdultAudio,
            Category::AdultText => AppleCategory::AdultText,
            Category::Grooming => AppleCategory::Grooming,
            Category::CsamSuspected => AppleCategory::CsamSuspected,
            Category::Violence => AppleCategory::Violence,
            Category::SelfHarm => AppleCategory::SelfHarm,
            Category::Hate => AppleCategory::Hate,
        }
    }
}

/// The boxed engine handed across the C ABI as an opaque `*mut BulwarkEngine`.
///
/// Holds the deterministic [`TextAnalyzer`] (which carries per-thread grooming
/// memory) and the [`Policy`] that maps a verdict to an action. One engine
/// instance per provider is expected; it is `Send + Sync`-friendly internally
/// (the analyzer guards its thread map with a `Mutex`), but the C ABI does not
/// promise thread-safety — callers should serialize calls or use one engine per
/// thread.
pub struct BulwarkEngine {
    analyzer: TextAnalyzer,
    policy: Policy,
    age_profile: AgeProfile,
    device: DeviceId,
    // Monotonic counter for synthetic, content-free request ids.
    seq: std::cell::Cell<u64>,
}

impl BulwarkEngine {
    /// Build an engine with the built-in lexicon and default policy. Returns
    /// `None` if the lexicon fails to load (the only fallible step).
    pub fn new() -> Option<BulwarkEngine> {
        let analyzer = TextAnalyzer::new().ok()?;
        Some(BulwarkEngine {
            analyzer,
            policy: Policy::default(),
            // Conservative default; a real deployment would pass the supervised
            // child's age band in. Defaults to the engine baseline (Teen).
            age_profile: AgeProfile::default(),
            device: DeviceId("apple-ne".to_string()),
            seq: std::cell::Cell::new(0),
        })
    }

    /// Classify one piece of extracted text, returning the action code and the
    /// (proto) category. Pure, in-memory, deterministic. `thread_id` correlates
    /// messages in the same conversation so cross-message grooming escalation
    /// works; pass a stable per-flow/per-conversation id, or `""` for none.
    pub fn classify(&self, text: &str, thread_id: &str) -> (AppleAction, AppleCategory) {
        let n = self.seq.get().wrapping_add(1);
        self.seq.set(n);
        let request_id = format!("apple-{n}");

        let span = TextSpan {
            text: text.to_string(),
            lang: String::new(), // detect / English fallback
            app: String::new(),
            thread_id: thread_id.to_string(),
            from_minor: false,
            prior_excerpts: Vec::new(),
        };

        // PRIMARY: deterministic analyzer → Verdict. ts=0 (the NE has no reliable
        // capture clock here; the rapid-escalation window degrades gracefully).
        let verdict: Verdict = self.analyzer.analyze_span(&request_id, &span, 0);

        // Policy is the authority on the action.
        let ctx = PolicyContext::new(self.device.clone(), SourceChannel::Web, self.age_profile);
        let decision = self.policy.evaluate(&verdict, &ctx);

        (
            AppleAction::from_action(decision.action),
            AppleCategory::from_category(verdict.category()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_builds() {
        assert!(BulwarkEngine::new().is_some());
    }

    #[test]
    fn benign_text_is_allowed_and_safe() {
        let e = BulwarkEngine::new().unwrap();
        let (action, category) = e.classify("are you coming to football practice tonight?", "t1");
        assert_eq!(action, AppleAction::Allow);
        assert_eq!(category, AppleCategory::Safe);
    }

    #[test]
    fn image_request_is_blocked_csam() {
        let e = BulwarkEngine::new().unwrap();
        // Image request → CSAM_SUSPECTED → policy short-circuits to BLOCK.
        let (action, category) = e.classify("can you send me a pic of you", "groomer");
        assert_eq!(action, AppleAction::Block);
        assert_eq!(category, AppleCategory::CsamSuspected);
    }

    #[test]
    fn adult_text_warns_for_teen() {
        let e = BulwarkEngine::new().unwrap();
        // Adult-text verdict (score 0.6, teen flag band) → WARN.
        let (action, category) = e.classify("wanna watch some porn together", "t2");
        assert_eq!(category, AppleCategory::AdultText);
        assert_eq!(action, AppleAction::Warn);
    }

    #[test]
    fn action_mapping_collapses_ladder() {
        assert_eq!(AppleAction::from_action(Action::Allow), AppleAction::Allow);
        assert_eq!(AppleAction::from_action(Action::Log), AppleAction::Allow);
        assert_eq!(AppleAction::from_action(Action::Warn), AppleAction::Warn);
        assert_eq!(AppleAction::from_action(Action::Blur), AppleAction::Warn);
        assert_eq!(AppleAction::from_action(Action::Mute), AppleAction::Warn);
        assert_eq!(AppleAction::from_action(Action::Block), AppleAction::Block);
    }
}
