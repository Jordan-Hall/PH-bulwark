//! The deterministic grooming rule engine — the PRIMARY detector.
//!
//! This is the real work: no model, no network, no LLM. It runs the eight
//! indicator categories from model-research.md §grooming, applies per-category
//! weights and cross-message context multipliers, normalizes to 0.0–1.0, and
//! bands the score to a [`Severity`]. Every decision cites the rules that fired,
//! so the verdict is explainable and auditable.
//!
//! Scoring (model-research.md §grooming):
//!   weights — secrecy +0.5, platform_switching +0.5, personal_info_age_probing
//!   +0.4, sexualization +0.6, gifts_bribery +0.4, emotional_manipulation +0.5,
//!   boundary_testing +0.3, image_request **+5.0**.
//!   context multipliers (additive bonuses) —
//!     secrecy × platform-switch                       +2.0
//!     personal-info + age-probing (single category)   +1.5
//!     sexualization × (gifts | emotional-manip)       +2.0
//!     image-request present                            +5.0
//!     rapid escalation (≥2 distinct categories <7d)    ×1.5 (multiplicative)
//!   normalize: `/10`, cap at 1.0.
//!   thresholds: ≥0.7 alert · ≥0.5 flag · ≥0.3 log · <0.3 pass.
//!
//! Cross-message multipliers consult [`ThreadState`] so e.g. secrecy in one
//! message and a platform switch in the next still combine.

use aegis_proto::{GroomingRule, Severity};

use crate::lexicon::LanguageLexicon;
use crate::state::{ThreadState, ESCALATION_WINDOW_MS};

/// Per-category weight (model-research.md §grooming table).
pub fn weight(rule: GroomingRule) -> f32 {
    match rule {
        GroomingRule::Secrecy => 0.5,
        GroomingRule::PlatformSwitching => 0.5,
        GroomingRule::PersonalInfoAgeProbing => 0.4,
        GroomingRule::Sexualization => 0.6,
        GroomingRule::GiftsBribery => 0.4,
        GroomingRule::EmotionalManipulation => 0.5,
        GroomingRule::BoundaryTesting => 0.3,
        GroomingRule::ImageRequest => 5.0,
    }
}

/// Normalization divisor (raw score `/10`, then capped at 1.0).
const NORMALIZE_DIVISOR: f32 = 10.0;

/// Outcome of scoring one message in the context of its thread.
#[derive(Clone, Debug)]
pub struct RuleOutcome {
    /// Categories that fired on THIS message.
    pub fired: Vec<GroomingRule>,
    /// Normalized score in 0.0–1.0.
    pub score: f32,
    /// Severity band for the score (image-request escalates to CRITICAL).
    pub severity: Severity,
    /// Human-readable, explainable rationale citing the fired rules + multipliers.
    pub rationale: String,
    /// True if an image request fired now or earlier in this thread (CSAM risk).
    pub image_request: bool,
}

impl RuleOutcome {
    /// Did anything fire at all?
    pub fn is_silent(&self) -> bool {
        self.fired.is_empty() && self.score == 0.0
    }
}

/// A single applied multiplier, captured for the rationale.
struct Applied {
    label: &'static str,
    /// Additive bonus (most multipliers) or `None` if it is the multiplicative
    /// escalation factor (reported separately).
    bonus: f32,
}

/// The deterministic engine. Holds no per-thread state itself — thread memory is
/// passed in (and owned by the analyzer / `Store`), keeping the engine a pure
/// function of (message, thread-so-far).
#[derive(Debug, Default, Clone, Copy)]
pub struct GroomingRuleEngine;

impl GroomingRuleEngine {
    pub fn new() -> Self {
        GroomingRuleEngine
    }

    /// Score `text` against `lex`, combining with prior `thread` state for the
    /// cross-message multipliers. `now_ms` is the message timestamp.
    ///
    /// Does NOT mutate `thread`; the caller records the fired categories
    /// afterwards (so the multipliers see the pre-update view).
    pub fn evaluate(
        &self,
        text: &str,
        lex: &LanguageLexicon,
        thread: &ThreadState,
        now_ms: i64,
    ) -> RuleOutcome {
        let fired = lex.fired_rules(text);

        // --- base weight sum (this message) ---
        let mut raw: f32 = fired.iter().map(|&r| weight(r)).sum();

        // Helper: did a category fire now OR earlier in-thread?
        let fired_now = |r: GroomingRule| fired.contains(&r);
        let in_thread = |r: GroomingRule| fired_now(r) || thread.has_seen(r);

        // --- additive context multipliers (model-research §grooming) ---
        let mut applied: Vec<Applied> = Vec::new();

        // secrecy × platform-switch (+2.0), across messages.
        if in_thread(GroomingRule::Secrecy) && in_thread(GroomingRule::PlatformSwitching) {
            raw += 2.0;
            applied.push(Applied {
                label: "secrecy × platform-switch (+2.0)",
                bonus: 2.0,
            });
        }

        // personal-info + age probing (+1.5). The lexicon folds both into one
        // category; firing it contributes the bonus.
        if in_thread(GroomingRule::PersonalInfoAgeProbing) {
            raw += 1.5;
            applied.push(Applied {
                label: "personal-info + age-probing (+1.5)",
                bonus: 1.5,
            });
        }

        // sexualization × (gifts | emotional-isolation) (+2.0).
        if in_thread(GroomingRule::Sexualization)
            && (in_thread(GroomingRule::GiftsBribery)
                || in_thread(GroomingRule::EmotionalManipulation))
        {
            raw += 2.0;
            applied.push(Applied {
                label: "sexualization × (gifts | emotional-isolation) (+2.0)",
                bonus: 2.0,
            });
        }

        // image-request present (+5.0) — now or earlier in-thread (CSAM risk).
        let image_request = fired_now(GroomingRule::ImageRequest) || thread.image_request_seen();
        if image_request {
            raw += 5.0;
            applied.push(Applied {
                label: "image-request present (+5.0, CSAM risk)",
                bonus: 5.0,
            });
        }

        // --- multiplicative rapid-escalation (≥2 distinct categories <7d) ---
        // Count distinct categories seen recently across the thread, including
        // those firing on this message.
        let mut recent_distinct = thread.distinct_within(now_ms, ESCALATION_WINDOW_MS);
        for &r in &fired {
            if !thread.seen_within(r, now_ms, ESCALATION_WINDOW_MS) {
                recent_distinct += 1;
            }
        }
        let escalated = recent_distinct >= 2;
        if escalated {
            raw *= 1.5;
        }

        // --- normalize + cap ---
        let score = (raw / NORMALIZE_DIVISOR).clamp(0.0, 1.0);

        // --- severity band; image request hard-escalates to CRITICAL ---
        let severity = if image_request {
            Severity::Critical
        } else {
            aegis_proto::severity_for_score(score)
        };

        let rationale = build_rationale(&fired, &applied, escalated, score, severity);

        RuleOutcome {
            fired,
            score,
            severity,
            rationale,
            image_request,
        }
    }
}

/// Build the explainable, audit-friendly rationale string. Cites every fired
/// category (with its weight) and every multiplier that applied. No message text.
fn build_rationale(
    fired: &[GroomingRule],
    applied: &[Applied],
    escalated: bool,
    score: f32,
    severity: Severity,
) -> String {
    if fired.is_empty() && applied.is_empty() {
        return "no grooming indicators fired".to_string();
    }

    let mut parts: Vec<String> = Vec::new();
    if !fired.is_empty() {
        let cats = fired
            .iter()
            .map(|&r| format!("{} (+{:.1})", r.as_str(), weight(r)))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("fired: {cats}"));
    }
    for a in applied {
        parts.push(format!("context: {} +{:.1}", a.label, a.bonus));
    }
    if escalated {
        parts.push("rapid escalation (≥2 categories <7d) ×1.5".to_string());
    }
    parts.push(format!("score={score:.2} → {}", severity_name(severity)));
    parts.join("; ")
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL (image request / CSAM risk)",
        Severity::High => "HIGH (≥0.7 alert + human review)",
        Severity::Medium => "MEDIUM (≥0.5 flag + log)",
        Severity::Low => "LOW (≥0.3 log)",
        Severity::Info => "INFO (<0.3 pass)",
        Severity::Unspecified => "unspecified",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexicon::Lexicon;

    fn en() -> Lexicon {
        Lexicon::load_builtin().unwrap()
    }

    #[test]
    fn benign_message_scores_zero_and_passes() {
        let lex = en();
        let eng = GroomingRuleEngine::new();
        let st = ThreadState::new("t");
        let out = eng.evaluate(
            "want to play minecraft after school?",
            lex.resolve("en"),
            &st,
            0,
        );
        assert!(out.is_silent());
        assert_eq!(out.score, 0.0);
        assert_eq!(out.severity, Severity::Info);
    }

    #[test]
    fn single_secrecy_logs_but_does_not_alert() {
        let lex = en();
        let eng = GroomingRuleEngine::new();
        let st = ThreadState::new("t");
        // secrecy weight 0.5 / 10 = 0.05 → below 0.3 (INFO/pass) on its own.
        let out = eng.evaluate("our little secret ok", lex.resolve("en"), &st, 0);
        assert_eq!(out.fired, vec![GroomingRule::Secrecy]);
        assert!(out.score < 0.3);
    }

    #[test]
    fn image_request_forces_critical() {
        let lex = en();
        let eng = GroomingRuleEngine::new();
        let st = ThreadState::new("t");
        let out = eng.evaluate("send me a pic of you", lex.resolve("en"), &st, 0);
        assert!(out.image_request);
        assert_eq!(out.severity, Severity::Critical);
        // 5.0 weight + 5.0 image-request bonus = 10.0 → normalizes to 1.0.
        assert_eq!(out.score, 1.0);
    }

    #[test]
    fn secrecy_then_platform_switch_combines_across_messages() {
        let lex = en();
        let eng = GroomingRuleEngine::new();
        let mut st = ThreadState::new("t");

        // Message 1: secrecy only.
        let m1 = eng.evaluate("keep this between us", lex.resolve("en"), &st, 1_000);
        st.record(&m1.fired, 1_000);

        // Message 2: platform switch — should pull in the +2.0 secrecy×switch
        // bonus from thread memory, plus rapid-escalation ×1.5.
        let m2 = eng.evaluate("lets move to telegram", lex.resolve("en"), &st, 2_000);
        assert!(m2.fired.contains(&GroomingRule::PlatformSwitching));
        // raw = 0.5 (switch) + 2.0 (secrecy×switch) = 2.5; ×1.5 escalation = 3.75
        // → /10 = 0.375 (LOG band). Higher than the switch alone (0.05).
        assert!(m2.score > 0.3, "score was {}", m2.score);
        assert!(m2.rationale.contains("secrecy × platform-switch"));
    }
}
