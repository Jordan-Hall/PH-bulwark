//! # aegis-policy — `Verdict → Action`, deterministically.
//!
//! Pure, synchronous policy: given an analysis [`Verdict`], an [`AgeProfile`],
//! and a configurable [`PolicyConfig`], decide the [`Action`] to take on the
//! flow/segment and whether (and how) to raise a guardian alert. No I/O, no
//! AI/ML, no telemetry — just thresholds and a category→action table.
//!
//! This crate implements the [`PolicyEngine`] trait from
//! `docs/design/interfaces.md` (which is **sync** — pure thresholds/profiles).
//! It additionally exposes a richer [`PolicyDecision`] (action + alert kind +
//! severity + reason) via [`Policy::evaluate`], because callers (aegis-client,
//! aegis-store, aegis-alert) want the alert/severity/reason in one pass rather
//! than three trait calls.
//!
//! ## Score bands (model-research §grooming)
//!
//! | Band (score)        | Action                                | Alert         |
//! |---------------------|----------------------------------------|---------------|
//! | `< log` (def 0.3)   | ALLOW (LOG if `>= log`)                | none          |
//! | `[log, flag)`       | LOG                                    | none          |
//! | `[flag, block)`     | flag: WARN/LOG (+ alert for grooming)  | category-dep. |
//! | `>= block` (def .7) | enforce: BLOCK/BLUR/MUTE               | INTERVENTION  |
//!
//! `CSAM_SUSPECTED` short-circuits the whole ladder: **CRITICAL**, BLOCK,
//! immediate INTERVENTION alert, and the **report flag** is set
//! (report-never-archive — this engine only *flags*; reporting is a human/legal
//! action per PLAN §0c).
//!
//! ## False-positive mitigation (PLAN §5)
//!
//! Borderline signals **log + alert, they do not hard-censor**. Most visibly,
//! a borderline GROOMING verdict raises a `GROOMING_SUSPECTED` alert and LOGs —
//! it does **not** BLOCK a child's whole conversation — unless the score is
//! genuinely critical (image-request / CSAM territory).

#![forbid(unsafe_code)]
// `PolicyError` carries rich, context-bearing variants (config parse + validation
// detail). The functions that return it are COLD config-load/parse paths, so the
// by-value size of the `Err` variant is not a hot-path concern; boxing it would
// churn the error API for no runtime benefit. Allow `result_large_err` here.
#![allow(clippy::result_large_err)]

pub mod allowlist;
mod config;
mod error;

pub use allowlist::{Allowlist, ApplyOutcome, AuditEntry, AuditLog, DeviceAllowlist, ReviewItem};
pub use config::{AgeBandThresholds, AgeProfile, PolicyConfig, Thresholds};
pub use error::{PolicyError, Result};

use aegis_proto::v1::{Action, AlertKind, Category, Severity, SourceChannel, Verdict};
use aegis_proto::DeviceId;

// ---------------------------------------------------------------------------
// PolicyContext (matches docs/design/interfaces.md)
// ---------------------------------------------------------------------------

/// The non-verdict inputs to a decision: which device, which capture channel,
/// and the supervised child's age band. Mirrors `PolicyContext` in
/// `docs/design/interfaces.md`.
#[derive(Clone, Debug)]
pub struct PolicyContext {
    /// Supervised device the verdict came from.
    pub device: DeviceId,
    /// Where the content was captured (web / video stream / OCR / …). Reserved
    /// for channel-specific tuning; the default policy treats channels uniformly
    /// but it is carried so future config can special-case (e.g.) OCR text.
    pub source_channel: SourceChannel,
    /// Age band driving threshold + action selection.
    pub age_profile: AgeProfile,
}

impl PolicyContext {
    /// Convenience constructor.
    pub fn new(device: DeviceId, source_channel: SourceChannel, age_profile: AgeProfile) -> Self {
        PolicyContext {
            device,
            source_channel,
            age_profile,
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyDecision
// ---------------------------------------------------------------------------

/// The full result of evaluating a verdict: the action to apply, whether to
/// raise an alert (and which kind), the severity band the engine settled on,
/// a short explainable reason, and the CSAM report flag.
///
/// `raise_alert == None` means no alert (e.g. a plain LOG). `report` is only
/// ever `true` for the CSAM-suspected path; it tells the orchestrator to invoke
/// the documented legal-reporting workflow — the engine never reports or stores
/// anything itself.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyDecision {
    /// What the data plane should do with the flow/segment.
    pub action: Action,
    /// `Some(kind)` to raise a guardian alert; `None` for no alert.
    pub raise_alert: Option<AlertKind>,
    /// The severity band this decision corresponds to.
    pub severity: Severity,
    /// Short, human-readable, explainable justification (no explicit content).
    pub reason: String,
    /// Report-never-archive flag: `true` only for CSAM_SUSPECTED, signalling the
    /// orchestrator to start the legal-reporting workflow. The engine does not
    /// report or persist.
    pub report: bool,
}

impl PolicyDecision {
    fn new(
        action: Action,
        raise_alert: Option<AlertKind>,
        severity: Severity,
        reason: impl Into<String>,
    ) -> Self {
        PolicyDecision {
            action,
            raise_alert,
            severity,
            reason: reason.into(),
            report: false,
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyEngine trait (the interfaces.md contract)
// ---------------------------------------------------------------------------

/// The contract from `docs/design/interfaces.md`. **Sync** — pure
/// thresholds/profiles, no I/O.
///
/// [`Policy`] is the canonical implementation. Both methods are derived from
/// the single [`Policy::evaluate`] pass so they can never disagree.
pub trait PolicyEngine: Send + Sync {
    /// Decide the action for a verdict under the given context.
    fn decide(&self, verdict: &Verdict, ctx: &PolicyContext) -> Action;

    /// Whether (and how) this verdict+action should raise a guardian alert.
    /// `None` = no alert (e.g. plain LOG). aegis-alert dedupes downstream.
    fn alert_for(
        &self,
        verdict: &Verdict,
        action: Action,
        ctx: &PolicyContext,
    ) -> Option<AlertKind>;
}

// ---------------------------------------------------------------------------
// Policy — the engine
// ---------------------------------------------------------------------------

/// The deterministic policy engine. Construct from a [`PolicyConfig`]
/// (`Policy::new`) or use [`Policy::default`] for the built-in defaults.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    config: PolicyConfig,
}

impl Policy {
    /// Build an engine from a (validated) configuration.
    pub fn new(config: PolicyConfig) -> Self {
        Policy { config }
    }

    /// Load config (defaults → optional TOML file → `AEGIS_POLICY_*` env) and
    /// build the engine. See [`PolicyConfig::load`].
    pub fn load(path: Option<&str>) -> Result<Self> {
        Ok(Policy::new(PolicyConfig::load(path)?))
    }

    /// The configuration this engine was built from.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// The full decision for a verdict in a context. This is the single source
    /// of truth; the [`PolicyEngine`] trait methods are thin projections of it.
    ///
    /// The verdict's own `score`/`category` drive everything; the engine ignores
    /// the analyzer's *recommended* `Verdict.action` (policy is the authority
    /// per the proto comment) but does honour `CSAM_SUSPECTED` unconditionally.
    pub fn evaluate(&self, verdict: &Verdict, ctx: &PolicyContext) -> PolicyDecision {
        let category = verdict.category();
        let score = verdict.score.clamp(0.0, 1.0);
        let band = self.config.band(ctx.age_profile);
        let t = band.thresholds;

        // --- CSAM: critical short-circuit, regardless of score/thresholds. ---
        if category == Category::CsamSuspected {
            let mut d = PolicyDecision::new(
                Action::Block,
                Some(AlertKind::Intervention),
                Severity::Critical,
                "CSAM suspected: blocked and never shown or stored",
            );
            d.report = self.config.csam_report_flag;
            return d;
        }

        // --- Uncovered media: the analyzer could NOT score it (no model/coverage,
        // e.g. no image/audio analyzer registered or a stub scorer). Fail CLOSED
        // for child safety unless the deployment explicitly opts out. ---
        if category == Category::Unspecified {
            return if self.config.fail_closed_uncovered {
                PolicyDecision::new(
                    Action::Block,
                    Some(AlertKind::Intervention),
                    Severity::High,
                    "content could not be analyzed (no coverage); blocked (fail-closed)",
                )
            } else {
                PolicyDecision::new(
                    Action::Allow,
                    None,
                    Severity::Info,
                    "content could not be analyzed (no coverage); allowed (fail-open)",
                )
            };
        }

        // --- SAFE: always allow, no alert. ---
        if category == Category::Safe {
            return PolicyDecision::new(Action::Allow, None, Severity::Info, "safe content");
        }

        // --- Below the log threshold: allow, nothing recorded. ---
        if score < t.log {
            return PolicyDecision::new(
                Action::Allow,
                None,
                Severity::Info,
                "score below log threshold; allowed",
            );
        }

        // --- Grooming gets the false-positive-minimizing treatment. ---
        if category == Category::Grooming {
            return self.decide_grooming(score, &t);
        }

        // --- Enforcement band: BLOCK/BLUR/MUTE + intervention alert. ---
        if score >= t.block {
            let action = self.enforce_action(category, &band);
            return PolicyDecision::new(
                action,
                Some(AlertKind::Intervention),
                Severity::High,
                format!(
                    "{} at/above block threshold ({:.2} >= {:.2}); enforced",
                    category_label(category),
                    score,
                    t.block
                ),
            );
        }

        // --- Flag band [flag, block): forward-but-record / soft action. ---
        if score >= t.flag {
            let (action, alert) = self.flag_action(category, &band);
            return PolicyDecision::new(
                action,
                alert,
                Severity::Medium,
                format!(
                    "{} in flag band ({:.2}); recorded",
                    category_label(category),
                    score
                ),
            );
        }

        // --- Log band [log, flag): forward, record only. ---
        PolicyDecision::new(
            Action::Log,
            None,
            Severity::Low,
            format!(
                "{} in log band ({:.2}); recorded",
                category_label(category),
                score
            ),
        )
    }

    /// Like [`Policy::evaluate`], but first consults a guardian [`Allowlist`].
    /// If the verdict's `host` or content hash was APPROVEd for this device, the
    /// item short-circuits to [`Action::Allow`] with no alert (it must not be
    /// re-blocked). **CSAM is never bypassed** (belt-and-braces; the allowlist
    /// also refuses to store CSAM). `host` is the app/site (`AlertEvent.app`);
    /// pass `""` if unknown. See docs/design/parent-notifications.md.
    pub fn decide_with_allowlist(
        &self,
        verdict: &Verdict,
        ctx: &PolicyContext,
        allowlist: &Allowlist,
        host: &str,
    ) -> PolicyDecision {
        if verdict.category() != Category::CsamSuspected {
            let host_allowed = !host.is_empty() && allowlist.is_host_allowed(&ctx.device, host);
            let hash_allowed = verdict
                .evidence
                .as_ref()
                .map(|e| allowlist.is_hash_allowed(&ctx.device, &e.sha256))
                .unwrap_or(false);
            if host_allowed || hash_allowed {
                let why = if host_allowed && hash_allowed {
                    "host and content hash"
                } else if host_allowed {
                    "host"
                } else {
                    "content hash"
                };
                return PolicyDecision::new(
                    Action::Allow,
                    None,
                    Severity::Info,
                    format!("guardian-approved ({why}); allowlisted for this device"),
                );
            }
        }
        self.evaluate(verdict, ctx)
    }

    /// Grooming policy (PLAN §5): prefer alert + log over hard-blocking a child's
    /// whole conversation on a borderline signal.
    fn decide_grooming(&self, score: f32, t: &Thresholds) -> PolicyDecision {
        if !self.config.grooming_alert_not_block && score >= t.block {
            // Opt-out path: treat grooming like other categories — enforce.
            return PolicyDecision::new(
                Action::Block,
                Some(AlertKind::Intervention),
                Severity::High,
                format!(
                    "grooming at/above block threshold ({:.2}); blocked \
                     (grooming_alert_not_block disabled)",
                    score
                ),
            );
        }

        if score >= t.block {
            // Genuinely high-confidence grooming: still do NOT silently censor
            // the whole conversation. Raise a high-severity GROOMING_SUSPECTED
            // alert + LOG for human review (rules are explainable). Blocking the
            // thread is left to the guardian / intervention workflow.
            return PolicyDecision::new(
                Action::Log,
                Some(AlertKind::GroomingSuspected),
                Severity::High,
                format!(
                    "grooming suspected (high, {:.2}); logged + alerted for human \
                     review (not auto-blocked: minimize false-positive harm)",
                    score
                ),
            );
        }

        if score >= t.flag {
            // Borderline grooming: the canonical "log + alert, not censorship".
            return PolicyDecision::new(
                Action::Log,
                Some(AlertKind::GroomingSuspected),
                Severity::Medium,
                format!(
                    "grooming suspected (borderline, {:.2}); logged + alerted, \
                     conversation NOT blocked",
                    score
                ),
            );
        }

        // Log band: record, no alert yet.
        PolicyDecision::new(
            Action::Log,
            None,
            Severity::Low,
            format!("grooming indicators (low, {:.2}); logged", score),
        )
    }

    /// Category → enforcement action at/above the block threshold.
    fn enforce_action(&self, category: Category, band: &AgeBandThresholds) -> Action {
        match category {
            Category::AdultImage => {
                if band.adult_image_prefer_blur {
                    Action::Blur
                } else {
                    Action::Block
                }
            }
            Category::AdultAudio => Action::Mute,
            // Adult text, violence, self-harm, hate, and anything else explicit:
            // block the flow/segment.
            _ => Action::Block,
        }
    }

    /// Category → (action, alert) in the flag band `[flag, block)`.
    fn flag_action(
        &self,
        category: Category,
        band: &AgeBandThresholds,
    ) -> (Action, Option<AlertKind>) {
        match category {
            // Image: blur the region but keep the page navigable; this is an
            // intervention, so it alerts.
            Category::AdultImage => {
                let action = if band.adult_image_prefer_blur {
                    Action::Blur
                } else {
                    Action::Block
                };
                (action, Some(AlertKind::Intervention))
            }
            // Audio: mute the flagged span; intervention.
            Category::AdultAudio => (Action::Mute, Some(AlertKind::Intervention)),
            // Adult text: younger bands block (intervention); teens get a WARN
            // interstitial (an intervention overlay still alerts the guardian).
            Category::AdultText => {
                if band.adult_text_flag_blocks {
                    (Action::Block, Some(AlertKind::Intervention))
                } else {
                    (Action::Warn, Some(AlertKind::Intervention))
                }
            }
            // Violence / self-harm / hate in the flag band: WARN interstitial +
            // intervention alert (forward but flag, do not hard-block borderline).
            _ => (Action::Warn, Some(AlertKind::Intervention)),
        }
    }
}

/// Stable, content-free label for a category (used in `reason` strings).
fn category_label(c: Category) -> &'static str {
    match c {
        Category::Unspecified => "unspecified",
        Category::Safe => "safe",
        Category::AdultImage => "adult image",
        Category::AdultAudio => "adult audio",
        Category::AdultText => "adult text",
        Category::Grooming => "grooming",
        Category::CsamSuspected => "CSAM suspected",
        Category::Violence => "violence",
        Category::SelfHarm => "self-harm",
        Category::Hate => "hate",
    }
}

// ---------------------------------------------------------------------------
// Trait impl: derived from evaluate() so the two views can never disagree.
// ---------------------------------------------------------------------------

impl PolicyEngine for Policy {
    fn decide(&self, verdict: &Verdict, ctx: &PolicyContext) -> Action {
        self.evaluate(verdict, ctx).action
    }

    fn alert_for(
        &self,
        verdict: &Verdict,
        action: Action,
        ctx: &PolicyContext,
    ) -> Option<AlertKind> {
        let decision = self.evaluate(verdict, ctx);
        // If a caller overrode the action away from what the engine decided, an
        // intervention (BLOCK/BLUR/MUTE/WARN) still warrants an INTERVENTION
        // alert even if the engine itself would not have alerted. This keeps
        // `alert_for` consistent with "a blocker acted" (AlertKind::INTERVENTION).
        match decision.raise_alert {
            Some(kind) => Some(kind),
            None => {
                if is_intervention(action) {
                    Some(AlertKind::Intervention)
                } else {
                    None
                }
            }
        }
    }
}

/// True for actions that visibly act on content (a "blocker acted").
fn is_intervention(action: Action) -> bool {
    matches!(
        action,
        Action::Block | Action::Blur | Action::Mute | Action::Warn
    )
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::v1::{Action, AlertKind, Category, Severity, SourceChannel};

    fn ctx(age: AgeProfile) -> PolicyContext {
        PolicyContext::new(DeviceId("dev-1".into()), SourceChannel::Web, age)
    }

    fn verdict(category: Category, score: f32) -> Verdict {
        Verdict {
            request_id: "r1".into(),
            category: category as i32,
            // The analyzer's recommended action is intentionally bogus to prove
            // the engine ignores it (policy is the authority).
            action: Action::Allow as i32,
            severity: Severity::Unspecified as i32,
            score,
            rationale: String::new(),
            evidence: None,
            grooming: None,
            worker_id: String::new(),
            latency_ms: 0,
            ..Default::default()
        }
    }

    // ---- Score bands -----------------------------------------------------

    #[test]
    fn band_below_log_allows_no_alert() {
        let p = Policy::default();
        // Teen log threshold is 0.3; 0.1 is below it.
        let d = p.evaluate(&verdict(Category::AdultText, 0.1), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.raise_alert, None);
        assert_eq!(d.severity, Severity::Info);
        assert!(!d.report);
    }

    #[test]
    fn band_log_records_only_no_alert() {
        let p = Policy::default();
        // Teen: [0.3, 0.5) is the log band.
        let d = p.evaluate(&verdict(Category::AdultText, 0.35), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Log);
        assert_eq!(d.raise_alert, None);
        assert_eq!(d.severity, Severity::Low);
    }

    #[test]
    fn band_flag_forwards_and_alerts() {
        let p = Policy::default();
        // Teen: [0.5, 0.7) flag band; adult text → WARN (teen) + intervention.
        let d = p.evaluate(&verdict(Category::AdultText, 0.55), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Warn);
        assert_eq!(d.raise_alert, Some(AlertKind::Intervention));
        assert_eq!(d.severity, Severity::Medium);
    }

    #[test]
    fn band_block_enforces_and_alerts() {
        let p = Policy::default();
        // Teen: >= 0.7 enforce band; adult text → BLOCK + intervention.
        let d = p.evaluate(&verdict(Category::AdultText, 0.9), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.raise_alert, Some(AlertKind::Intervention));
        assert_eq!(d.severity, Severity::High);
    }

    // ---- Per-category mapping -------------------------------------------

    #[test]
    fn safe_always_allows() {
        let p = Policy::default();
        for age in AgeProfile::ALL {
            // Even a (nonsensical) high score on SAFE must allow.
            let d = p.evaluate(&verdict(Category::Safe, 0.99), &ctx(age));
            assert_eq!(d.action, Action::Allow);
            assert_eq!(d.raise_alert, None);
        }
    }

    #[test]
    fn adult_image_blurs_by_default() {
        let p = Policy::default();
        let d = p.evaluate(&verdict(Category::AdultImage, 0.95), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Blur);
        assert_eq!(d.raise_alert, Some(AlertKind::Intervention));
    }

    #[test]
    fn adult_image_blocks_when_blur_disabled() {
        let mut cfg = PolicyConfig::default();
        let mut band = cfg.band(AgeProfile::Teen);
        band.adult_image_prefer_blur = false;
        cfg.age_bands.insert("teen".into(), band);
        let p = Policy::new(cfg);
        let d = p.evaluate(&verdict(Category::AdultImage, 0.95), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn adult_audio_mutes() {
        let p = Policy::default();
        let d = p.evaluate(&verdict(Category::AdultAudio, 0.95), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Mute);
        assert_eq!(d.raise_alert, Some(AlertKind::Intervention));
    }

    #[test]
    fn adult_text_blocks_at_high_score() {
        let p = Policy::default();
        let d = p.evaluate(&verdict(Category::AdultText, 0.85), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn adult_text_flag_band_blocks_for_young_child_warns_for_teen() {
        let p = Policy::default();
        // Young child flag band [0.4, 0.6): a score of 0.5 → BLOCK.
        let young = p.evaluate(
            &verdict(Category::AdultText, 0.5),
            &ctx(AgeProfile::YoungChild),
        );
        assert_eq!(young.action, Action::Block);
        // Teen flag band [0.5, 0.7): a score of 0.55 → WARN (not block).
        let teen = p.evaluate(&verdict(Category::AdultText, 0.55), &ctx(AgeProfile::Teen));
        assert_eq!(teen.action, Action::Warn);
    }

    #[test]
    fn violence_flag_warns_block_blocks() {
        let p = Policy::default();
        let flag = p.evaluate(&verdict(Category::Violence, 0.55), &ctx(AgeProfile::Teen));
        assert_eq!(flag.action, Action::Warn);
        let block = p.evaluate(&verdict(Category::Violence, 0.95), &ctx(AgeProfile::Teen));
        assert_eq!(block.action, Action::Block);
    }

    #[test]
    fn uncovered_media_fails_closed_by_default() {
        // Category::Unspecified = the analyzer could not score it (no model/coverage,
        // e.g. no image/audio analyzer registered). Child-safety default: block +
        // alert the guardian to the coverage gap, never silently allow.
        let p = Policy::default();
        let d = p.evaluate(&verdict(Category::Unspecified, 0.0), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Block, "uncovered media must fail closed");
        assert!(
            d.raise_alert.is_some(),
            "coverage gap must alert the guardian"
        );
    }

    // ---- CSAM critical path ---------------------------------------------

    #[test]
    fn csam_is_critical_block_alert_and_report() {
        let p = Policy::default();
        // Even with a low score, CSAM short-circuits to the critical path.
        let d = p.evaluate(
            &verdict(Category::CsamSuspected, 0.2),
            &ctx(AgeProfile::Teen),
        );
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.raise_alert, Some(AlertKind::Intervention));
        assert_eq!(d.severity, Severity::Critical);
        assert!(d.report, "CSAM must set the report-never-archive flag");
    }

    #[test]
    fn csam_report_flag_can_be_isolated_for_tests() {
        let cfg = PolicyConfig {
            csam_report_flag: false,
            ..Default::default()
        };
        let p = Policy::new(cfg);
        let d = p.evaluate(
            &verdict(Category::CsamSuspected, 0.9),
            &ctx(AgeProfile::Teen),
        );
        // Still blocks + alerts critically; only the report flag is suppressed.
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.severity, Severity::Critical);
        assert!(!d.report);
    }

    // ---- Borderline grooming: log + alert, NOT block --------------------

    #[test]
    fn borderline_grooming_logs_and_alerts_not_blocks() {
        let p = Policy::default();
        // Teen flag band [0.5, 0.7): borderline grooming at 0.55.
        let d = p.evaluate(&verdict(Category::Grooming, 0.55), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Log, "must NOT hard-block a conversation");
        assert_eq!(d.raise_alert, Some(AlertKind::GroomingSuspected));
        assert_eq!(d.severity, Severity::Medium);
        assert!(!d.report);
    }

    #[test]
    fn high_grooming_still_logs_and_alerts_not_blocks_by_default() {
        let p = Policy::default();
        // Even high-confidence grooming defaults to LOG + alert (not BLOCK).
        let d = p.evaluate(&verdict(Category::Grooming, 0.9), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Log);
        assert_eq!(d.raise_alert, Some(AlertKind::GroomingSuspected));
        assert_eq!(d.severity, Severity::High);
    }

    #[test]
    fn low_grooming_logs_without_alert() {
        let p = Policy::default();
        // Teen log band [0.3, 0.5): just record, no alert yet.
        let d = p.evaluate(&verdict(Category::Grooming, 0.35), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Log);
        assert_eq!(d.raise_alert, None);
        assert_eq!(d.severity, Severity::Low);
    }

    #[test]
    fn grooming_can_be_made_to_block_via_opt_out() {
        let cfg = PolicyConfig {
            grooming_alert_not_block: false,
            ..Default::default()
        };
        let p = Policy::new(cfg);
        let d = p.evaluate(&verdict(Category::Grooming, 0.9), &ctx(AgeProfile::Teen));
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.raise_alert, Some(AlertKind::Intervention));
    }

    // ---- Trait projection -------------------------------------------------

    #[test]
    fn trait_decide_matches_evaluate() {
        let p = Policy::default();
        let v = verdict(Category::AdultImage, 0.95);
        let c = ctx(AgeProfile::PreTeen);
        assert_eq!(p.decide(&v, &c), p.evaluate(&v, &c).action);
    }

    #[test]
    fn trait_alert_for_reports_intervention_on_overridden_action() {
        let p = Policy::default();
        // A low-score adult-text verdict would itself produce ALLOW/no-alert,
        // but if the caller hands us a BLOCK action, alert_for must flag it.
        let v = verdict(Category::AdultText, 0.1);
        let c = ctx(AgeProfile::Teen);
        assert_eq!(
            p.alert_for(&v, Action::Block, &c),
            Some(AlertKind::Intervention)
        );
        // …and a plain LOG override stays alert-free.
        assert_eq!(p.alert_for(&v, Action::Log, &c), None);
    }

    // ---- Config round-trips ----------------------------------------------

    #[test]
    fn config_serde_round_trips_json() {
        let cfg = PolicyConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: PolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn load_defaults_without_file_or_env() {
        // No path, no AEGIS_POLICY_* env in test → pure defaults, validated.
        let p = Policy::load(None).expect("default load");
        assert_eq!(p.config(), &PolicyConfig::default());
    }
}
