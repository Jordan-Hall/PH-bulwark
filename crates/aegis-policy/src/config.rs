//! Configurable, serde/figment-loadable policy.
//!
//! Everything a guardian (or deployment) can tune lives here: the score-band
//! thresholds, the per-age-profile policy, and the category → default-action
//! table. The [`crate::PolicyEngine`] implementation reads these values; it
//! holds no hard-coded magic numbers of its own.
//!
//! Loading is a thin convenience over [`figment`] so the same struct can be
//! merged from compiled-in defaults, a TOML/JSON file, and environment
//! variables (`AEGIS_POLICY_*`) without a parallel DTO layer.

use std::collections::BTreeMap;

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

use crate::error::{PolicyError, Result};

// ---------------------------------------------------------------------------
// Age profiles
// ---------------------------------------------------------------------------

/// Coarse age band for the supervised child. Younger bands censor more
/// aggressively (lower thresholds, prefer BLOCK over WARN); older bands lean on
/// alert-and-log so a teenager's whole conversation is not hard-censored on a
/// borderline signal (PLAN §5 false-positive mitigation).
///
/// This is the crate-local `AgeProfile` referenced by `PolicyContext` in
/// `docs/design/interfaces.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeProfile {
    /// Roughly under ~9. Most protective.
    YoungChild,
    /// Roughly 9–12.
    PreTeen,
    /// Roughly 13–17. Most permissive of the three; favours alert+log.
    Teen,
}

/// Default profile is `Teen` — the engine's canonical baseline. It still alerts
/// the guardian on all material content but does not hard-block a whole
/// conversation on a borderline signal (PLAN §5); dial it down for a younger child.
impl Default for AgeProfile {
    fn default() -> Self {
        AgeProfile::Teen
    }
}

impl AgeProfile {
    /// All bands, youngest first.
    pub const ALL: [AgeProfile; 3] = [
        AgeProfile::YoungChild,
        AgeProfile::PreTeen,
        AgeProfile::Teen,
    ];

    fn key(self) -> &'static str {
        match self {
            AgeProfile::YoungChild => "young_child",
            AgeProfile::PreTeen => "pre_teen",
            AgeProfile::Teen => "teen",
        }
    }
}

// ---------------------------------------------------------------------------
// Score-band thresholds
// ---------------------------------------------------------------------------

/// The four score-band edges from `docs/research/model-research.md`.
///
/// Bands (using the defaults): `[0,log) → ALLOW/LOG`, `[log,flag) → LOG`,
/// `[flag,block) → flag (WARN/LOG + alert)`, `[block,1] → enforce (BLOCK/BLUR/
/// MUTE) + intervention alert`. They are configurable so a deployment can tune
/// sensitivity per its own evaluation set, and per age band (see
/// [`AgeBandThresholds`]).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Below this, content is allowed (the `<0.3` band). At/above it we at
    /// least keep a LOG record.
    pub log: f32,
    /// At/above this we treat the signal as worth flagging (the `0.5` edge):
    /// forward but record (and, for grooming, alert).
    pub flag: f32,
    /// At/above this we enforce (BLOCK/BLUR/MUTE) and raise an intervention
    /// alert (the `0.7` edge).
    pub block: f32,
}

impl Default for Thresholds {
    fn default() -> Self {
        // model-research §grooming: ≥0.7 alert+enforce · ≥0.5 flag+log ·
        // ≥0.3 log · <0.3 pass.
        Thresholds {
            log: 0.3,
            flag: 0.5,
            block: 0.7,
        }
    }
}

impl Thresholds {
    fn validate(&self, ctx: &str) -> Result<()> {
        for (name, v) in [
            ("log", self.log),
            ("flag", self.flag),
            ("block", self.block),
        ] {
            if !v.is_finite() || !(0.0..=1.0).contains(&v) {
                return Err(PolicyError::Invalid(format!(
                    "{ctx}: threshold `{name}` must be a finite value in [0.0, 1.0], got {v}"
                )));
            }
        }
        if !(self.log <= self.flag && self.flag <= self.block) {
            return Err(PolicyError::Invalid(format!(
                "{ctx}: thresholds must be ordered log <= flag <= block, got \
                 log={}, flag={}, block={}",
                self.log, self.flag, self.block
            )));
        }
        Ok(())
    }
}

/// Per-age-band tuning: the score thresholds plus a couple of behavioural
/// switches that distinguish a young child's profile from a teenager's.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgeBandThresholds {
    /// Score-band edges for this age band.
    pub thresholds: Thresholds,
    /// When an ADULT_TEXT verdict lands in the flag band (`[flag, block)`),
    /// should we WARN (interstitial, content still reachable) or BLOCK it?
    /// Younger bands default to BLOCK; teens to WARN.
    pub adult_text_flag_blocks: bool,
    /// For ADULT_IMAGE at/above the block threshold, prefer BLUR (content
    /// stays navigable, just obscured) vs. a hard BLOCK. Defaults to BLUR for
    /// all bands (least-disruptive enforcement that still hides the image).
    pub adult_image_prefer_blur: bool,
}

impl AgeBandThresholds {
    fn for_profile(profile: AgeProfile) -> Self {
        match profile {
            // Most protective: low thresholds, hard-block borderline adult text.
            AgeProfile::YoungChild => AgeBandThresholds {
                thresholds: Thresholds {
                    log: 0.25,
                    flag: 0.4,
                    block: 0.6,
                },
                adult_text_flag_blocks: true,
                adult_image_prefer_blur: true,
            },
            AgeProfile::PreTeen => AgeBandThresholds {
                thresholds: Thresholds {
                    log: 0.3,
                    flag: 0.45,
                    block: 0.65,
                },
                adult_text_flag_blocks: true,
                adult_image_prefer_blur: true,
            },
            // Most permissive: standard research thresholds, WARN (not BLOCK)
            // on borderline adult text to avoid over-censoring a teen.
            AgeProfile::Teen => AgeBandThresholds {
                thresholds: Thresholds::default(),
                adult_text_flag_blocks: false,
                adult_image_prefer_blur: true,
            },
        }
    }

    fn validate(&self, ctx: &str) -> Result<()> {
        self.thresholds.validate(ctx)
    }
}

// ---------------------------------------------------------------------------
// Top-level policy config
// ---------------------------------------------------------------------------

/// The full, loadable policy. This is the single struct a deployment edits or
/// loads from a file/env; the engine is constructed straight from it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Per-age-band thresholds + behavioural switches. Missing bands fall back
    /// to the built-in default for that band when loaded via [`Self::load`].
    pub age_bands: BTreeMap<String, AgeBandThresholds>,

    /// Master switch for the grooming "minimize false-positive harm" rule. When
    /// true (default), a grooming verdict in the flag band logs + raises a
    /// GROOMING_SUSPECTED alert instead of hard-blocking the conversation
    /// (PLAN §5). When false, grooming uses the same enforcement ladder as
    /// other categories.
    pub grooming_alert_not_block: bool,

    /// Whether a CSAM_SUSPECTED verdict sets the report flag (report-never-
    /// archive). On by default and should essentially never be disabled; exposed
    /// only so a test/eval harness can isolate it.
    pub csam_report_flag: bool,

    /// Fail-CLOSED on uncovered media (child-safety posture). When true (default),
    /// a verdict the analyzer could NOT score — `Category::Unspecified`, e.g. no
    /// image/audio model registered or a stub scorer — is surfaced as a WARN +
    /// intervention alert (a coverage gap the guardian must see) instead of being
    /// silently allowed. When false, uncovered media is allowed (legacy behaviour).
    pub fail_closed_uncovered: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        let mut age_bands = BTreeMap::new();
        for profile in AgeProfile::ALL {
            age_bands.insert(
                profile.key().to_string(),
                AgeBandThresholds::for_profile(profile),
            );
        }
        PolicyConfig {
            age_bands,
            grooming_alert_not_block: true,
            csam_report_flag: true,
            fail_closed_uncovered: true,
        }
    }
}

impl PolicyConfig {
    /// Resolve the per-band settings for a profile, falling back to the built-in
    /// default for that band if a custom config omitted it.
    pub fn band(&self, profile: AgeProfile) -> AgeBandThresholds {
        self.age_bands
            .get(profile.key())
            .copied()
            .unwrap_or_else(|| AgeBandThresholds::for_profile(profile))
    }

    /// Validate the merged configuration. Called by [`Self::load`]; also useful
    /// directly when a config is built in code.
    pub fn validate(&self) -> Result<()> {
        for profile in AgeProfile::ALL {
            self.band(profile).validate(profile.key())?;
        }
        for (key, band) in &self.age_bands {
            band.validate(key)?;
        }
        Ok(())
    }

    /// Load policy by merging, in increasing precedence:
    ///   1. compiled-in [`PolicyConfig::default`],
    ///   2. the optional TOML file at `path` (if `Some` and present),
    ///   3. environment variables prefixed `AEGIS_POLICY_`.
    ///
    /// The result is validated before being returned. No I/O beyond reading the
    /// config file and process env — the engine itself never touches I/O.
    pub fn load(path: Option<&str>) -> Result<Self> {
        let mut fig = Figment::from(Serialized::defaults(PolicyConfig::default()));
        if let Some(p) = path {
            fig = fig.merge(Toml::file(p));
        }
        fig = fig.merge(Env::prefixed("AEGIS_POLICY_").split("__"));

        let cfg: PolicyConfig = fig.extract()?;
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_and_has_all_bands() {
        let cfg = PolicyConfig::default();
        cfg.validate().expect("default config must validate");
        for profile in AgeProfile::ALL {
            assert!(cfg.age_bands.contains_key(profile.key()));
        }
    }

    #[test]
    fn younger_bands_block_at_lower_scores() {
        let cfg = PolicyConfig::default();
        let young = cfg.band(AgeProfile::YoungChild).thresholds.block;
        let teen = cfg.band(AgeProfile::Teen).thresholds.block;
        assert!(young < teen, "young child should enforce at a lower score");
    }

    #[test]
    fn out_of_order_thresholds_are_rejected() {
        let mut cfg = PolicyConfig::default();
        cfg.age_bands.insert(
            AgeProfile::Teen.key().to_string(),
            AgeBandThresholds {
                thresholds: Thresholds {
                    log: 0.8,
                    flag: 0.5,
                    block: 0.7,
                },
                adult_text_flag_blocks: false,
                adult_image_prefer_blur: true,
            },
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn out_of_range_threshold_is_rejected() {
        let mut cfg = PolicyConfig::default();
        cfg.age_bands.insert(
            AgeProfile::Teen.key().to_string(),
            AgeBandThresholds {
                thresholds: Thresholds {
                    log: 0.3,
                    flag: 0.5,
                    block: 1.5,
                },
                adult_text_flag_blocks: false,
                adult_image_prefer_blur: true,
            },
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn missing_band_falls_back_to_builtin_default() {
        let mut cfg = PolicyConfig::default();
        cfg.age_bands.clear();
        // Even with an empty map, band() yields the built-in defaults.
        assert_eq!(
            cfg.band(AgeProfile::YoungChild),
            AgeBandThresholds::for_profile(AgeProfile::YoungChild)
        );
        cfg.validate()
            .expect("empty map still validates via fallback");
    }
}
