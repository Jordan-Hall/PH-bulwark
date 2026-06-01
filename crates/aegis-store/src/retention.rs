//! Retention policy + auto-purge (`docs/security/data-handling.md` §4).
//!
//! Data-handling.md mandates **short retention with auto-purge**, guardian-
//! configurable within sane bounds:
//!
//! * **C1 flagged evidence** (thumbnail refs / hashes / metadata): default
//!   **30 days**, then auto-delete — unless an item is **pinned** under review.
//! * **C3 audit/metadata**: a bounded ring (age cap + size cap), rotated.
//!
//! [`RetentionPolicy`] holds those knobs (with the defaults above); the actual
//! deletion is performed by each backend's `purge_expired` against this policy
//! and is exposed on the [`crate::Store`] trait so a scheduler (`aegis-client` /
//! `aegis-server`) can run it on the retention clock. A purge that removes a
//! subject's C1 data also records a purge event in the audit log (right-to-
//! erasure, data-handling.md §4) — the backends append that audit row so it is
//! itself part of the tamper-evident chain.

use serde::{Deserialize, Serialize};

/// Default C1 (flagged-evidence) retention: 30 days, per data-handling.md §4.
pub const DEFAULT_EVIDENCE_TTL_DAYS: u32 = 30;

/// Default C3 (audit/metadata) age cap: 90 days (bounded ring; tunable).
pub const DEFAULT_AUDIT_TTL_DAYS: u32 = 90;

/// Default C3 audit ring size cap (max rows kept regardless of age).
pub const DEFAULT_AUDIT_MAX_ROWS: u64 = 500_000;

const MS_PER_DAY: i64 = 24 * 60 * 60 * 1000;

/// Guardian-configurable retention knobs (serde-loadable from config).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionPolicy {
    /// TTL for C1 flagged evidence (`evidence_meta` + its `audit_log` rows),
    /// in days. `0` disables time-based evidence purge (size cap still applies).
    pub evidence_ttl_days: u32,
    /// Age cap for the C3 audit ring, in days. `0` disables the age cap.
    pub audit_ttl_days: u32,
    /// Size cap for the C3 audit ring (oldest rows beyond this are rotated out).
    /// `0` disables the size cap.
    pub audit_max_rows: u64,
    /// If true, never delete an audit row that is `pinned` (under guardian
    /// review), even past TTL. Defaults true.
    pub honor_pins: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        RetentionPolicy {
            evidence_ttl_days: DEFAULT_EVIDENCE_TTL_DAYS,
            audit_ttl_days: DEFAULT_AUDIT_TTL_DAYS,
            audit_max_rows: DEFAULT_AUDIT_MAX_ROWS,
            honor_pins: true,
        }
    }
}

impl RetentionPolicy {
    /// The cutoff timestamp (unix millis) before which audit rows are expired,
    /// given `now_ms`. `None` if the age cap is disabled.
    pub fn audit_cutoff_ms(&self, now_ms: i64) -> Option<i64> {
        if self.audit_ttl_days == 0 {
            None
        } else {
            Some(now_ms - (self.audit_ttl_days as i64) * MS_PER_DAY)
        }
    }

    /// The cutoff timestamp (unix millis) before which C1 evidence is expired.
    /// `None` if evidence TTL is disabled.
    pub fn evidence_cutoff_ms(&self, now_ms: i64) -> Option<i64> {
        if self.evidence_ttl_days == 0 {
            None
        } else {
            Some(now_ms - (self.evidence_ttl_days as i64) * MS_PER_DAY)
        }
    }

    /// Validate the policy is within sane bounds (data-handling.md §4
    /// "guardian-configurable within sane bounds"). Caps absurd retention.
    pub fn validate(&self) -> crate::error::Result<()> {
        // Cap evidence retention at one year to honour storage-limitation.
        if self.evidence_ttl_days > 365 {
            return Err(crate::error::StoreError::invalid(
                "evidence_ttl_days exceeds the 365-day storage-limitation cap",
            ));
        }
        if self.audit_ttl_days > 365 {
            return Err(crate::error::StoreError::invalid(
                "audit_ttl_days exceeds the 365-day storage-limitation cap",
            ));
        }
        Ok(())
    }
}

/// What a purge run removed (returned by `Store::purge_expired`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PurgeReport {
    /// Audit rows deleted by the age cap.
    pub audit_rows_aged_out: u64,
    /// Audit rows deleted by the size cap (ring rotation).
    pub audit_rows_rotated: u64,
    /// `evidence_meta` rows deleted by the evidence TTL.
    pub evidence_rows_purged: u64,
}

impl PurgeReport {
    /// Total rows removed across all categories.
    pub fn total(&self) -> u64 {
        self.audit_rows_aged_out + self.audit_rows_rotated + self.evidence_rows_purged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_data_handling_doc() {
        let p = RetentionPolicy::default();
        assert_eq!(p.evidence_ttl_days, 30); // §4: C1 = 30 days
        assert!(p.honor_pins);
        p.validate().unwrap();
    }

    #[test]
    fn cutoffs_compute_from_now() {
        let p = RetentionPolicy::default();
        let now = 100 * MS_PER_DAY;
        assert_eq!(p.evidence_cutoff_ms(now), Some(70 * MS_PER_DAY)); // 100-30
        assert_eq!(p.audit_cutoff_ms(now), Some(10 * MS_PER_DAY)); // 100-90
    }

    #[test]
    fn disabled_ttl_yields_no_cutoff() {
        let p = RetentionPolicy {
            evidence_ttl_days: 0,
            audit_ttl_days: 0,
            ..Default::default()
        };
        assert_eq!(p.evidence_cutoff_ms(123), None);
        assert_eq!(p.audit_cutoff_ms(123), None);
    }

    #[test]
    fn absurd_retention_rejected() {
        let p = RetentionPolicy {
            evidence_ttl_days: 9999,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn purge_report_totals() {
        let r = PurgeReport {
            audit_rows_aged_out: 3,
            audit_rows_rotated: 2,
            evidence_rows_purged: 5,
        };
        assert_eq!(r.total(), 10);
    }
}
