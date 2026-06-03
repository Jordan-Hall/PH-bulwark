//! aegis-proto — the shared gRPC/protobuf contract for Aegis.
//!
//! Every client, server, and cluster node codes against the types and service
//! stubs generated here, so the wire format can never drift between crates.
//! See `docs/design/architecture.md` (boundaries + latency budget) and
//! `docs/design/interfaces.md` (the Rust traits builders implement in terms of
//! these types).
//!
//! Transport is tonic gRPC over HTTP/2 with **mTLS** on every link.
//!
//! PRIVACY INVARIANT (also encoded in the `.proto`): no message in this crate
//! ever carries raw explicit media back from analysis. `Evidence` is restricted
//! to hashes, a SAFE thumbnail, or a redacted text snippet.

// The generated code is unsafe-free, but prost/tonic codegen does not itself
// carry `#![forbid(unsafe_code)]`; we forbid it for our hand-written code and
// trust the audited generated module. No FFI lives in this crate.
#![forbid(unsafe_code)]
#![allow(clippy::all)] // generated code; do not lint tonic/prost output

/// Generated protobuf messages and gRPC service stubs for package `aegis.v1`.
///
/// Re-exported at the crate root below for ergonomic `aegis_proto::Verdict`
/// style paths.
pub mod v1 {
    tonic::include_proto!("aegis.v1");
}

pub use v1::*;

// ---------------------------------------------------------------------------
// Hand-written helper newtypes & conveniences (NOT part of the wire format).
//
// These give builders typed handles over the stringly/opaque fields in the
// generated messages without changing the protobuf contract.
// ---------------------------------------------------------------------------

use std::fmt;

/// Stable identifier for a supervised device (matches the mTLS client-cert
/// subject). Wrapping the raw `device_id` string prevents accidentally mixing
/// it with request/work/alert ids at call sites.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceId(pub String);

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for DeviceId {
    fn from(s: String) -> Self {
        DeviceId(s)
    }
}

impl From<&str> for DeviceId {
    fn from(s: &str) -> Self {
        DeviceId(s.to_owned())
    }
}

/// Stable identifier for a cluster node (SWIM member id).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeId(pub String);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The eight deterministic grooming indicator categories (model-research §grooming).
/// Stable string names are the contract; this enum is the typed view used by
/// `aegis-text` and the review UI. `as_str` round-trips with
/// [`GroomingSignal::fired_categories`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GroomingRule {
    Secrecy,
    PlatformSwitching,
    PersonalInfoAgeProbing,
    Sexualization,
    GiftsBribery,
    EmotionalManipulation,
    BoundaryTesting,
    ImageRequest,
}

impl GroomingRule {
    /// All eight rule categories, in spec order.
    pub const ALL: [GroomingRule; 8] = [
        GroomingRule::Secrecy,
        GroomingRule::PlatformSwitching,
        GroomingRule::PersonalInfoAgeProbing,
        GroomingRule::Sexualization,
        GroomingRule::GiftsBribery,
        GroomingRule::EmotionalManipulation,
        GroomingRule::BoundaryTesting,
        GroomingRule::ImageRequest,
    ];

    /// Stable wire name used in `GroomingSignal.fired_categories`.
    pub fn as_str(self) -> &'static str {
        match self {
            GroomingRule::Secrecy => "secrecy",
            GroomingRule::PlatformSwitching => "platform_switching",
            GroomingRule::PersonalInfoAgeProbing => "personal_info_age_probing",
            GroomingRule::Sexualization => "sexualization",
            GroomingRule::GiftsBribery => "gifts_bribery",
            GroomingRule::EmotionalManipulation => "emotional_manipulation",
            GroomingRule::BoundaryTesting => "boundary_testing",
            GroomingRule::ImageRequest => "image_request",
        }
    }

    /// Parse a wire name back into a typed rule, if recognised.
    pub fn from_str(s: &str) -> Option<GroomingRule> {
        GroomingRule::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

impl fmt::Display for GroomingRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Map a normalized score (0.0–1.0) onto a [`Severity`] band using the
/// thresholds from model-research (≥0.7 HIGH, ≥0.5 MEDIUM, ≥0.3 LOW, else INFO).
/// `aegis-policy` is the authority on actions; this is a shared default so
/// every crate bands scores identically.
pub fn severity_for_score(score: f32) -> Severity {
    if score >= 0.7 {
        Severity::High
    } else if score >= 0.5 {
        Severity::Medium
    } else if score >= 0.3 {
        Severity::Low
    } else {
        Severity::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grooming_rule_names_round_trip() {
        for rule in GroomingRule::ALL {
            assert_eq!(GroomingRule::from_str(rule.as_str()), Some(rule));
        }
        assert_eq!(GroomingRule::from_str("nonsense"), None);
    }

    #[test]
    fn severity_bands_match_thresholds() {
        assert_eq!(severity_for_score(0.95), Severity::High);
        assert_eq!(severity_for_score(0.7), Severity::High);
        assert_eq!(severity_for_score(0.6), Severity::Medium);
        assert_eq!(severity_for_score(0.4), Severity::Low);
        assert_eq!(severity_for_score(0.1), Severity::Info);
    }
}
