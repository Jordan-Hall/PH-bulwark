//! Cert-pinning detection + the route-to-OCR signal.
//!
//! When an app pins certificates (banking apps, Signal, WhatsApp, many Android
//! apps), it rejects our MITM leaf at the TLS handshake. We can't decrypt it.
//! Per the threat model's fail-safe table, the default is **fail-OPEN + log**:
//! blocking every pinned app is too disruptive for parental control, so instead
//! we (a) forward the flow, (b) record the coverage gap, and (c) emit a signal
//! that this host/app must be routed to the **on-device agent** (bulwark-agent
//! OCR / accessibility) — the only way to observe E2E/pinned content.
//!
//! Pinning is only discoverable on handshake failure, so we maintain a learned
//! per-host capability map (platform-feasibility §5: "per-app capability matrix
//! MITM vs route-to-OCR").

use std::collections::HashMap;
use std::sync::RwLock;

/// What we know about whether a host can be MITM'd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostCapability {
    /// Never attempted / unknown — try MITM.
    Unknown,
    /// MITM succeeded before — keep decrypting.
    Mitmable,
    /// MITM was rejected (pinned / E2E) — route to on-device OCR.
    Pinned,
}

/// Emitted when a flow is detected as cert-pinned. The orchestrator forwards
/// this to `bulwark-agent` so the host/app is covered by OCR instead, and to the
/// coverage dashboard so the gap is shown honestly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinningSignal {
    /// The host (SNI) or app id that rejected MITM.
    pub app_or_host: String,
    /// Whether we forwarded the flow (fail-open) or blocked it (fail-closed).
    pub failed_open: bool,
}

/// Learns and records which hosts are MITM-able vs pinned. Cheap, in-memory,
/// concurrent. Persisted by the orchestrator across runs (capability matrix).
#[derive(Default)]
pub struct PinningRegistry {
    map: RwLock<HashMap<String, HostCapability>>,
    /// Fail-open policy: forward pinned flows (true) vs block (false).
    fail_open: bool,
}

impl PinningRegistry {
    /// New registry with the configured fail-open policy.
    pub fn new(fail_open: bool) -> Self {
        PinningRegistry {
            map: RwLock::new(HashMap::new()),
            fail_open,
        }
    }

    /// Current known capability for a host.
    pub fn capability(&self, app_or_host: &str) -> HostCapability {
        self.map
            .read()
            .ok()
            .and_then(|m| m.get(app_or_host).copied())
            .unwrap_or(HostCapability::Unknown)
    }

    /// True if this host is known-pinned (interfaces.md `Interceptor::is_pinned`).
    pub fn is_pinned(&self, app_or_host: &str) -> bool {
        self.capability(app_or_host) == HostCapability::Pinned
    }

    /// Record that MITM succeeded for a host (it is decryptable).
    pub fn record_mitmable(&self, app_or_host: &str) {
        if let Ok(mut m) = self.map.write() {
            m.insert(app_or_host.to_owned(), HostCapability::Mitmable);
        }
    }

    /// Record a rejected handshake (pinned). Returns the [`PinningSignal`] the
    /// caller forwards to bulwark-agent + the coverage dashboard. Honours the
    /// fail-open policy in the returned signal.
    pub fn record_pinned(&self, app_or_host: &str) -> PinningSignal {
        if let Ok(mut m) = self.map.write() {
            m.insert(app_or_host.to_owned(), HostCapability::Pinned);
        }
        if self.fail_open {
            tracing::info!(
                host = %app_or_host,
                "cert-pinned host: failing OPEN (forward + log) → routing to on-device OCR"
            );
        } else {
            tracing::warn!(host = %app_or_host, "cert-pinned host: failing CLOSED (blocked)");
        }
        PinningSignal {
            app_or_host: app_or_host.to_owned(),
            failed_open: self.fail_open,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_until_observed() {
        let r = PinningRegistry::new(true);
        assert_eq!(r.capability("bank.example"), HostCapability::Unknown);
        assert!(!r.is_pinned("bank.example"));
    }

    #[test]
    fn records_and_reports_pinned_fail_open() {
        let r = PinningRegistry::new(true);
        let sig = r.record_pinned("signal.org");
        assert!(r.is_pinned("signal.org"));
        assert_eq!(sig.app_or_host, "signal.org");
        assert!(sig.failed_open); // default fail-open per threat model
    }

    #[test]
    fn fail_closed_policy_reflected() {
        let r = PinningRegistry::new(false);
        let sig = r.record_pinned("bank.example");
        assert!(!sig.failed_open);
    }

    #[test]
    fn mitmable_overrides_unknown() {
        let r = PinningRegistry::new(true);
        r.record_mitmable("example.com");
        assert_eq!(r.capability("example.com"), HostCapability::Mitmable);
        assert!(!r.is_pinned("example.com"));
    }
}
