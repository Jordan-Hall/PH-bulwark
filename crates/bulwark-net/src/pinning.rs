//! Cert-pinning detection + the route-to-OCR signal.
//!
//! When an app pins certificates (banking apps, Signal, WhatsApp, many Android
//! apps), it rejects our TLS inspection leaf at the TLS handshake. We can't decrypt it.
//! Per the threat model's fail-safe table, the default is **fail-OPEN + log**:
//! blocking every pinned app is too disruptive for parental control, so instead
//! we (a) forward the flow, (b) record the coverage gap, and (c) emit a signal
//! that this host/app must be routed to the **on-device agent** (bulwark-agent
//! OCR / accessibility) — the only way to observe E2E/pinned content.
//!
//! Pinning is only discoverable on handshake failure, so we maintain a learned
//! per-host capability map (platform-feasibility §5: "per-app capability matrix
//! TLS inspection vs route-to-OCR").

use std::collections::HashMap;
use std::sync::RwLock;

/// What we know about whether a host can be inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostCapability {
    /// Never attempted / unknown — try TLS inspection.
    Unknown,
    /// TLS inspection succeeded before — keep decrypting.
    Mitmable,
    /// TLS inspection was rejected (pinned / E2E) — route to on-device OCR.
    Pinned,
}

/// Emitted when a flow is detected as cert-pinned. The orchestrator forwards
/// this to `bulwark-agent` so the host/app is covered by OCR instead, and to the
/// coverage dashboard so the gap is shown honestly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinningSignal {
    /// The host (SNI) or app id that rejected TLS inspection.
    pub app_or_host: String,
    /// Whether we forwarded the flow (fail-open) or blocked it (fail-closed).
    pub failed_open: bool,
}

/// Consecutive TLS-interception attempts a host may accumulate WITHOUT a single
/// successful decrypt before it is treated as cert-pinned. hudsucker swallows the
/// client-side leaf-rejection internally (no handler callback), so pinning is
/// inferred from the *absence* of a decrypt across this many attempts. A threshold
/// (not 1) guards against a single transient handshake failure permanently flipping
/// a host to pinned; any successful decrypt resets the count (decay).
const PIN_STRIKE_THRESHOLD: u32 = 3;

/// Learns and records which hosts are TLS inspection-able vs pinned. Cheap, in-memory,
/// concurrent. Persisted by the orchestrator across runs (capability matrix).
#[derive(Default)]
pub struct PinningRegistry {
    map: RwLock<HashMap<String, HostCapability>>,
    /// Per-host count of TLS-interception attempts (client ClientHello seen via a
    /// CONNECT) not yet confirmed decryptable. Reset by record_mitmable (a success
    /// decays strikes), so transient failures can't permanently pin a host.
    strikes: RwLock<HashMap<String, u32>>,
    /// Fail-open policy: forward pinned flows (true) vs block (false).
    fail_open: bool,
}

impl PinningRegistry {
    /// New registry with the configured fail-open policy.
    pub fn new(fail_open: bool) -> Self {
        PinningRegistry {
            map: RwLock::new(HashMap::new()),
            strikes: RwLock::new(HashMap::new()),
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

    /// Record that TLS inspection succeeded for a host (it is decryptable). Also
    /// clears any accumulated pinning strikes: a proven-inspectable host can never
    /// later be flipped to pinned by a burst of transient handshake failures.
    pub fn record_mitmable(&self, app_or_host: &str) {
        if let Ok(mut m) = self.map.write() {
            m.insert(app_or_host.to_owned(), HostCapability::Mitmable);
        }
        if let Ok(mut s) = self.strikes.write() {
            s.remove(app_or_host);
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

    /// The configured fail-open policy (forward pinned flows vs block them). The
    /// proxy consults this to decide whether a known-pinned host is tunnelled
    /// through (fail-open) or kept blocked (fail-closed).
    pub fn fail_open(&self) -> bool {
        self.fail_open
    }

    /// A point-in-time snapshot of every host with a LEARNED capability,
    /// sorted by host for deterministic output. This is the live feed for the
    /// guardian coverage matrix (bulwark-ui): each entry becomes one honest
    /// row — inspectable in-line vs pinned → routed to on-device OCR. Hosts
    /// still `Unknown` are not listed (nothing has been learned yet).
    pub fn snapshot(&self) -> Vec<(String, HostCapability)> {
        let mut out: Vec<(String, HostCapability)> = self
            .map
            .read()
            .map(|m| m.iter().map(|(h, c)| (h.clone(), *c)).collect())
            .unwrap_or_default();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Record a TLS-interception ATTEMPT for `app_or_host` (the client sent a TLS
    /// ClientHello through the CONNECT tunnel) that has not yet produced a decrypted
    /// flow. Because hudsucker gives us no callback for the client rejecting our
    /// minted leaf, we infer pinning from repeated attempts that never decrypt: once
    /// a host reaches PIN_STRIKE_THRESHOLD strikes it is recorded pinned. A single
    /// record_mitmable resets the count, so a transient network failure cannot
    /// permanently mark a host pinned.
    ///
    /// Returns `Some(PinningSignal)` exactly once — on the strike that crosses the
    /// threshold — so the caller can route the host to OCR and stop intercepting;
    /// `None` while below threshold or for an already-known (mitmable/pinned) host.
    pub fn record_intercept_attempt(&self, app_or_host: &str) -> Option<PinningSignal> {
        // Already classified -> no strike bookkeeping. A mitmable host must never
        // accrue strikes; a pinned host is already recorded.
        if self.capability(app_or_host) != HostCapability::Unknown {
            return None;
        }
        let strikes = {
            let mut s = self.strikes.write().ok()?;
            let n = s.entry(app_or_host.to_owned()).or_insert(0);
            *n += 1;
            *n
        };
        if strikes >= PIN_STRIKE_THRESHOLD {
            if let Ok(mut s) = self.strikes.write() {
                s.remove(app_or_host);
            }
            Some(self.record_pinned(app_or_host))
        } else {
            None
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

    #[test]
    fn strikes_below_threshold_do_not_pin() {
        let r = PinningRegistry::new(true);
        for _ in 0..(PIN_STRIKE_THRESHOLD - 1) {
            assert!(r.record_intercept_attempt("pinned.example").is_none());
        }
        assert_eq!(r.capability("pinned.example"), HostCapability::Unknown);
        assert!(!r.is_pinned("pinned.example"));
    }

    #[test]
    fn threshold_strike_marks_pinned_and_signals_once() {
        let r = PinningRegistry::new(true);
        for _ in 0..(PIN_STRIKE_THRESHOLD - 1) {
            assert!(r.record_intercept_attempt("signal.org").is_none());
        }
        let sig = r
            .record_intercept_attempt("signal.org")
            .expect("crossing strike signals");
        assert_eq!(sig.app_or_host, "signal.org");
        assert!(sig.failed_open);
        assert!(r.is_pinned("signal.org"));
        // Already pinned -> no further signal.
        assert!(r.record_intercept_attempt("signal.org").is_none());
    }

    #[test]
    fn snapshot_lists_learned_hosts_sorted() {
        let r = PinningRegistry::new(true);
        assert!(r.snapshot().is_empty());
        r.record_mitmable("web.example");
        r.record_pinned("signal.org");
        r.record_mitmable("api.example");
        assert_eq!(
            r.snapshot(),
            vec![
                ("api.example".to_string(), HostCapability::Mitmable),
                ("signal.org".to_string(), HostCapability::Pinned),
                ("web.example".to_string(), HostCapability::Mitmable),
            ]
        );
    }

    #[test]
    fn success_resets_strikes_so_transient_failures_never_pin() {
        let r = PinningRegistry::new(true);
        assert!(r.record_intercept_attempt("api.example").is_none());
        assert!(r.record_intercept_attempt("api.example").is_none());
        r.record_mitmable("api.example"); // decrypt succeeded -> decay strikes
                                          // Counter reset + mitmable guard: the host can no longer be pinned.
        assert!(r.record_intercept_attempt("api.example").is_none());
        assert_eq!(r.capability("api.example"), HostCapability::Mitmable);
        assert!(!r.is_pinned("api.example"));
    }
}
