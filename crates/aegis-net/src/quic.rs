//! QUIC / HTTP-3 downgrade.
//!
//! QUIC runs over **UDP/443** and is end-to-end encrypted with no on-path
//! decryption point, so it bypasses our TCP MITM entirely. The threat model's
//! fail-safe table mandates **downgrade**: block UDP/443 so apps fall back to
//! inspectable TCP/HTTP-2 (~85–90% do — platform-feasibility §4). A small number
//! of apps won't fall back; those go on a per-app allowlist and the failure is
//! shown on the coverage dashboard.
//!
//! ## Mechanism (documented per platform)
//!   * **Windows** → Windows Filtering Platform (WFP) filter, or a
//!     `netsh advfirewall firewall add rule` blocking outbound UDP remoteport 443.
//!     The in-process WFP path is the robust option (survives, scoped); the
//!     `netsh` path is the simple/documented fallback. **Rule application here is
//!     a TODO** — this module provides the policy + the function shape; wiring the
//!     actual WFP/netsh call is the platform task.
//!   * **Linux** → `nft add rule ... udp dport 443 drop` alongside the TPROXY
//!     ruleset; torn down on `ExecStop` with the rest.
//!   * **Android** → `VpnService` simply does not route UDP/443 (drops it).
//!
//! The cost is a 1–3 s first-connection delay while the app retries over TCP
//! (documented; acceptable for parental control).

use crate::Result;

/// QUIC downgrade controller: decides which flows to block and (eventually)
/// applies the platform firewall rule.
pub struct QuicDowngrade {
    enabled: bool,
    /// Hosts/apps exempt from downgrade (they don't fall back to TCP).
    allowlist: Vec<String>,
}

impl QuicDowngrade {
    /// New controller from config.
    pub fn new(enabled: bool, allowlist: Vec<String>) -> Self {
        QuicDowngrade { enabled, allowlist }
    }

    /// Should this UDP destination be blocked to force a TCP fallback?
    /// Blocks UDP/443 unless downgrade is disabled or the host is allowlisted.
    pub fn should_block_udp(&self, dst_port: u16, app_or_host: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if dst_port != 443 {
            return false; // only QUIC's well-known port; DNS/QUIC-on-other-ports untouched
        }
        !self
            .allowlist
            .iter()
            .any(|a| a.eq_ignore_ascii_case(app_or_host))
    }

    /// Apply the platform firewall rule that blocks outbound UDP/443.
    ///
    /// **TODO (platform):** wire the actual WFP filter / `netsh` rule (Windows)
    /// or `nft` rule (Linux). The function exists now so the interceptor can call
    /// it unconditionally; today it logs intent and returns Ok so non-Windows and
    /// pre-wiring builds don't fail. The teardown counterpart is [`remove_rule`].
    pub fn apply_rule(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        #[cfg(windows)]
        {
            // TODO(windows): add a WFP filter (preferred) or run
            // `netsh advfirewall firewall add rule name="Aegis-QUIC-Downgrade"
            //  dir=out action=block protocol=UDP remoteport=443`.
            tracing::warn!(
                "QUIC downgrade rule application is a TODO (WFP/netsh); UDP/443 NOT yet blocked"
            );
        }
        #[cfg(not(windows))]
        {
            // TODO(linux/android): nft `udp dport 443 drop` / VpnService no-route.
            tracing::warn!("QUIC downgrade rule application is a TODO on this platform");
        }
        Ok(())
    }

    /// Remove the QUIC-downgrade firewall rule (teardown — pairs with shutdown).
    /// **TODO (platform):** mirror of [`apply_rule`]. Must run on shutdown so we
    /// don't leave UDP/443 blocked after the VPN is gone.
    pub fn remove_rule(&self) -> Result<()> {
        tracing::debug!("removing QUIC downgrade rule (TODO: actual rule removal)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_udp_443_by_default() {
        let q = QuicDowngrade::new(true, vec![]);
        assert!(q.should_block_udp(443, "youtube.com"));
        assert!(!q.should_block_udp(53, "youtube.com")); // not 443 → leave alone
        assert!(!q.should_block_udp(443, "")); // still 443 → block (no allowlist)
    }

    #[test]
    fn allowlist_exempts_non_fallback_apps() {
        let q = QuicDowngrade::new(true, vec!["stubborn-app.example".to_owned()]);
        assert!(!q.should_block_udp(443, "stubborn-app.example"));
        assert!(!q.should_block_udp(443, "STUBBORN-APP.EXAMPLE")); // case-insensitive
        assert!(q.should_block_udp(443, "other.example"));
    }

    #[test]
    fn disabled_blocks_nothing() {
        let q = QuicDowngrade::new(false, vec![]);
        assert!(!q.should_block_udp(443, "youtube.com"));
        q.apply_rule().unwrap(); // no-op when disabled
    }
}
