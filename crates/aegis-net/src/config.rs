//! Interception-layer configuration.
//!
//! These knobs layer under `aegis_core::Config` (the orchestrator can embed
//! [`NetConfig`] as a `net` section). They are kept here so the security-relevant
//! defaults — fail-open vs fail-closed, QUIC downgrade, CA validity — live next
//! to the code that enforces them and are documented at the point of use.
//!
//! Fail-safe defaults follow the threat model's explicit policy table:
//!   * CA key missing / cannot sign  → **fail-CLOSED** (block + alert).
//!   * Cert-pinned / E2E host         → **fail-OPEN + log** (configurable).
//!   * QUIC / HTTP3                    → **downgrade** (block UDP/443 → TCP).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Configuration for the `aegis-net` interception layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetConfig {
    /// Loopback address:port the MITM proxy listens on. The TUN redirects
    /// captured TCP here. Loopback-only by default (never exposed off-host).
    pub proxy_listen: String,

    /// Human-readable Common Name stamped into the per-install root CA subject.
    /// Purely cosmetic (shown in the OS trust store UI); it does NOT make the CA
    /// shared — the key behind it is unique per install.
    pub ca_common_name: String,

    /// Bounded validity for the generated root CA, in days (threat-model
    /// rotation requirement: ≤ ~2 years). The documented rotation procedure
    /// regenerates before expiry.
    pub ca_validity_days: u32,

    /// Where the *wrapped* (DPAPI-encrypted) CA key blob and the public cert are
    /// stored on disk. The blob is ciphertext only; the raw key never lands here.
    /// `None` → a platform default under the per-user app-data dir.
    pub ca_store_dir: Option<PathBuf>,

    /// QUIC downgrade: block UDP/443 so apps fall back to inspectable TCP.
    /// Default ON (threat-model "QUIC/HTTP3 → downgrade").
    pub quic_downgrade: bool,

    /// Per-app allowlist of hosts/apps that are NOT downgraded (apps that refuse
    /// to fall back from QUIC). Matched against SNI / app id.
    pub quic_allowlist: Vec<String>,

    /// **Fail-open** on a cert-pinned / MITM-rejected host (forward + log) vs.
    /// fail-closed (block). Default `true` (fail-open) per the threat model:
    /// blocking every pinned app is too disruptive for parental control; the
    /// coverage gap is surfaced honestly and the host is routed to on-device OCR.
    pub pinning_fail_open: bool,

    /// **Fail-closed** when the CA key is missing / the keystore cannot sign.
    /// Default `true`: silently passing unfiltered traffic defeats the product
    /// and hides the failure (threat-model Asset 1 / fail-safe table). Exposed as
    /// config only so a test harness can flip it; production stays fail-closed.
    pub ca_missing_fail_closed: bool,

    /// Bounded capacity of the channel that surfaces decrypted flows up to
    /// `aegis-flow`. Backpressure caps memory holding plaintext intermediates.
    pub flow_channel_capacity: usize,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            proxy_listen: "127.0.0.1:0".to_owned(), // ephemeral loopback port
            ca_common_name: "Aegis Per-Install Root (DO NOT SHARE)".to_owned(),
            ca_validity_days: 365, // ≤ 2 years; conservative 1-year default
            ca_store_dir: None,
            quic_downgrade: true,
            quic_allowlist: Vec::new(),
            pinning_fail_open: true,    // disruptive to block all pinned apps
            ca_missing_fail_closed: true, // crown-jewel: never pass unfiltered silently
            flow_channel_capacity: 1024,
        }
    }
}

impl NetConfig {
    /// Validate cross-field invariants. Cheap, pure; call after loading.
    pub fn validate(&self) -> crate::Result<()> {
        if self.ca_validity_days == 0 {
            return Err(crate::NetError::Ca(
                "ca_validity_days must be > 0".to_owned(),
            ));
        }
        // Bounded lifetime is a threat-model requirement; reject absurd values
        // that would defeat rotation (cap at ~2 years).
        if self.ca_validity_days > 730 {
            return Err(crate::NetError::Ca(format!(
                "ca_validity_days {} exceeds the 730-day (2yr) rotation ceiling",
                self.ca_validity_days
            )));
        }
        if self.flow_channel_capacity == 0 {
            return Err(crate::NetError::proxy(
                "flow_channel_capacity must be > 0",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_fail_safe() {
        let c = NetConfig::default();
        // Crown-jewel: missing CA key fails CLOSED.
        assert!(c.ca_missing_fail_closed);
        // Pinned apps fail OPEN (documented coverage gap), per threat model.
        assert!(c.pinning_fail_open);
        // QUIC downgraded by default so traffic stays inspectable.
        assert!(c.quic_downgrade);
        assert!(c.ca_validity_days > 0 && c.ca_validity_days <= 730);
        c.validate().expect("defaults validate");
    }

    #[test]
    fn rejects_unbounded_ca_validity() {
        let mut c = NetConfig::default();
        c.ca_validity_days = 100_000; // ~273 years — defeats rotation
        assert!(c.validate().is_err());
    }
}
