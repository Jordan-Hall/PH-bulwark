//! Crate-local error type for `aegis-net`, convertible into the shared
//! [`aegis_core::Error`].
//!
//! The [`Interceptor`](crate::Interceptor) trait (interfaces.md) returns
//! [`aegis_core::Result`], so [`NetError`] implements `Into<aegis_core::Error>`
//! at the single conversion point below. Internally the interception code uses
//! the richer [`NetError`] so failures are classified (CA / keystore / trust
//! store / TUN / proxy / pinning) — these distinctions matter for the
//! **fail-open vs fail-closed** policy in the threat model (a missing CA key is
//! fail-CLOSED; a pinned host is fail-OPEN+log).

use thiserror::Error;

/// Result alias used throughout `aegis-net`.
pub type Result<T> = std::result::Result<T, NetError>;

/// Everything that can go wrong in the interception layer.
///
/// Variants are deliberately specific around the **crown-jewel CA key** and the
/// trust store, because the threat model assigns them distinct fail behaviours.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetError {
    /// A code path tried to load, ship, or transmit a **shared / baked-in CA**.
    /// This is a hard invariant violation (threat-model Asset 1, "No shared CA")
    /// and is rejected unconditionally — never downgraded to a warning.
    #[error("REJECTED: shared/baked-in CA is forbidden — CA must be per-install ({0})")]
    SharedCaRejected(String),

    /// Generating or parsing the per-install root CA failed (`rcgen`).
    #[error("CA generation/parse error: {0}")]
    Ca(String),

    /// The OS keystore that wraps the CA private key failed (DPAPI / TPM /
    /// Keychain / Keystore). Per the threat model this is **fail-CLOSED**: if we
    /// cannot unwrap the signing key we must NOT silently pass traffic.
    #[error("CA keystore error (fail-closed): {0}")]
    KeyStore(String),

    /// Installing or removing our root from the OS trust store failed. A failed
    /// *uninstall* is security-relevant (orphaned root = latent MITM backdoor).
    #[error("trust store error: {0}")]
    TrustStore(String),

    /// The platform TUN device could not be created / configured / torn down.
    #[error("TUN device error: {0}")]
    Tun(String),

    /// The MITM proxy (hudsucker / rustls) failed to start, bind, or run.
    #[error("MITM proxy error: {0}")]
    Proxy(String),

    /// A QUIC-downgrade firewall rule could not be applied or removed.
    #[error("QUIC downgrade error: {0}")]
    Quic(String),

    /// A feature is not implemented on this platform yet (stubbed backend).
    #[error("not supported on this platform: {0}")]
    Unsupported(String),

    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for wrapped foreign errors with no dedicated variant.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl NetError {
    /// Convenience constructor for a CA error from any displayable value.
    pub fn ca(msg: impl std::fmt::Display) -> Self {
        NetError::Ca(msg.to_string())
    }

    /// Convenience constructor for a keystore error.
    pub fn keystore(msg: impl std::fmt::Display) -> Self {
        NetError::KeyStore(msg.to_string())
    }

    /// Convenience constructor for a trust-store error.
    pub fn trust_store(msg: impl std::fmt::Display) -> Self {
        NetError::TrustStore(msg.to_string())
    }

    /// Convenience constructor for a TUN error.
    pub fn tun(msg: impl std::fmt::Display) -> Self {
        NetError::Tun(msg.to_string())
    }

    /// Convenience constructor for a proxy error.
    pub fn proxy(msg: impl std::fmt::Display) -> Self {
        NetError::Proxy(msg.to_string())
    }

    /// Convenience constructor for an unsupported-platform error.
    pub fn unsupported(msg: impl std::fmt::Display) -> Self {
        NetError::Unsupported(msg.to_string())
    }
}

/// Single conversion point into the workspace-wide error type. The interception
/// layer's specific variants are collapsed onto the coarse `aegis_core::Error`
/// surface the trait boundary speaks; the detail survives in the message.
impl From<NetError> for aegis_core::Error {
    fn from(e: NetError) -> Self {
        match e {
            NetError::Io(io) => aegis_core::Error::Io(io),
            // A shared-CA rejection / keystore failure is a configuration-level
            // safety stop; surface it as a config error so callers fail loudly.
            NetError::SharedCaRejected(_) | NetError::KeyStore(_) => {
                aegis_core::Error::Config(e.to_string())
            }
            other => aegis_core::Error::Other(anyhow::Error::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_ca_rejection_maps_to_config_error() {
        let e: aegis_core::Error = NetError::SharedCaRejected("bundled key".into()).into();
        assert!(matches!(e, aegis_core::Error::Config(_)));
    }

    #[test]
    fn keystore_failure_is_loud() {
        // Fail-closed: a keystore failure must not vanish into a soft variant.
        let e: aegis_core::Error = NetError::keystore("DPAPI unavailable").into();
        assert!(matches!(e, aegis_core::Error::Config(_)));
    }

    #[test]
    fn io_roundtrips() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no admin");
        let e: aegis_core::Error = NetError::from(io).into();
        assert!(matches!(e, aegis_core::Error::Io(_)));
    }
}
