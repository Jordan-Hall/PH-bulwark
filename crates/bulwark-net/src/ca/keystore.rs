//! The [`CaKeyStore`] trait — the boundary that wraps the **crown-jewel CA
//! private key** (threat-model Asset 1).
//!
//! ## Why this is a trait
//! The private key must be stored *wrapped by a hardware/OS keystore, never as a
//! plaintext file* (threat-model Asset 1, STRIDE-I mitigation). Different
//! platforms have different keystores:
//!   * **Windows** → DPAPI (`CryptProtectData`) or TPM via CNG; non-exportable.
//!   * **Android** → Android Keystore (StrongBox/TEE), non-exportable.
//!   * **macOS**   → Keychain / Secure Enclave, non-exportable.
//!   * **Linux**   → TPM 2.0 if present, else kernel keyring + root-only `0600`.
//!
//! This trait ([`CaKeyStore`]) **is** the keystore abstraction issue #141 asks
//! for — the file-based / OS / hardware impls are interchangeable behind it, so
//! the default file path is unchanged while hardware tiers slot in. The impls:
//!   * [`crate::ca::dpapi`] — Windows DPAPI (live, host-tested).
//!   * [`crate::ca::enc_file`] — AES-256-GCM encrypted-file (live, host-tested);
//!     the Linux no-TPM fallback + defense-in-depth over a bare file.
//!   * [`crate::ca::file`] — plaintext app-sandbox file (the live Android tier).
//!   * [`crate::ca::tpm`] / [`crate::ca::keychain`] / [`crate::ca::strongbox`] —
//!     per-OS hardware scaffolds (Linux TPM 2.0 / macOS Keychain+Secure Enclave /
//!     Android StrongBox), documented + `device-validated-later`.
//!   * [`DevInMemoryKeyStore`] — in-memory, **for tests only**.
//!
//! ## Honest limitation (documented, not hidden)
//! The *ideal* posture (threat-model Asset 1) is signing **inside** the keystore
//! so the raw key never enters Bulwark address space (e.g. CNG `NCryptSignHash`
//! with a non-exportable TPM key). `rcgen` / `rustls` need an in-process signer,
//! so the DPAPI tier instead keeps the key encrypted at rest and only unwraps it
//! transiently in memory to mint leaf certs. The TPM-backed-signer path (raw key
//! never in-process) is documented as the stronger tier to slot in later
//! ([`KeyStoreTier`]).

use crate::Result;

/// How strongly the backing keystore protects the CA private key. Surfaced so
/// the UI / audit log can be honest about the protection level on this host
/// (threat-model: "documented as a weaker tier" for the fallbacks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStoreTier {
    /// Raw key never enters Bulwark memory; signing happens in hardware (TPM /
    /// Secure Enclave / StrongBox). Strongest. **Scaffolded, device-validated
    /// later** — the documented target for the TPM ([`crate::ca::tpm`]), Secure
    /// Enclave ([`crate::ca::keychain`]), and StrongBox ([`crate::ca::strongbox`])
    /// upgrades. Reaching it requires the trait to grow a `sign()` primitive (a
    /// non-exportable key cannot satisfy [`CaKeyStore::load_key`]).
    HardwareNonExportable,
    /// Key is encrypted at rest by an OS facility (DPAPI machine+user scope) and
    /// only unwrapped transiently in-process to sign. This is the Windows
    /// default tier today.
    OsWrappedAtRest,
    /// Plaintext PKCS#8 DER file in an APP-PRIVATE directory (Android `filesDir`,
    /// file `0600`, dir `0700`). Protection comes from the OS per-app sandbox
    /// (per-UID isolation), NOT from key wrapping — an honest, documented weaker
    /// tier; the Android Keystore/TEE-wrapped signer is the planned upgrade.
    AppSandboxFile,
    /// Plaintext in process memory, nothing persisted securely. **TESTS ONLY.**
    InMemoryInsecure,
}

impl KeyStoreTier {
    /// True if this tier is acceptable for production use. The insecure
    /// in-memory tier must never be selected outside tests.
    pub fn is_production_grade(self) -> bool {
        !matches!(self, KeyStoreTier::InMemoryInsecure)
    }
}

/// Wraps the per-install root CA's private key behind an OS/hardware keystore.
///
/// Implementors MUST:
///   * never write the raw private key as plaintext to disk, logs, or swap;
///   * never transmit the key off-host (no network egress — crown-jewel rule);
///   * mark the key non-exportable where the platform supports it.
///
/// The key material exchanged here is **PKCS#8 DER** (what `rcgen` produces and
/// consumes). On platforms with in-keystore signing (the [`KeyStoreTier::
/// HardwareNonExportable`] target), an implementor may instead keep an opaque
/// handle and expose a sign primitive; that richer shape is layered in later
/// without changing this storage contract.
pub trait CaKeyStore: Send + Sync {
    /// Protection tier this keystore provides (for audit / UI honesty).
    fn tier(&self) -> KeyStoreTier;

    /// True if a wrapped CA key is already present (→ load it; do NOT regenerate).
    fn exists(&self) -> bool;

    /// Persist the CA private key (PKCS#8 DER), wrapping it via the platform
    /// keystore. Overwrites any existing key (used on first-run + rotation).
    ///
    /// `key_der` is sensitive: callers hold it only transiently and should
    /// zeroize their copy after this returns.
    fn store_key(&self, key_der: &[u8]) -> Result<()>;

    /// Unwrap and return the CA private key (PKCS#8 DER) for in-process signing.
    /// On a [`KeyStoreTier::HardwareNonExportable`] tier this is **intentionally
    /// unavailable** — the key cannot be read out of the TPM / Secure Enclave /
    /// StrongBox, so those impls return an error here and signing happens via a
    /// future `sign()` primitive on this trait instead (see the hardware
    /// scaffolds). Today the exportable tiers (DPAPI / encrypted-file / file)
    /// return the unwrapped DER.
    ///
    /// Returns `KeyStore` error if no key is present — callers treat that as
    /// **fail-CLOSED** (block + alert + re-provision), per the threat model.
    fn load_key(&self) -> Result<Vec<u8>>;

    /// Permanently remove the wrapped key (uninstall / rotation cleanup). After
    /// this, [`exists`](CaKeyStore::exists) returns `false`. Best-effort secure
    /// erase of the on-disk ciphertext.
    fn delete_key(&self) -> Result<()>;

    /// Persist the **public** root cert (DER) alongside the wrapped key.
    ///
    /// The cert is public (safe to store in the clear); it is kept so that on
    /// restart [`CaManager::load`](super::CaManager::load) returns the *exact*
    /// cert that was generated + installed into the trust store, rather than
    /// re-deriving a non-identical one (validity timestamps would differ). The
    /// key store co-locates it because it already owns the storage location.
    fn store_public_cert(&self, cert_der: &[u8]) -> Result<()>;

    /// Load the previously stored public root cert (DER), if present.
    fn load_public_cert(&self) -> Result<Option<Vec<u8>>>;
}

// ---------------------------------------------------------------------------
// Dev / in-memory fallback — TESTS ONLY.
// ---------------------------------------------------------------------------

/// An in-memory [`CaKeyStore`] that holds the key as plaintext in process RAM.
///
/// **FOR TESTS / LOCAL DEV ONLY.** It provides NO at-rest protection and must
/// never be selected on a real install — doing so would violate threat-model
/// Asset 1 (the key would be unprotected). [`select_keystore`](super::
/// select_keystore) refuses to hand this back in a production build; it is only
/// reachable explicitly via this constructor, which is gated behind being
/// clearly named and tiered [`KeyStoreTier::InMemoryInsecure`].
#[derive(Default)]
pub struct DevInMemoryKeyStore {
    key: std::sync::Mutex<Option<Vec<u8>>>,
    cert: std::sync::Mutex<Option<Vec<u8>>>,
}

impl DevInMemoryKeyStore {
    /// Construct an empty in-memory keystore. Tests only.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CaKeyStore for DevInMemoryKeyStore {
    fn tier(&self) -> KeyStoreTier {
        KeyStoreTier::InMemoryInsecure
    }

    fn exists(&self) -> bool {
        self.key.lock().map(|k| k.is_some()).unwrap_or(false)
    }

    fn store_key(&self, key_der: &[u8]) -> Result<()> {
        let mut guard = self
            .key
            .lock()
            .map_err(|_| crate::NetError::keystore("in-memory keystore lock poisoned"))?;
        *guard = Some(key_der.to_vec());
        Ok(())
    }

    fn load_key(&self) -> Result<Vec<u8>> {
        let guard = self
            .key
            .lock()
            .map_err(|_| crate::NetError::keystore("in-memory keystore lock poisoned"))?;
        guard
            .clone()
            .ok_or_else(|| crate::NetError::keystore("no CA key present (in-memory)"))
    }

    fn delete_key(&self) -> Result<()> {
        let mut guard = self
            .key
            .lock()
            .map_err(|_| crate::NetError::keystore("in-memory keystore lock poisoned"))?;
        *guard = None;
        if let Ok(mut c) = self.cert.lock() {
            *c = None;
        }
        Ok(())
    }

    fn store_public_cert(&self, cert_der: &[u8]) -> Result<()> {
        let mut guard = self
            .cert
            .lock()
            .map_err(|_| crate::NetError::keystore("in-memory cert lock poisoned"))?;
        *guard = Some(cert_der.to_vec());
        Ok(())
    }

    fn load_public_cert(&self) -> Result<Option<Vec<u8>>> {
        let guard = self
            .cert
            .lock()
            .map_err(|_| crate::NetError::keystore("in-memory cert lock poisoned"))?;
        Ok(guard.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_roundtrips_but_is_marked_insecure() {
        let ks = DevInMemoryKeyStore::new();
        assert!(!ks.exists());
        assert_eq!(ks.tier(), KeyStoreTier::InMemoryInsecure);
        assert!(!ks.tier().is_production_grade());

        ks.store_key(b"fake-pkcs8-der").unwrap();
        assert!(ks.exists());
        assert_eq!(ks.load_key().unwrap(), b"fake-pkcs8-der");

        ks.delete_key().unwrap();
        assert!(!ks.exists());
        assert!(ks.load_key().is_err()); // fail-closed: no key → error
    }
}
