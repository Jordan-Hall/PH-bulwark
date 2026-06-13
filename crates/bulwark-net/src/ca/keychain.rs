//! macOS **Keychain** CA-key storage — scaffold + the real call sequence,
//! `device-validated-later`.
//!
//! ## Status (honest)
//! This module is a **documented scaffold**, NOT a host-verified code path. There
//! is no macOS toolchain target on the Windows dev/CI host, so nothing here is
//! compile-checked locally — the `cfg(target_os = "macos")` body would only
//! build on a Mac. Until a Mac CI runner exists, [`select_macos_keystore`]
//! returns an honest `Unsupported` error rather than pretending to protect the
//! crown-jewel CA key. The real impl + device validation is a later increment
//! (issue #141 is explicitly multi-week + needs device testing).
//!
//! ## Why scaffold, not a live `security-framework` dep
//! Writing real `Security.framework` FFI behind `cfg(target_os = "macos")` on a
//! Windows host produces code that NEVER compiles here or in CI — it silently
//! rots. We document the exact call sequence instead, so the live impl is a
//! mechanical fill-in once a Mac runner can verify it. `security-framework`
//! (MIT/Apache-2.0, permissive) is the intended binding when that lands; gate it
//! behind `[target.'cfg(target_os = "macos")'.dependencies]`.
//!
//! ## The real Keychain sequence (what the live impl will do)
//! Two tiers, strongest first:
//!
//! ### Tier A — Secure Enclave (genuine [`KeyStoreTier::HardwareNonExportable`])
//! The Secure Enclave only holds **256-bit ECC (P-256)** keys, and they are
//! **non-exportable by construction** — you sign with them, you never read them
//! out. To use it for the CA, the CA keypair must be P-256 (rcgen supports
//! `PKCS_ECDSA_P256_SHA256`) and **generated inside the Enclave**:
//!   1. `SecAccessControlCreateWithFlags(.., kSecAccessControlPrivateKeyUsage, ..)`
//!      with `kSecAttrTokenIDSecureEnclave`.
//!   2. `SecKeyCreateRandomKey` with `kSecAttrIsPermanent = true` + the access
//!      control → the private key lives in the Enclave; we only ever hold a
//!      `SecKeyRef` handle + can derive the public key.
//!   3. Sign leaves with `SecKeyCreateSignature` (the raw key never enters our
//!      address space). This requires the trait to grow a `sign()` primitive
//!      (see [`super::keystore`]) — `load_key()` is intentionally unavailable on
//!      a non-exportable tier.
//!
//! ### Tier B — Keychain item (`OsWrappedAtRest`)
//! If an exportable in-process signer is required (today's `rcgen` shape), store
//! the CA PKCS#8 DER as a Keychain **generic password** item:
//!   1. `SecItemAdd` with `kSecClass = kSecClassGenericPassword`,
//!      `kSecAttrService = "co.predatorhunters.bulwark.ca"`,
//!      `kSecAttrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
//!      (never synced to iCloud, never leaves the device), value = the DER.
//!   2. `load_key` → `SecItemCopyMatching` with `kSecReturnData`.
//!   3. `delete_key` → `SecItemDelete`.
//!
//! The Keychain wraps the item with a key derived from the login/device
//! credentials (held by the OS, not on disk) → this is a real `OsWrappedAtRest`
//! tier, stronger than the encrypted-file fallback.
//!
//! The public root cert is non-secret and can be co-located as a second Keychain
//! item or a plain file, same as the other stores.

use std::path::PathBuf;
use std::sync::Arc;

use super::keystore::CaKeyStore;
use crate::{NetError, Result};

/// Select the macOS production CA keystore.
///
/// `device-validated-later`: returns an honest `Unsupported` error until the
/// `Security.framework` impl is written + validated on a Mac CI runner. We do
/// NOT fall back to a weaker store silently — a missing real keystore is
/// fail-CLOSED (the caller blocks + alerts), consistent with the crown-jewel
/// threat model.
pub fn select_macos_keystore(_dir: PathBuf) -> Result<Arc<dyn CaKeyStore>> {
    Err(NetError::unsupported(
        "macOS Keychain / Secure Enclave CA keystore is scaffolded but not yet \
         device-validated (issue #141); refusing to protect the CA key with an \
         unverified backend — see ca::keychain for the implementation plan",
    ))
}

// The live impl will add, behind `#[cfg(target_os = "macos")]`:
//   pub struct KeychainKeyStore { service: String, dir: PathBuf }
//   impl CaKeyStore for KeychainKeyStore { /* SecItemAdd / CopyMatching / Delete */ }
// kept out of the tree until a Mac runner can compile-check + device-test it,
// per the honesty rule above (no silently-rotting cfg-gated FFI).
