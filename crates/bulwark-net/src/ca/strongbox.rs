//! Android **AndroidKeyStore / StrongBox** CA-key interface — scaffold + the JNI
//! contract the Kotlin shell would implement, `device-validated-later`.
//!
//! ## Status (honest)
//! This is a **documented interface scaffold**, NOT a live code path. The
//! shipping Android child app stores the per-install CA today via
//! [`super::file::FileKeyStore`] (`KeyStoreTier::AppSandboxFile`) — wired in
//! `crate::vpn::build_interceptor`, NOT via `select_keystore`. StrongBox is the
//! `HardwareNonExportable` upgrade; this module pins down the JNI shape so the
//! Kotlin/Rust contract is agreed before the device-tested impl lands.
//!
//! ## Why this is a DIFFERENT SHAPE (not a `CaKeyStore` you can `load_key` from)
//! An AndroidKeyStore/StrongBox key is **non-exportable by construction** — the
//! private key is generated and sealed inside the StrongBox secure element (or
//! TEE on devices without StrongBox) and can NEVER be read back out. You **sign
//! in place**; there is no DER to return. Routing this through
//! [`CaKeyStore::load_key`] would imply the key is exportable — the exact
//! opposite of the goal. So StrongBox does NOT implement `load_key`: the
//! [`CaKeyStore`] trait grows a `sign()` primitive (see [`super::keystore`]) and
//! leaf minting calls `sign()` instead of holding the raw key. That signer-shape
//! migration is the work this scaffold precedes.
//!
//! Because the CA key must be P-256 to live in StrongBox/Keymaster as a signing
//! key, the CA keypair generation switches to `rcgen`'s
//! `PKCS_ECDSA_P256_SHA256` for the StrongBox tier (RSA is also supported by
//! Keymaster but ECDSA P-256 is the StrongBox-friendly choice).
//!
//! ## The JNI contract (Kotlin shell ⇄ Rust core)
//! The Rust core never touches the key bytes; it calls three JNI methods the
//! Kotlin shell (`platform/android`) implements over `java.security.KeyStore`
//! ("AndroidKeyStore" provider):
//!
//! ```text
//! // Kotlin side (AndroidKeyStore provider, StrongBox-backed when available):
//! //
//! // 1. ensureCaKey(alias): generate the sealed CA key ONCE, return its cert.
//! //    KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)
//! //      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
//! //      .setDigests(DIGEST_SHA256)
//! //      .setIsStrongBoxBacked(true)        // TEE fallback if NoSuchProvider
//! //      .setUserAuthenticationRequired(false)
//! //      .build()
//! //    -> KeyPairGenerator("EC","AndroidKeyStore").generateKeyPair()
//! //    The private key is non-exportable; only its public cert is returned.
//! //
//! // 2. signWithCaKey(alias, tbsBytes): Signature("SHA256withECDSA")
//! //      .apply { initSign(privateKeyFromKeystore(alias)) ; update(tbs) }.sign()
//! //    -> DER ECDSA signature. The key never leaves StrongBox.
//! //
//! // 3. deleteCaKey(alias): KeyStore.deleteEntry(alias)   // rotation/uninstall
//! ```
//!
//! Rust calls these via the existing `jni` bridge (the same shim the VpnService
//! data path uses). The to-be-signed (`tbs`) bytes for a leaf cert come from
//! `rcgen` (it can produce the TBS and accept an external signature), so the raw
//! CA key never enters the Rust address space — the genuine
//! [`KeyStoreTier::HardwareNonExportable`] posture, signing inside the secure
//! element.
//!
//! ## Why no `cfg(target_os = "android")` body yet
//! Like the other hardware tiers, a half-written JNI impl that can only be
//! exercised on a StrongBox device would be unverified-on-CI churn. We agree the
//! interface here; the live `jni`-calling impl + Pixel device validation is the
//! next increment. The trait-shape change (`sign()`) is the prerequisite and is
//! noted in [`super::keystore`].

// Intentionally no Rust types yet — this module is the interface contract for
// the JNI bridge. The StrongBox signer is added alongside the `CaKeyStore::
// sign()` trait extension in a device-validated increment.
