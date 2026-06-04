//! Per-install root CA management (threat-model Asset 1 — the CROWN JEWEL).
//!
//! The MITM proxy mints a leaf cert per visited host, signed by a root CA that
//! is installed into the device trust store. This module:
//!   * **generates a unique root CA on first run** (`rcgen`), never a shared one;
//!   * stores the CA private key via a [`CaKeyStore`] (DPAPI on Windows);
//!   * mints leaf certs on demand for `hudsucker`;
//!   * exposes the CA fingerprint for audit logging + the trust-store install.
//!
//! ## Hard invariants enforced here (non-negotiable, threat-model §"No shared CA")
//!   * [`CaManager::load_or_generate`] NEVER accepts an externally supplied key:
//!     it either loads the host's own wrapped key or generates a fresh one.
//!   * [`reject_shared_ca`] is the guard reviewers asked for: any attempt to load
//!     a CA from a baked-in / shipped artifact is rejected unconditionally.
//!   * The key never leaves the host — there is no method that serializes the
//!     private key to the network. (`store_key` writes only DPAPI ciphertext.)

pub mod dpapi;
pub mod keystore;

pub use keystore::{CaKeyStore, DevInMemoryKeyStore, KeyStoreTier};

use std::path::PathBuf;
use std::sync::Arc;

use crate::{NetError, Result};

/// A loaded per-install Certificate Authority: the root cert (public, installed
/// into the trust store) plus the material needed to mint leaf certs.
///
/// We hold the CA key as **PKCS#8 DER** ([`ca_key_der`]) and re-derive an rcgen
/// `KeyPair` + `Issuer` on each [`mint_leaf`](CaManager::mint_leaf). This keeps
/// the struct free of rcgen's lifetime-parameterized `Issuer` (more robust to
/// version drift) and means the unwrapped key is held in one owned buffer that
/// can be zeroized on drop in a future hardening pass. (Per the threat-model
/// honest limitation, an in-process signer must hold the key in memory; the
/// stronger TPM-in-keystore-signer tier is the documented upgrade.)
pub struct CaManager {
    /// The root CA certificate in DER (public — safe to share / install).
    cert_der: Vec<u8>,
    /// PEM of the root cert, for trust-store tools that prefer PEM (`certutil`).
    cert_pem: String,
    /// SHA-256 fingerprint of the root cert, hex. Logged at startup + surfaced
    /// in the UI so an unexpected root is detectable (threat-model Asset 1 / T).
    fingerprint_hex: String,
    /// The keystore wrapping the private key (DPAPI / dev). Retained so we can
    /// re-sign / rotate / delete without re-reading config.
    keystore: Arc<dyn CaKeyStore>,
    /// The CA's private key in PKCS#8 DER, unwrapped from the keystore. SENSITIVE
    /// (the crown jewel in plaintext while resident). Never serialized off-host.
    ca_key_der: Vec<u8>,
}

impl CaManager {
    /// First-run / restart entry point: load the host's existing per-install CA
    /// from the keystore, or generate a fresh one and persist it.
    ///
    /// This is the ONLY supported way to obtain a `CaManager`. There is no
    /// constructor that takes externally supplied CA key bytes — that path is a
    /// shared-CA risk and is intentionally absent (see [`reject_shared_ca`]).
    pub fn load_or_generate(
        keystore: Arc<dyn CaKeyStore>,
        common_name: &str,
        validity_days: u32,
    ) -> Result<Self> {
        // Refuse to run a real install on the insecure in-memory tier.
        if !keystore.tier().is_production_grade() && !cfg!(test) {
            return Err(NetError::keystore(
                "in-memory keystore is tests-only; refusing to protect a real CA with it",
            ));
        }

        if keystore.exists() {
            Self::load(keystore)
        } else {
            Self::generate(keystore, common_name, validity_days)
        }
    }

    /// Generate a brand-new, unique root CA and persist its key via the keystore.
    /// Each call produces a fresh keypair → the CA is per-install by construction.
    pub fn generate(
        keystore: Arc<dyn CaKeyStore>,
        common_name: &str,
        validity_days: u32,
    ) -> Result<Self> {
        let key_pair =
            rcgen::KeyPair::generate().map_err(|e| NetError::ca(format!("keygen: {e}")))?;

        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|e| NetError::ca(format!("ca params: {e}")))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        // Bounded validity (threat-model rotation requirement).
        let now = std::time::SystemTime::now();
        params.not_before = now.into();
        params.not_after =
            (now + std::time::Duration::from_secs(u64::from(validity_days) * 24 * 60 * 60)).into();
        // Mark as a CA that can sign certs.
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| NetError::ca(format!("self-sign: {e}")))?;

        // Persist the private key WRAPPED by the keystore (PKCS#8 DER), and the
        // PUBLIC cert in the clear, so a restart reloads the identical root.
        let key_der = key_pair.serialize_der();
        keystore.store_key(&key_der)?;

        let cert_der = cert.der().to_vec();
        keystore.store_public_cert(&cert_der)?;
        let cert_pem = cert.pem();
        let fingerprint_hex = sha256_hex(&cert_der);

        tracing::info!(
            fingerprint = %fingerprint_hex,
            tier = ?keystore.tier(),
            "generated per-install root CA (crown jewel) — key wrapped in keystore, NOT shared"
        );

        Ok(CaManager {
            cert_der,
            cert_pem,
            fingerprint_hex,
            keystore,
            ca_key_der: key_der,
        })
    }

    /// Load an existing per-install CA: read the stored PUBLIC cert and unwrap
    /// the key from the keystore. Used on every restart after first run.
    ///
    /// We load the cert that was actually generated + installed (not a
    /// re-derived one — validity timestamps would differ and break the
    /// trust-store match / fingerprint).
    pub fn load(keystore: Arc<dyn CaKeyStore>) -> Result<Self> {
        let key_der = keystore.load_key()?; // fail-CLOSED if absent
                                            // Re-parse once to fail fast if the key is corrupt.
        let _ = reparse_keypair(&key_der)?;

        let cert_der = keystore.load_public_cert()?.ok_or_else(|| {
            // Key present but cert missing → inconsistent install. Fail-closed:
            // do not silently re-mint a different root (it would not be trusted).
            NetError::ca("CA key present but public cert missing — re-provision the CA")
        })?;

        let cert_pem = der_to_pem(&cert_der);
        let fingerprint_hex = sha256_hex(&cert_der);

        tracing::info!(fingerprint = %fingerprint_hex, "loaded existing per-install root CA");

        Ok(CaManager {
            cert_der,
            cert_pem,
            fingerprint_hex,
            keystore,
            ca_key_der: key_der,
        })
    }

    /// The CA's PKCS#8 private key DER, for adapting into hudsucker's
    /// `RcgenAuthority` (which needs an in-process key + cert to mint leaves).
    /// SENSITIVE — callers must NOT log, persist unwrapped, or transmit it.
    pub fn ca_key_der(&self) -> &[u8] {
        &self.ca_key_der
    }

    /// Root CA certificate, DER. Public — safe to install into the trust store.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Root CA certificate, PEM (for `certutil` / file-based install).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// SHA-256 fingerprint (hex) of the root cert. Log this at startup and show
    /// it in the UI so an unexpected/foreign root is detectable.
    pub fn fingerprint_hex(&self) -> &str {
        &self.fingerprint_hex
    }

    /// The keystore protection tier in effect (for audit / UI honesty).
    pub fn tier(&self) -> KeyStoreTier {
        self.keystore.tier()
    }

    /// Mint a leaf certificate for `host`, signed by this root CA. Called by the
    /// MITM proxy per visited host. Returns `(leaf_cert_der, leaf_key_der)`.
    ///
    /// The leaf is short-lived and minted **locally** — leaf certs are never
    /// requested from the cluster (threat-model Asset 1 / S).
    pub fn mint_leaf(&self, host: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let key_pair =
            rcgen::KeyPair::generate().map_err(|e| NetError::ca(format!("leaf keygen: {e}")))?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_owned()])
            .map_err(|e| NetError::ca(format!("leaf params: {e}")))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        let now = std::time::SystemTime::now();
        params.not_before = now.into();
        // Short-lived leaf (a few days is plenty for a live MITM session).
        params.not_after = (now + std::time::Duration::from_secs(7 * 24 * 60 * 60)).into();

        // Build the CA issuer directly from the stored root cert DER + key, so
        // the leaf's issuer DN matches the installed root exactly. Built fresh
        // per mint and consumed here; the proxy's RcgenAuthority caches leaves.
        let ca_key = reparse_keypair(&self.ca_key_der)?;
        let ca_cert_der = rustls::pki_types::CertificateDer::from(self.cert_der.clone());
        let issuer = rcgen::Issuer::from_ca_cert_der(&ca_cert_der, ca_key)
            .map_err(|e| NetError::ca(format!("build issuer from CA cert: {e}")))?;
        let leaf = params
            .signed_by(&key_pair, &issuer)
            .map_err(|e| NetError::ca(format!("leaf sign: {e}")))?;
        Ok((leaf.der().to_vec(), key_pair.serialize_der()))
    }

    /// Rotate the CA: generate a fresh one, persisting the new key. The caller is
    /// responsible for re-installing the new root and removing the old one from
    /// the trust store (threat-model rotation procedure). Returns the new manager.
    pub fn rotate(
        keystore: Arc<dyn CaKeyStore>,
        common_name: &str,
        validity_days: u32,
    ) -> Result<Self> {
        tracing::warn!("rotating per-install root CA (audit event)");
        Self::generate(keystore, common_name, validity_days)
    }
}

/// The reviewer-requested guard: reject ANY attempt to obtain a CA from a
/// shipped/baked-in/shared source. There is intentionally no code path that
/// loads a CA key from the binary, an embedded asset, or the network — this
/// function exists so such a call is an explicit, greppable, hard error rather
/// than a silent footgun. (threat-model §"No shared / baked-in CA")
pub fn reject_shared_ca(source: &str) -> Result<std::convert::Infallible> {
    Err(NetError::SharedCaRejected(format!(
        "attempt to load CA from {source}; the CA must be generated per-install \
         and stored only in this host's keystore — never shipped or transmitted"
    )))
}

/// Select the production keystore for this platform. Windows → DPAPI. Other
/// platforms currently return an `Unsupported` error (their real keystores —
/// Keychain / Android Keystore / TPM — are future impls). NEVER returns the
/// insecure in-memory store; that is reachable only via its explicit `new()`.
pub fn select_keystore(store_dir: Option<PathBuf>) -> Result<Arc<dyn CaKeyStore>> {
    #[cfg(windows)]
    {
        let dir = store_dir.unwrap_or_else(default_store_dir);
        Ok(Arc::new(dpapi::DpapiKeyStore::new(dir)))
    }
    #[cfg(not(windows))]
    {
        let _ = store_dir;
        Err(NetError::unsupported(
            "production CA keystore not yet implemented for this OS \
             (Windows DPAPI is the only real backend so far; \
              macOS Keychain / Android Keystore / Linux TPM are TODO)",
        ))
    }
}

/// Default per-user directory for the wrapped key + public cert.
#[cfg(windows)]
fn default_store_dir() -> PathBuf {
    // %LOCALAPPDATA%\Aegis — per-user so DPAPI's user scope lines up.
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Aegis")
}

/// SHA-256 of `bytes` as lowercase hex. Uses `ring` transitively via rustls? No
/// — implemented locally with a tiny dependency-free routine to avoid pulling a
/// hashing crate just for a fingerprint. (Standard FIPS-180-4 SHA-256.)
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Re-parse PKCS#8 DER into an rcgen `KeyPair`. Kept in one place so
/// `generate`/`load`/`issuer`/`mint` agree on how the key is reconstructed.
/// `rcgen::KeyPair` implements `TryFrom<&[u8]>` over PKCS#8 DER (the form
/// `serialize_der` produces), inferring the signature algorithm from the key.
fn reparse_keypair(key_der: &[u8]) -> Result<rcgen::KeyPair> {
    rcgen::KeyPair::try_from(key_der).map_err(|e| NetError::ca(format!("reparse pkcs8 key: {e}")))
}

/// Wrap a DER certificate into a PEM `CERTIFICATE` block (for `certutil` / file
/// install). The cert is public, so a tiny hand-rolled base64 keeps us from
/// pulling a base64 crate just for this.
fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Standard base64 (RFC 4648) encoder. No padding shortcuts; public data only.
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 0x3f) as usize] as char);
        out.push(T[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

// --- Minimal, dependency-free SHA-256 (fingerprint only; not a crypto API). ---
// We only need a stable content hash of the public cert for the audit log /
// trust-store dedupe; pulling a full hashing crate for this would widen the
// dependency surface for no security benefit (the cert is public).

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for (hi, vi) in h.iter_mut().zip(v.iter()) {
            *hi = hi.wrapping_add(*vi);
        }
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // SHA-256("") empty
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn reject_shared_ca_always_errors() {
        let err = reject_shared_ca("baked-in binary asset").unwrap_err();
        assert!(matches!(err, NetError::SharedCaRejected(_)));
    }

    #[test]
    fn generate_then_load_yields_same_keystore_key() {
        let ks: Arc<dyn CaKeyStore> = Arc::new(DevInMemoryKeyStore::new());
        let ca = CaManager::generate(ks.clone(), "Test Root", 365).unwrap();
        assert!(!ca.cert_der().is_empty());
        assert_eq!(ca.fingerprint_hex().len(), 64);
        assert_eq!(ca.tier(), KeyStoreTier::InMemoryInsecure);

        // Key + public cert were persisted; loading returns the SAME root.
        assert!(ks.exists());
        let reloaded = CaManager::load(ks.clone()).unwrap();
        assert_eq!(
            reloaded.fingerprint_hex(),
            ca.fingerprint_hex(),
            "reload must yield the identical installed root, not a re-derived one"
        );
        assert_eq!(reloaded.cert_der(), ca.cert_der());
    }

    #[test]
    fn pem_wraps_der_with_certificate_block() {
        let pem = der_to_pem(b"abc");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
        // base64("abc") == "YWJj"
        assert!(pem.contains("YWJj"));
    }

    #[test]
    fn load_without_cert_fails_closed() {
        // Key present but no stored cert → must NOT silently re-mint a new root.
        let ks: Arc<dyn CaKeyStore> = Arc::new(DevInMemoryKeyStore::new());
        let kp = rcgen::KeyPair::generate().unwrap();
        ks.store_key(&kp.serialize_der()).unwrap();
        assert!(CaManager::load(ks).is_err());
    }

    #[test]
    fn each_generate_is_unique_no_shared_ca() {
        // Two installs (two keystores) must NOT share a CA — different fingerprints.
        let a = CaManager::generate(Arc::new(DevInMemoryKeyStore::new()), "Root", 365).unwrap();
        let b = CaManager::generate(Arc::new(DevInMemoryKeyStore::new()), "Root", 365).unwrap();
        assert_ne!(
            a.fingerprint_hex(),
            b.fingerprint_hex(),
            "per-install CAs must be unique"
        );
    }

    #[test]
    fn mints_a_leaf_for_a_host() {
        let ca = CaManager::generate(Arc::new(DevInMemoryKeyStore::new()), "Root", 365).unwrap();
        let (leaf_der, leaf_key) = ca.mint_leaf("example.com").unwrap();
        assert!(!leaf_der.is_empty());
        assert!(!leaf_key.is_empty());
    }
}
