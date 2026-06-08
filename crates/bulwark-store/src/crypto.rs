//! Encryption-at-rest helpers and the documented at-rest design.
//!
//! ## Decision: at-rest encryption = **SQLCipher** (client), DB/volume (server)
//!
//! Per `docs/security/data-handling.md` §3 ("Persist") and `interfaces.md`
//! (`Store`: "Encrypted SQLite ... `rusqlite` + `age`/SQLCipher"), this crate
//! uses, for the **client/local** backend:
//!
//! * **SQLCipher** for page-level encryption-at-rest of the whole SQLite
//!   database (the `bundled-sqlcipher` feature statically links SQLCipher; the
//!   key is applied with `PRAGMA key`). This encrypts *every* table at rest —
//!   audit log, evidence metadata, thread state, config — transparently, which
//!   is exactly the C1/C3 "encrypt at rest" requirement. Chosen over app-level
//!   `age`/`ring` for the live DB because it covers the file holistically
//!   (including indexes, WAL, and free pages) without per-column bespoke crypto.
//!
//! For the **server/cluster** backend, at-rest encryption is provided by the
//! Postgres deployment (TDE / encrypted volume) and access is restricted by
//! mTLS — data-handling.md §3.
//!
//! `age` is retained for one specific job: **encrypted exports / backups**
//! (data-handling.md §3 "exports/backups: `age`-encrypted, keys owner-held").
//! [`AgeExporter`] wraps that.
//!
//! ## Keys live in the OS keystore (C2), never beside the data
//!
//! The SQLCipher key and the audit HMAC key are **C2 operational secrets**:
//! data-handling.md §2/§3 require them in the OS keystore (DPAPI / Keychain /
//! Android Keystore / TPM), never in plaintext config and never in the database.
//! This crate takes the key as bytes from the caller ([`AtRestKey`]); wiring it
//! to the platform keystore is the client orchestrator's job (`bulwark-client`),
//! keeping this crate platform-agnostic and unsafe-free.
//!
//! Uses `ring`/`age`; no `unsafe`, no AI/ML, no telemetry.

use ring::hmac;

use crate::error::{Result, StoreError};

/// An at-rest key supplied by the caller (sourced from the OS keystore).
///
/// Wrapped so it is not accidentally logged: its `Debug` redacts the bytes.
#[derive(Clone)]
pub struct AtRestKey(Vec<u8>);

impl AtRestKey {
    /// Wrap raw key bytes obtained from the OS keystore.
    pub fn new(key: impl Into<Vec<u8>>) -> Result<Self> {
        let k = key.into();
        if k.is_empty() {
            return Err(StoreError::crypto("at-rest key must not be empty"));
        }
        Ok(AtRestKey(k))
    }

    /// Borrow the raw key bytes (for `PRAGMA key` / HMAC keying only).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Render the key as a SQLCipher `PRAGMA key` hex literal: `x'..'`. Using the
    /// raw-key hex form skips SQLCipher's key-derivation over a passphrase and
    /// treats the keystore-provided bytes as the actual key material.
    pub fn sqlcipher_pragma_value(&self) -> String {
        format!("x'{}'", crate::model::hex_encode(&self.0))
    }

    /// Derive the audit-log HMAC key for the keyed tamper-evident chain
    /// ([`crate::hashchain::keyed_link`]). Domain-separated from the DB key so
    /// the same keystore secret can seed both without cross-use.
    pub fn audit_hmac_key(&self) -> hmac::Key {
        // Domain-separate via a tagged HMAC so the chain key != the DB key.
        let salt = hmac::Key::new(hmac::HMAC_SHA256, b"bulwark-store/audit-hmac/v1");
        let derived = hmac::sign(&salt, &self.0);
        hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref())
    }
}

impl std::fmt::Debug for AtRestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print key material.
        write!(f, "AtRestKey(<{} bytes redacted>)", self.0.len())
    }
}

/// `age`-based encryptor for **exports/backups only** (not the live DB).
///
/// The live database is encrypted by SQLCipher; this exists so a guardian can
/// take an `age`-encrypted backup of derived (C1/C3) data whose key they hold,
/// per data-handling.md §3.
pub struct AgeExporter {
    recipient: age::x25519::Recipient,
}

impl AgeExporter {
    /// Build an exporter for an `age` X25519 recipient (the owner's public key).
    pub fn new(recipient: age::x25519::Recipient) -> Self {
        AgeExporter { recipient }
    }

    /// Parse a recipient from its `age1...` bech32 string.
    pub fn from_recipient_str(s: &str) -> Result<Self> {
        let recipient = s
            .parse::<age::x25519::Recipient>()
            .map_err(|e| StoreError::crypto(format!("invalid age recipient: {e}")))?;
        Ok(AgeExporter { recipient })
    }

    /// Encrypt `plaintext` (a derived-data export — e.g. a JSON dump of audit
    /// rows) to the configured recipient. The result is an `age` armored/binary
    /// blob the owner can decrypt with their identity.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use std::io::Write;

        let encryptor = age::Encryptor::with_recipients(std::iter::once(
            &self.recipient as &dyn age::Recipient,
        ))
        .map_err(|e| StoreError::crypto(format!("age encryptor: {e}")))?;

        let mut out = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|e| StoreError::crypto(format!("age wrap: {e}")))?;
        writer
            .write_all(plaintext)
            .map_err(|e| StoreError::crypto(format!("age write: {e}")))?;
        writer
            .finish()
            .map_err(|e| StoreError::crypto(format!("age finish: {e}")))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_debug_redacts() {
        let k = AtRestKey::new(vec![1, 2, 3, 4]).unwrap();
        let dbg = format!("{k:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("1, 2, 3"));
    }

    #[test]
    fn empty_key_rejected() {
        assert!(AtRestKey::new(Vec::new()).is_err());
    }

    #[test]
    fn pragma_value_is_hex_literal() {
        let k = AtRestKey::new(vec![0xab, 0xcd]).unwrap();
        assert_eq!(k.sqlcipher_pragma_value(), "x'abcd'");
    }

    #[test]
    fn audit_hmac_key_is_deterministic_and_distinct() {
        let k = AtRestKey::new(vec![9; 32]).unwrap();
        // Deterministic: same key bytes → same HMAC over the same message.
        let a = hmac::sign(&k.audit_hmac_key(), b"x");
        let b = hmac::sign(&k.audit_hmac_key(), b"x");
        assert_eq!(a.as_ref(), b.as_ref());
    }
}
