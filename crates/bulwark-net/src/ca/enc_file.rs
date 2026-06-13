//! AES-256-GCM **encrypted-file** [`CaKeyStore`] — the documented Linux fallback
//! when no TPM 2.0 is available, and a defense-in-depth layer over a bare file.
//!
//! ## What this is (and, honestly, is not)
//! On Linux with a TPM the CA key should be wrapped/sealed by hardware
//! ([`super::tpm`], the [`KeyStoreTier::HardwareNonExportable`] target). When no
//! TPM is present we still must persist the per-install CA across sessions
//! (a session-only CA resets user trust + pinning learning every restart). This
//! store keeps the key as **AES-256-GCM ciphertext at rest** instead of
//! plaintext, with a fresh random 96-bit nonce per write.
//!
//! ## Honest tier: this is still [`KeyStoreTier::AppSandboxFile`]
//! The AEAD envelope key lives in a sibling `0600` file on the SAME disk as the
//! ciphertext. Against the threat the tiers are calibrated to — a deliberate
//! same-UID / root actor, or a full offline disk image — both files leak
//! together, so this is **no stronger** than a plaintext file in the OS sandbox.
//! Its real, narrower benefit is defense-in-depth against *accidental* partial
//! exposure (a stray copy / a log that cats one file but not the other) and
//! "data at rest is not human-readable plaintext". The trust boundary is still
//! the OS per-app/per-user sandbox. The genuine `OsWrappedAtRest` /
//! `HardwareNonExportable` upgrade is a TPM-sealed key whose wrapping secret is
//! held by hardware and is **never on disk** — that is [`super::tpm`].
//!
//! We deliberately do NOT derive the envelope key from `/etc/machine-id` or
//! similar (it is world-readable → security theater); a real random key in a
//! `0600` file is honest about exactly what it protects.
//!
//! The encrypted-vs-plaintext distinction is surfaced in the audit log via a
//! tracing field at construction, NOT via a separate tier (which would imply a
//! protection gradient this does not have).

use std::path::PathBuf;

use super::keystore::{CaKeyStore, KeyStoreTier};
use crate::{NetError, Result};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};

/// Ciphertext file holding `nonce(12) || AES-256-GCM(ct||tag)` of the CA key.
const ENC_KEY_FILE: &str = "ca-key.aesgcm";
/// The 32-byte AEAD envelope key (`0600`). On the same disk as the ciphertext —
/// see the module-level honesty note about what this does and does not protect.
const ENVELOPE_KEY_FILE: &str = "ca-key.envelope";
/// Public root cert (DER) — public material, stored in the clear.
const PUBLIC_CERT_FILE: &str = "ca-cert.der";

/// AES-256 key length in bytes.
const AES_256_KEY_LEN: usize = 32;

/// AES-256-GCM encrypted-file keystore (see module docs). The protection
/// boundary is the OS sandbox; tier is [`KeyStoreTier::AppSandboxFile`].
pub struct EncryptedFileKeyStore {
    dir: PathBuf,
}

impl EncryptedFileKeyStore {
    /// Keystore rooted at `dir` (a per-app/per-user directory the platform shell
    /// owns). The directory + the `0600` envelope key are created on first write.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let s = Self { dir: dir.into() };
        tracing::debug!(
            dir = %s.dir.display(),
            "CA key store: AES-256-GCM encrypted-file (no-TPM fallback; \
             at-rest AEAD is defense-in-depth, trust boundary is the OS sandbox)"
        );
        s
    }

    fn enc_key_path(&self) -> PathBuf {
        self.dir.join(ENC_KEY_FILE)
    }

    fn envelope_path(&self) -> PathBuf {
        self.dir.join(ENVELOPE_KEY_FILE)
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join(PUBLIC_CERT_FILE)
    }

    fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| NetError::keystore(format!("create CA dir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    /// Read the persisted envelope key. **Read-only — never mutates on-disk
    /// state.** Used by [`load_key`](Self::load_key): a read path must not
    /// recreate the AEAD secret. If the envelope is missing (e.g. a transient
    /// partial restore / slow mount) this returns an error so the caller
    /// fail-CLOSES and a retry can still succeed once the file reappears —
    /// recreating it here would clobber the slot and permanently brick the
    /// ciphertext (the tag would never verify again).
    fn load_envelope(&self) -> Result<[u8; AES_256_KEY_LEN]> {
        let path = self.envelope_path();
        let bytes = std::fs::read(&path)
            .map_err(|e| NetError::keystore(format!("read CA envelope key: {e}")))?;
        bytes.as_slice().try_into().map_err(|_| {
            NetError::keystore("CA envelope key is the wrong length — re-provision the CA")
        })
    }

    /// Load the envelope key, generating + persisting a fresh random one (`0600`)
    /// on first use. Used ONLY by [`store_key`](Self::store_key) (the write path),
    /// where creating the AEAD secret on first write is correct. The read path
    /// uses [`load_envelope`](Self::load_envelope) instead so a read never writes.
    fn load_or_create_envelope(&self) -> Result<[u8; AES_256_KEY_LEN]> {
        let path = self.envelope_path();
        match std::fs::read(&path) {
            Ok(bytes) => bytes.as_slice().try_into().map_err(|_| {
                NetError::keystore("CA envelope key is the wrong length — re-provision the CA")
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.ensure_dir()?;
                let key = random_envelope_key()?;
                std::fs::write(&path, key)
                    .map_err(|e| NetError::keystore(format!("write CA envelope key: {e}")))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .map_err(|e| NetError::keystore(format!("chmod 600 envelope: {e}")))?;
                }
                Ok(key)
            }
            Err(e) => Err(NetError::keystore(format!("read CA envelope key: {e}"))),
        }
    }
}

impl CaKeyStore for EncryptedFileKeyStore {
    fn tier(&self) -> KeyStoreTier {
        // Honest: AEAD at rest, but the envelope key is on the same disk → the
        // trust boundary is still the OS sandbox. NOT OsWrappedAtRest.
        KeyStoreTier::AppSandboxFile
    }

    fn exists(&self) -> bool {
        self.enc_key_path().is_file()
    }

    fn store_key(&self, key_der: &[u8]) -> Result<()> {
        self.ensure_dir()?;
        let envelope = self.load_or_create_envelope()?;
        let blob = seal(&envelope, key_der)?;
        let path = self.enc_key_path();
        std::fs::write(&path, blob)
            .map_err(|e| NetError::keystore(format!("write encrypted CA key: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| NetError::keystore(format!("chmod 600 encrypted key: {e}")))?;
        }
        Ok(())
    }

    fn load_key(&self) -> Result<Vec<u8>> {
        // Absent/unreadable/undecryptable key is FAIL-CLOSED upstream.
        let blob = std::fs::read(self.enc_key_path()).map_err(|e| {
            NetError::keystore(format!("no CA key present (encrypted-file store): {e}"))
        })?;
        // Read-only: never recreate the envelope on a read (would brick the
        // ciphertext on a transient absence). Missing envelope => fail-CLOSED.
        let envelope = self.load_envelope()?;
        open(&envelope, &blob)
    }

    fn delete_key(&self) -> Result<()> {
        for path in [self.enc_key_path(), self.envelope_path()] {
            if path.is_file() {
                // Best-effort overwrite before unlink (cheap hygiene — NOT a
                // secure-erase guarantee on flash; documented limitation).
                if let Ok(meta) = std::fs::metadata(&path) {
                    let _ = std::fs::write(&path, vec![0u8; meta.len() as usize]);
                }
                std::fs::remove_file(&path)
                    .map_err(|e| NetError::keystore(format!("delete CA key material: {e}")))?;
            }
        }
        let _ = std::fs::remove_file(self.cert_path()); // cert is public; best-effort
        Ok(())
    }

    fn store_public_cert(&self, cert_der: &[u8]) -> Result<()> {
        self.ensure_dir()?;
        std::fs::write(self.cert_path(), cert_der)
            .map_err(|e| NetError::keystore(format!("write CA cert: {e}")))
    }

    fn load_public_cert(&self) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.cert_path()) {
            Ok(der) => Ok(Some(der)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(NetError::keystore(format!("read CA cert: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// cfg-AGNOSTIC AEAD helpers — these compile + unit-test on every host (incl.
// this Windows dev box), so the encrypt/decrypt logic is real host-verified
// coverage rather than an unverifiable cfg block.
// ---------------------------------------------------------------------------

/// 32 random bytes from the OS CSPRNG for use as an AES-256 envelope key.
fn random_envelope_key() -> Result<[u8; AES_256_KEY_LEN]> {
    let rng = SystemRandom::new();
    let mut key = [0u8; AES_256_KEY_LEN];
    rng.fill(&mut key)
        .map_err(|_| NetError::keystore("CSPRNG failed generating CA envelope key"))?;
    Ok(key)
}

/// AES-256-GCM seal: returns `nonce(12) || ciphertext || tag(16)`. A fresh random
/// nonce is drawn per call (GCM requires nonce uniqueness under a fixed key).
fn seal(envelope_key: &[u8; AES_256_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let unbound = UnboundKey::new(&AES_256_GCM, envelope_key)
        .map_err(|_| NetError::keystore("AEAD key init failed"))?;
    let key = LessSafeKey::new(unbound);

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| NetError::keystore("CSPRNG failed generating AEAD nonce"))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| NetError::keystore("AEAD seal failed"))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + in_out.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&in_out);
    Ok(blob)
}

/// AES-256-GCM open: inverse of [`seal`]. A failed tag check (tamper / wrong key)
/// is an error → FAIL-CLOSED upstream, never a silent plaintext pass-through.
fn open(envelope_key: &[u8; AES_256_KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(NetError::keystore("encrypted CA key blob too short"));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| NetError::keystore("encrypted CA key nonce malformed"))?;
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let unbound = UnboundKey::new(&AES_256_GCM, envelope_key)
        .map_err(|_| NetError::keystore("AEAD key init failed"))?;
    let key = LessSafeKey::new(unbound);

    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| NetError::keystore("AEAD open failed (tampered/wrong key) — fail-closed"))?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrips_and_is_authenticated() {
        // Runs on EVERY host (the encrypt/decrypt logic is cfg-agnostic).
        let key = random_envelope_key().unwrap();
        let pt = b"fake-pkcs8-der-crown-jewel";
        let blob = seal(&key, pt).unwrap();

        // Ciphertext is not the plaintext, and carries nonce(12)+tag(16) overhead.
        assert_ne!(&blob[NONCE_LEN..], pt);
        assert_eq!(blob.len(), NONCE_LEN + pt.len() + 16);
        assert_eq!(open(&key, &blob).unwrap(), pt);
    }

    #[test]
    fn fresh_nonce_per_seal_yields_distinct_ciphertext() {
        let key = random_envelope_key().unwrap();
        let pt = b"same-input";
        let a = seal(&key, pt).unwrap();
        let b = seal(&key, pt).unwrap();
        assert_ne!(a, b, "GCM nonce must be fresh per write");
    }

    #[test]
    fn wrong_key_fails_closed() {
        let k1 = random_envelope_key().unwrap();
        let k2 = random_envelope_key().unwrap();
        let blob = seal(&k1, b"secret").unwrap();
        assert!(open(&k2, &blob).is_err(), "wrong key must fail, not leak");
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let key = random_envelope_key().unwrap();
        let mut blob = seal(&key, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff; // flip a tag bit
        assert!(open(&key, &blob).is_err(), "tamper must fail the auth tag");
    }

    #[test]
    fn short_blob_fails_closed() {
        let key = random_envelope_key().unwrap();
        assert!(open(&key, b"x").is_err());
    }

    fn temp_store() -> (EncryptedFileKeyStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-encfileks-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        (EncryptedFileKeyStore::new(dir.clone()), dir)
    }

    #[test]
    fn store_roundtrips_key_and_cert_and_deletes() {
        let (ks, dir) = temp_store();
        assert_eq!(ks.tier(), KeyStoreTier::AppSandboxFile);
        assert!(ks.tier().is_production_grade());
        assert!(!ks.exists());
        assert!(ks.load_key().is_err(), "no key -> fail-closed");
        assert_eq!(ks.load_public_cert().unwrap(), None);

        ks.store_key(b"fake-pkcs8-der").unwrap();
        ks.store_public_cert(b"fake-cert-der").unwrap();
        assert!(ks.exists());
        assert_eq!(ks.load_key().unwrap(), b"fake-pkcs8-der");
        assert_eq!(ks.load_public_cert().unwrap().unwrap(), b"fake-cert-der");

        // On-disk key file is ciphertext, never the plaintext DER.
        let on_disk = std::fs::read(ks.enc_key_path()).unwrap();
        assert_ne!(on_disk, b"fake-pkcs8-der");

        ks.delete_key().unwrap();
        assert!(!ks.exists());
        assert!(ks.load_key().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reopen_with_persisted_envelope_decrypts() {
        // A second store over the same dir reuses the persisted envelope key.
        let (ks, dir) = temp_store();
        ks.store_key(b"persisted-der").unwrap();
        let ks2 = EncryptedFileKeyStore::new(dir.clone());
        assert_eq!(ks2.load_key().unwrap(), b"persisted-der");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_envelope_fails_closed_without_recreating() {
        // Ciphertext present but the envelope key transiently absent: load_key
        // must FAIL-CLOSED and must NOT recreate the envelope (recreating it
        // would permanently brick the existing ciphertext — the tag would never
        // verify again — and forecloses recovery once the file reappears).
        let (ks, dir) = temp_store();
        ks.store_key(b"der").unwrap();
        std::fs::remove_file(ks.envelope_path()).unwrap();
        assert!(ks.load_key().is_err(), "missing envelope -> fail-closed");
        assert!(
            !ks.envelope_path().is_file(),
            "load_key must NOT recreate the envelope on a read"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_and_envelope_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (ks, dir) = temp_store();
        ks.store_key(b"k").unwrap();
        for p in [ks.enc_key_path(), ks.envelope_path()] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{p:?} must be chmod 600");
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
