//! File-persisted [`CaKeyStore`] — the Android per-install CA tier.
//!
//! Android has no DPAPI; the real Android Keystore/TEE-wrapped signer is the
//! documented follow-up ([`KeyStoreTier::HardwareNonExportable`]). Until then the
//! per-install CA key must still SURVIVE across VPN sessions — a per-session
//! in-memory CA resets user trust and pinning learning every restart (audit
//! 2026-06-10, Med). This store writes the PKCS#8 DER under an APP-PRIVATE
//! directory (the Kotlin side passes `filesDir/ca`), `0600`/dir `0700` on unix.
//!
//! HONEST LIMITATION: the key is plaintext AT REST inside the app sandbox. The
//! sandbox (per-UID isolation) is the protection boundary; this is deliberately
//! surfaced as [`KeyStoreTier::AppSandboxFile`] so audit/UI never overstate it.

use std::path::PathBuf;

use super::keystore::{CaKeyStore, KeyStoreTier};
use crate::{NetError, Result};

const KEY_FILE: &str = "ca_key.der";
const CERT_FILE: &str = "ca_cert.der";

/// App-sandbox file keystore (see module docs). Construct with the app-private
/// directory the platform shell owns (Android: `filesDir/ca`).
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    /// Keystore rooted at `dir` (the platform shell's app-private directory;
    /// Android passes `filesDir/ca`). The directory is created on first write.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join(KEY_FILE)
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join(CERT_FILE)
    }

    fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| NetError::keystore(format!("create CA dir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Owner-only directory; best-effort (the app-private dir already is).
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }
}

impl CaKeyStore for FileKeyStore {
    fn tier(&self) -> KeyStoreTier {
        KeyStoreTier::AppSandboxFile
    }

    fn exists(&self) -> bool {
        self.key_path().is_file()
    }

    fn store_key(&self, key_der: &[u8]) -> Result<()> {
        self.ensure_dir()?;
        let path = self.key_path();
        std::fs::write(&path, key_der)
            .map_err(|e| NetError::keystore(format!("write CA key: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| NetError::keystore(format!("chmod 600 CA key: {e}")))?;
        }
        Ok(())
    }

    fn load_key(&self) -> Result<Vec<u8>> {
        // Absent/unreadable key is FAIL-CLOSED upstream (CaManager::load).
        std::fs::read(self.key_path())
            .map_err(|e| NetError::keystore(format!("no CA key present (file store): {e}")))
    }

    fn delete_key(&self) -> Result<()> {
        let path = self.key_path();
        if path.is_file() {
            // Best-effort overwrite before unlink (cheap hygiene, not a secure-
            // erase guarantee on flash storage — documented limitation).
            if let Ok(meta) = std::fs::metadata(&path) {
                let _ = std::fs::write(&path, vec![0u8; meta.len() as usize]);
            }
            std::fs::remove_file(&path)
                .map_err(|e| NetError::keystore(format!("delete CA key: {e}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (FileKeyStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-fileks-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        (FileKeyStore::new(dir.clone()), dir)
    }

    #[test]
    fn roundtrips_key_and_cert_and_deletes() {
        let (ks, dir) = temp_store();
        assert_eq!(ks.tier(), KeyStoreTier::AppSandboxFile);
        assert!(ks.tier().is_production_grade(), "sandbox tier is accepted");
        assert!(!ks.exists());
        assert!(ks.load_key().is_err(), "no key -> fail-closed error");
        assert_eq!(ks.load_public_cert().unwrap(), None);

        ks.store_key(b"fake-pkcs8-der").unwrap();
        ks.store_public_cert(b"fake-cert-der").unwrap();
        assert!(ks.exists());
        assert_eq!(ks.load_key().unwrap(), b"fake-pkcs8-der");
        assert_eq!(ks.load_public_cert().unwrap().unwrap(), b"fake-cert-der");

        ks.delete_key().unwrap();
        assert!(!ks.exists());
        assert!(ks.load_key().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (ks, dir) = temp_store();
        ks.store_key(b"k").unwrap();
        let mode = std::fs::metadata(ks.key_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "CA key must be chmod 600");
        let _ = std::fs::remove_dir_all(dir);
    }
}
