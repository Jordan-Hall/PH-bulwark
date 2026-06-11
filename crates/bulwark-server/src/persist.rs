//! Optional file-backed durability for the in-memory guardian stores.
//!
//! std + serde_json only — **no** rusqlite/sled (rusqlite does not build on this
//! host, env error 4551). Opt in by pointing `BULWARK_STATE_DIR` /
//! [`ServerConfig::state_dir`](crate::ServerConfig) at a directory; unset = pure
//! in-memory (the default, unchanged behaviour).
//!
//! Durability guarantees:
//! - **Atomic write**: serialize → write a unique temp file → `fsync` → `rename`
//!   over the target. A crash mid-write leaves the previous good file intact.
//! - **Corruption-safe load**: a missing OR unparseable file yields `T::default()`
//!   with a logged warning — never a panic. A bad state file can't crash startup.
//!
//! Persisted data is **content-free** (KDF hashes, ids, hosts) — never plaintext
//! passwords, raw media, or message text.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{de::DeserializeOwned, Serialize};

/// A handle to one JSON document on disk. Cheap to clone (just a path).
#[derive(Clone, Debug)]
pub struct JsonFile {
    path: PathBuf,
}

impl JsonFile {
    /// `dir` is the state directory; `name` the file (e.g. `"accounts.json"`).
    /// Creates `dir` if missing — the only fatal error (an unusable directory
    /// means the operator asked for persistence we genuinely can't provide).
    pub fn new(dir: &Path, name: &str) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        // Guardian state (KDF hashes, session digests, child configs) is
        // operator-only: tighten the dir to 700 on unix (no-op elsewhere).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            path: dir.join(name),
        })
    }

    /// Load + deserialize, or `T::default()` when the file is absent OR corrupt.
    /// A parse failure is logged and treated as empty so a bad file is never fatal.
    pub fn load_or_default<T: DeserializeOwned + Default>(&self) -> T {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return T::default(),
            Err(e) => {
                tracing::warn!(path = %self.path.display(), error = %e,
                    "could not read state file; starting empty");
                return T::default();
            }
        };
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %self.path.display(), error = %e,
                    "state file is corrupt/unparseable; starting empty");
                T::default()
            }
        }
    }

    /// Atomically persist `value` (temp file + fsync + rename). Returns the
    /// `io::Error` on failure; callers log and continue in-memory (never panic).
    pub fn store<T: Serialize>(&self, value: &T) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        // Unique temp name so two concurrent writers don't clobber one tmp before
        // the rename; the final rename is last-writer-wins (each writer persisted a
        // full, lock-consistent snapshot, so that's correct).
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp = self.path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        {
            // 600 from creation on unix (rename preserves it) — the state JSONs
            // hold KDF hashes + session digests and are operator/service-only.
            #[cfg(unix)]
            let mut f = {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)?
            };
            #[cfg(not(unix))]
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bulwark-persist-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn round_trips_and_overwrites_cleanly() {
        let dir = tmp_dir("roundtrip");
        let f = JsonFile::new(&dir, "data.json").unwrap();
        let mut m = HashMap::new();
        m.insert("a".to_string(), 1u32);
        f.store(&m).unwrap();
        let back: HashMap<String, u32> = f.load_or_default();
        assert_eq!(back.get("a"), Some(&1));

        // Overwrite + no stray .tmp left behind.
        m.insert("b".to_string(), 2);
        f.store(&m).unwrap();
        let back: HashMap<String, u32> = f.load_or_default();
        assert_eq!(back.len(), 2);
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            strays.is_empty(),
            "no temp files should remain after rename"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_default() {
        let dir = tmp_dir("missing");
        let f = JsonFile::new(&dir, "nope.json").unwrap();
        let v: HashMap<String, u32> = f.load_or_default();
        assert!(v.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_file_is_default_not_panic() {
        let dir = tmp_dir("corrupt");
        std::fs::write(dir.join("bad.json"), b"{ not valid json").unwrap();
        let f = JsonFile::new(&dir, "bad.json").unwrap();
        let v: HashMap<String, u32> = f.load_or_default(); // must NOT panic
        assert!(v.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
