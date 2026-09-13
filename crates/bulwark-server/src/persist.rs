//! Optional JSON durability for guardian/server state.
//!
//! Writes are atomic (unique temp + fsync + rename). Development keeps the
//! historical tolerant load/write behavior, but production treats durable state
//! as an authority: a present corrupt file or failed write terminates the process
//! rather than continuing with state that can disappear on restart.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{de::DeserializeOwned, Serialize};

/// Handle to one JSON document in `BULWARK_STATE_DIR`.
#[derive(Clone, Debug)]
pub struct JsonFile {
    path: PathBuf,
}

impl JsonFile {
    /// Open a state document, creating/protecting its parent directory.
    pub fn new(dir: &Path, name: &str) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            path: dir.join(name),
        })
    }

    /// Load state, returning the type default only when the document is absent.
    /// Outside production unreadable/corrupt files retain legacy tolerant
    /// behavior; production aborts because silently empty authority state can
    /// revoke protections, identities or approvals.
    pub fn load_or_default<T: DeserializeOwned + Default>(&self) -> T {
        match self.load_strict() {
            Ok(Some(value)) => value,
            Ok(None) => T::default(),
            Err(error) => {
                if production_mode() {
                    fatal_state(
                        &self.path,
                        &format!("durable state cannot be loaded: {error}"),
                    );
                }
                tracing::warn!(path = %self.path.display(), %error, "state file unreadable/corrupt; development is starting empty");
                T::default()
            }
        }
    }

    /// Strict load: absent is `Ok(None)`; a present unreadable or corrupt file is
    /// an error.
    pub fn load_strict<T: DeserializeOwned>(&self) -> io::Result<Option<T>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Atomically persist one complete snapshot. In production a failed durable
    /// write terminates the process before callers can acknowledge a mutation that
    /// would be lost after restart.
    pub fn store<T: Serialize>(&self, value: &T) -> io::Result<()> {
        let result = self.store_inner(value);
        if let Err(error) = &result {
            if production_mode() {
                fatal_state(
                    &self.path,
                    &format!("durable state cannot be written: {error}"),
                );
            }
        }
        result
    }

    fn store_inner<T: Serialize>(&self, value: &T) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let temp = self.path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        {
            #[cfg(unix)]
            let mut file = {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&temp)?
            };
            #[cfg(not(unix))]
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&temp, &self.path)?;
        sync_parent(&self.path)?;
        Ok(())
    }
}

fn production_mode() -> bool {
    matches!(
        std::env::var("BULWARK_PRODUCTION").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn fatal_state(path: &Path, detail: &str) -> ! {
    tracing::error!(path = %path.display(), detail, "fatal durable-state integrity failure");
    eprintln!(
        "fatal durable-state integrity failure at {}: {detail}",
        path.display()
    );
    std::process::abort()
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-persist-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn round_trip_is_atomic_and_clean() {
        let dir = temp_dir("roundtrip");
        let file = JsonFile::new(&dir, "data.json").unwrap();
        let mut data = HashMap::new();
        data.insert("a".to_string(), 1u32);
        file.store(&data).unwrap();
        let loaded: HashMap<String, u32> = file.load_or_default();
        assert_eq!(loaded.get("a"), Some(&1));
        assert!(std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp.")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_is_default_and_corrupt_is_strict_error() {
        let dir = temp_dir("strict");
        let file = JsonFile::new(&dir, "state.json").unwrap();
        let empty: HashMap<String, u32> = file.load_or_default();
        assert!(empty.is_empty());
        std::fs::write(dir.join("state.json"), b"not-json").unwrap();
        assert!(file.load_strict::<HashMap<String, u32>>().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
