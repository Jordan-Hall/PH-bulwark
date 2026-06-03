//! Local, content-addressed store for blocked/borderline video segments so a
//! guardian can review the exact clip behind a decision.
//!
//! ## Hard safety boundary
//! Suspected **CSAM is NEVER written** — [`SegmentStore::store_if_safe`] rejects
//! [`Category::CsamSuspected`] **before any hashing or I/O**. This is the single
//! most important invariant in this module.
//!
//! ## Privacy
//! Everything here stays **local to the guardian's node**. The proto [`Evidence`]
//! keeps its no-raw-media invariant — raw clips NEVER ride the alert channel.
//! Segments are content-addressed by SHA-256 (`blob://<hex>`) and expire on a TTL
//! (a confirmed block is kept longer than a borderline warn/log). Only segments
//! tied to an actual decision are kept; benign `ALLOW` traffic is not stored.
//!
//! [`Evidence`]: aegis_proto::v1::Evidence

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_proto::v1::{Action, Category};

/// Retention for a confirmed blocking action (BLOCK/BLUR/MUTE) — guardians need
/// time to review and approve/deny.
const BLOCK_TTL_SECS: u64 = 7 * 24 * 3600;
/// Retention for a borderline-but-forwarded segment (WARN/LOG) — shorter.
const REVIEW_TTL_SECS: u64 = 2 * 24 * 3600;

/// A content-addressed local segment store rooted at a directory.
#[derive(Clone)]
pub struct SegmentStore {
    base: PathBuf,
}

/// A successfully stored segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSegment {
    /// `blob://<sha256-hex>` — the reference the guardian app resolves locally.
    pub uri: String,
    /// The lowercase hex SHA-256 of the segment bytes.
    pub sha256_hex: String,
}

impl SegmentStore {
    /// Open/create a store rooted at `base`.
    pub fn new(base: impl Into<PathBuf>) -> io::Result<Self> {
        let base = base.into();
        std::fs::create_dir_all(&base)?;
        Ok(Self { base })
    }

    /// Open the per-user default location
    /// (`%LOCALAPPDATA%/Aegis/segments`, `$XDG_DATA_HOME/aegis/segments`, …).
    pub fn default_location() -> io::Result<Self> {
        Self::new(default_segments_dir())
    }

    /// Store `segment` **iff it is safe + worth reviewing**. Returns `None` (no
    /// write) when `category == CsamSuspected` (the HARD BOUNDARY, checked before
    /// any I/O), when the `action` is benign (`ALLOW`/unspecified — nothing to
    /// review), or when `segment` is empty. BLOCK/BLUR/MUTE are kept for
    /// [`BLOCK_TTL_SECS`]; WARN/LOG for [`REVIEW_TTL_SECS`].
    pub fn store_if_safe(
        &self,
        category: Category,
        action: Action,
        segment: &[u8],
    ) -> io::Result<Option<StoredSegment>> {
        // HARD BOUNDARY: suspected CSAM is never persisted — block + hash only.
        if category == Category::CsamSuspected {
            return Ok(None);
        }
        let ttl = match action {
            Action::Block | Action::Blur | Action::Mute => BLOCK_TTL_SECS,
            Action::Warn | Action::Log => REVIEW_TTL_SECS,
            // ALLOW / UNSPECIFIED: benign, not retained (don't archive the stream).
            _ => return Ok(None),
        };
        if segment.is_empty() {
            return Ok(None);
        }

        let sha = sha256_hex(segment);
        let blob = self.base.join(format!("{sha}.blob"));
        let meta = self.base.join(format!("{sha}.meta"));
        if !blob.exists() {
            std::fs::write(&blob, segment)?;
        }
        // meta: creation-ts + ttl (seconds), one per line — enough for purge.
        std::fs::write(&meta, format!("{}\n{}\n", now_secs(), ttl))?;
        Ok(Some(StoredSegment {
            uri: format!("blob://{sha}"),
            sha256_hex: sha,
        }))
    }

    /// Load a stored segment by `blob://<sha256-hex>`. `None` if absent/purged or
    /// the URI is malformed.
    pub fn load(&self, uri: &str) -> io::Result<Option<Vec<u8>>> {
        let Some(sha) = parse_blob_uri(uri) else {
            return Ok(None);
        };
        match std::fs::read(self.base.join(format!("{sha}.blob"))) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Delete segments whose TTL has elapsed. Returns the number purged.
    pub fn purge_expired(&self) -> io::Result<usize> {
        let now = now_secs();
        let mut purged = 0;
        for entry in std::fs::read_dir(&self.base)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("meta") {
                continue;
            }
            if let Some((ts, ttl)) = read_meta(&path) {
                if now > ts.saturating_add(ttl) {
                    let _ = std::fs::remove_file(path.with_extension("blob"));
                    let _ = std::fs::remove_file(&path);
                    purged += 1;
                }
            }
        }
        Ok(purged)
    }
}

/// Validate + extract the hex from a `blob://<sha256-hex>` URI.
fn parse_blob_uri(uri: &str) -> Option<String> {
    let sha = uri.strip_prefix("blob://")?;
    (sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit())).then(|| sha.to_string())
}

fn read_meta(path: &Path) -> Option<(u64, u64)> {
    let s = std::fs::read_to_string(path).ok()?;
    let mut lines = s.lines();
    let ts = lines.next()?.trim().parse().ok()?;
    let ttl = lines.next()?.trim().parse().ok()?;
    Some((ts, ttl))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut s = String::with_capacity(64);
    for b in d.as_ref() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn default_segments_dir() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|s| !s.is_empty()) {
        return PathBuf::from(local).join("Aegis").join("segments");
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|s| !s.is_empty()) {
        return PathBuf::from(xdg).join("aegis").join("segments");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        return PathBuf::from(home).join(".local/share/aegis/segments");
    }
    std::env::temp_dir().join("aegis-segments")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(tag: &str) -> SegmentStore {
        let dir = std::env::temp_dir().join(format!(
            "aegis-seg-test-{}-{}-{}",
            tag,
            std::process::id(),
            now_secs()
        ));
        SegmentStore::new(dir).expect("create store")
    }

    #[test]
    fn csam_is_never_stored() {
        let s = tmp_store("csam");
        let out = s
            .store_if_safe(Category::CsamSuspected, Action::Block, b"explicit-bytes")
            .unwrap();
        assert!(out.is_none(), "CSAM must never be persisted");
    }

    #[test]
    fn blocked_segment_round_trips() {
        let s = tmp_store("block");
        let bytes = b"a blocked adult clip";
        let stored = s
            .store_if_safe(Category::AdultImage, Action::Block, bytes)
            .unwrap()
            .expect("non-CSAM block is stored");
        assert!(stored.uri.starts_with("blob://"));
        let loaded = s.load(&stored.uri).unwrap().expect("loads back");
        assert_eq!(loaded, bytes);
    }

    #[test]
    fn benign_allow_is_not_stored() {
        let s = tmp_store("allow");
        let out = s
            .store_if_safe(Category::Safe, Action::Allow, b"benign")
            .unwrap();
        assert!(out.is_none(), "benign ALLOW traffic is not archived");
    }

    #[test]
    fn empty_segment_is_not_stored() {
        let s = tmp_store("empty");
        assert!(s
            .store_if_safe(Category::AdultImage, Action::Block, b"")
            .unwrap()
            .is_none());
    }

    #[test]
    fn purge_removes_expired() {
        let s = tmp_store("purge");
        let stored = s
            .store_if_safe(Category::AdultImage, Action::Block, b"clip")
            .unwrap()
            .unwrap();
        // Backdate the meta so it's already expired.
        let meta = s.base.join(format!("{}.meta", stored.sha256_hex));
        std::fs::write(&meta, "0\n1\n").unwrap();
        assert_eq!(s.purge_expired().unwrap(), 1);
        assert!(s.load(&stored.uri).unwrap().is_none(), "purged blob is gone");
    }

    #[test]
    fn malformed_uri_loads_none() {
        let s = tmp_store("bad");
        assert!(s.load("blob://not-hex").unwrap().is_none());
        assert!(s.load("http://x").unwrap().is_none());
    }
}
