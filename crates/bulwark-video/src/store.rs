//! Owner-scoped local review-segment storage.
//!
//! Production defaults to **no raw-media retention**. Operators must explicitly
//! opt in with `BULWARK_RETAIN_REVIEW_CLIPS=1`; when enabled every retained clip
//! is bound to the originating device/family metadata and is expiry-checked on
//! every read. Suspected CSAM is never written under any mode.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bulwark_proto::v1::{Action, Category};

const BLOCK_TTL_SECS: u64 = 24 * 3600;
const REVIEW_TTL_SECS: u64 = 6 * 3600;
const LEGACY_OWNER: &str = "__legacy_dev_only__";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionMode {
    Disabled,
    Scoped,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SegmentOwner {
    pub device_id: String,
    pub child_id: String,
    pub family_id: String,
    pub alert_id: String,
}

impl SegmentOwner {
    pub fn for_device(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            ..Self::default()
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.device_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "retained segment requires device ownership",
            ));
        }
        for value in [
            self.device_id.as_str(),
            self.child_id.as_str(),
            self.family_id.as_str(),
            self.alert_id.as_str(),
        ] {
            if value.chars().any(|c| c == '\n' || c == '\r') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "segment ownership metadata contains a newline",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SegmentStore {
    base: PathBuf,
    retention: RetentionMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSegment {
    pub uri: String,
    pub sha256_hex: String,
    pub device_id: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
struct SegmentMeta {
    created_at: u64,
    ttl_secs: u64,
    device_id: String,
    child_id: String,
    family_id: String,
    alert_id: String,
}

impl SegmentMeta {
    fn expires_at(&self) -> u64 {
        self.created_at.saturating_add(self.ttl_secs)
    }

    fn expired(&self, now: u64) -> bool {
        now >= self.expires_at()
    }
}

impl SegmentStore {
    /// Explicit/dev constructor. Retention is enabled because the caller chose a
    /// concrete path. Production composition should use [`Self::default_location`].
    pub fn new(base: impl Into<PathBuf>) -> io::Result<Self> {
        Self::new_with_mode(base, RetentionMode::Scoped)
    }

    pub fn new_with_mode(base: impl Into<PathBuf>, retention: RetentionMode) -> io::Result<Self> {
        let base = base.into();
        std::fs::create_dir_all(&base)?;
        harden_dir_permissions(&base)?;
        Ok(Self { base, retention })
    }

    /// Production constructor: raw review clips are disabled unless the operator
    /// explicitly opts in. This makes privacy-safe, content-free alerts the
    /// default deployment behavior.
    pub fn default_location() -> io::Result<Self> {
        let enabled = matches!(
            std::env::var("BULWARK_RETAIN_REVIEW_CLIPS").ok().as_deref(),
            Some("1") | Some("true") | Some("yes")
        );
        Self::new_with_mode(
            default_segments_dir(),
            if enabled {
                RetentionMode::Scoped
            } else {
                RetentionMode::Disabled
            },
        )
    }

    pub fn retention_mode(&self) -> RetentionMode {
        self.retention
    }

    /// Compatibility helper for local tests/tools. Product code should call
    /// [`Self::store_scoped_if_allowed`] so an authenticated device owns the clip.
    pub fn store_if_safe(
        &self,
        category: Category,
        action: Action,
        segment: &[u8],
    ) -> io::Result<Option<StoredSegment>> {
        self.store_scoped_if_allowed(
            &SegmentOwner::for_device(LEGACY_OWNER),
            category,
            action,
            segment,
        )
    }

    pub fn store_scoped_if_allowed(
        &self,
        owner: &SegmentOwner,
        category: Category,
        action: Action,
        segment: &[u8],
    ) -> io::Result<Option<StoredSegment>> {
        if category == Category::CsamSuspected || self.retention == RetentionMode::Disabled {
            return Ok(None);
        }
        let ttl_secs = match action {
            Action::Block | Action::Blur | Action::Mute => BLOCK_TTL_SECS,
            Action::Warn | Action::Log => REVIEW_TTL_SECS,
            _ => return Ok(None),
        };
        if segment.is_empty() {
            return Ok(None);
        }
        owner.validate()?;

        let sha = sha256_hex(segment);
        let created_at = now_secs();
        let metadata = SegmentMeta {
            created_at,
            ttl_secs,
            device_id: owner.device_id.trim().to_string(),
            child_id: owner.child_id.trim().to_string(),
            family_id: owner.family_id.trim().to_string(),
            alert_id: owner.alert_id.trim().to_string(),
        };

        // Never overwrite an existing object through a symlink. Metadata is
        // owner-specific, so identical bytes belonging to different devices do
        // not share an authorization handle.
        let opaque = opaque_id(&sha, &metadata);
        let blob = self.base.join(format!("{opaque}.blob"));
        let meta = self.base.join(format!("{opaque}.meta"));
        write_new_private(&blob, segment)?;
        write_new_private(&meta, render_meta(&metadata).as_bytes())?;

        Ok(Some(StoredSegment {
            uri: format!("blob://{opaque}"),
            sha256_hex: sha,
            device_id: metadata.device_id,
            expires_at: metadata.expires_at(),
        }))
    }

    /// Legacy/dev full read. Production Review must use [`Self::open_authorized`].
    pub fn load(&self, uri: &str) -> io::Result<Option<Vec<u8>>> {
        let Some(id) = parse_blob_uri(uri) else {
            return Ok(None);
        };
        let Some(meta) = self.read_live_meta(&id)? else {
            return Ok(None);
        };
        if meta.device_id != LEGACY_OWNER {
            return Ok(None);
        }
        match std::fs::read(self.base.join(format!("{id}.blob"))) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Authorize before opening bytes. `allowed_device_ids` comes from the live
    /// guardian session scope; ownership is checked from server-written metadata,
    /// never from a request-supplied device id.
    pub fn open_authorized(
        &self,
        uri: &str,
        allowed_device_ids: &HashSet<String>,
    ) -> io::Result<Option<File>> {
        if self.retention == RetentionMode::Disabled {
            return Ok(None);
        }
        let Some(id) = parse_blob_uri(uri) else {
            return Ok(None);
        };
        let Some(meta) = self.read_live_meta(&id)? else {
            return Ok(None);
        };
        if meta.device_id == LEGACY_OWNER || !allowed_device_ids.contains(&meta.device_id) {
            return Ok(None);
        }
        match File::open(self.base.join(format!("{id}.blob"))) {
            Ok(file) => Ok(Some(file)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn purge_expired(&self) -> io::Result<usize> {
        let now = now_secs();
        let mut purged = 0;
        for entry in std::fs::read_dir(&self.base)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("meta") {
                continue;
            }
            let expired = read_meta(&path).map(|m| m.expired(now)).unwrap_or(true);
            if expired {
                let _ = std::fs::remove_file(path.with_extension("blob"));
                let _ = std::fs::remove_file(&path);
                purged += 1;
            }
        }
        Ok(purged)
    }

    fn read_live_meta(&self, id: &str) -> io::Result<Option<SegmentMeta>> {
        let path = self.base.join(format!("{id}.meta"));
        let meta = match read_meta(&path) {
            Some(meta) => meta,
            None => return Ok(None),
        };
        if meta.expired(now_secs()) {
            let _ = std::fs::remove_file(self.base.join(format!("{id}.blob")));
            let _ = std::fs::remove_file(path);
            return Ok(None);
        }
        Ok(Some(meta))
    }
}

fn opaque_id(sha: &str, meta: &SegmentMeta) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(sha.as_bytes());
    material.extend_from_slice(meta.device_id.as_bytes());
    material.extend_from_slice(meta.child_id.as_bytes());
    material.extend_from_slice(meta.family_id.as_bytes());
    material.extend_from_slice(meta.alert_id.as_bytes());
    material.extend_from_slice(&meta.created_at.to_le_bytes());
    sha256_hex(&material)
}

fn render_meta(meta: &SegmentMeta) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        meta.created_at,
        meta.ttl_secs,
        meta.device_id,
        meta.child_id,
        meta.family_id,
        meta.alert_id
    )
}

fn parse_blob_uri(uri: &str) -> Option<String> {
    let id = uri.strip_prefix("blob://")?;
    (id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_ascii_lowercase())
}

fn read_meta(path: &Path) -> Option<SegmentMeta> {
    let s = std::fs::read_to_string(path).ok()?;
    let mut lines = s.lines();
    Some(SegmentMeta {
        created_at: lines.next()?.trim().parse().ok()?,
        ttl_secs: lines.next()?.trim().parse().ok()?,
        device_id: lines.next()?.to_string(),
        child_id: lines.next().unwrap_or_default().to_string(),
        family_id: lines.next().unwrap_or_default().to_string(),
        alert_id: lines.next().unwrap_or_default().to_string(),
    })
}

fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(path)?;
            if !meta.file_type().is_file() || meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing non-regular retained-media path",
                ));
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn harden_dir_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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
        return PathBuf::from(local).join("Bulwark").join("segments");
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|s| !s.is_empty()) {
        return PathBuf::from(xdg).join("bulwark").join("segments");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        return PathBuf::from(home).join(".local/share/bulwark/segments");
    }
    std::env::temp_dir().join("bulwark-segments")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(tag: &str) -> SegmentStore {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-seg-test-{}-{}-{}",
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
        assert!(out.is_none());
    }

    #[test]
    fn legacy_dev_round_trip_is_explicit() {
        let s = tmp_store("block");
        let bytes = b"a blocked adult clip";
        let stored = s
            .store_if_safe(Category::AdultImage, Action::Block, bytes)
            .unwrap()
            .expect("dev store retains");
        assert_eq!(s.load(&stored.uri).unwrap().unwrap(), bytes);
    }

    #[test]
    fn scoped_clip_rejects_wrong_guardian_device_scope() {
        let s = tmp_store("scope");
        let owner = SegmentOwner::for_device("child-device-a");
        let stored = s
            .store_scoped_if_allowed(&owner, Category::AdultImage, Action::Block, b"clip")
            .unwrap()
            .unwrap();
        let mut wrong = HashSet::new();
        wrong.insert("child-device-b".to_string());
        assert!(s.open_authorized(&stored.uri, &wrong).unwrap().is_none());
        let mut right = HashSet::new();
        right.insert("child-device-a".to_string());
        assert!(s.open_authorized(&stored.uri, &right).unwrap().is_some());
    }

    #[test]
    fn disabled_store_never_writes() {
        let dir = std::env::temp_dir().join(format!("bulwark-disabled-{}", std::process::id()));
        let s = SegmentStore::new_with_mode(dir, RetentionMode::Disabled).unwrap();
        assert!(s
            .store_scoped_if_allowed(
                &SegmentOwner::for_device("d"),
                Category::AdultImage,
                Action::Block,
                b"clip"
            )
            .unwrap()
            .is_none());
    }
}
