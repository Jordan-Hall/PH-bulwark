//! Owner-scoped local review-segment storage.
//!
//! Production defaults to no raw-media retention. Operators explicitly opt in
//! with `BULWARK_RETAIN_REVIEW_CLIPS=1`. Every retained object is bound to its
//! originating supervised device, expiry is enforced at read time, files are
//! private, and suspected CSAM is never persisted.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bulwark_proto::v1::{Action, Category};

const BLOCK_TTL_SECS: u64 = 24 * 60 * 60;
const REVIEW_TTL_SECS: u64 = 6 * 60 * 60;
const LEGACY_OWNER: &str = "__legacy_dev_only__";

/// Whether local raw review clips may be retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionMode {
    /// Never write raw media.
    Disabled,
    /// Retain only review-worthy media with an owner + TTL.
    Scoped,
}

/// Server-written ownership facts for one retained segment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SegmentOwner {
    /// Authenticated supervised-device id.
    pub device_id: String,
    /// Child id, when known.
    pub child_id: String,
    /// Family id, when known.
    pub family_id: String,
    /// Alert/request id that caused retention.
    pub alert_id: String,
}

impl SegmentOwner {
    /// Build the minimum scoped owner for a device.
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
            if value.chars().any(|c| matches!(c, '\r' | '\n')) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "segment ownership metadata contains a newline",
                ));
            }
        }
        Ok(())
    }
}

/// Local content-addressed review store.
#[derive(Clone)]
pub struct SegmentStore {
    base: PathBuf,
    retention: RetentionMode,
}

/// Reference returned after a successful retained-media write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSegment {
    /// Opaque `blob://` handle; not the content hash.
    pub uri: String,
    /// SHA-256 of the original bytes for audit/dedup.
    pub sha256_hex: String,
    /// Authenticated owning supervised device.
    pub device_id: String,
    /// Absolute unix-seconds expiry.
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
    /// Explicit/dev constructor. Choosing a path opts into scoped retention.
    pub fn new(base: impl Into<PathBuf>) -> io::Result<Self> {
        Self::new_with_mode(base, RetentionMode::Scoped)
    }

    /// Construct at `base` with an explicit retention mode.
    pub fn new_with_mode(base: impl Into<PathBuf>, retention: RetentionMode) -> io::Result<Self> {
        let base = base.into();
        std::fs::create_dir_all(&base)?;
        harden_dir_permissions(&base)?;
        Ok(Self { base, retention })
    }

    /// Per-user production location. Raw retention is disabled unless explicitly
    /// enabled by `BULWARK_RETAIN_REVIEW_CLIPS=1`.
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

    /// Current retention mode.
    pub fn retention_mode(&self) -> RetentionMode {
        self.retention
    }

    /// Legacy/dev helper. Product code should use `store_scoped_if_allowed`.
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

    /// Retain a non-CSAM segment only when the policy action makes it reviewable.
    pub fn store_scoped_if_allowed(
        &self,
        owner: &SegmentOwner,
        category: Category,
        action: Action,
        segment: &[u8],
    ) -> io::Result<Option<StoredSegment>> {
        if self.retention == RetentionMode::Disabled || category == Category::CsamSuspected {
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

        let sha256_hex = sha256_hex(segment);
        let metadata = SegmentMeta {
            created_at: now_secs(),
            ttl_secs,
            device_id: owner.device_id.trim().to_owned(),
            child_id: owner.child_id.trim().to_owned(),
            family_id: owner.family_id.trim().to_owned(),
            alert_id: owner.alert_id.trim().to_owned(),
        };
        let expires_at = metadata.expires_at();
        let device_id = metadata.device_id.clone();
        let opaque = opaque_id(&sha256_hex, &metadata);
        write_new_private(&self.base.join(format!("{opaque}.blob")), segment)?;
        write_new_private(
            &self.base.join(format!("{opaque}.meta")),
            render_meta(&metadata).as_bytes(),
        )?;

        Ok(Some(StoredSegment {
            uri: format!("blob://{opaque}"),
            sha256_hex,
            device_id,
            expires_at,
        }))
    }

    /// Legacy/dev read. Scoped product media deliberately cannot be read through
    /// this method.
    pub fn load(&self, uri: &str) -> io::Result<Option<Vec<u8>>> {
        let Some(id) = parse_blob_uri(uri) else {
            return Ok(None);
        };
        let Some(metadata) = self.read_live_meta(&id)? else {
            return Ok(None);
        };
        if metadata.device_id != LEGACY_OWNER {
            return Ok(None);
        }
        read_optional(self.base.join(format!("{id}.blob")))
    }

    /// Open a retained clip only after checking server-written ownership against
    /// the authenticated guardian's live device scope.
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
        let Some(metadata) = self.read_live_meta(&id)? else {
            return Ok(None);
        };
        if metadata.device_id == LEGACY_OWNER
            || !allowed_device_ids.contains(metadata.device_id.as_str())
        {
            return Ok(None);
        }
        match File::open(self.base.join(format!("{id}.blob"))) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Purge expired or malformed retained objects.
    pub fn purge_expired(&self) -> io::Result<usize> {
        let now = now_secs();
        let mut purged = 0;
        for entry in std::fs::read_dir(&self.base)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("meta") {
                continue;
            }
            if read_meta(&path).map(|m| m.expired(now)).unwrap_or(true) {
                let _ = std::fs::remove_file(path.with_extension("blob"));
                let _ = std::fs::remove_file(&path);
                purged += 1;
            }
        }
        Ok(purged)
    }

    fn read_live_meta(&self, id: &str) -> io::Result<Option<SegmentMeta>> {
        let path = self.base.join(format!("{id}.meta"));
        let Some(metadata) = read_meta(&path) else {
            return Ok(None);
        };
        if metadata.expired(now_secs()) {
            let _ = std::fs::remove_file(self.base.join(format!("{id}.blob")));
            let _ = std::fs::remove_file(path);
            return Ok(None);
        }
        Ok(Some(metadata))
    }
}

fn read_optional(path: PathBuf) -> io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn opaque_id(sha: &str, metadata: &SegmentMeta) -> String {
    let mut material = Vec::with_capacity(sha.len() + 128);
    material.extend_from_slice(sha.as_bytes());
    material.extend_from_slice(metadata.device_id.as_bytes());
    material.extend_from_slice(metadata.child_id.as_bytes());
    material.extend_from_slice(metadata.family_id.as_bytes());
    material.extend_from_slice(metadata.alert_id.as_bytes());
    material.extend_from_slice(&metadata.created_at.to_le_bytes());
    sha256_hex(&material)
}

fn render_meta(metadata: &SegmentMeta) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        metadata.created_at,
        metadata.ttl_secs,
        metadata.device_id,
        metadata.child_id,
        metadata.family_id,
        metadata.alert_id
    )
}

fn parse_blob_uri(uri: &str) -> Option<String> {
    let id = uri.strip_prefix("blob://")?;
    (id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_ascii_lowercase())
}

fn read_meta(path: &Path) -> Option<SegmentMeta> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    Some(SegmentMeta {
        created_at: lines.next()?.trim().parse().ok()?,
        ttl_secs: lines.next()?.trim().parse().ok()?,
        device_id: lines.next()?.to_owned(),
        child_id: lines.next().unwrap_or_default().to_owned(),
        family_id: lines.next().unwrap_or_default().to_owned(),
        alert_id: lines.next().unwrap_or_default().to_owned(),
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
            file.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing non-regular retained-media path",
                ));
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn harden_dir_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_ref() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn default_segments_dir() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        return PathBuf::from(local).join("Bulwark").join("segments");
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg).join("bulwark").join("segments");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join(".local/share/bulwark/segments");
    }
    std::env::temp_dir().join("bulwark-segments")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(tag: &str) -> SegmentStore {
        SegmentStore::new(std::env::temp_dir().join(format!(
            "bulwark-segment-{tag}-{}-{}",
            std::process::id(),
            now_secs()
        )))
        .unwrap()
    }

    #[test]
    fn csam_is_never_stored() {
        assert!(store("csam")
            .store_if_safe(Category::CsamSuspected, Action::Block, b"bytes")
            .unwrap()
            .is_none());
    }

    #[test]
    fn explicit_dev_store_round_trips() {
        let store = store("legacy");
        let stored = store
            .store_if_safe(Category::AdultImage, Action::Block, b"clip")
            .unwrap()
            .unwrap();
        assert_eq!(store.load(&stored.uri).unwrap().unwrap(), b"clip");
    }

    #[test]
    fn scoped_read_checks_guardian_device_scope() {
        let store = store("scope");
        let stored = store
            .store_scoped_if_allowed(
                &SegmentOwner::for_device("device-a"),
                Category::AdultImage,
                Action::Block,
                b"clip",
            )
            .unwrap()
            .unwrap();

        let wrong = HashSet::from(["device-b".to_string()]);
        assert!(store
            .open_authorized(&stored.uri, &wrong)
            .unwrap()
            .is_none());

        let right = HashSet::from(["device-a".to_string()]);
        assert!(store
            .open_authorized(&stored.uri, &right)
            .unwrap()
            .is_some());
    }

    #[test]
    fn disabled_store_never_writes_media() {
        let dir = std::env::temp_dir().join(format!("bulwark-disabled-{}", std::process::id()));
        let store = SegmentStore::new_with_mode(dir, RetentionMode::Disabled).unwrap();
        assert!(store
            .store_scoped_if_allowed(
                &SegmentOwner::for_device("device"),
                Category::AdultImage,
                Action::Block,
                b"clip",
            )
            .unwrap()
            .is_none());
    }
}
