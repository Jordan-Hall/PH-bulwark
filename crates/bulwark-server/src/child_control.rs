//! ChildControl — parent-set, child-applied runtime config (the remote "VPN
//! switch": region/server, filtering on/off, strictness band).
//!
//! CONTENT-FREE: this carries policy + routing only, never message/media text.
//!
//! AUTH / SCOPING (same model as [`crate::relay::ReviewService`] and
//! [`crate::accounts`]):
//!   * `SetChildConfig` is GUARDIAN-authenticated — a session token (explicit
//!     field OR `authorization: Bearer <token>` metadata) resolved through
//!     [`AccountStore::guardian_scope`]; the caller MUST guard the target child
//!     (`child_id` in their [`GuardianScope`]). The server stamps the monotonic
//!     `config_version` (starts at 1, +1 per change), `updated_ts`, and
//!     `updated_by` (the guardian's account id) — clients cannot forge these.
//!   * `GetChildConfig` / `StreamChildConfig` resolve the child by `device_id`
//!     (the child identifies by its own device identity / mTLS subject) and need
//!     no guardian token — a child reads ONLY its own config.
//!
//! `config_version` is monotonic per child so a stale config can never roll back
//! protection: the child applies a config only when `version > have_version`.
//!
//! State is **in-memory** (`Arc<Mutex<…>>`) with optional write-through JSON
//! persistence under `BULWARK_STATE_DIR` (the `persist` module) — the SAME shape
//! as [`AccountStore`]. We deliberately do NOT pull in `bulwark-store`/rusqlite
//! (env error 4551 on the Windows host); `bulwark-server` must keep building.

use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::accounts::AccountStore;
use crate::persist::JsonFile;
use bulwark_proto::v1::child_control_server::ChildControl;
use bulwark_proto::v1::{
    ChildConfig, ChildConfigAck, ChildConfigFilter, ChildConfigStatus, ChildStatusRequest,
    SetChildConfigRequest,
};
use futures_core::Stream;
use tonic::{Request, Response, Status};

/// The response-stream type tonic expects for `ChildControl::StreamChildConfig`.
pub type ChildConfigStream =
    Pin<Box<dyn Stream<Item = Result<ChildConfig, Status>> + Send + 'static>>;

/// One child's live desired-config entry: the latest config plus a `watch`
/// sender. The current value lives in the `watch` channel (it always retains the
/// most recent value), so a freshly-subscribed child immediately sees the
/// current config, then every guardian change.
struct ConfigEntry {
    /// Broadcast-with-retained-latest: `watch` keeps exactly the newest config,
    /// which is precisely the "push current, then on every change" semantics the
    /// child stream needs (vs. `broadcast`, which has no retained latest).
    tx: tokio::sync::watch::Sender<ChildConfig>,
}

/// The child's last applied-version report for one device: which
/// `config_version` it said it applied, and when it last checked in.
/// Child-reported state — kept SEPARATE from the guardian's desired ChildConfig.
#[derive(Clone, Copy, Default)]
struct AppliedReport {
    version: u64,
    /// In-memory only ("last seen" honestly resets on restart, never invented).
    ts: i64,
}

#[derive(Default)]
struct Inner {
    /// child_id → its live config entry (latest value + watch sender).
    by_child: HashMap<String, ConfigEntry>,
    /// device_id → child_id, so the child can resolve its own config by device
    /// identity (Get/Stream). Mirrors the accounts store's device routing.
    device_to_child: HashMap<String, String>,
    /// device_id → the child's last applied-version report (the `have_version`
    /// it sends on Get/Stream). ONLY devices already enrolled (present in
    /// `device_to_child`) are recorded, so an unauthenticated caller polling
    /// random device ids can never grow this map.
    applied_by_device: HashMap<String, AppliedReport>,
}

/// Cloneable handle to the in-memory child-config state. Every clone shares the
/// same maps + per-child watch channels.
#[derive(Clone)]
pub struct ChildConfigStore {
    inner: Arc<Mutex<Inner>>,
    /// `Some` → write-through JSON persistence (configs survive a restart);
    /// `None` (default) → pure in-memory.
    persist: Option<JsonFile>,
}

impl Default for ChildConfigStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ChildConfigStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            persist: None,
        }
    }

    /// Durable store rooted at `dir`: loads `child_config.json` on startup and
    /// write-throughs every guardian change. A corrupt file starts empty
    /// (logged); only an unusable directory is fatal — same contract as
    /// [`AccountStore::with_state_dir`].
    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let file = JsonFile::new(dir, "child_config.json")?;
        let snap: ConfigSnapshot = file.load_or_default();
        let mut inner = Inner::default();
        for row in snap.applied {
            inner.applied_by_device.insert(
                row.device_id,
                AppliedReport {
                    version: row.version,
                    ts: 0, // "last seen" is not persisted — it restarts honest
                },
            );
        }
        for row in snap.configs {
            let cfg = row.into_proto();
            if !cfg.device_id.is_empty() {
                inner
                    .device_to_child
                    .insert(cfg.device_id.clone(), cfg.child_id.clone());
            }
            let (tx, _rx) = tokio::sync::watch::channel(cfg.clone());
            inner.by_child.insert(cfg.child_id.clone(), ConfigEntry { tx });
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            persist: Some(file),
        })
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Persist the current state under the held lock (consistent), then write.
    /// A write failure is logged, never fatal — in-memory stays authoritative.
    fn persist_locked(&self, inner: &Inner) {
        if let Some(file) = &self.persist {
            if let Err(e) = file.store(&inner.snapshot()) {
                tracing::warn!(error = %e, "failed to persist child configs; continuing in-memory");
            }
        }
    }

    /// Guardian sets a child's desired config. Authenticated + scoped by the
    /// caller: `child_id` MUST be in the token's [`GuardianScope`]. The server
    /// stamps `config_version` (monotonic, starts at 1), `updated_ts`, and
    /// `updated_by`; client-supplied values for those three are ignored.
    pub fn set_config(
        &self,
        accounts: &AccountStore,
        token: &str,
        mut config: ChildConfig,
    ) -> Result<(u64, ChildConfig), Status> {
        let scope = accounts
            .guardian_scope(token)
            .ok_or_else(|| Status::unauthenticated("invalid or missing session token"))?;

        let child_id = config.child_id.trim().to_string();
        if child_id.is_empty() {
            return Err(Status::invalid_argument("config.child_id is required"));
        }
        // SCOPING: the caller must guard this child (same gate as Review's
        // per-child filter). Anyone else is permission-denied — they can't push
        // a config to a family they don't belong to.
        if !scope.child_ids.contains(&child_id) {
            return Err(Status::permission_denied(
                "caller is not a guardian of this child",
            ));
        }

        let updated_by = accounts.account_for_session(token).unwrap_or_default();

        let mut inner = self.inner.lock().expect("child-config mutex poisoned");

        // Monotonic per child: previous version + 1, starting at 1.
        let prev_version = inner
            .by_child
            .get(&child_id)
            .map(|e| e.tx.borrow().config_version)
            .unwrap_or(0);
        let next_version = prev_version.saturating_add(1);

        // Server-stamped fields — never trusted from the client.
        config.child_id = child_id.clone();
        config.config_version = next_version;
        config.updated_ts = Self::now_ms();
        config.updated_by = updated_by;

        // Maintain the device→child index so the child can resolve by device id.
        if !config.device_id.trim().is_empty() {
            inner
                .device_to_child
                .insert(config.device_id.trim().to_string(), child_id.clone());
        }

        // Publish to the live stream (and create the watch channel on first set).
        match inner.by_child.get(&child_id) {
            Some(entry) => {
                // `send_replace` ALWAYS updates the retained value (and notifies
                // any subscribers) — unlike `send`, which fails and leaves the
                // value stale when there are currently zero receivers.
                entry.tx.send_replace(config.clone());
            }
            None => {
                let (tx, _rx) = tokio::sync::watch::channel(config.clone());
                inner.by_child.insert(child_id.clone(), ConfigEntry { tx });
            }
        }

        self.persist_locked(&inner);
        Ok((next_version, config))
    }

    /// Resolve a child's current config by its device id (child-facing read).
    pub fn get_by_device(&self, device_id: &str) -> Result<ChildConfig, Status> {
        let device_id = device_id.trim();
        if device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        let inner = self.inner.lock().expect("child-config mutex poisoned");
        let child_id = inner
            .device_to_child
            .get(device_id)
            .ok_or_else(|| Status::not_found("no config for this device yet"))?;
        let entry = inner
            .by_child
            .get(child_id)
            .ok_or_else(|| Status::not_found("no config for this device yet"))?;
        // Bind the clone before returning so the `watch::Ref` temporary drops
        // while `inner` (the MutexGuard) is still alive.
        let cfg = entry.tx.borrow().clone();
        Ok(cfg)
    }

    /// Record the child's applied-version report (the `have_version` it sends on
    /// every Get/Stream poll). Monotonic per device — a replayed/older report can
    /// never roll the recorded version back — and bounded: only enrolled devices
    /// (known in `device_to_child`) are recorded. `last_report_ts` refreshes on
    /// EVERY check-in (the "last seen" signal); the version is persisted only
    /// when it strictly increases, so the 60s poll never writes the JSON file
    /// just to bump a timestamp.
    pub fn record_applied_report(&self, device_id: &str, version: u64) {
        let device_id = device_id.trim();
        if device_id.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().expect("child-config mutex poisoned");
        if !inner.device_to_child.contains_key(device_id) {
            return; // unknown device: nothing to attribute the report to
        }
        let now = Self::now_ms();
        let entry = inner
            .applied_by_device
            .entry(device_id.to_string())
            .or_default();
        entry.ts = now;
        let bumped = version > entry.version;
        if bumped {
            entry.version = version;
        }
        if bumped {
            self.persist_locked(&inner);
        }
    }

    /// Guardian-side desired-vs-applied status for one child. Same auth gate as
    /// `set_config`: the caller's session must guard `child_id`.
    pub fn child_status(
        &self,
        accounts: &AccountStore,
        token: &str,
        child_id: &str,
    ) -> Result<ChildConfigStatus, Status> {
        let scope = accounts
            .guardian_scope(token)
            .ok_or_else(|| Status::unauthenticated("invalid or missing session token"))?;
        let child_id = child_id.trim().to_string();
        if child_id.is_empty() {
            return Err(Status::invalid_argument("child_id is required"));
        }
        if !scope.child_ids.contains(&child_id) {
            return Err(Status::permission_denied(
                "caller is not a guardian of this child",
            ));
        }

        let inner = self.inner.lock().expect("child-config mutex poisoned");
        let entry = inner
            .by_child
            .get(&child_id)
            .ok_or_else(|| Status::not_found("no config set for this child yet"))?;
        // Clone out immediately — never hold the watch::Ref across other work.
        let cfg = entry.tx.borrow().clone();
        let report = inner
            .applied_by_device
            .get(cfg.device_id.trim())
            .copied()
            .unwrap_or_default();
        Ok(ChildConfigStatus {
            child_id,
            desired_version: cfg.config_version,
            applied_version: report.version,
            last_report_ts: report.ts,
        })
    }

    /// Subscribe to a child's config stream by device id: returns the current
    /// config plus a watch receiver for subsequent guardian changes. `None` when
    /// no config exists for that device yet (the child long-polls / retries).
    fn subscribe_by_device(
        &self,
        device_id: &str,
    ) -> Option<tokio::sync::watch::Receiver<ChildConfig>> {
        let inner = self.inner.lock().expect("child-config mutex poisoned");
        let child_id = inner.device_to_child.get(device_id.trim())?;
        let entry = inner.by_child.get(child_id)?;
        Some(entry.tx.subscribe())
    }
}

// ---------------------------------------------------------------------------
// Durable snapshot (serde JSON). Content-free: ids, region/endpoint, flags,
// the strictness band, the monotonic version + audit stamps. No media/text.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct ConfigSnapshot {
    configs: Vec<ConfigRow>,
    /// Child-reported applied versions. `default` so a pre-existing snapshot
    /// file (written before this field existed) still loads.
    #[serde(default)]
    applied: Vec<AppliedRow>,
}

/// One device's persisted applied-version report. The check-in timestamp is
/// deliberately NOT persisted ("last seen" must not survive a restart as if
/// the child had just checked in).
#[derive(Serialize, Deserialize)]
struct AppliedRow {
    device_id: String,
    version: u64,
}

#[derive(Serialize, Deserialize)]
struct ConfigRow {
    child_id: String,
    device_id: String,
    filtering_enabled: bool,
    server_region: String,
    server_endpoint: String,
    profile: i32,
    require_always_on: bool,
    config_version: u64,
    updated_ts: i64,
    updated_by: String,
}

impl ConfigRow {
    fn from_proto(c: &ChildConfig) -> Self {
        Self {
            child_id: c.child_id.clone(),
            device_id: c.device_id.clone(),
            filtering_enabled: c.filtering_enabled,
            server_region: c.server_region.clone(),
            server_endpoint: c.server_endpoint.clone(),
            profile: c.profile,
            require_always_on: c.require_always_on,
            config_version: c.config_version,
            updated_ts: c.updated_ts,
            updated_by: c.updated_by.clone(),
        }
    }

    fn into_proto(self) -> ChildConfig {
        ChildConfig {
            child_id: self.child_id,
            device_id: self.device_id,
            filtering_enabled: self.filtering_enabled,
            server_region: self.server_region,
            server_endpoint: self.server_endpoint,
            profile: self.profile,
            require_always_on: self.require_always_on,
            config_version: self.config_version,
            updated_ts: self.updated_ts,
            updated_by: self.updated_by,
        }
    }
}

impl Inner {
    /// Build a stable (sorted by child_id) serde snapshot from the retained
    /// latest config in each child's watch channel.
    fn snapshot(&self) -> ConfigSnapshot {
        let mut configs: Vec<ConfigRow> = self
            .by_child
            .values()
            .map(|e| ConfigRow::from_proto(&e.tx.borrow()))
            .collect();
        configs.sort_by(|a, b| a.child_id.cmp(&b.child_id));
        let mut applied: Vec<AppliedRow> = self
            .applied_by_device
            .iter()
            .map(|(device_id, r)| AppliedRow {
                device_id: device_id.clone(),
                version: r.version,
            })
            .collect();
        applied.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        ConfigSnapshot { configs, applied }
    }
}

/// Turn a `watch` receiver into the boxed response stream tonic wants, emitting
/// the current config first and then each newer one. We use `futures_util`'s
/// `unfold` (same approach as the relay's broadcast stream) so the lib needs no
/// `tokio-stream` dependency.
///
/// `have_version` filters the FIRST emit: the child passes the version it
/// already applied, so we skip re-sending a config it already has (only emit
/// when `config_version > have_version`). Every subsequent change is emitted
/// because a guardian Set always bumps the version strictly upward.
fn watch_into_stream(
    rx: tokio::sync::watch::Receiver<ChildConfig>,
    have_version: u64,
) -> ChildConfigStream {
    // State: (receiver, last_version_emitted, first). Seed last_emitted with
    // have_version so the current config is sent iff it is strictly newer.
    let stream = futures_util::stream::unfold(
        (rx, have_version, true),
        move |(mut rx, last_emitted, first)| async move {
            // On the very first poll, the watch already holds the current value;
            // emit it without waiting if it is newer than have_version.
            if first {
                let cur = rx.borrow_and_update().clone();
                if cur.config_version > last_emitted {
                    let v = cur.config_version;
                    return Some((Ok(cur), (rx, v, false)));
                }
                // Current value already applied by the child → fall through to
                // wait for the next change.
            }
            loop {
                // Wait for the next guardian change. `changed()` errors only when
                // all senders are dropped → end the stream cleanly.
                if rx.changed().await.is_err() {
                    return None;
                }
                let cur = rx.borrow_and_update().clone();
                if cur.config_version > last_emitted {
                    let v = cur.config_version;
                    return Some((Ok(cur), (rx, v, false)));
                }
                // No-op wakeups (same/older version) are skipped, not emitted.
            }
        },
    );
    Box::pin(stream)
}

// ---------------------------------------------------------------------------
// gRPC service
// ---------------------------------------------------------------------------

/// Implements `bulwark_proto::v1::child_control_server::ChildControl` over a
/// [`ChildConfigStore`], scoping guardian writes against an [`AccountStore`].
#[derive(Clone)]
pub struct ChildControlService {
    store: ChildConfigStore,
    accounts: AccountStore,
}

impl ChildControlService {
    /// `accounts` is the SAME store that backs the Accounts service + Review
    /// scoping, so guardian→child assignments are shared (one source of truth).
    pub fn new(store: ChildConfigStore, accounts: AccountStore) -> Self {
        Self { store, accounts }
    }

    /// Effective token: the explicit field first, then `authorization: Bearer`.
    fn token_or_meta<T>(req: &Request<T>, field: &str) -> String {
        if !field.trim().is_empty() {
            return field.trim().to_string();
        }
        crate::accounts::bearer_token(req).unwrap_or_default()
    }
}

#[tonic::async_trait]
impl ChildControl for ChildControlService {
    async fn set_child_config(
        &self,
        req: Request<SetChildConfigRequest>,
    ) -> Result<Response<ChildConfigAck>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        let config = r
            .config
            .ok_or_else(|| Status::invalid_argument("config is required"))?;
        let (version, _stored) = self.store.set_config(&self.accounts, &token, config)?;
        Ok(Response::new(ChildConfigAck {
            applied: true,
            config_version: version,
            detail: "child config updated".to_string(),
        }))
    }

    async fn get_child_config(
        &self,
        req: Request<ChildConfigFilter>,
    ) -> Result<Response<ChildConfig>, Status> {
        let f = req.into_inner();
        // The poll IS the child's ack: `have_version` = the version it last
        // applied. Recorded (monotonic, enrolled devices only) for GetChildStatus.
        self.store.record_applied_report(&f.device_id, f.have_version);
        let cfg = self.store.get_by_device(&f.device_id)?;
        Ok(Response::new(cfg))
    }

    type StreamChildConfigStream = ChildConfigStream;

    async fn stream_child_config(
        &self,
        req: Request<ChildConfigFilter>,
    ) -> Result<Response<Self::StreamChildConfigStream>, Status> {
        let f = req.into_inner();
        let device_id = f.device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        self.store.record_applied_report(&device_id, f.have_version);
        let rx = self
            .store
            .subscribe_by_device(&device_id)
            .ok_or_else(|| Status::not_found("no config for this device yet"))?;
        Ok(Response::new(watch_into_stream(rx, f.have_version)))
    }

    async fn get_child_status(
        &self,
        req: Request<ChildStatusRequest>,
    ) -> Result<Response<ChildConfigStatus>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        let status = self
            .store
            .child_status(&self.accounts, &token, &r.child_id)?;
        Ok(Response::new(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::FilteringProfile;

    fn proto_config(child_id: &str, device_id: &str) -> ChildConfig {
        ChildConfig {
            child_id: child_id.to_string(),
            device_id: device_id.to_string(),
            filtering_enabled: true,
            server_region: "uk".to_string(),
            server_endpoint: "lon.example:8443".to_string(),
            profile: FilteringProfile::Preteen as i32,
            require_always_on: true,
            // server-stamped — these are overwritten by set_config:
            config_version: 999,
            updated_ts: 0,
            updated_by: String::new(),
        }
    }

    /// Helper: stand up an accounts store with a logged-in guardian who guards a
    /// child on `device_id`. Returns (accounts, token, child_id).
    fn accounts_with_child(device_id: &str) -> (AccountStore, String, String) {
        let accounts = AccountStore::new();
        accounts
            .create_account("p@x.com", "password123", "P")
            .unwrap();
        let (token, _aid, _) = accounts.login("p@x.com", "password123").unwrap();
        let child = accounts.add_child(&token, "Kid", device_id).unwrap();
        (accounts, token, child.child_id)
    }

    #[test]
    fn set_increments_version_and_stamps_audit() {
        let (accounts, token, child_id) = accounts_with_child("dev-1");
        let store = ChildConfigStore::new();

        let (v1, stored) = store
            .set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();
        assert_eq!(v1, 1, "first config version starts at 1");
        assert_eq!(stored.config_version, 1);
        assert!(stored.updated_ts > 0, "updated_ts is server-stamped");
        assert!(!stored.updated_by.is_empty(), "updated_by is the guardian");

        // A second Set bumps the version monotonically.
        let (v2, _) = store
            .set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();
        assert_eq!(v2, 2);
    }

    #[test]
    fn non_guardian_is_rejected() {
        let (accounts, _owner_token, child_id) = accounts_with_child("dev-1");
        // A second account that does NOT guard the child.
        accounts
            .create_account("intruder@x.com", "password123", "I")
            .unwrap();
        let (intruder, _aid, _) = accounts.login("intruder@x.com", "password123").unwrap();

        let store = ChildConfigStore::new();
        let err = store
            .set_config(&accounts, &intruder, proto_config(&child_id, "dev-1"))
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // An unknown token is unauthenticated (not permission-denied).
        let err = store
            .set_config(&accounts, "not-a-token", proto_config(&child_id, "dev-1"))
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn get_by_device_returns_current_and_unknown_is_not_found() {
        let (accounts, token, child_id) = accounts_with_child("dev-1");
        let store = ChildConfigStore::new();
        store
            .set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();

        let got = store.get_by_device("dev-1").unwrap();
        assert_eq!(got.child_id, child_id);
        assert_eq!(got.server_region, "uk");
        assert_eq!(got.config_version, 1);

        assert_eq!(
            store.get_by_device("no-such-device").unwrap_err().code(),
            tonic::Code::NotFound
        );
    }

    #[test]
    fn configs_persist_and_reload_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-childcfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let (accounts, token, child_id) = accounts_with_child("dev-1");
        let s1 = ChildConfigStore::with_state_dir(&dir).unwrap();
        s1.set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();
        s1.set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();
        drop(s1); // simulate a restart

        let s2 = ChildConfigStore::with_state_dir(&dir).unwrap();
        let got = s2.get_by_device("dev-1").unwrap();
        assert_eq!(got.config_version, 2, "monotonic version survived restart");
        // The next Set continues from the persisted version (no rollback).
        let (v3, _) = s2
            .set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();
        assert_eq!(v3, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn applied_report_is_monotonic_scoped_and_guardian_gated() {
        let (accounts, token, child_id) = accounts_with_child("dev-1");
        let store = ChildConfigStore::new();
        store
            .set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();

        // Before any report: desired v1, applied 0, never checked in.
        let st = store.child_status(&accounts, &token, &child_id).unwrap();
        assert_eq!(st.desired_version, 1);
        assert_eq!(st.applied_version, 0);
        assert_eq!(st.last_report_ts, 0);

        // The child polls with have_version = 1 -> recorded as applied.
        store.record_applied_report("dev-1", 1);
        let st = store.child_status(&accounts, &token, &child_id).unwrap();
        assert_eq!(st.applied_version, 1);
        assert!(st.last_report_ts > 0, "check-in time recorded");

        // A replayed OLDER report can never roll the recorded version back.
        store.record_applied_report("dev-1", 0);
        let st = store.child_status(&accounts, &token, &child_id).unwrap();
        assert_eq!(st.applied_version, 1, "monotonic — replay defense");

        // Unknown devices are never recorded (bounded map), and a non-guardian
        // cannot read the status.
        store.record_applied_report("rando-device", 99);
        accounts
            .create_account("intruder2@x.com", "password123", "I")
            .unwrap();
        let (intruder, _aid, _) = accounts.login("intruder2@x.com", "password123").unwrap();
        assert_eq!(
            store
                .child_status(&accounts, &intruder, &child_id)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn applied_version_persists_but_last_seen_does_not() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-childcfg-applied-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let (accounts, token, child_id) = accounts_with_child("dev-1");
        let s1 = ChildConfigStore::with_state_dir(&dir).unwrap();
        s1.set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();
        s1.record_applied_report("dev-1", 1);
        drop(s1); // simulate a restart

        let s2 = ChildConfigStore::with_state_dir(&dir).unwrap();
        let st = s2.child_status(&accounts, &token, &child_id).unwrap();
        assert_eq!(st.applied_version, 1, "applied version survived restart");
        assert_eq!(st.last_report_ts, 0, "last-seen honestly resets on restart");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
