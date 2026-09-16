//! Authenticated guardian desired-config and device policy synchronization.

use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bulwark_policy::{Allowlist, ReviewItem};
use bulwark_proto::v1::child_control_server::ChildControl;
use bulwark_proto::v1::{
    Category, ChildConfig, ChildConfigAck, ChildConfigFilter, ChildConfigStatus,
    ChildStatusRequest, ReviewDecision, ReviewScope, SetChildConfigRequest,
};
use bulwark_proto::DeviceId;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status};

use crate::accounts::AccountStore;
use crate::persist::JsonFile;

pub type ChildConfigStream =
    Pin<Box<dyn Stream<Item = Result<ChildConfig, Status>> + Send + 'static>>;

const DEVICE_POLICY_HEADER: &str = "x-bulwark-policy-bin";
const POLICY_ENTRY_CAP: usize = 128;

struct ConfigEntry {
    tx: tokio::sync::watch::Sender<ChildConfig>,
}

#[derive(Clone, Copy, Default)]
struct AppliedReport {
    version: u64,
    ts: i64,
}

#[derive(Default)]
struct Inner {
    by_child: HashMap<String, ConfigEntry>,
    device_to_child: HashMap<String, String>,
    applied_by_device: HashMap<String, AppliedReport>,
}

#[derive(Clone)]
pub struct ChildConfigStore {
    inner: Arc<Mutex<Inner>>,
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

    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let file = JsonFile::new(dir, "child_config.json")?;
        let snapshot: ConfigSnapshot = file.load_strict()?.unwrap_or_default();
        let mut inner = Inner::default();
        for row in snapshot.applied {
            inner.applied_by_device.insert(
                row.device_id,
                AppliedReport {
                    version: row.version,
                    ts: 0,
                },
            );
        }
        for row in snapshot.configs {
            let config = row.into_proto();
            if !config.device_id.is_empty() {
                inner
                    .device_to_child
                    .insert(config.device_id.clone(), config.child_id.clone());
            }
            let (tx, _) = tokio::sync::watch::channel(config.clone());
            inner
                .by_child
                .insert(config.child_id.clone(), ConfigEntry { tx });
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            persist: Some(file),
        })
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0)
    }

    fn persist_snapshot(&self, snapshot: &ConfigSnapshot) -> Result<(), Status> {
        if let Some(file) = &self.persist {
            file.store(snapshot).map_err(|error| {
                tracing::error!(%error, "failed to durably persist child config state");
                Status::unavailable("could not durably persist child configuration")
            })?;
        }
        Ok(())
    }

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
        if !scope.child_ids.contains(&child_id) {
            return Err(Status::permission_denied(
                "caller is not a guardian of this child",
            ));
        }
        let device_id = config.device_id.trim().to_string();
        if !device_id.is_empty() && !scope.device_ids.contains(&device_id) {
            return Err(Status::permission_denied(
                "device_id is not a supervised device of this guardian",
            ));
        }

        let mut inner = self.inner.lock().expect("child-config mutex poisoned");
        let previous_version = inner
            .by_child
            .get(&child_id)
            .map(|entry| entry.tx.borrow().config_version)
            .unwrap_or(0);
        let version = previous_version.saturating_add(1);
        config.child_id = child_id.clone();
        config.device_id = device_id.clone();
        config.config_version = version;
        config.updated_ts = Self::now_ms();
        config.updated_by = accounts.account_for_session(token).unwrap_or_default();

        // Durability is part of the guardian update transaction. The new desired
        // config must not become visible to devices until the exact authorization
        // document consumed after restart has been committed successfully.
        let mut next_snapshot = inner.snapshot();
        let next_row = ConfigRow::from_proto(&config);
        match next_snapshot
            .configs
            .iter_mut()
            .find(|row| row.child_id == child_id)
        {
            Some(existing) => *existing = next_row,
            None => next_snapshot.configs.push(next_row),
        }
        next_snapshot
            .configs
            .sort_by(|left, right| left.child_id.cmp(&right.child_id));
        self.persist_snapshot(&next_snapshot)?;

        if !device_id.is_empty() {
            inner
                .device_to_child
                .retain(|device, child| child != &child_id || device == &device_id);
            inner.device_to_child.insert(device_id, child_id.clone());
        }

        match inner.by_child.get(&child_id) {
            Some(entry) => {
                entry.tx.send_replace(config.clone());
            }
            None => {
                let (tx, _) = tokio::sync::watch::channel(config.clone());
                inner.by_child.insert(child_id, ConfigEntry { tx });
            }
        }
        Ok((version, config))
    }

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
        Ok(entry.tx.borrow().clone())
    }

    pub fn record_applied_report(&self, device_id: &str, version: u64) {
        let device_id = device_id.trim();
        if device_id.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().expect("child-config mutex poisoned");
        if !inner.device_to_child.contains_key(device_id) {
            return;
        }
        let desired = inner
            .device_to_child
            .get(device_id)
            .and_then(|child_id| inner.by_child.get(child_id))
            .map(|entry| entry.tx.borrow().config_version)
            .unwrap_or(0);
        let version = version.min(desired);
        let current = inner
            .applied_by_device
            .get(device_id)
            .copied()
            .unwrap_or_default();
        let now = Self::now_ms();
        let changed = version > current.version;

        if changed {
            let mut next_snapshot = inner.snapshot();
            match next_snapshot
                .applied
                .iter_mut()
                .find(|row| row.device_id == device_id)
            {
                Some(row) => row.version = version,
                None => next_snapshot.applied.push(AppliedRow {
                    device_id: device_id.to_string(),
                    version,
                }),
            }
            next_snapshot
                .applied
                .sort_by(|left, right| left.device_id.cmp(&right.device_id));
            if let Err(error) = self.persist_snapshot(&next_snapshot) {
                tracing::warn!(%error, device_id, "applied-version report not persisted");
                inner
                    .applied_by_device
                    .entry(device_id.to_string())
                    .or_default()
                    .ts = now;
                return;
            }
        }

        let report = inner
            .applied_by_device
            .entry(device_id.to_string())
            .or_default();
        report.ts = now;
        if changed {
            report.version = version;
        }
    }

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
        let config = inner
            .by_child
            .get(&child_id)
            .ok_or_else(|| Status::not_found("no config set for this child yet"))?
            .tx
            .borrow()
            .clone();
        let report = inner
            .applied_by_device
            .get(config.device_id.trim())
            .copied()
            .unwrap_or_default();
        Ok(ChildConfigStatus {
            child_id,
            desired_version: config.config_version,
            applied_version: report.version,
            last_report_ts: report.ts,
            desired: Some(config),
        })
    }

    fn subscribe_by_device(
        &self,
        device_id: &str,
    ) -> Option<tokio::sync::watch::Receiver<ChildConfig>> {
        let inner = self.inner.lock().ok()?;
        let child_id = inner.device_to_child.get(device_id.trim())?;
        inner
            .by_child
            .get(child_id)
            .map(|entry| entry.tx.subscribe())
    }
}

#[derive(Serialize, Deserialize, Default)]
struct ConfigSnapshot {
    configs: Vec<ConfigRow>,
    #[serde(default)]
    applied: Vec<AppliedRow>,
}

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
    #[serde(default)]
    filter_location: i32,
}

impl ConfigRow {
    fn from_proto(config: &ChildConfig) -> Self {
        Self {
            child_id: config.child_id.clone(),
            device_id: config.device_id.clone(),
            filtering_enabled: config.filtering_enabled,
            server_region: config.server_region.clone(),
            server_endpoint: config.server_endpoint.clone(),
            profile: config.profile,
            require_always_on: config.require_always_on,
            config_version: config.config_version,
            updated_ts: config.updated_ts,
            updated_by: config.updated_by.clone(),
            filter_location: config.filter_location,
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
            filter_location: self.filter_location,
        }
    }
}

impl Inner {
    fn snapshot(&self) -> ConfigSnapshot {
        let mut configs: Vec<_> = self
            .by_child
            .values()
            .map(|entry| ConfigRow::from_proto(&entry.tx.borrow()))
            .collect();
        configs.sort_by(|left, right| left.child_id.cmp(&right.child_id));
        let mut applied: Vec<_> = self
            .applied_by_device
            .iter()
            .map(|(device_id, report)| AppliedRow {
                device_id: device_id.clone(),
                version: report.version,
            })
            .collect();
        applied.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        ConfigSnapshot { configs, applied }
    }
}

fn watch_into_stream(
    rx: tokio::sync::watch::Receiver<ChildConfig>,
    have_version: u64,
) -> ChildConfigStream {
    let stream = futures_util::stream::unfold(
        (rx, have_version, true),
        |(mut rx, last_version, first)| async move {
            if first {
                let current = rx.borrow_and_update().clone();
                if current.config_version > last_version {
                    let version = current.config_version;
                    return Some((Ok(current), (rx, version, false)));
                }
            }
            loop {
                if rx.changed().await.is_err() {
                    return None;
                }
                let current = rx.borrow_and_update().clone();
                if current.config_version > last_version {
                    let version = current.config_version;
                    return Some((Ok(current), (rx, version, false)));
                }
            }
        },
    );
    Box::pin(stream)
}

#[derive(Deserialize)]
struct PolicyAuditRow {
    device_id: String,
    alert_id: String,
    decision: i32,
    scope: i32,
    host: String,
    sha256_hex: String,
    category: i32,
    ts: i64,
}

#[derive(Serialize)]
struct DevicePolicySnapshot {
    version: u64,
    issued_ts: i64,
    complete: bool,
    approved_hosts: Vec<String>,
    approved_sha256_hex: Vec<String>,
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.trim().as_bytes();
    if bytes.is_empty() || bytes.len() & 1 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

fn device_policy_snapshot(device_id: &str) -> DevicePolicySnapshot {
    let mut snapshot = DevicePolicySnapshot {
        version: 0,
        issued_ts: ChildConfigStore::now_ms(),
        complete: true,
        approved_hosts: Vec::new(),
        approved_sha256_hex: Vec::new(),
    };
    let Some(state_dir) = std::env::var_os("BULWARK_STATE_DIR")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
    else {
        return snapshot;
    };
    let path = state_dir.join("allowlist_audit.json");
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return snapshot,
        Err(error) => {
            tracing::error!(%error, "device policy audit is unreadable; sending fail-closed empty policy");
            snapshot.complete = false;
            return snapshot;
        }
    };
    let rows: Vec<PolicyAuditRow> = match serde_json::from_slice(&bytes) {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(%error, "device policy audit is corrupt; sending fail-closed empty policy");
            snapshot.complete = false;
            return snapshot;
        }
    };
    snapshot.version = rows.len() as u64;
    let mut allowlist = Allowlist::new();
    for row in rows {
        let decision =
            ReviewDecision::try_from(row.decision).unwrap_or(ReviewDecision::Unspecified);
        let scope = ReviewScope::try_from(row.scope).unwrap_or(ReviewScope::Unspecified);
        let category = Category::try_from(row.category).unwrap_or(Category::Unspecified);
        let item = ReviewItem::new(
            DeviceId(row.device_id),
            row.alert_id,
            row.host,
            decode_hex(&row.sha256_hex).unwrap_or_default(),
            category,
        );
        let _ = allowlist.apply(&item, decision, scope, row.ts);
    }
    let device = DeviceId(device_id.trim().to_string());
    if let Some(policy) = allowlist.device(&device) {
        snapshot.approved_hosts = policy.hosts().map(str::to_string).collect();
        snapshot.approved_sha256_hex = policy.hashes().map(str::to_string).collect();
    }
    if snapshot.approved_hosts.len() > POLICY_ENTRY_CAP
        || snapshot.approved_sha256_hex.len() > POLICY_ENTRY_CAP
    {
        tracing::warn!(
            device_id,
            "device policy exceeds sync cap; failing closed to no approvals"
        );
        snapshot.approved_hosts.clear();
        snapshot.approved_sha256_hex.clear();
        snapshot.complete = false;
    }
    snapshot
}

fn attach_device_policy<T>(response: &mut Response<T>, device_id: &str) -> Result<(), Status> {
    let snapshot = serde_json::to_vec(&device_policy_snapshot(device_id))
        .map_err(|_| Status::internal("could not serialize device policy snapshot"))?;
    response.metadata_mut().insert_bin(
        DEVICE_POLICY_HEADER,
        tonic::metadata::MetadataValue::from_bytes(&snapshot),
    );
    Ok(())
}

#[derive(Clone)]
pub struct ChildControlService {
    store: ChildConfigStore,
    accounts: AccountStore,
}

impl ChildControlService {
    pub fn new(store: ChildConfigStore, accounts: AccountStore) -> Self {
        Self { store, accounts }
    }

    fn token_or_meta<T>(request: &Request<T>, field: &str) -> String {
        if !field.trim().is_empty() {
            return field.trim().to_string();
        }
        crate::accounts::bearer_token(request).unwrap_or_default()
    }

    fn verify_device(&self, device_id: &str, device_token: &str) -> Result<(), Status> {
        if crate::auth::verify_device_token_strict(&self.accounts, device_id, device_token) {
            Ok(())
        } else {
            Err(Status::unauthenticated(
                "unknown, legacy-unpaired, or invalid device credential",
            ))
        }
    }
}

#[tonic::async_trait]
impl ChildControl for ChildControlService {
    async fn set_child_config(
        &self,
        request: Request<SetChildConfigRequest>,
    ) -> Result<Response<ChildConfigAck>, Status> {
        let token = Self::token_or_meta(&request, &request.get_ref().token);
        let config = request
            .into_inner()
            .config
            .ok_or_else(|| Status::invalid_argument("config is required"))?;
        let (version, _) = self.store.set_config(&self.accounts, &token, config)?;
        Ok(Response::new(ChildConfigAck {
            applied: true,
            config_version: version,
            detail: "child config updated".to_string(),
        }))
    }

    async fn get_child_config(
        &self,
        request: Request<ChildConfigFilter>,
    ) -> Result<Response<ChildConfig>, Status> {
        let filter = request.into_inner();
        if filter.device_id.trim().is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        self.verify_device(&filter.device_id, &filter.device_token)?;
        self.store
            .record_applied_report(&filter.device_id, filter.have_version);
        let config = self.store.get_by_device(&filter.device_id)?;
        let mut response = Response::new(config);
        attach_device_policy(&mut response, &filter.device_id)?;
        Ok(response)
    }

    type StreamChildConfigStream = ChildConfigStream;

    async fn stream_child_config(
        &self,
        request: Request<ChildConfigFilter>,
    ) -> Result<Response<Self::StreamChildConfigStream>, Status> {
        let filter = request.into_inner();
        let device_id = filter.device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        self.verify_device(&device_id, &filter.device_token)?;
        self.store
            .record_applied_report(&device_id, filter.have_version);
        let receiver = self
            .store
            .subscribe_by_device(&device_id)
            .ok_or_else(|| Status::not_found("no config for this device yet"))?;
        let mut response = Response::new(watch_into_stream(receiver, filter.have_version));
        attach_device_policy(&mut response, &device_id)?;
        Ok(response)
    }

    async fn get_child_status(
        &self,
        request: Request<ChildStatusRequest>,
    ) -> Result<Response<ChildConfigStatus>, Status> {
        let token = Self::token_or_meta(&request, &request.get_ref().token);
        let child_id = request.into_inner().child_id;
        let status = self.store.child_status(&self.accounts, &token, &child_id)?;
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
            config_version: 999,
            updated_ts: 0,
            updated_by: String::new(),
            filter_location: 0,
        }
    }

    fn accounts_with_child(device_id: &str) -> (AccountStore, String, String) {
        let accounts = AccountStore::new();
        accounts
            .create_account("parent@example.test", "password123", "Parent")
            .unwrap();
        let (token, _, _) = accounts
            .login("parent@example.test", "password123")
            .unwrap();
        let child = accounts.add_child(&token, "Kid", device_id).unwrap();
        (accounts, token, child.child_id)
    }

    #[test]
    fn set_is_monotonic_and_device_scoped() {
        let (accounts, token, child_id) = accounts_with_child("dev-1");
        let store = ChildConfigStore::new();
        let (first, _) = store
            .set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();
        let (second, _) = store
            .set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();
        assert_eq!((first, second), (1, 2));
        assert_eq!(store.get_by_device("dev-1").unwrap().config_version, 2);
    }

    #[test]
    fn applied_report_cannot_exceed_desired_version() {
        let (accounts, token, child_id) = accounts_with_child("dev-1");
        let store = ChildConfigStore::new();
        store
            .set_config(&accounts, &token, proto_config(&child_id, "dev-1"))
            .unwrap();
        store.record_applied_report("dev-1", 999);
        let status = store.child_status(&accounts, &token, &child_id).unwrap();
        assert_eq!(status.applied_version, 1);
    }

    #[test]
    fn non_guardian_cannot_change_config() {
        let (accounts, _, child_id) = accounts_with_child("dev-1");
        accounts
            .create_account("other@example.test", "password123", "Other")
            .unwrap();
        let (other, _, _) = accounts.login("other@example.test", "password123").unwrap();
        let error = ChildConfigStore::new()
            .set_config(&accounts, &other, proto_config(&child_id, "dev-1"))
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }
}
