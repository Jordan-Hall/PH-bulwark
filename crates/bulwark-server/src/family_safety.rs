//! Authenticated child SOS and staff-originated family safety notices.

use std::path::Path;
use std::sync::{Arc, Mutex};

use bulwark_proto::v1::family_safety_server::FamilySafety;
use bulwark_proto::v1::{
    AlertEvent, AlertKind, Category, ListSafetyBroadcastsRequest, SafetyBroadcast,
    SafetyBroadcastAck, SafetyBroadcasts, SendSafetyBroadcastRequest, Severity, SosAck, SosRequest,
    StaffRole,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status};

use crate::accounts::AccountStore;
use crate::persist::JsonFile;
use crate::relay::AlertHub;
use crate::staff::StaffStore;

const MAX_STORED_BROADCASTS: usize = 64;
const MAX_TITLE_CHARS: usize = 120;
const MAX_BODY_CHARS: usize = 2_000;

#[derive(Clone, Serialize, Deserialize)]
struct BroadcastRow {
    broadcast_id: String,
    title: String,
    body: String,
    severity: i32,
    region: String,
    issued_ts: i64,
    expires_ts: i64,
    notify_child_devices: bool,
    issued_by: String,
}

impl BroadcastRow {
    fn from_proto(value: &SafetyBroadcast) -> Self {
        Self {
            broadcast_id: value.broadcast_id.clone(),
            title: value.title.clone(),
            body: value.body.clone(),
            severity: value.severity,
            region: value.region.clone(),
            issued_ts: value.issued_ts,
            expires_ts: value.expires_ts,
            notify_child_devices: value.notify_child_devices,
            issued_by: value.issued_by.clone(),
        }
    }

    fn into_proto(self) -> SafetyBroadcast {
        SafetyBroadcast {
            broadcast_id: self.broadcast_id,
            title: self.title,
            body: self.body,
            severity: self.severity,
            region: self.region,
            issued_ts: self.issued_ts,
            expires_ts: self.expires_ts,
            notify_child_devices: self.notify_child_devices,
            issued_by: self.issued_by,
        }
    }

    fn active(&self, now_ms: i64) -> bool {
        self.expires_ts <= 0 || now_ms < self.expires_ts
    }
}

/// Durable bounded safety-broadcast state.
#[derive(Clone)]
pub struct SafetyBroadcastStore {
    inner: Arc<Mutex<Vec<BroadcastRow>>>,
    persist: Option<JsonFile>,
}

impl Default for SafetyBroadcastStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyBroadcastStore {
    /// Create an in-memory store for development/tests.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
            persist: None,
        }
    }

    /// Open durable state. A present-but-corrupt file is fatal instead of
    /// silently erasing active notices.
    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let file = JsonFile::new(dir, "safety_broadcasts.json")?;
        let rows: Vec<BroadcastRow> = file.load_strict()?.unwrap_or_default();
        Ok(Self {
            inner: Arc::new(Mutex::new(rows)),
            persist: Some(file),
        })
    }

    fn add(&self, broadcast: &SafetyBroadcast) -> std::io::Result<()> {
        let mut guard = self.inner.lock().expect("broadcast mutex poisoned");
        let mut next = guard.clone();
        next.push(BroadcastRow::from_proto(broadcast));
        if next.len() > MAX_STORED_BROADCASTS {
            let excess = next.len() - MAX_STORED_BROADCASTS;
            next.drain(..excess);
        }
        if let Some(file) = &self.persist {
            file.store(&next)?;
        }
        *guard = next;
        Ok(())
    }

    fn active(&self, now_ms: i64, region: &str) -> Vec<SafetyBroadcast> {
        let region = region.trim().to_ascii_lowercase();
        let mut output = self
            .inner
            .lock()
            .expect("broadcast mutex poisoned")
            .iter()
            .filter(|row| row.active(now_ms))
            .filter(|row| region.is_empty() || row.region.is_empty() || row.region == region)
            .cloned()
            .map(BroadcastRow::into_proto)
            .collect::<Vec<_>>();
        output.sort_by_key(|broadcast| std::cmp::Reverse(broadcast.issued_ts));
        output
    }
}

fn sos_alert(
    alert_id: &str,
    device_id: &str,
    child_id: &str,
    family_id: &str,
    child_name: &str,
    now_ms: i64,
) -> AlertEvent {
    let who = if child_name.trim().is_empty() {
        "Your child"
    } else {
        child_name.trim()
    };
    AlertEvent {
        alert_id: alert_id.to_string(),
        kind: AlertKind::ChildSos as i32,
        category: Category::Safe as i32,
        severity: Severity::Critical as i32,
        device_id: device_id.to_string(),
        child_id: child_id.to_string(),
        family_id: family_id.to_string(),
        ts: now_ms,
        redacted_context: format!(
            "URGENT: {who} pressed the SOS button in PH Bulwark on their device. Please contact them right away."
        ),
        ..Default::default()
    }
}

/// Convert a staff notice to the guardian alert-stream shape.
pub fn broadcast_alert_event(broadcast: &SafetyBroadcast) -> AlertEvent {
    AlertEvent {
        alert_id: broadcast.broadcast_id.clone(),
        kind: AlertKind::SafetyBroadcast as i32,
        category: Category::Safe as i32,
        severity: broadcast.severity,
        app: broadcast.region.clone(),
        ts: broadcast.issued_ts,
        redacted_context: if broadcast.body.is_empty() {
            broadcast.title.clone()
        } else {
            format!("{} — {}", broadcast.title, broadcast.body)
        },
        ..Default::default()
    }
}

/// Family safety gRPC implementation.
#[derive(Clone)]
pub struct FamilySafetyService {
    hub: AlertHub,
    broadcasts: SafetyBroadcastStore,
    accounts: Option<AccountStore>,
    sink: Option<Arc<dyn bulwark_alert::AlertSink>>,
    staff: Option<StaffStore>,
    staff_token_sha256: Option<String>,
    rng: Arc<SystemRandom>,
}

impl FamilySafetyService {
    /// Construct over a shared alert hub and broadcast store.
    pub fn new(hub: AlertHub, broadcasts: SafetyBroadcastStore) -> Self {
        Self {
            hub,
            broadcasts,
            accounts: None,
            sink: None,
            staff: None,
            staff_token_sha256: None,
            rng: Arc::new(SystemRandom::new()),
        }
    }

    /// Authenticate staff notices with the dedicated staff account store.
    pub fn with_staff_store(mut self, staff: StaffStore) -> Self {
        self.staff = Some(staff);
        self
    }

    /// Require enrolled-device credentials and guardian sessions.
    pub fn with_accounts(mut self, accounts: AccountStore) -> Self {
        self.accounts = Some(accounts);
        self
    }

    /// Add best-effort email/push delivery for SOS alerts.
    pub fn with_alert_sink(mut self, sink: Option<Arc<dyn bulwark_alert::AlertSink>>) -> Self {
        self.sink = sink;
        self
    }

    /// Configure the legacy shared staff token for non-production compatibility.
    pub fn with_staff_token(mut self, raw: Option<String>) -> Self {
        self.staff_token_sha256 = raw
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty())
            .map(|token| sha256_hex(&token));
        self
    }

    /// Load the legacy staff token only outside production. Production family
    /// listeners never expose a shared-secret staff control surface.
    pub fn with_staff_token_from_env(self) -> Self {
        if production_mode() {
            return self.with_staff_token(None);
        }
        self.with_staff_token(std::env::var("BULWARK_STAFF_BROADCAST_TOKEN").ok())
    }
}

#[tonic::async_trait]
impl FamilySafety for FamilySafetyService {
    async fn raise_sos(&self, request: Request<SosRequest>) -> Result<Response<SosAck>, Status> {
        let sos = request.into_inner();
        let device_id = sos.device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        let mut child_id = String::new();
        let mut family_id = String::new();
        let mut child_name = String::new();
        if let Some(accounts) = &self.accounts {
            if !crate::auth::verify_device_token_strict(
                accounts,
                &device_id,
                sos.device_token.trim(),
            ) {
                return Err(Status::unauthenticated(
                    "unknown, legacy-unpaired, or invalid device credential",
                ));
            }
            let Some((authoritative_child, authoritative_family, authoritative_name)) =
                accounts.child_for_device(&device_id)
            else {
                return Err(Status::unauthenticated("device enrollment is no longer valid"));
            };
            child_id = authoritative_child;
            family_id = authoritative_family;
            child_name = authoritative_name;
        }

        let now = now_ms();
        let alert_id = if sos.client_sos_id.trim().is_empty() {
            format!("{device_id}-sos-{}", now / 1000)
        } else {
            sos.client_sos_id.trim().to_string()
        };
        let event = sos_alert(
            &alert_id,
            &device_id,
            &child_id,
            &family_id,
            &child_name,
            now,
        );
        let reached = self.hub.publish(event.clone());
        let mut sink_delivered = false;
        if let Some(sink) = &self.sink {
            match sink.raise(event).await {
                Ok(ack) => sink_delivered = ack.delivered,
                Err(error) => tracing::warn!(%error, "SOS notification sink failed"),
            }
        }
        let delivered = reached > 0 || sink_delivered;
        Ok(Response::new(SosAck {
            delivered,
            alert_id,
            guardian_streams_reached: reached as u32,
            detail: if delivered {
                "your guardian has been alerted".to_string()
            } else {
                "SOS accepted; no guardian delivery path is currently online".to_string()
            },
        }))
    }

    async fn send_safety_broadcast(
        &self,
        request: Request<SendSafetyBroadcastRequest>,
    ) -> Result<Response<SafetyBroadcastAck>, Status> {
        let metadata_token = crate::accounts::bearer_token(&request);
        let incoming = request.into_inner();

        let issued_by = if let Some(staff) = &self.staff {
            let token = metadata_token
                .as_deref()
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| incoming.staff_token.trim().to_string());
            staff
                .authorize(&token, &[StaffRole::SafetyOfficer, StaffRole::Admin])?
                .staff_id
        } else if let Some(expected) = &self.staff_token_sha256 {
            if !token_matches(expected, &incoming.staff_token) {
                return Err(Status::permission_denied("invalid staff token"));
            }
            "staff-shared-token".to_string()
        } else {
            return Err(Status::unimplemented(
                "staff safety broadcasts are not enabled on this listener",
            ));
        };

        let mut broadcast = incoming
            .broadcast
            .ok_or_else(|| Status::invalid_argument("broadcast is required"))?;
        broadcast.title = broadcast.title.trim().to_string();
        broadcast.body = broadcast.body.trim().to_string();
        if broadcast.title.is_empty() {
            return Err(Status::invalid_argument("broadcast.title is required"));
        }
        if broadcast.title.chars().count() > MAX_TITLE_CHARS
            || broadcast.body.chars().count() > MAX_BODY_CHARS
        {
            return Err(Status::invalid_argument(
                "broadcast title/body exceeds the allowed length",
            ));
        }
        broadcast.region = broadcast.region.trim().to_ascii_lowercase();
        broadcast.broadcast_id = format!("bcast-{}", random_hex(&self.rng, 8));
        broadcast.issued_ts = now_ms();
        broadcast.issued_by = issued_by;
        if broadcast.severity == Severity::Unspecified as i32 {
            broadcast.severity = Severity::High as i32;
        }

        self.broadcasts.add(&broadcast).map_err(|error| {
            tracing::error!(%error, "safety broadcast persistence failed");
            Status::unavailable("could not durably record safety broadcast")
        })?;
        let reached = self.hub.publish(broadcast_alert_event(&broadcast));
        Ok(Response::new(SafetyBroadcastAck {
            accepted: true,
            broadcast_id: broadcast.broadcast_id,
            guardian_streams_reached: reached as u32,
            detail: format!("broadcast stored and fanned out to {reached} guardian stream(s)"),
        }))
    }

    async fn list_safety_broadcasts(
        &self,
        request: Request<ListSafetyBroadcastsRequest>,
    ) -> Result<Response<SafetyBroadcasts>, Status> {
        let metadata_token = crate::accounts::bearer_token(&request);
        let filter = request.into_inner();
        if let Some(accounts) = &self.accounts {
            let session = if filter.token.trim().is_empty() {
                metadata_token.unwrap_or_default()
            } else {
                filter.token.trim().to_string()
            };
            let guardian_ok = !session.is_empty() && accounts.guardian_scope(&session).is_some();
            let device_ok = !filter.device_id.trim().is_empty()
                && crate::auth::verify_device_token_strict(
                    accounts,
                    filter.device_id.trim(),
                    filter.device_token.trim(),
                );
            if !guardian_ok && !device_ok {
                return Err(Status::unauthenticated(
                    "a guardian session or paired-device credential is required",
                ));
            }
        }

        Ok(Response::new(SafetyBroadcasts {
            broadcasts: self.broadcasts.active(now_ms(), filter.region.trim()),
        }))
    }
}

fn production_mode() -> bool {
    matches!(
        std::env::var("BULWARK_PRODUCTION").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        })
}

fn sha256_hex(value: &str) -> String {
    to_hex(ring::digest::digest(&ring::digest::SHA256, value.as_bytes()).as_ref())
}

fn token_matches(expected_sha256_hex: &str, presented: &str) -> bool {
    let presented = sha256_hex(presented.trim());
    if presented.len() != expected_sha256_hex.len() {
        return false;
    }
    presented
        .bytes()
        .zip(expected_sha256_hex.bytes())
        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn random_hex(rng: &SystemRandom, bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    if rng.fill(&mut value).is_err() {
        return format!("{:x}", now_ms());
    }
    to_hex(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupt_durable_broadcast_state_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-broadcast-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("safety_broadcasts.json"), b"not-json").unwrap();
        assert!(SafetyBroadcastStore::with_state_dir(&dir).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
