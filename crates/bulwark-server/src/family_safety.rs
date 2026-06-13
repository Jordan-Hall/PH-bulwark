//! FamilySafety — the family safety-alert surface: child SOS + staff safety
//! broadcasts ("amber-alert-like" notices).
//!
//! TWO directions, one service:
//!
//!   1. **Child SOS** (`RaiseSos`) — the supervised child's one-tap "I need
//!      help" action in the child app. Device-authenticated exactly like
//!      [`crate::tamper::TamperService`] heartbeats (the pairing-minted
//!      `device_token`, with the accounts store's logged legacy grace), then
//!      fanned out as an URGENT `AlertEvent(kind = CHILD_SOS, severity =
//!      CRITICAL)` through the SAME [`AlertHub`] as every other guardian alert
//!      (scoped per child/device by Review's stream), PLUS the configured
//!      email/push [`AlertSink`](bulwark_alert::AlertSink) when one exists.
//!      CONTENT-FREE by construction: child name + device id + time — never
//!      location, messages, or media. (A consent-gated coarse-location
//!      attachment is a LATER increment; nothing here collects location.)
//!
//!   2. **Staff safety broadcasts** (`SendSafetyBroadcast` /
//!      `ListSafetyBroadcasts`) — PH-staff-originated, region-wide family
//!      safety notices fanned out to guardian consoles. HARD RULE: broadcasts
//!      are STAFF-originated only — never crowd-sourced, never a public
//!      accusation. AUTH PLACEHOLDER: until the per-staff accounts/roles
//!      system ships (separate design in progress), the rpc is gated by a
//!      server-side shared token (`BULWARK_STAFF_BROADCAST_TOKEN`); unset =
//!      the rpc is OFF (`Unimplemented`). TODO(staff-system): replace the
//!      shared token with per-staff credentials + a real audit identity — the
//!      proto already carries `issued_by`, so this swaps in without breakage.
//!
//! State: broadcasts persist as JSON under `BULWARK_STATE_DIR` (the `persist`
//! module — the same shape as [`crate::child_control::ChildConfigStore`]; we
//! deliberately do NOT pull in `bulwark-store`/rusqlite, which does not build
//! on the Windows host). SOS events are relayed, not stored: the live stream
//! and the email/push sink are the delivery paths, and the ack tells the child
//! HONESTLY whether a guardian path took the alert.

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::accounts::AccountStore;
use crate::persist::JsonFile;
use crate::relay::AlertHub;
use bulwark_proto::v1::family_safety_server::FamilySafety;
use bulwark_proto::v1::{
    AlertEvent, AlertKind, Category, ListSafetyBroadcastsRequest, SafetyBroadcast,
    SafetyBroadcastAck, SafetyBroadcasts, SendSafetyBroadcastRequest, Severity, SosAck, SosRequest,
};
use ring::rand::{SecureRandom, SystemRandom};
use tonic::{Request, Response, Status};

/// Keep at most this many broadcasts on disk/in memory (oldest dropped) so a
/// misbehaving staff token can't grow the state file without bound.
const MAX_STORED_BROADCASTS: usize = 64;
/// Staff-notice content clamps — plain text, console-card sized.
const MAX_TITLE_CHARS: usize = 120;
const MAX_BODY_CHARS: usize = 2000;

// ---------------------------------------------------------------------------
// Broadcast store — JsonFile-persisted, bounded, newest-first reads.
// ---------------------------------------------------------------------------

/// One persisted staff notice. Content-free in the privacy sense: staff-written
/// plain text + routing metadata only — never media or third-party reports.
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
    fn from_proto(b: &SafetyBroadcast) -> Self {
        Self {
            broadcast_id: b.broadcast_id.clone(),
            title: b.title.clone(),
            body: b.body.clone(),
            severity: b.severity,
            region: b.region.clone(),
            issued_ts: b.issued_ts,
            expires_ts: b.expires_ts,
            notify_child_devices: b.notify_child_devices,
            issued_by: b.issued_by.clone(),
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

    /// Active = no expiry, or not yet expired.
    fn active(&self, now_ms: i64) -> bool {
        self.expires_ts <= 0 || now_ms < self.expires_ts
    }
}

/// Cloneable handle to the staff-notice state. Every clone shares the list.
#[derive(Clone)]
pub struct SafetyBroadcastStore {
    inner: Arc<Mutex<Vec<BroadcastRow>>>,
    /// `Some` → write-through JSON persistence (notices survive a restart);
    /// `None` (default) → pure in-memory.
    persist: Option<JsonFile>,
}

impl Default for SafetyBroadcastStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyBroadcastStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
            persist: None,
        }
    }

    /// Durable store rooted at `dir`: loads `safety_broadcasts.json` on startup
    /// and write-throughs every accepted notice. A corrupt file starts empty
    /// (logged); only an unusable directory is fatal — the same contract as
    /// [`crate::child_control::ChildConfigStore::with_state_dir`].
    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let file = JsonFile::new(dir, "safety_broadcasts.json")?;
        let rows: Vec<BroadcastRow> = file.load_or_default();
        Ok(Self {
            inner: Arc::new(Mutex::new(rows)),
            persist: Some(file),
        })
    }

    /// Append an accepted (already server-stamped) notice, dropping the oldest
    /// beyond the cap, then persist. A write failure is logged, never fatal
    /// (unlike wg-provision, the live stream has already fanned the notice out;
    /// persistence only feeds late-joining consoles).
    fn add(&self, b: &SafetyBroadcast) {
        let mut rows = self.inner.lock().expect("broadcast mutex poisoned");
        rows.push(BroadcastRow::from_proto(b));
        if rows.len() > MAX_STORED_BROADCASTS {
            let excess = rows.len() - MAX_STORED_BROADCASTS;
            rows.drain(..excess);
        }
        if let Some(file) = &self.persist {
            if let Err(e) = file.store(&*rows) {
                tracing::warn!(error = %e, "failed to persist safety broadcasts; continuing in-memory");
            }
        }
    }

    /// Active (unexpired) notices, newest first, optionally filtered to a
    /// region (a notice with an empty region matches every region).
    fn active(&self, now_ms: i64, region: &str) -> Vec<SafetyBroadcast> {
        let region = region.trim().to_ascii_lowercase();
        let rows = self.inner.lock().expect("broadcast mutex poisoned");
        let mut out: Vec<SafetyBroadcast> = rows
            .iter()
            .filter(|r| r.active(now_ms))
            .filter(|r| region.is_empty() || r.region.is_empty() || r.region == region)
            .cloned()
            .map(BroadcastRow::into_proto)
            .collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.issued_ts)); // newest first
        out
    }
}

// ---------------------------------------------------------------------------
// Alert builders — redacted, content-free events for the guardian fan-out.
// ---------------------------------------------------------------------------

/// Build the URGENT child-SOS alert. Content-free: who (name, when known),
/// which device, and when — never location, messages, or media.
fn sos_alert(
    alert_id: &str,
    device_id: &str,
    child_id: &str,
    family_id: &str,
    child_name: &str,
    now_ms: i64,
) -> AlertEvent {
    let who = if child_name.trim().is_empty() {
        "Your child".to_string()
    } else {
        child_name.trim().to_string()
    };
    AlertEvent {
        alert_id: alert_id.to_string(),
        kind: AlertKind::ChildSos as i32,
        category: Category::Safe as i32, // a help signal, not a content category
        severity: Severity::Critical as i32,
        device_id: device_id.to_string(),
        child_id: child_id.to_string(),
        family_id: family_id.to_string(),
        ts: now_ms,
        redacted_context: format!(
            "URGENT: {who} pressed the SOS button in PH Bulwark on their device. \
             Please contact them right away."
        ),
        ..Default::default()
    }
}

/// Re-shape a staff notice as the SAFETY_BROADCAST alert the console renders.
/// `app` carries the region label (the console shows it as the notice's scope).
pub fn broadcast_alert_event(b: &SafetyBroadcast) -> AlertEvent {
    AlertEvent {
        alert_id: b.broadcast_id.clone(),
        kind: AlertKind::SafetyBroadcast as i32,
        category: Category::Safe as i32,
        severity: b.severity,
        app: b.region.clone(),
        ts: b.issued_ts,
        redacted_context: if b.body.is_empty() {
            b.title.clone()
        } else {
            format!("{} — {}", b.title, b.body)
        },
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// gRPC service
// ---------------------------------------------------------------------------

/// Implements `bulwark_proto::v1::family_safety_server::FamilySafety` over the
/// shared [`AlertHub`] + an optional [`AccountStore`] (device auth + child
/// lookup) + an optional alert sink (email/push for the URGENT SOS path).
#[derive(Clone)]
pub struct FamilySafetyService {
    hub: AlertHub,
    broadcasts: SafetyBroadcastStore,
    /// `Some` (accounts mode) → SOS must present the pairing-minted device
    /// token and List requires a guardian session OR device identity;
    /// `None` (legacy/dev) → open, exactly like [`crate::tamper::TamperService`].
    accounts: Option<AccountStore>,
    /// URGENT delivery beyond live streams: the same email/push sink
    /// `AlertRelay` uses, when the operator configured one.
    sink: Option<Arc<dyn bulwark_alert::AlertSink>>,
    /// sha256-hex of the shared staff token. `None` = broadcasts disabled.
    /// PLACEHOLDER until the staff-management system ships (see module docs).
    staff_token_sha256: Option<String>,
    rng: Arc<SystemRandom>,
}

impl FamilySafetyService {
    pub fn new(hub: AlertHub, broadcasts: SafetyBroadcastStore) -> Self {
        Self {
            hub,
            broadcasts,
            accounts: None,
            sink: None,
            staff_token_sha256: None,
            rng: Arc::new(SystemRandom::new()),
        }
    }

    /// Require SOS device authentication (and gate List) against `accounts` —
    /// the SAME store that minted each device's token at pairing.
    pub fn with_accounts(mut self, accounts: AccountStore) -> Self {
        self.accounts = Some(accounts);
        self
    }

    /// Also deliver SOS alerts through the configured email/push sink.
    pub fn with_alert_sink(mut self, sink: Option<Arc<dyn bulwark_alert::AlertSink>>) -> Self {
        self.sink = sink;
        self
    }

    /// Enable staff broadcasts gated by `raw` (hashed immediately; the raw
    /// token never sits in memory longer than this call). `None`/empty = off.
    pub fn with_staff_token(mut self, raw: Option<String>) -> Self {
        self.staff_token_sha256 = raw
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .map(|t| sha256_hex(&t));
        self
    }

    /// PLACEHOLDER staff gate from the environment
    /// (`BULWARK_STAFF_BROADCAST_TOKEN`). TODO(staff-system): retire this in
    /// favour of per-staff credentials once the staff-management design ships.
    pub fn with_staff_token_from_env(self) -> Self {
        let raw = std::env::var("BULWARK_STAFF_BROADCAST_TOKEN").ok();
        match raw.as_deref().map(str::trim) {
            Some(t) if !t.is_empty() => tracing::info!(
                "staff safety broadcasts ENABLED via shared env token \
                 (placeholder until the staff accounts system ships)"
            ),
            _ => tracing::info!(
                "staff safety broadcasts disabled (BULWARK_STAFF_BROADCAST_TOKEN unset)"
            ),
        }
        self.with_staff_token(raw)
    }
}

#[tonic::async_trait]
impl FamilySafety for FamilySafetyService {
    async fn raise_sos(&self, req: Request<SosRequest>) -> Result<Response<SosAck>, Status> {
        let r = req.into_inner();
        let device_id = r.device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }

        // Devices authenticate (accounts mode): the SOS must carry the
        // per-device token minted at pairing, so knowing a device_id alone is
        // never enough to page a family. Devices enrolled before tokens
        // existed pass under the store's logged legacy grace — exactly the
        // Tamper.Heartbeat contract.
        let mut child_id = String::new();
        let mut family_id = String::new();
        let mut child_name = String::new();
        if let Some(accounts) = &self.accounts {
            if !accounts.verify_device_token(&device_id, &r.device_token) {
                return Err(Status::unauthenticated(
                    "unknown device or invalid device token",
                ));
            }
            if let Some((cid, fid, name)) = accounts.child_for_device(&device_id) {
                child_id = cid;
                family_id = fid;
                child_name = name;
            }
        }

        let now = now_ms();
        // Idempotency: a retried tap re-uses its client id; the alert path
        // (stream consumers + the email sink) dedupes on alert_id.
        let alert_id = if r.client_sos_id.trim().is_empty() {
            format!("{device_id}-sos-{}", now / 1000)
        } else {
            r.client_sos_id.trim().to_string()
        };

        let event = sos_alert(
            &alert_id,
            &device_id,
            &child_id,
            &family_id,
            &child_name,
            now,
        );

        // Fan out to live guardian streams (scoped per child/device by Review).
        let reached = self.hub.publish(event.clone());

        // URGENT: also email/push when the node has a sink. Best-effort — a
        // sink failure must never turn a delivered stream alert into an error.
        let mut sink_delivered = false;
        if let Some(sink) = &self.sink {
            match sink.raise(event).await {
                Ok(ack) => sink_delivered = ack.delivered,
                Err(e) => {
                    tracing::warn!(error = %e, "SOS sink delivery failed (stream fan-out unaffected)")
                }
            }
        }

        let delivered = reached > 0 || sink_delivered;
        tracing::warn!(
            device = %device_id,
            streams = reached,
            sink = sink_delivered,
            "child SOS raised"
        );
        Ok(Response::new(SosAck {
            delivered,
            alert_id,
            guardian_streams_reached: reached as u32,
            detail: if delivered {
                "your guardian has been alerted".to_string()
            } else {
                "sent, but no guardian is connected right now".to_string()
            },
        }))
    }

    async fn send_safety_broadcast(
        &self,
        req: Request<SendSafetyBroadcastRequest>,
    ) -> Result<Response<SafetyBroadcastAck>, Status> {
        let r = req.into_inner();

        // PLACEHOLDER staff gate (see module docs). Unset = the rpc is off, so
        // a default deployment exposes NO broadcast surface at all.
        let Some(expected) = &self.staff_token_sha256 else {
            return Err(Status::unimplemented(
                "staff safety broadcasts are not enabled on this node \
                 (BULWARK_STAFF_BROADCAST_TOKEN unset; per-staff accounts are in design)",
            ));
        };
        if !token_matches(expected, &r.staff_token) {
            return Err(Status::permission_denied("invalid staff token"));
        }

        let mut b = r
            .broadcast
            .ok_or_else(|| Status::invalid_argument("broadcast is required"))?;
        let title = b.title.trim().to_string();
        if title.is_empty() {
            return Err(Status::invalid_argument("broadcast.title is required"));
        }
        if title.chars().count() > MAX_TITLE_CHARS || b.body.trim().chars().count() > MAX_BODY_CHARS
        {
            return Err(Status::invalid_argument(
                "broadcast title/body exceeds the allowed length",
            ));
        }

        // Server-stamped fields — never trusted from the caller.
        b.title = title;
        b.body = b.body.trim().to_string();
        b.region = b.region.trim().to_ascii_lowercase();
        b.broadcast_id = format!("bcast-{}", random_hex(&self.rng, 8));
        b.issued_ts = now_ms();
        // TODO(staff-system): a real staff account id once staff auth exists.
        b.issued_by = "staff-shared-token".to_string();
        if b.severity == Severity::Unspecified as i32 {
            b.severity = Severity::High as i32;
        }

        // Persist FIRST (late-joining consoles fetch via List), then fan out
        // to every live guardian stream (Review passes SAFETY_BROADCAST
        // through its per-child scoping — region-wide by design).
        self.broadcasts.add(&b);
        let reached = self.hub.publish(broadcast_alert_event(&b));
        tracing::warn!(broadcast = %b.broadcast_id, region = %b.region, streams = reached,
            "staff safety broadcast issued");

        Ok(Response::new(SafetyBroadcastAck {
            accepted: true,
            broadcast_id: b.broadcast_id,
            guardian_streams_reached: reached as u32,
            detail: format!("broadcast stored and fanned out to {reached} guardian stream(s)"),
        }))
    }

    async fn list_safety_broadcasts(
        &self,
        req: Request<ListSafetyBroadcastsRequest>,
    ) -> Result<Response<SafetyBroadcasts>, Status> {
        let meta_token = crate::accounts::bearer_token(&req);
        let r = req.into_inner();

        // In accounts mode the caller must be EITHER a signed-in guardian or
        // an enrolled device. Legacy/dev (no accounts mounted) stays open,
        // matching every other read on such nodes.
        if let Some(accounts) = &self.accounts {
            let token = if !r.token.trim().is_empty() {
                r.token.trim().to_string()
            } else {
                meta_token.unwrap_or_default()
            };
            let guardian_ok = !token.is_empty() && accounts.guardian_scope(&token).is_some();
            let device_ok = !r.device_id.trim().is_empty()
                && accounts.verify_device_token(r.device_id.trim(), &r.device_token);
            if !guardian_ok && !device_ok {
                return Err(Status::unauthenticated(
                    "a guardian session token or an enrolled device identity is required",
                ));
            }
        }

        Ok(Response::new(SafetyBroadcasts {
            broadcasts: self.broadcasts.active(now_ms(), r.region.trim()),
        }))
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn sha256_hex(s: &str) -> String {
    to_hex(ring::digest::digest(&ring::digest::SHA256, s.as_bytes()).as_ref())
}

/// Constant-time compare of the presented staff token against the stored
/// sha256-hex digest. Both sides are sha256-hex (fixed 64 chars), so length
/// never leaks and the fold below runs the full width regardless of where the
/// first mismatch is — no early-out timing oracle. (`ring`'s own
/// `verify_slices_are_equal` is deprecated as an internal API, so we keep a
/// tiny explicit constant-time fold here.)
fn token_matches(expected_sha256_hex: &str, presented: &str) -> bool {
    let presented_hex = sha256_hex(presented.trim());
    let a = presented_hex.as_bytes();
    let b = expected_sha256_hex.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Random hex id for a broadcast (a routing key, not a secret). Falls back to
/// a time-based id if the system RNG ever fails — never panics.
fn random_hex(rng: &SystemRandom, bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if rng.fill(&mut buf).is_err() {
        return format!("{:x}", now_ms());
    }
    to_hex(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::review_server::Review;
    use bulwark_proto::v1::DeviceFilter;
    use futures_util::StreamExt;

    /// Accounts store with one PAIRED device — returns the raw device token
    /// exactly the way the device received it at redeem (the tamper-test shape).
    fn accounts_with_paired_device(device: &str) -> (AccountStore, String) {
        let accounts = AccountStore::new();
        accounts
            .create_account("p@x.com", "password123", "P")
            .unwrap();
        let (tok, _aid, _) = accounts.login("p@x.com", "password123").unwrap();
        let (code, _) = accounts.create_pair_code(&tok, "Kid").unwrap();
        let (_child, _family, device_token) = accounts.redeem_pair_code(&code, device).unwrap();
        (accounts, device_token)
    }

    fn sos(device: &str, token: &str) -> SosRequest {
        SosRequest {
            device_id: device.to_string(),
            device_token: token.to_string(),
            ts: 1,
            client_sos_id: String::new(),
        }
    }

    #[tokio::test]
    async fn sos_reaches_a_guardian_stream_and_acks_delivered() {
        let hub = AlertHub::new();
        let review = crate::relay::ReviewService::new(hub.clone());
        let resp = review
            .stream_pending_reviews(Request::new(DeviceFilter::default()))
            .await
            .expect("stream opens");
        let mut stream = resp.into_inner();

        let svc = FamilySafetyService::new(hub, SafetyBroadcastStore::new());
        let mut req = sos("kids-phone", "");
        req.client_sos_id = "sos-1".into();
        let ack = svc
            .raise_sos(Request::new(req))
            .await
            .expect("open in non-accounts mode")
            .into_inner();
        assert!(ack.delivered);
        assert_eq!(ack.guardian_streams_reached, 1);
        assert_eq!(ack.alert_id, "sos-1");

        let got = stream.next().await.expect("an item").expect("ok event");
        assert_eq!(got.kind, AlertKind::ChildSos as i32);
        assert_eq!(got.severity, Severity::Critical as i32);
        assert_eq!(got.device_id, "kids-phone");
        assert!(got.evidence.is_none(), "an SOS carries no content");
    }

    #[tokio::test]
    async fn sos_without_subscribers_is_accepted_but_honest() {
        let svc = FamilySafetyService::new(AlertHub::new(), SafetyBroadcastStore::new());
        let ack = svc
            .raise_sos(Request::new(sos("kids-phone", "")))
            .await
            .expect("accepted")
            .into_inner();
        assert!(!ack.delivered, "no stream + no sink = honestly undelivered");
        assert_eq!(ack.guardian_streams_reached, 0);
    }

    #[tokio::test]
    async fn sos_requires_the_device_token_in_accounts_mode() {
        let (accounts, device_token) = accounts_with_paired_device("kids-phone");
        let svc = FamilySafetyService::new(AlertHub::new(), SafetyBroadcastStore::new())
            .with_accounts(accounts);

        // Wrong token → unauthenticated (no spoofed SOS pages a family).
        let err = svc
            .raise_sos(Request::new(sos("kids-phone", "not-the-token")))
            .await
            .expect_err("wrong token rejected");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        // Unknown device → unauthenticated.
        let err = svc
            .raise_sos(Request::new(sos("never-enrolled", "x")))
            .await
            .expect_err("unknown device rejected");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        // The real token is accepted and the alert carries the child's name.
        let ack = svc
            .raise_sos(Request::new(sos("kids-phone", &device_token)))
            .await
            .expect("real device accepted")
            .into_inner();
        assert!(!ack.alert_id.is_empty());
    }

    #[test]
    fn sos_alert_is_urgent_and_content_free() {
        let ev = sos_alert("a1", "dev-1", "c1", "f1", "Kid", 42);
        assert_eq!(ev.kind, AlertKind::ChildSos as i32);
        assert_eq!(ev.severity, Severity::Critical as i32);
        assert!(ev.redacted_context.contains("Kid"));
        assert!(ev.evidence.is_none());
        assert_eq!(ev.child_id, "c1");
        assert_eq!(ev.family_id, "f1");

        // Unknown child name degrades gracefully — never blocks the SOS.
        let ev = sos_alert("a2", "dev-1", "", "", "", 42);
        assert!(ev.redacted_context.contains("Your child"));
    }

    fn staff_broadcast(title: &str) -> SendSafetyBroadcastRequest {
        SendSafetyBroadcastRequest {
            staff_token: "s3cret-staff".to_string(),
            broadcast: Some(SafetyBroadcast {
                title: title.to_string(),
                body: "A reminder from PH staff for families in this region.".to_string(),
                severity: Severity::High as i32,
                region: "uk".to_string(),
                ..Default::default()
            }),
        }
    }

    #[tokio::test]
    async fn broadcasts_are_gated_stamped_and_listed() {
        // No token configured → the rpc is OFF.
        let off = FamilySafetyService::new(AlertHub::new(), SafetyBroadcastStore::new());
        let err = off
            .send_safety_broadcast(Request::new(staff_broadcast("Notice")))
            .await
            .expect_err("disabled without a staff token");
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let svc = FamilySafetyService::new(AlertHub::new(), SafetyBroadcastStore::new())
            .with_staff_token(Some("s3cret-staff".to_string()));

        // Wrong token → permission denied.
        let mut wrong = staff_broadcast("Notice");
        wrong.staff_token = "guess".to_string();
        let err = svc
            .send_safety_broadcast(Request::new(wrong))
            .await
            .expect_err("wrong staff token rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // Right token → accepted, server-stamped, listed (open: no accounts).
        let ack = svc
            .send_safety_broadcast(Request::new(staff_broadcast("Safety notice")))
            .await
            .expect("accepted")
            .into_inner();
        assert!(ack.accepted);
        assert!(ack.broadcast_id.starts_with("bcast-"));

        let listed = svc
            .list_safety_broadcasts(Request::new(ListSafetyBroadcastsRequest::default()))
            .await
            .expect("listable")
            .into_inner();
        assert_eq!(listed.broadcasts.len(), 1);
        let b = &listed.broadcasts[0];
        assert_eq!(b.broadcast_id, ack.broadcast_id);
        assert_eq!(b.issued_by, "staff-shared-token", "server-stamped");
        assert!(b.issued_ts > 0, "server-stamped");
    }

    #[tokio::test]
    async fn expired_broadcasts_are_not_listed() {
        let store = SafetyBroadcastStore::new();
        let svc = FamilySafetyService::new(AlertHub::new(), store.clone())
            .with_staff_token(Some("s3cret-staff".to_string()));

        // An already-expired notice (stamped directly into the store).
        store.add(&SafetyBroadcast {
            broadcast_id: "bcast-old".into(),
            title: "Old".into(),
            issued_ts: 1,
            expires_ts: 2, // long past
            ..Default::default()
        });
        svc.send_safety_broadcast(Request::new(staff_broadcast("Fresh")))
            .await
            .expect("accepted");

        let listed = svc
            .list_safety_broadcasts(Request::new(ListSafetyBroadcastsRequest::default()))
            .await
            .expect("listable")
            .into_inner();
        assert_eq!(listed.broadcasts.len(), 1);
        assert_eq!(listed.broadcasts[0].title, "Fresh");
    }

    #[tokio::test]
    async fn list_requires_identity_in_accounts_mode() {
        let (accounts, device_token) = accounts_with_paired_device("kids-phone");
        let svc = FamilySafetyService::new(AlertHub::new(), SafetyBroadcastStore::new())
            .with_accounts(accounts.clone());

        // Anonymous → unauthenticated.
        let err = svc
            .list_safety_broadcasts(Request::new(ListSafetyBroadcastsRequest::default()))
            .await
            .expect_err("anonymous list rejected");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        // Enrolled device identity → allowed.
        let ok = svc
            .list_safety_broadcasts(Request::new(ListSafetyBroadcastsRequest {
                device_id: "kids-phone".into(),
                device_token,
                ..Default::default()
            }))
            .await
            .expect("device identity accepted");
        assert!(ok.into_inner().broadcasts.is_empty());

        // Guardian session → allowed.
        let (tok, _aid, _) = accounts.login("p@x.com", "password123").unwrap();
        let ok = svc
            .list_safety_broadcasts(Request::new(ListSafetyBroadcastsRequest {
                token: tok,
                ..Default::default()
            }))
            .await
            .expect("guardian session accepted");
        assert!(ok.into_inner().broadcasts.is_empty());
    }

    #[tokio::test]
    async fn broadcasts_persist_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-broadcasts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let s1 = SafetyBroadcastStore::with_state_dir(&dir).unwrap();
        let svc = FamilySafetyService::new(AlertHub::new(), s1)
            .with_staff_token(Some("s3cret-staff".to_string()));
        let ack = svc
            .send_safety_broadcast(Request::new(staff_broadcast("Survives restarts")))
            .await
            .expect("accepted")
            .into_inner();
        drop(svc); // simulate a restart

        let s2 = SafetyBroadcastStore::with_state_dir(&dir).unwrap();
        let active = s2.active(now_ms(), "");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].broadcast_id, ack.broadcast_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staff_token_compare_is_exact() {
        let digest = sha256_hex("s3cret-staff");
        assert!(token_matches(&digest, "s3cret-staff"));
        assert!(token_matches(&digest, "  s3cret-staff  "), "trims");
        assert!(!token_matches(&digest, "s3cret-staf"));
        assert!(!token_matches(&digest, ""));
    }
}
