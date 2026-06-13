//! Guardian-facing relay state shared by the `AlertRelay` and `Review` gRPC
//! services.
//!
//! Both services fan a redacted [`AlertEvent`] out to subscribed guardian
//! clients over a [`tokio::sync::broadcast`] channel:
//!   * `AlertRelay::RaiseAlert` / `RaiseAlerts` accept alerts (from the
//!     client/server data plane or `bulwark-alert`) and **publish** them into the
//!     channel (in addition to handing them to the e-mail sink).
//!   * `Review::StreamPendingReviews` **subscribes** to the channel and streams
//!     the same redacted events to a guardian's Review screen.
//!   * `Review::SubmitDecision` applies an APPROVE/DENY to the per-device
//!     [`Allowlist`] from `bulwark-policy` (CSAM is never allowlistable — the
//!     allowlist module enforces this; we surface its refusal as a `Status`).
//!   * `Review::RegisterPushTarget` records a guardian's self-hosted UnifiedPush
//!     endpoint URL.
//!
//! PRIVACY INVARIANT: only the redacted [`AlertEvent`] (hashes / safe thumbnail
//! / redacted context) ever crosses these channels — never raw media. This is
//! the same no-media guarantee `bulwark-alert` enforces at render time.
//!
//! State is **in-memory** for this wave (broadcast channel + `Arc<Mutex<…>>`
//! maps). See the `// SEAM:` markers for where durable storage (an audited
//! allowlist + a pending-review queue) would plug in. We deliberately do NOT
//! pull in `bulwark-store`/rusqlite here — it fails to build on the Windows host
//! (os error 4551, environmental) and `bulwark-server` must keep building.

use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::persist::JsonFile;
use bulwark_policy::{Allowlist, ApplyOutcome, ReviewItem};
use bulwark_proto::v1::{
    AlertEvent, AlertKind, Category, DeviceFilter, PushAck, PushTarget, ReviewAck, ReviewDecision,
    ReviewRequest, ReviewScope, SegmentChunk, SegmentRequest,
};
use bulwark_proto::DeviceId;
use futures_core::Stream;
use tonic::{Request, Response, Status};

/// How many alerts a slow guardian subscriber can fall behind before the
/// broadcast channel starts dropping the oldest for that receiver. Lagged
/// receivers get a `Lagged` error which we map to a skipped item (never a hard
/// stream failure) so one slow client cannot stall the relay.
const ALERT_BROADCAST_CAPACITY: usize = 256;

/// Shared, cloneable handle to the guardian relay's in-memory state.
///
/// Clone freely — every clone shares the same broadcast channel and maps. The
/// rest of the server publishes alerts through [`AlertHub::publish`].
#[derive(Clone)]
pub struct AlertHub {
    /// Fan-out channel of redacted alerts. `AlertRelay` publishes; `Review`'s
    /// `StreamPendingReviews` subscribes.
    tx: tokio::sync::broadcast::Sender<AlertEvent>,
    /// Per-device guardian approve-allowlist + tamper-evident audit chain.
    // SEAM: durable storage — back this with an audited, persisted allowlist
    // (e.g. bulwark-store) so guardian decisions survive a restart. The
    // `bulwark-policy::Allowlist` API (`apply`, `is_host_allowed`, `audit`) is
    // unchanged; only construction/load + write-through would move here.
    allowlist: Arc<Mutex<Allowlist>>,
    /// Registered remote-push targets, keyed by OWNER: the guardian **account
    /// id** in accounts mode (so a re-registration overwrites and one guardian
    /// can't clobber another), or the device id in single-tenant dev. Fan-out is
    /// SCOPED — see [`AlertHub::endpoints_for`].
    // SEAM: durable storage — persist UnifiedPush endpoint URLs (no alert
    // content) so a guardian stays reachable across restarts.
    push_targets: Arc<Mutex<HashMap<String, PushTarget>>>,
    /// Pending-review records keyed by `alert_id`: the redacted facts a
    /// `SubmitDecision` needs to resolve a `ReviewItem` (host/hash/category)
    /// without re-shipping the original event. A `ReviewRequest` carries only
    /// `alert_id` + the guardian's decision, so the server must remember which
    /// host/category that alert referred to in order to (a) key an APPROVE on a
    /// real host and (b) re-check the CSAM-never-allowlistable rule. Content-free
    /// (host + hash + category only — never raw media or message text).
    // Persisted as JSON when a state dir is configured (`with_state_dir`).
    pending: Arc<Mutex<HashMap<String, PendingReview>>>,
    /// `Some` → write-through JSON persistence for push targets, pending reviews,
    /// AND the approve-allowlist (persisted as a decision journal + replayed on
    /// load — see `replay_audit`). `None` (default) → pure in-memory.
    persist: Option<HubPersist>,
    /// Parent-accounts store, ATTACHED in `run()` once it's built
    /// ([`AlertHub::attach_accounts`]). Lets [`AlertHub::endpoints_for`] map an
    /// alert's child/device → the assigned guardians → their push endpoints, so a
    /// redacted alert reaches ONLY that family (multi-tenant isolation). Never
    /// attached (single-tenant dev) → fan out to every registered endpoint.
    accounts: Arc<std::sync::OnceLock<crate::accounts::AccountStore>>,
}

/// Where the hub's push targets + pending reviews are persisted (push-target/
/// pending-review JSON files under the state dir). Cheap to clone (paths only).
#[derive(Clone, Debug)]
struct HubPersist {
    push: JsonFile,
    pending: JsonFile,
    /// The guardian-decision journal (`Vec<AuditEntryRow>`). The live `Allowlist`
    /// is rebuilt by re-applying these rows on load (`replay_audit`), which also
    /// re-derives a valid audit chain deterministically.
    audit: JsonFile,
}

/// One persisted guardian-decision journal row (content-free). Enough to re-run
/// `Allowlist::apply` and reproduce both the allow-sets and the audit chain.
#[derive(Serialize, Deserialize)]
struct AuditEntryRow {
    device_id: String,
    alert_id: String,
    decision: i32, // ReviewDecision
    scope: i32,    // ReviewScope
    host: String,
    sha256_hex: String,
    category: i32, // Category
    ts: i64,
}

/// The content-free facts the relay retains about a raised alert so a later
/// guardian decision can be resolved into a `ReviewItem`. Mirrors the
/// `Evidence`/`AlertEvent` no-media invariant: host (the app/site), the content
/// hash, and the category only.
#[derive(Clone, Serialize, Deserialize)]
struct PendingReview {
    /// `AlertEvent.app` — the host/site an APPROVE(THIS_HOST) allowlists.
    host: String,
    /// `Evidence.sha256` (may be empty) — the hash an APPROVE(THIS_ITEM) keys on.
    sha256: Vec<u8>,
    /// The flagged category, so CSAM stays un-allowlistable even at decision time.
    category: Category,
}

impl Default for AlertHub {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertHub {
    /// Build a fresh hub with an empty allowlist and no subscribers.
    pub fn new() -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(ALERT_BROADCAST_CAPACITY);
        Self {
            tx,
            allowlist: Arc::new(Mutex::new(Allowlist::new())),
            push_targets: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            persist: None,
            accounts: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Durable hub rooted at `dir`: loads push targets + pending reviews on
    /// startup and write-throughs each change. (The allowlist is not yet
    /// persisted — see `persist`.) A corrupt file starts empty; only an unusable
    /// directory is fatal.
    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let (tx, _rx) = tokio::sync::broadcast::channel(ALERT_BROADCAST_CAPACITY);
        let push = JsonFile::new(dir, "push_targets.json")?;
        let pending = JsonFile::new(dir, "pending_reviews.json")?;
        let audit = JsonFile::new(dir, "allowlist_audit.json")?;
        let push_targets: HashMap<String, PushTarget> = push.load_or_default();
        let pending_map: HashMap<String, PendingReview> = pending.load_or_default();
        // Rebuild the allowlist by re-applying the persisted decision journal.
        let allowlist = replay_audit(audit.load_or_default());
        Ok(Self {
            tx,
            allowlist: Arc::new(Mutex::new(allowlist)),
            push_targets: Arc::new(Mutex::new(push_targets)),
            pending: Arc::new(Mutex::new(pending_map)),
            persist: Some(HubPersist {
                push,
                pending,
                audit,
            }),
            accounts: Arc::new(std::sync::OnceLock::new()),
        })
    }

    fn persist_audit(&self, allowlist: &Allowlist) {
        if let Some(p) = &self.persist {
            if let Err(e) = p.audit.store(&audit_rows(allowlist)) {
                tracing::warn!(error = %e, "failed to persist allowlist audit; continuing in-memory");
            }
        }
    }

    fn persist_push(&self, map: &HashMap<String, PushTarget>) {
        if let Some(p) = &self.persist {
            if let Err(e) = p.push.store(map) {
                tracing::warn!(error = %e, "failed to persist push targets; continuing in-memory");
            }
        }
    }

    fn persist_pending(&self, map: &HashMap<String, PendingReview>) {
        if let Some(p) = &self.persist {
            if let Err(e) = p.pending.store(map) {
                tracing::warn!(error = %e, "failed to persist pending reviews; continuing in-memory");
            }
        }
    }

    /// Publish a redacted [`AlertEvent`] to all current guardian subscribers.
    ///
    /// This is how the rest of the server (the data plane, or the `AlertRelay`
    /// service) injects an alert into the fan-out: hold an [`AlertHub`] (it is
    /// `Clone`) and call `publish`. Returns the number of subscribers the event
    /// reached (`0` when nobody is currently streaming — not an error).
    pub fn publish(&self, event: AlertEvent) -> usize {
        // Remember the content-free facts of this alert so a later guardian
        // SubmitDecision (which carries only the alert_id) can resolve the real
        // host/hash/category — keyed by alert_id. No raw media is retained.
        if !event.alert_id.trim().is_empty() {
            let record = PendingReview {
                host: event.app.clone(),
                sha256: event
                    .evidence
                    .as_ref()
                    .map(|e| e.sha256.clone())
                    .unwrap_or_default(),
                category: event.category(),
            };
            let mut guard = self.pending.lock().expect("pending-review mutex poisoned");
            guard.insert(event.alert_id.clone(), record);
            self.persist_pending(&guard);
        }
        // `send` errors only when there are zero receivers; that is normal
        // (no guardian streaming right now), so treat it as "reached 0".
        self.tx.send(event).unwrap_or(0)
    }

    /// Resolve the retained facts for a raised alert into the `ReviewItem` the
    /// allowlist applies. Returns `None` when no alert with this id was seen
    /// (the decision then keys on an empty item — an APPROVE it cannot resolve
    /// is refused, conservatively, which is the documented behaviour).
    fn resolve_item(&self, device: DeviceId, alert_id: &str) -> ReviewItem {
        let pending = self.pending.lock().expect("pending-review mutex poisoned");
        match pending.get(alert_id) {
            Some(p) => ReviewItem::new(
                device,
                alert_id.to_string(),
                p.host.clone(),
                p.sha256.clone(),
                p.category,
            ),
            None => ReviewItem::new(
                device,
                alert_id.to_string(),
                String::new(),
                Vec::new(),
                Category::Unspecified,
            ),
        }
    }

    /// Choose the scope to actually apply. An APPROVE(THIS_HOST) for an alert that
    /// has NO host — image blocks happen on the response leg, which carries no
    /// hostname — but DOES have a content hash is downgraded to THIS_ITEM, so it
    /// allowlists that specific image by hash (the "approve this image" model).
    /// DENY and host-bearing alerts keep the requested scope.
    fn effective_scope(
        &self,
        alert_id: &str,
        requested: ReviewScope,
        decision: ReviewDecision,
    ) -> ReviewScope {
        if decision != ReviewDecision::Approve || requested != ReviewScope::ThisHost {
            return requested;
        }
        let pending = self.pending.lock().expect("pending-review mutex poisoned");
        match pending.get(alert_id) {
            Some(p) if p.host.trim().is_empty() && !p.sha256.is_empty() => ReviewScope::ThisItem,
            _ => requested,
        }
    }

    /// Subscribe to the alert fan-out (used by `StreamPendingReviews`).
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<AlertEvent> {
        self.tx.subscribe()
    }

    /// Apply a resolved guardian decision to the per-device allowlist, returning
    /// the policy outcome. CSAM APPROVEs are refused inside `bulwark-policy`.
    fn apply_decision(
        &self,
        item: &ReviewItem,
        decision: ReviewDecision,
        scope: ReviewScope,
        ts: i64,
    ) -> ApplyOutcome {
        // SEAM: durable storage — wrap this in a write-through to a persisted,
        // audited allowlist. The in-memory `Allowlist` already chains its audit
        // log (`allowlist.audit().verify()`); persistence would flush it.
        let mut guard = self.allowlist.lock().expect("allowlist mutex poisoned");
        let outcome = guard.apply(item, decision, scope, ts);
        self.persist_audit(&guard);
        outcome
    }

    /// Attach the parent-accounts store so push fan-out is SCOPED per guardian
    /// (see [`Self::endpoints_for`]). Called once in `run()` after the store is
    /// built; idempotent (a second call is ignored).
    pub fn attach_accounts(&self, store: crate::accounts::AccountStore) {
        let _ = self.accounts.set(store);
    }

    /// Record a guardian's remote-push routing endpoint (no alert content), keyed
    /// by `owner` — the guardian account id in accounts mode (so re-registration
    /// overwrites and one guardian can't clobber another), or the device id in dev.
    fn register_push(&self, owner: String, target: PushTarget) {
        let mut guard = self
            .push_targets
            .lock()
            .expect("push-target mutex poisoned");
        guard.insert(owner, target);
        self.persist_push(&guard);
    }

    /// Snapshot of EVERY registered guardian UnifiedPush endpoint URL (empties
    /// dropped). The single-tenant / dev fan-out target; accounts mode uses the
    /// SCOPED [`Self::endpoints_for`] instead.
    pub fn push_tokens(&self) -> Vec<String> {
        self.push_targets
            .lock()
            .expect("push-target mutex poisoned")
            .values()
            .map(|t| t.push_endpoint.clone())
            .filter(|t| !t.trim().is_empty())
            .collect()
    }

    /// The guardian endpoints that should receive `event` — SCOPED so a redacted
    /// alert reaches ONLY the guardians assigned to its child/device, never
    /// another family (multi-tenant isolation, #140). With an accounts store
    /// attached: resolve the alert's child (by `child_id`, else the child
    /// `device_id`) → its guardian account ids → their registered endpoints.
    /// Without one (single-tenant dev) every registered endpoint is returned.
    pub fn endpoints_for(&self, event: &AlertEvent) -> Vec<String> {
        let Some(accounts) = self.accounts.get() else {
            return self.push_tokens(); // single-tenant dev: no scoping needed
        };
        let owners: Vec<String> = if !event.child_id.trim().is_empty() {
            accounts.guardians_for_child(&event.child_id)
        } else {
            accounts.guardians_for_device(&event.device_id)
        };
        let guard = self
            .push_targets
            .lock()
            .expect("push-target mutex poisoned");
        owners
            .iter()
            .filter_map(|owner| guard.get(owner))
            .map(|t| t.push_endpoint.clone())
            .filter(|e| !e.trim().is_empty())
            .collect()
    }
}

/// Adapts an [`AlertHub`] to `bulwark_alert::TokenRegistry` so the UnifiedPush
/// fan-out sink reads the live guardian endpoint URLs at raise time. Push-feature
/// only.
#[cfg(feature = "push")]
pub struct HubTokenRegistry {
    hub: AlertHub,
}

#[cfg(feature = "push")]
impl HubTokenRegistry {
    pub fn new(hub: AlertHub) -> Self {
        Self { hub }
    }
}

#[cfg(feature = "push")]
impl bulwark_alert::TokenRegistry for HubTokenRegistry {
    fn endpoints_for(&self, event: &AlertEvent) -> Vec<String> {
        self.hub.endpoints_for(event)
    }
}

/// Build the persistable decision journal from the live allowlist's audit log.
fn audit_rows(allowlist: &Allowlist) -> Vec<AuditEntryRow> {
    allowlist
        .audit()
        .entries()
        .iter()
        .map(|e| AuditEntryRow {
            device_id: e.device_id.clone(),
            alert_id: e.alert_id.clone(),
            decision: e.decision as i32,
            scope: e.scope as i32,
            host: e.host.clone(),
            sha256_hex: e.sha256_hex.clone(),
            category: e.category as i32,
            ts: e.ts,
        })
        .collect()
}

/// Rebuild an [`Allowlist`] by re-applying a persisted decision journal in order.
/// Each row reproduces the original `apply` (same per-device allow-sets + a fresh,
/// valid audit chain — re-derived deterministically). A malformed row is skipped;
/// CSAM approvals replay to `Refused` again. Never panics.
fn replay_audit(rows: Vec<AuditEntryRow>) -> Allowlist {
    let mut allowlist = Allowlist::new();
    for r in rows {
        let decision = ReviewDecision::try_from(r.decision).unwrap_or(ReviewDecision::Unspecified);
        let scope = ReviewScope::try_from(r.scope).unwrap_or(ReviewScope::Unspecified);
        let category = Category::try_from(r.category).unwrap_or(Category::Unspecified);
        let item = ReviewItem::new(
            DeviceId(r.device_id),
            r.alert_id,
            r.host,
            from_hex_bytes(&r.sha256_hex),
            category,
        );
        allowlist.apply(&item, decision, scope, r.ts);
    }
    allowlist
}

/// Decode a lowercase-hex string to bytes; empty on odd-length/invalid input.
fn from_hex_bytes(s: &str) -> Vec<u8> {
    if !s.len().is_multiple_of(2) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < s.len() {
        match u8::from_str_radix(&s[i..i + 2], 16) {
            Ok(b) => out.push(b),
            Err(_) => return Vec::new(),
        }
        i += 2;
    }
    out
}

/// The response-stream type tonic expects for `Review::StreamPendingReviews`.
pub type AlertEventStream =
    Pin<Box<dyn Stream<Item = Result<AlertEvent, Status>> + Send + 'static>>;

/// The response-stream type tonic expects for `Review::FetchSegment`.
pub type SegmentChunkStream =
    Pin<Box<dyn Stream<Item = Result<SegmentChunk, Status>> + Send + 'static>>;

/// Server-stream a clip's bytes in ~64 KiB chunks (the clip is already in memory).
const SEGMENT_CHUNK_BYTES: usize = 64 * 1024;

/// Turn a broadcast receiver into the boxed response stream tonic wants.
///
/// A lagged receiver (slow guardian client) skips the dropped events rather
/// than failing the whole stream; a closed channel ends the stream cleanly.
/// Built with `futures_util::stream::unfold` so we need no `tokio-stream` dep.
fn broadcast_into_stream(rx: tokio::sync::broadcast::Receiver<AlertEvent>) -> AlertEventStream {
    use tokio::sync::broadcast::error::RecvError;

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(event) => return Some((Ok(event), rx)),
                // Slow consumer: we dropped `n` events for this receiver. Don't
                // kill the stream — just keep going from the newest available.
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "guardian alert stream lagged; skipping");
                    continue;
                }
                // All senders dropped: end the stream.
                Err(RecvError::Closed) => return None,
            }
        }
    });
    Box::pin(stream)
}

// ---------------------------------------------------------------------------
// Review service
// ---------------------------------------------------------------------------

/// Implements `bulwark_proto::v1::review_server::Review`: guardian approve/deny,
/// remote-push registration, and the pending-review stream.
#[derive(Clone)]
pub struct ReviewService {
    hub: AlertHub,
    /// When set, `StreamPendingReviews` scopes a guardian's stream (by session
    /// token) to ONLY the children they're assigned to. `None` = legacy
    /// device-only filtering (every subscriber sees every alert).
    accounts: Option<crate::accounts::AccountStore>,
    /// When set, `FetchSegment` streams retained video clips from this store to a
    /// remote guardian. `None` = no server-side video review on this node (a
    /// distributed worker keeps no store; the co-located parent reads disk).
    segment_store: Option<Arc<bulwark_video::SegmentStore>>,
}

impl ReviewService {
    /// Legacy constructor: no per-guardian scoping (device_id filter only).
    pub fn new(hub: AlertHub) -> Self {
        Self {
            hub,
            accounts: None,
            segment_store: None,
        }
    }

    /// Scope guardian streams by session token against `store`'s child→guardian
    /// assignments.
    pub fn with_accounts(hub: AlertHub, store: crate::accounts::AccountStore) -> Self {
        Self {
            hub,
            accounts: Some(store),
            segment_store: None,
        }
    }

    /// Enable `FetchSegment` against a retained-clip store (all-in-one node).
    pub fn with_segment_store(mut self, store: Option<Arc<bulwark_video::SegmentStore>>) -> Self {
        self.segment_store = store;
        self
    }
}

/// SSRF guard for a registered UnifiedPush endpoint. The server POSTs the
/// redacted alert payload to this URL on every alert, so an attacker who could
/// store an arbitrary value here could aim the server at internal/metadata
/// services. Require an `https` URL to a **public** host; reject loopback,
/// private (RFC1918 / ULA), link-local (incl. the `169.254.169.254` cloud
/// metadata IP), unspecified and multicast literals.
///
/// A self-hoster running an `http`/private-network ntfy can opt out of both the
/// scheme and the address checks with `BULWARK_PUSH_ALLOW_INSECURE_ENDPOINTS=1`.
/// Hostnames are NOT resolved here (DNS resolution at registration is itself an
/// SSRF/rebind surface); the guardian-auth gate above is the primary control —
/// only an authenticated guardian, scoped to the device, can register at all.
fn validate_push_endpoint(endpoint: &str) -> Result<(), Status> {
    let allow_insecure =
        std::env::var_os("BULWARK_PUSH_ALLOW_INSECURE_ENDPOINTS").is_some_and(|v| !v.is_empty());
    let url = url::Url::parse(endpoint)
        .map_err(|_| Status::invalid_argument("push_endpoint must be a valid absolute URL"))?;
    match url.scheme() {
        "https" => {}
        "http" if allow_insecure => {}
        _ => {
            return Err(Status::invalid_argument(
                "push_endpoint must be an https URL (set BULWARK_PUSH_ALLOW_INSECURE_ENDPOINTS=1 \
                 to allow http for a self-hosted distributor on a trusted network)",
            ));
        }
    }
    match url.host() {
        None => {
            return Err(Status::invalid_argument(
                "push_endpoint must include a host",
            ));
        }
        Some(url::Host::Ipv4(ip)) if !allow_insecure && !is_public_v4(ip) => {
            return Err(Status::invalid_argument(
                "push_endpoint must not point at a private/loopback/link-local address (SSRF guard)",
            ));
        }
        Some(url::Host::Ipv6(ip)) if !allow_insecure && !is_public_v6(ip) => {
            return Err(Status::invalid_argument(
                "push_endpoint must not point at a private/loopback/link-local address (SSRF guard)",
            ));
        }
        // A public IP literal, or a domain (resolved at send time, not here).
        Some(_) => {}
    }
    Ok(())
}

/// `true` only for a globally-routable IPv4 (rejects loopback/private/link-local/
/// unspecified/broadcast/multicast/documentation ranges).
fn is_public_v4(ip: std::net::Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation())
}

/// `true` only for a globally-routable IPv6 (rejects loopback/unspecified/
/// multicast, ULA `fc00::/7`, link-local `fe80::/10`, and IPv4-mapped private
/// addresses). Uses manual masks for ULA/link-local since the std helpers are
/// still unstable.
fn is_public_v6(ip: std::net::Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let seg0 = ip.segments()[0];
    let link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
    let unique_local = (seg0 & 0xfe00) == 0xfc00; // fc00::/7
    if link_local || unique_local {
        return false;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    true
}

#[tonic::async_trait]
impl bulwark_proto::v1::review_server::Review for ReviewService {
    async fn submit_decision(
        &self,
        req: Request<ReviewRequest>,
    ) -> Result<Response<ReviewAck>, Status> {
        // Bearer token (if any) for accounts-mode authentication of the decision.
        let meta_token = crate::accounts::bearer_token(&req);
        let r = req.into_inner();

        // --- validate ----------------------------------------------------
        if r.alert_id.trim().is_empty() {
            return Err(Status::invalid_argument("alert_id is required"));
        }
        if r.device_id.trim().is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        let decision = r.decision();
        if decision == ReviewDecision::Unspecified {
            return Err(Status::invalid_argument("decision must be APPROVE or DENY"));
        }

        // SECURITY: when accounts are wired, a guardian decision must be
        // AUTHENTICATED and SCOPED — a valid session token (authorization: Bearer)
        // whose assigned children include this alert's device. Without this, anyone
        // reaching `Review` could approve/deny another family's item by guessing an
        // alert_id/device_id. (Previously only StreamPendingReviews was gated.)
        if let Some(store) = &self.accounts {
            let token = meta_token.unwrap_or_default();
            if token.is_empty() {
                return Err(Status::unauthenticated(
                    "a session token (authorization: Bearer …) is required to submit a review decision",
                ));
            }
            let gscope = store
                .guardian_scope(&token)
                .ok_or_else(|| Status::unauthenticated("invalid session token"))?;
            if !gscope.device_ids.contains(r.device_id.trim()) {
                return Err(Status::permission_denied(
                    "guardian is not assigned to the child/device for this decision",
                ));
            }
        }

        let scope = r.scope(); // ignored for DENY by the allowlist

        // Resolve the host/sha256/category for this alert_id from the in-memory
        // pending-review store populated by `AlertHub::publish` when the alert
        // was raised. A `ReviewRequest` carries only the alert_id + decision, so
        // this is how an APPROVE(THIS_HOST) gets a real host to allowlist and how
        // the CSAM-never-allowlistable rule is re-checked at decision time. An
        // alert_id we never saw resolves to an empty item — an APPROVE the
        // allowlist cannot key on is refused (audited); DENY is unaffected.
        let item = self
            .hub
            .resolve_item(DeviceId(r.device_id.clone()), &r.alert_id);

        // Image blocks carry no host (response leg) → approve the specific image by
        // its content hash (THIS_ITEM) instead of THIS_HOST, so "approve" applies
        // instead of failing with "THIS_HOST approve with no host".
        let scope = self.hub.effective_scope(&r.alert_id, scope, decision);

        let outcome = self.hub.apply_decision(&item, decision, scope, r.ts);

        let applied = match outcome {
            ApplyOutcome::Approved | ApplyOutcome::DenyConfirmed => true,
            ApplyOutcome::Refused(reason) => {
                // Surface a refusal (e.g. CSAM-not-allowlistable, or an APPROVE
                // with nothing to key on) as a precondition failure. The
                // decision is still recorded in the tamper-evident audit log.
                tracing::info!(alert_id = %r.alert_id, %reason, "review decision refused");
                return Err(Status::failed_precondition(reason));
            }
        };

        Ok(Response::new(ReviewAck {
            alert_id: r.alert_id,
            applied,
        }))
    }

    async fn register_push_target(
        &self,
        req: Request<PushTarget>,
    ) -> Result<Response<PushAck>, Status> {
        // Bearer token (if any) for accounts-mode authentication.
        let meta_token = crate::accounts::bearer_token(&req);
        let target = req.into_inner();
        if target.device_id.trim().is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if target.push_endpoint.trim().is_empty() {
            return Err(Status::invalid_argument("push_endpoint is required"));
        }
        // SSRF guard: `push_endpoint` becomes a server-side POST target that
        // `UnifiedPushTransport::send` dereferences on EVERY alert. Reject
        // anything that isn't an https URL to a public host (no loopback /
        // private / link-local / metadata addresses) before it is stored.
        validate_push_endpoint(target.push_endpoint.trim())?;

        // SECURITY + SCOPING: when accounts are wired, registering a push endpoint
        // must be AUTHENTICATED (else any caller reaching `Review.RegisterPushTarget`
        // could register an arbitrary server-side POST target — SSRF / push
        // disruption). We resolve the authenticated guardian's ACCOUNT ID and key
        // the registration by it: that makes a re-registration overwrite the
        // guardian's own entry (not accumulate or clobber another's) AND lets the
        // fan-out scope alerts to a guardian's children (#140). We deliberately do
        // NOT scope on `PushTarget.device_id` (the GUARDIAN's own device id, a
        // different namespace from the supervised CHILD device ids). In
        // single-tenant dev (no accounts) the device id is the owner key.
        let owner = if let Some(store) = &self.accounts {
            let token = meta_token.unwrap_or_default();
            match store.account_for_session(&token) {
                Some(account_id) => account_id,
                None => {
                    return Err(Status::unauthenticated(
                        "a valid session token (authorization: Bearer …) is required to register a push endpoint",
                    ));
                }
            }
        } else {
            target.device_id.trim().to_string()
        };

        self.hub.register_push(owner, target);
        Ok(Response::new(PushAck { ok: true }))
    }

    type StreamPendingReviewsStream = AlertEventStream;

    async fn stream_pending_reviews(
        &self,
        req: Request<DeviceFilter>,
    ) -> Result<Response<Self::StreamPendingReviewsStream>, Status> {
        use futures_util::StreamExt;

        // Token may come from the message field or `authorization: Bearer …`.
        let meta_token = crate::accounts::bearer_token(&req);
        let filter = req.into_inner();
        let want_device = filter.device_id.trim().to_string();
        let token = if !filter.token.trim().is_empty() {
            filter.token.trim().to_string()
        } else {
            meta_token.unwrap_or_default()
        };

        let rx = self.hub.subscribe();
        let base = broadcast_into_stream(rx);

        // SECURITY: when an account store is wired (guardian accounts exist), a
        // valid session token is REQUIRED. Without this gate a client that sends
        // no token would fall through to the unscoped legacy path below and
        // receive EVERY family's pending reviews. So the unscoped path is only
        // reachable when no account store is configured (`self.accounts == None`).
        if let Some(store) = &self.accounts {
            if token.is_empty() {
                return Err(Status::unauthenticated(
                    "a session token is required (Accounts.Login) to stream pending reviews",
                ));
            }
            // Scope to the guardian's assigned children: keep an alert only if its
            // child_id OR device_id belongs to one of those children (the data
            // plane stamps device_id; child_id is set when known). An unknown
            // token is rejected, never leaked to.
            let scope = store
                .guardian_scope(&token)
                .ok_or_else(|| Status::unauthenticated("invalid session token"))?;
            let want_device = want_device.clone();
            let stream: Self::StreamPendingReviewsStream = Box::pin(base.filter(move |item| {
                let keep = match item {
                    Ok(ev) => {
                        // Staff SAFETY_BROADCASTs are region-wide notices
                        // addressed to EVERY guardian console (staff-originated
                        // only — never crowd-sourced), so they bypass the
                        // per-child scoping below.
                        if ev.kind == AlertKind::SafetyBroadcast as i32 {
                            true
                        } else {
                            let in_scope = scope.child_ids.contains(&ev.child_id)
                                || scope.device_ids.contains(&ev.device_id);
                            let dev_ok = want_device.is_empty() || ev.device_id == want_device;
                            in_scope && dev_ok
                        }
                    }
                    Err(_) => true, // surface transport errors regardless
                };
                async move { keep }
            }));
            return Ok(Response::new(stream));
        }

        // Legacy path — ONLY when no account store is configured (single-node dev
        // without guardian accounts). Empty device_id = all supervised devices.
        let stream: Self::StreamPendingReviewsStream = if want_device.is_empty() {
            base
        } else {
            Box::pin(base.filter(move |item| {
                let keep = match item {
                    Ok(ev) => ev.device_id == want_device,
                    Err(_) => true, // surface transport errors regardless
                };
                async move { keep }
            }))
        };

        Ok(Response::new(stream))
    }

    type FetchSegmentStream = SegmentChunkStream;

    async fn fetch_segment(
        &self,
        req: Request<SegmentRequest>,
    ) -> Result<Response<Self::FetchSegmentStream>, Status> {
        let meta_token = crate::accounts::bearer_token(&req);
        let r = req.into_inner();

        // In accounts mode a valid guardian session is required (same gate as the
        // review stream). CSAM clips are never retained, so they can't be fetched.
        if let Some(store) = &self.accounts {
            let token = if !r.token.trim().is_empty() {
                r.token.trim().to_string()
            } else {
                meta_token.unwrap_or_default()
            };
            if token.is_empty() || store.guardian_scope(&token).is_none() {
                return Err(Status::unauthenticated(
                    "a valid session token is required (Accounts.Login) to fetch a clip",
                ));
            }
        }

        let segments = self.segment_store.as_ref().ok_or_else(|| {
            Status::unavailable("video review storage is not enabled on this node")
        })?;
        let bytes = segments
            .load(&r.local_segment_uri)
            .map_err(|e| Status::internal(format!("reading segment: {e}")))?
            .ok_or_else(|| Status::not_found("segment not found or expired"))?;

        // Chunk the in-memory clip into the response stream.
        let chunks: Vec<Result<SegmentChunk, Status>> = bytes
            .chunks(SEGMENT_CHUNK_BYTES)
            .map(|c| Ok(SegmentChunk { data: c.to_vec() }))
            .collect();
        let stream: Self::FetchSegmentStream = Box::pin(futures_util::stream::iter(chunks));
        Ok(Response::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::review_server::Review; // trait must be in scope to call its methods
    use bulwark_proto::v1::AlertKind;

    fn alert(device: &str) -> AlertEvent {
        AlertEvent {
            alert_id: "a1".into(),
            kind: AlertKind::Intervention as i32,
            category: Category::AdultImage as i32,
            severity: 0,
            app: "example.com".into(),
            device_id: device.into(),
            ts: 1,
            redacted_context: "redacted".into(),
            evidence: None,
            ..Default::default()
        }
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bulwark-relay-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn fetch_segment_streams_a_stored_clip() {
        use bulwark_proto::v1::review_server::Review;
        use bulwark_proto::v1::{Action, Category};
        use futures_util::StreamExt;

        let dir = tmp_dir("segments");
        let store = bulwark_video::SegmentStore::new(dir.clone()).unwrap();
        let clip = vec![7u8; 200_000]; // spans multiple 64 KiB chunks
        let stored = store
            .store_if_safe(Category::AdultImage, Action::Block, &clip)
            .unwrap()
            .expect("a safe blocked clip is retained");

        let svc = ReviewService::new(AlertHub::new()).with_segment_store(Some(Arc::new(store)));

        // Fetch + reassemble the streamed chunks.
        let resp = svc
            .fetch_segment(Request::new(SegmentRequest {
                local_segment_uri: stored.uri.clone(),
                token: String::new(),
            }))
            .await
            .unwrap();
        let mut stream = resp.into_inner();
        let mut got = Vec::new();
        while let Some(chunk) = stream.next().await {
            got.extend_from_slice(&chunk.unwrap().data);
        }
        assert_eq!(got, clip);
        assert!(
            got.len() > SEGMENT_CHUNK_BYTES,
            "exercised multi-chunk streaming"
        );

        // Unknown uri → NotFound (and CSAM is never stored, so never fetchable).
        let miss = svc
            .fetch_segment(Request::new(SegmentRequest {
                local_segment_uri: "blob://deadbeef".into(),
                token: String::new(),
            }))
            .await;
        assert_eq!(miss.err().map(|s| s.code()), Some(tonic::Code::NotFound));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn push_targets_and_pending_persist_across_restart() {
        let dir = tmp_dir("persist");
        let hub1 = AlertHub::with_state_dir(&dir).unwrap();
        hub1.register_push(
            "g-phone".into(),
            PushTarget {
                device_id: "g-phone".into(),
                push_endpoint: "https://ntfy.example/upTok".into(),
                platform: "android".into(),
            },
        );
        hub1.publish(alert("kids-tablet")); // writes a pending review
        drop(hub1); // simulate a restart

        let hub2 = AlertHub::with_state_dir(&dir).unwrap();
        // Push targets reloaded.
        assert_eq!(
            hub2.push_tokens(),
            vec!["https://ntfy.example/upTok".to_string()]
        );
        // Pending reviews were persisted on publish.
        assert!(dir.join("pending_reviews.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_journal_round_trips_via_replay() {
        // Apply an APPROVE(THIS_HOST), then rebuild the allowlist from its journal.
        let mut a = Allowlist::new();
        let dev = DeviceId("kids-tablet".into());
        let item = ReviewItem::new(
            dev.clone(),
            "a1",
            "example.com",
            Vec::new(),
            Category::AdultImage,
        );
        a.apply(&item, ReviewDecision::Approve, ReviewScope::ThisHost, 1);
        assert!(a.is_host_allowed(&dev, "example.com"));

        let replayed = replay_audit(audit_rows(&a));
        // The allow-set survived the journal round-trip and the chain re-verifies.
        assert!(replayed.is_host_allowed(&dev, "example.com"));
        assert!(replayed.audit().verify().is_ok());

        // CSAM approvals are never allow-listed — replay reproduces the refusal.
        let mut c = Allowlist::new();
        let csam = ReviewItem::new(
            dev.clone(),
            "a2",
            "bad.example",
            Vec::new(),
            Category::CsamSuspected,
        );
        c.apply(&csam, ReviewDecision::Approve, ReviewScope::ThisHost, 2);
        let replayed_c = replay_audit(audit_rows(&c));
        assert!(!replayed_c.is_host_allowed(&dev, "bad.example"));
    }

    #[test]
    fn publish_with_no_subscribers_is_not_an_error() {
        let hub = AlertHub::new();
        assert_eq!(hub.publish(alert("kids-tablet")), 0);
    }

    #[tokio::test]
    async fn published_alert_reaches_a_subscriber() {
        use futures_util::StreamExt;
        let hub = AlertHub::new();
        let svc = ReviewService::new(hub.clone());

        let resp = svc
            .stream_pending_reviews(Request::new(DeviceFilter::default()))
            .await
            .expect("stream opens");
        let mut stream = resp.into_inner();

        // Subscriber is live now; publish reaches exactly one receiver.
        assert_eq!(hub.publish(alert("kids-tablet")), 1);

        let got = stream.next().await.expect("an item").expect("ok event");
        assert_eq!(got.device_id, "kids-tablet");
    }

    #[tokio::test]
    async fn device_filter_excludes_other_devices() {
        use futures_util::StreamExt;
        let hub = AlertHub::new();
        let svc = ReviewService::new(hub.clone());

        let filter = DeviceFilter {
            device_id: "kids-tablet".into(),
            ..Default::default()
        };
        let resp = svc
            .stream_pending_reviews(Request::new(filter))
            .await
            .expect("stream opens");
        let mut stream = resp.into_inner();

        // Two subscribers exist now (this stream's rx). Publish a non-matching
        // then a matching alert; only the matching one comes through.
        hub.publish(alert("other-phone"));
        hub.publish(alert("kids-tablet"));

        let got = stream.next().await.expect("an item").expect("ok event");
        assert_eq!(got.device_id, "kids-tablet");
    }

    #[tokio::test]
    async fn register_push_target_rejects_empty_endpoint() {
        let hub = AlertHub::new();
        let svc = ReviewService::new(hub);
        let t = PushTarget {
            device_id: "guardian-phone".into(),
            ..Default::default()
        };
        // missing push_endpoint
        let err = svc
            .register_push_target(Request::new(t))
            .await
            .expect_err("must reject empty endpoint");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn register_push_target_accepts_public_https() {
        // No account store → auth gate is skipped, isolating endpoint validation.
        let svc = ReviewService::new(AlertHub::new());
        svc.register_push_target(Request::new(PushTarget {
            device_id: "kids-tablet".into(),
            push_endpoint: "https://ntfy.sh/abc123".into(),
            ..Default::default()
        }))
        .await
        .expect("public https endpoint accepted");
    }

    #[tokio::test]
    async fn register_push_target_bad_endpoints_are_invalid_argument() {
        // The SSRF guard rejects non-https, cloud-metadata, loopback and private
        // literals, and unparseable input (auth gate skipped — accounts None).
        let svc = ReviewService::new(AlertHub::new());
        for bad in [
            "http://ntfy.sh/abc",
            "https://169.254.169.254/latest/meta",
            "https://127.0.0.1/x",
            "https://10.0.0.5/x",
            "https://[::1]/x",
            "not-a-url",
        ] {
            let err = svc
                .register_push_target(Request::new(PushTarget {
                    device_id: "kids-tablet".into(),
                    push_endpoint: bad.into(),
                    ..Default::default()
                }))
                .await
                .expect_err("must reject");
            assert_eq!(
                err.code(),
                tonic::Code::InvalidArgument,
                "endpoint {bad} should be InvalidArgument"
            );
        }
    }

    #[tokio::test]
    async fn register_push_target_requires_auth_in_accounts_mode() {
        use crate::accounts::AccountStore;
        // Accounts wired → registering an endpoint needs a valid session token
        // bound to the device, else anyone could aim the server's per-alert POST
        // at a target of their choosing or clobber another guardian's endpoint.
        let svc = ReviewService::with_accounts(AlertHub::new(), AccountStore::new());
        let err = svc
            .register_push_target(Request::new(PushTarget {
                device_id: "kids-tablet".into(),
                push_endpoint: "https://ntfy.sh/abc123".into(),
                ..Default::default()
            }))
            .await
            .expect_err("must require a session token");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn push_fanout_is_scoped_to_the_alerts_guardians() {
        // #140: a redacted alert must reach ONLY the guardians assigned to its
        // child/device — never another family. Build two families, register each
        // guardian's endpoint, and assert the fan-out target is family-scoped.
        use crate::accounts::AccountStore;
        let accounts = AccountStore::new();
        let acct_a = accounts.create_account("a@ex.com", "passworda", "A").unwrap().0;
        let acct_b = accounts.create_account("b@ex.com", "passwordb", "B").unwrap().0;
        let (tok_a, _, _) = accounts.login("a@ex.com", "passworda").unwrap();
        let (tok_b, _, _) = accounts.login("b@ex.com", "passwordb").unwrap();
        accounts.add_child(&tok_a, "Kid A", "device-a").unwrap();
        accounts.add_child(&tok_b, "Kid B", "device-b").unwrap();

        let hub = AlertHub::new();
        hub.attach_accounts(accounts.clone());
        // Endpoints keyed by guardian ACCOUNT id, exactly as register_push_target does.
        hub.register_push(
            acct_a.clone(),
            PushTarget {
                device_id: "guardian-a-phone".into(),
                push_endpoint: "https://ntfy.sh/a".into(),
                ..Default::default()
            },
        );
        hub.register_push(
            acct_b.clone(),
            PushTarget {
                device_id: "guardian-b-phone".into(),
                push_endpoint: "https://ntfy.sh/b".into(),
                ..Default::default()
            },
        );

        // Alert for child A's device → ONLY guardian A's endpoint (NOT B's).
        assert_eq!(
            hub.endpoints_for(&alert("device-a")),
            vec!["https://ntfy.sh/a".to_string()],
            "child A's alert must reach only guardian A",
        );
        assert_eq!(
            hub.endpoints_for(&alert("device-b")),
            vec!["https://ntfy.sh/b".to_string()],
            "child B's alert must reach only guardian B",
        );
        // An alert for an unknown device routes to NOBODY — scoped, never broadcast.
        assert!(
            hub.endpoints_for(&alert("device-unknown")).is_empty(),
            "an unknown device must not fan out to any family",
        );
    }

    #[tokio::test]
    async fn push_fanout_without_accounts_is_flat_single_tenant() {
        // Single-tenant dev (no accounts store attached): no families to scope to,
        // so every registered endpoint receives the alert (the legacy behaviour).
        let hub = AlertHub::new();
        hub.register_push(
            "device-a".into(),
            PushTarget {
                device_id: "device-a".into(),
                push_endpoint: "https://ntfy.sh/only".into(),
                ..Default::default()
            },
        );
        assert_eq!(
            hub.endpoints_for(&alert("anything")),
            vec!["https://ntfy.sh/only".to_string()],
        );
    }

    #[tokio::test]
    async fn submit_decision_validates_and_denies() {
        let hub = AlertHub::new();
        let svc = ReviewService::new(hub);

        // Missing alert_id → invalid argument.
        let bad = ReviewRequest {
            alert_id: String::new(),
            decision: ReviewDecision::Deny as i32,
            device_id: "kids-tablet".into(),
            scope: ReviewScope::ThisItem as i32,
            ts: 1,
        };
        let err = svc
            .submit_decision(Request::new(bad))
            .await
            .expect_err("empty alert_id rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // A well-formed DENY is applied (confirms the block).
        let deny = ReviewRequest {
            alert_id: "a1".into(),
            decision: ReviewDecision::Deny as i32,
            device_id: "kids-tablet".into(),
            scope: ReviewScope::Unspecified as i32,
            ts: 2,
        };
        let ack = svc
            .submit_decision(Request::new(deny))
            .await
            .expect("deny applied")
            .into_inner();
        assert!(ack.applied);
        assert_eq!(ack.alert_id, "a1");
    }

    #[tokio::test]
    async fn submit_decision_requires_auth_in_accounts_mode() {
        use crate::accounts::AccountStore;
        // Accounts wired → a decision needs a valid session token (bearer); a
        // tokenless request must be rejected, so no one can approve/deny another
        // family's item by guessing an alert_id/device_id.
        let svc = ReviewService::with_accounts(AlertHub::new(), AccountStore::new());
        let req = ReviewRequest {
            alert_id: "a1".into(),
            decision: ReviewDecision::Deny as i32,
            device_id: "kids-tablet".into(),
            scope: ReviewScope::Unspecified as i32,
            ts: 1,
        };
        let err = svc
            .submit_decision(Request::new(req))
            .await
            .expect_err("must require a session token");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
