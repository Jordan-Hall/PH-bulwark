//! Guardian-facing relay state shared by the `AlertRelay` and `Review` gRPC
//! services.
//!
//! Both services fan a redacted [`AlertEvent`] out to subscribed guardian
//! clients over a [`tokio::sync::broadcast`] channel:
//!   * `AlertRelay::RaiseAlert` / `RaiseAlerts` accept alerts (from the
//!     client/server data plane or `aegis-alert`) and **publish** them into the
//!     channel (in addition to handing them to the e-mail sink).
//!   * `Review::StreamPendingReviews` **subscribes** to the channel and streams
//!     the same redacted events to a guardian's Review screen.
//!   * `Review::SubmitDecision` applies an APPROVE/DENY to the per-device
//!     [`Allowlist`] from `aegis-policy` (CSAM is never allowlistable — the
//!     allowlist module enforces this; we surface its refusal as a `Status`).
//!   * `Review::RegisterPushTarget` records a guardian's FCM routing token.
//!
//! PRIVACY INVARIANT: only the redacted [`AlertEvent`] (hashes / safe thumbnail
//! / redacted context) ever crosses these channels — never raw media. This is
//! the same no-media guarantee `aegis-alert` enforces at render time.
//!
//! State is **in-memory** for this wave (broadcast channel + `Arc<Mutex<…>>`
//! maps). See the `// SEAM:` markers for where durable storage (an audited
//! allowlist + a pending-review queue) would plug in. We deliberately do NOT
//! pull in `aegis-store`/rusqlite here — it fails to build on the Windows host
//! (os error 4551, environmental) and `aegis-server` must keep building.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use aegis_policy::{Allowlist, ApplyOutcome, ReviewItem};
use aegis_proto::v1::{
    AlertEvent, Category, DeviceFilter, PushAck, PushTarget, ReviewAck, ReviewDecision,
    ReviewRequest, ReviewScope,
};
use aegis_proto::DeviceId;
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
    // (e.g. aegis-store) so guardian decisions survive a restart. The
    // `aegis-policy::Allowlist` API (`apply`, `is_host_allowed`, `audit`) is
    // unchanged; only construction/load + write-through would move here.
    allowlist: Arc<Mutex<Allowlist>>,
    /// Registered remote-push targets, keyed by guardian device id.
    // SEAM: durable storage — persist FCM routing tokens (no alert content) so
    // a guardian stays reachable across restarts.
    push_targets: Arc<Mutex<HashMap<String, PushTarget>>>,
    /// Pending-review records keyed by `alert_id`: the redacted facts a
    /// `SubmitDecision` needs to resolve a `ReviewItem` (host/hash/category)
    /// without re-shipping the original event. A `ReviewRequest` carries only
    /// `alert_id` + the guardian's decision, so the server must remember which
    /// host/category that alert referred to in order to (a) key an APPROVE on a
    /// real host and (b) re-check the CSAM-never-allowlistable rule. Content-free
    /// (host + hash + category only — never raw media or message text).
    // SEAM: durable storage — this is the in-memory pending-review queue the
    // `submit_decision` SEAM comment refers to; persist it so a decision can be
    // resolved across a restart.
    pending: Arc<Mutex<HashMap<String, PendingReview>>>,
}

/// The content-free facts the relay retains about a raised alert so a later
/// guardian decision can be resolved into a `ReviewItem`. Mirrors the
/// `Evidence`/`AlertEvent` no-media invariant: host (the app/site), the content
/// hash, and the category only.
#[derive(Clone)]
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
            self.pending
                .lock()
                .expect("pending-review mutex poisoned")
                .insert(event.alert_id.clone(), record);
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
    /// the policy outcome. CSAM APPROVEs are refused inside `aegis-policy`.
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
        guard.apply(item, decision, scope, ts)
    }

    /// Record a guardian's remote-push routing token (no alert content).
    fn register_push(&self, target: PushTarget) {
        let mut guard = self
            .push_targets
            .lock()
            .expect("push-target mutex poisoned");
        guard.insert(target.device_id.clone(), target);
    }
}

/// The response-stream type tonic expects for `Review::StreamPendingReviews`.
pub type AlertEventStream =
    Pin<Box<dyn Stream<Item = Result<AlertEvent, Status>> + Send + 'static>>;

/// Turn a broadcast receiver into the boxed response stream tonic wants.
///
/// A lagged receiver (slow guardian client) skips the dropped events rather
/// than failing the whole stream; a closed channel ends the stream cleanly.
/// Built with `futures_util::stream::unfold` so we need no `tokio-stream` dep.
fn broadcast_into_stream(
    rx: tokio::sync::broadcast::Receiver<AlertEvent>,
) -> AlertEventStream {
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

/// Implements `aegis_proto::v1::review_server::Review`: guardian approve/deny,
/// remote-push registration, and the pending-review stream.
#[derive(Clone)]
pub struct ReviewService {
    hub: AlertHub,
    /// When set, `StreamPendingReviews` scopes a guardian's stream (by session
    /// token) to ONLY the children they're assigned to. `None` = legacy
    /// device-only filtering (every subscriber sees every alert).
    accounts: Option<crate::accounts::AccountStore>,
}

impl ReviewService {
    /// Legacy constructor: no per-guardian scoping (device_id filter only).
    pub fn new(hub: AlertHub) -> Self {
        Self { hub, accounts: None }
    }

    /// Scope guardian streams by session token against `store`'s child→guardian
    /// assignments.
    pub fn with_accounts(hub: AlertHub, store: crate::accounts::AccountStore) -> Self {
        Self {
            hub,
            accounts: Some(store),
        }
    }
}

#[tonic::async_trait]
impl aegis_proto::v1::review_server::Review for ReviewService {
    async fn submit_decision(
        &self,
        req: Request<ReviewRequest>,
    ) -> Result<Response<ReviewAck>, Status> {
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
            return Err(Status::invalid_argument(
                "decision must be APPROVE or DENY",
            ));
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
        let target = req.into_inner();
        if target.device_id.trim().is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if target.fcm_token.trim().is_empty() {
            return Err(Status::invalid_argument("fcm_token is required"));
        }
        self.hub.register_push(target);
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

        // Per-guardian scoping: a session token + a wired account store restricts
        // the stream to the children this guardian is assigned to. An alert is
        // kept only if its child_id OR device_id belongs to one of those children
        // (the data plane stamps device_id; child_id is set when known). An
        // unknown token is rejected rather than leaking every family's alerts.
        if !token.is_empty() {
            if let Some(store) = &self.accounts {
                let scope = store
                    .guardian_scope(&token)
                    .ok_or_else(|| Status::unauthenticated("invalid session token"))?;
                let want_device = want_device.clone();
                let stream: Self::StreamPendingReviewsStream = Box::pin(base.filter(move |item| {
                    let keep = match item {
                        Ok(ev) => {
                            let in_scope = scope.child_ids.contains(&ev.child_id)
                                || scope.device_ids.contains(&ev.device_id);
                            let dev_ok = want_device.is_empty() || ev.device_id == want_device;
                            in_scope && dev_ok
                        }
                        Err(_) => true, // surface transport errors regardless
                    };
                    async move { keep }
                }));
                return Ok(Response::new(stream));
            }
        }

        // Legacy path: empty device_id = all supervised devices; else that device.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::v1::review_server::Review; // trait must be in scope to call its methods
    use aegis_proto::v1::AlertKind;

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
    async fn register_push_target_requires_token() {
        let hub = AlertHub::new();
        let svc = ReviewService::new(hub);
        let t = PushTarget {
            device_id: "guardian-phone".into(),
            ..Default::default()
        };
        // missing fcm_token
        let err = svc
            .register_push_target(Request::new(t))
            .await
            .expect_err("must reject empty token");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
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
}
