//! Durable guardian-review authority layered in front of the legacy relay.
//!
//! The ledger is content-safe: it stores only the already-redacted AlertEvent
//! fields and Evidence hashes/safe preview. It binds `alert_id` to the original
//! device/child/family and refuses conflicting reuse, so a ReviewRequest cannot
//! substitute another device. It also provides offline replay and owner-scoped
//! streaming of retained review clips.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bulwark_proto::v1::review_server::Review;
use bulwark_proto::v1::{
    AlertEvent, DeviceFilter, Evidence, PushAck, PushTarget, ReviewAck, ReviewRequest,
    SegmentChunk, SegmentRequest,
};
use futures_core::Stream;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tonic::{Request, Response, Status};

use crate::accounts::{bearer_token, AccountStore, GuardianScope};
use crate::persist::JsonFile;
use crate::relay::ReviewService;

const MAX_REPLAY_ALERTS: usize = 10_000;
const SEGMENT_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredEvidence {
    sha256: Vec<u8>,
    perceptual_hash: Vec<u8>,
    safe_thumbnail: Vec<u8>,
    text_snippet: String,
    model_id: String,
    model_version: String,
}

impl StoredEvidence {
    fn from_proto(value: &Evidence) -> Self {
        Self {
            sha256: value.sha256.clone(),
            perceptual_hash: value.perceptual_hash.clone(),
            safe_thumbnail: value.safe_thumbnail.clone(),
            text_snippet: value.text_snippet.clone(),
            model_id: value.model_id.clone(),
            model_version: value.model_version.clone(),
        }
    }

    fn to_proto(&self) -> Evidence {
        Evidence {
            sha256: self.sha256.clone(),
            perceptual_hash: self.perceptual_hash.clone(),
            safe_thumbnail: self.safe_thumbnail.clone(),
            text_snippet: self.text_snippet.clone(),
            model_id: self.model_id.clone(),
            model_version: self.model_version.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredAlert {
    alert_id: String,
    kind: i32,
    category: i32,
    severity: i32,
    app: String,
    device_id: String,
    ts: i64,
    redacted_context: String,
    evidence: Option<StoredEvidence>,
    child_id: String,
    family_id: String,
    local_segment_uri: String,
}

impl StoredAlert {
    fn from_proto(event: &AlertEvent) -> Self {
        Self {
            alert_id: event.alert_id.clone(),
            kind: event.kind,
            category: event.category,
            severity: event.severity,
            app: event.app.clone(),
            device_id: event.device_id.clone(),
            ts: event.ts,
            redacted_context: event.redacted_context.clone(),
            evidence: event.evidence.as_ref().map(StoredEvidence::from_proto),
            child_id: event.child_id.clone(),
            family_id: event.family_id.clone(),
            local_segment_uri: event.local_segment_uri.clone(),
        }
    }

    fn to_proto(&self) -> AlertEvent {
        AlertEvent {
            alert_id: self.alert_id.clone(),
            kind: self.kind,
            category: self.category,
            severity: self.severity,
            app: self.app.clone(),
            device_id: self.device_id.clone(),
            ts: self.ts,
            redacted_context: self.redacted_context.clone(),
            evidence: self.evidence.as_ref().map(StoredEvidence::to_proto),
            child_id: self.child_id.clone(),
            family_id: self.family_id.clone(),
            local_segment_uri: self.local_segment_uri.clone(),
        }
    }

    fn immutable_identity_eq(&self, other: &Self) -> bool {
        self.alert_id == other.alert_id
            && self.device_id == other.device_id
            && self.child_id == other.child_id
            && self.family_id == other.family_id
            && self.kind == other.kind
            && self.category == other.category
            && self.evidence.as_ref().map(|e| &e.sha256)
                == other.evidence.as_ref().map(|e| &e.sha256)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LedgerState {
    order: Vec<String>,
    alerts: HashMap<String, StoredAlert>,
}

#[derive(Clone)]
pub struct ReviewLedger {
    inner: Arc<Mutex<LedgerState>>,
    persist: Option<JsonFile>,
}

impl ReviewLedger {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LedgerState::default())),
            persist: None,
        }
    }

    /// Strict durable startup: a present-but-corrupt review ledger is fatal. A
    /// production node must never silently forget ownership or acknowledged alerts.
    pub fn with_state_dir(dir: &Path) -> io::Result<Self> {
        let persist = JsonFile::new(dir, "review_ledger.json")?;
        let state = persist.load_strict()?.unwrap_or_default();
        Ok(Self {
            inner: Arc::new(Mutex::new(state)),
            persist: Some(persist),
        })
    }

    /// Durably record before delivery. Reusing an alert_id with different tenant,
    /// device, category or content hash is rejected instead of overwriting history.
    pub fn record(&self, event: &AlertEvent) -> io::Result<bool> {
        if event.alert_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "alert_id is required",
            ));
        }
        let incoming = StoredAlert::from_proto(event);
        let mut guard = self.inner.lock().expect("review-ledger mutex poisoned");
        if let Some(existing) = guard.alerts.get(&incoming.alert_id) {
            if existing.immutable_identity_eq(&incoming) {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "alert_id was already bound to different immutable facts",
            ));
        }

        let mut next = guard.clone();
        next.order.push(incoming.alert_id.clone());
        next.alerts.insert(incoming.alert_id.clone(), incoming);
        while next.order.len() > MAX_REPLAY_ALERTS {
            let oldest = next.order.remove(0);
            next.alerts.remove(&oldest);
        }
        if let Some(persist) = &self.persist {
            persist.store(&next)?;
        }
        *guard = next;
        Ok(true)
    }

    /// Durably remove a resolved alert from the pending-review set. The
    /// allowlist audit remains the immutable decision history; this ledger is
    /// specifically the queue of outstanding review work.
    pub fn retire(&self, alert_id: &str) -> io::Result<bool> {
        let alert_id = alert_id.trim();
        if alert_id.is_empty() {
            return Ok(false);
        }
        let mut guard = self.inner.lock().expect("review-ledger mutex poisoned");
        if !guard.alerts.contains_key(alert_id) {
            return Ok(false);
        }
        let mut next = guard.clone();
        next.alerts.remove(alert_id);
        next.order.retain(|id| id != alert_id);
        if let Some(persist) = &self.persist {
            persist.store(&next)?;
        }
        *guard = next;
        Ok(true)
    }

    fn alert(&self, alert_id: &str) -> Option<StoredAlert> {
        self.inner
            .lock()
            .expect("review-ledger mutex poisoned")
            .alerts
            .get(alert_id.trim())
            .cloned()
    }

    fn replay(&self, scope: &GuardianScope, want_device: &str) -> Vec<AlertEvent> {
        let guard = self.inner.lock().expect("review-ledger mutex poisoned");
        guard
            .order
            .iter()
            .filter_map(|id| guard.alerts.get(id))
            .filter(|event| {
                let in_scope = scope.child_ids.contains(&event.child_id)
                    || scope.device_ids.contains(&event.device_id);
                let device_matches = want_device.is_empty() || event.device_id == want_device;
                in_scope && device_matches
            })
            .map(StoredAlert::to_proto)
            .collect()
    }
}

impl Default for ReviewLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct SecureReviewService {
    inner: ReviewService,
    accounts: AccountStore,
    ledger: ReviewLedger,
    segment_store: Option<Arc<bulwark_video::SegmentStore>>,
}

impl SecureReviewService {
    pub fn new(inner: ReviewService, accounts: AccountStore, ledger: ReviewLedger) -> Self {
        Self {
            inner,
            accounts,
            ledger,
            segment_store: None,
        }
    }

    pub fn with_segment_store(
        mut self,
        segment_store: Option<Arc<bulwark_video::SegmentStore>>,
    ) -> Self {
        self.segment_store = segment_store;
        self
    }

    fn token_for<T>(&self, req: &Request<T>, field_token: &str) -> String {
        if !field_token.trim().is_empty() {
            field_token.trim().to_string()
        } else {
            bearer_token(req).unwrap_or_default()
        }
    }

    fn authenticated_scope(&self, token: &str) -> Result<GuardianScope, Status> {
        if token.trim().is_empty() {
            return Err(Status::unauthenticated(
                "guardian session token is required",
            ));
        }
        self.accounts
            .guardian_scope(token)
            .ok_or_else(|| Status::unauthenticated("guardian session is invalid or expired"))
    }
}

pub type AlertEventStream =
    Pin<Box<dyn Stream<Item = Result<AlertEvent, Status>> + Send + 'static>>;
pub type SegmentChunkStream =
    Pin<Box<dyn Stream<Item = Result<SegmentChunk, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl Review for SecureReviewService {
    async fn submit_decision(
        &self,
        req: Request<ReviewRequest>,
    ) -> Result<Response<ReviewAck>, Status> {
        let token = self.token_for(&req, "");
        let scope = self.authenticated_scope(&token)?;
        let review = req.get_ref();
        let alert_id = review.alert_id.trim().to_string();
        let authoritative = self
            .ledger
            .alert(&alert_id)
            .ok_or_else(|| Status::not_found("unknown or expired alert_id"))?;

        if authoritative.device_id.trim().is_empty()
            || !scope.device_ids.contains(&authoritative.device_id)
        {
            return Err(Status::permission_denied(
                "guardian is not assigned to the alert's original device",
            ));
        }
        if review.device_id.trim() != authoritative.device_id {
            return Err(Status::permission_denied(
                "review device_id does not match the alert's original device",
            ));
        }
        if !authoritative.child_id.is_empty() && !scope.child_ids.contains(&authoritative.child_id)
        {
            return Err(Status::permission_denied(
                "guardian is not assigned to the alert's original child",
            ));
        }

        let response = Review::submit_decision(&self.inner, req).await?;
        self.ledger.retire(&alert_id).map_err(|error| {
            tracing::error!(%error, %alert_id, "review decision applied but pending alert retirement failed");
            Status::unavailable("review decision could not be durably retired from the pending queue")
        })?;
        Ok(response)
    }

    async fn register_push_target(
        &self,
        req: Request<PushTarget>,
    ) -> Result<Response<PushAck>, Status> {
        Review::register_push_target(&self.inner, req).await
    }

    type StreamPendingReviewsStream = AlertEventStream;

    async fn stream_pending_reviews(
        &self,
        req: Request<DeviceFilter>,
    ) -> Result<Response<Self::StreamPendingReviewsStream>, Status> {
        let filter = req.get_ref().clone();
        let token = self.token_for(&req, &filter.token);
        let scope = self.authenticated_scope(&token)?;
        let want_device = filter.device_id.trim().to_string();
        let replay = self.ledger.replay(&scope, &want_device);

        let live = Review::stream_pending_reviews(&self.inner, req)
            .await?
            .into_inner();
        let accounts = self.accounts.clone();
        let token_for_live = token.clone();
        let want_for_live = want_device.clone();
        let live = live.filter_map(move |item| {
            let accounts = accounts.clone();
            let token = token_for_live.clone();
            let want_device = want_for_live.clone();
            async move {
                match item {
                    Err(status) => Some(Err(status)),
                    Ok(event) => {
                        let Some(scope) = accounts.guardian_scope(&token) else {
                            return Some(Err(Status::unauthenticated(
                                "guardian session was revoked or expired",
                            )));
                        };
                        let in_scope = scope.child_ids.contains(&event.child_id)
                            || scope.device_ids.contains(&event.device_id);
                        let device_matches =
                            want_device.is_empty() || event.device_id == want_device;
                        (in_scope && device_matches).then_some(Ok(event))
                    }
                }
            }
        });

        let replay_stream = futures_util::stream::iter(replay.into_iter().map(Ok));
        Ok(Response::new(Box::pin(replay_stream.chain(live))))
    }

    type FetchSegmentStream = SegmentChunkStream;

    async fn fetch_segment(
        &self,
        req: Request<SegmentRequest>,
    ) -> Result<Response<Self::FetchSegmentStream>, Status> {
        let token = self.token_for(&req, &req.get_ref().token);
        let scope = self.authenticated_scope(&token)?;
        let uri = req.get_ref().local_segment_uri.trim().to_string();
        let segments = self.segment_store.as_ref().ok_or_else(|| {
            Status::unavailable("raw review clip retention is disabled on this node")
        })?;
        let file = segments
            .open_authorized(&uri, &scope.device_ids)
            .map_err(|error| Status::internal(format!("opening retained clip: {error}")))?
            .ok_or_else(|| {
                Status::not_found("clip not found, expired, or not owned by this guardian")
            })?;
        let file = tokio::fs::File::from_std(file);

        let stream = futures_util::stream::unfold((file, false), |(mut file, done)| async move {
            if done {
                return None;
            }
            let mut data = vec![0u8; SEGMENT_CHUNK_BYTES];
            match file.read(&mut data).await {
                Ok(0) => None,
                Ok(read) => {
                    data.truncate(read);
                    Some((Ok(SegmentChunk { data }), (file, false)))
                }
                Err(error) => Some((
                    Err(Status::internal(format!("reading retained clip: {error}"))),
                    (file, true),
                )),
            }
        });
        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str, device: &str) -> AlertEvent {
        AlertEvent {
            alert_id: id.into(),
            device_id: device.into(),
            child_id: "child-1".into(),
            family_id: "family-1".into(),
            category: bulwark_proto::v1::Category::AdultImage as i32,
            ..Default::default()
        }
    }

    #[test]
    fn conflicting_alert_id_is_rejected() {
        let ledger = ReviewLedger::new();
        assert!(ledger.record(&event("a", "d1")).unwrap());
        assert!(!ledger.record(&event("a", "d1")).unwrap());
        let error = ledger.record(&event("a", "d2")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn retired_alert_is_not_pending() {
        let ledger = ReviewLedger::new();
        assert!(ledger.record(&event("a", "d1")).unwrap());
        assert!(ledger.alert("a").is_some());
        assert!(ledger.retire("a").unwrap());
        assert!(ledger.alert("a").is_none());
        assert!(!ledger.retire("a").unwrap());
    }

    #[test]
    fn durable_corruption_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-review-ledger-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("review_ledger.json"), b"not json").unwrap();
        assert!(ReviewLedger::with_state_dir(&dir).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
