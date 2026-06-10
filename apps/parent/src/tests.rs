//! Console unit + loopback-gRPC tests (FakeReview server), exercising the
//! api/servers/state seams across the new module boundaries.

use crate::api::{
    open_pending_review_stream_from, request_with_bearer, review_request_at, submit_decision_to,
};
use crate::servers::{
    custom_server_id, normalize_custom_servers, resolve_endpoint, server_for_choice_from,
    server_inventory_for_choice, server_session_key, server_settings_initial_state, SavedServer,
};
use crate::state::{
    can_show_evidence, pair_expiry_text, seed, should_show_snippet, should_show_thumbnail, Alert,
};


use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bulwark_proto::v1::review_server::{Review, ReviewServer};
use bulwark_proto::v1::{
    AlertEvent, AlertKind, Category, DeviceFilter, Evidence, PushAck, PushTarget, ReviewAck,
    ReviewDecision, ReviewRequest, ReviewScope, SegmentChunk, SegmentRequest, Severity,
};
use futures_util::Stream;
use tokio::net::TcpListener;
use tonic::transport::{Endpoint, Server};
use tonic::{Request, Response, Status};

type AlertStream = Pin<Box<dyn Stream<Item = Result<AlertEvent, Status>> + Send + 'static>>;
type SegmentStream = Pin<Box<dyn Stream<Item = Result<SegmentChunk, Status>> + Send + 'static>>;

#[derive(Clone, Debug)]
struct CapturedDecision {
    auth: Option<String>,
    request: ReviewRequest,
}

#[derive(Clone, Debug)]
struct CapturedFilter {
    auth: Option<String>,
    filter: DeviceFilter,
}

#[derive(Clone)]
struct FakeReview {
    events: Arc<Vec<AlertEvent>>,
    decisions: Arc<Mutex<Vec<CapturedDecision>>>,
    filters: Arc<Mutex<Vec<CapturedFilter>>>,
    ack_applied: bool,
}

impl FakeReview {
    fn with_events(events: Vec<AlertEvent>) -> Self {
        Self {
            events: Arc::new(events),
            decisions: Arc::new(Mutex::new(Vec::new())),
            filters: Arc::new(Mutex::new(Vec::new())),
            ack_applied: true,
        }
    }

    fn with_unapplied_ack() -> Self {
        Self {
            ack_applied: false,
            ..Self::with_events(Vec::new())
        }
    }
}

#[tonic::async_trait]
impl Review for FakeReview {
    async fn submit_decision(
        &self,
        req: Request<ReviewRequest>,
    ) -> Result<Response<ReviewAck>, Status> {
        let auth = auth_header(&req);
        let request = req.into_inner();
        self.decisions
            .lock()
            .expect("decisions lock")
            .push(CapturedDecision {
                auth,
                request: request.clone(),
            });
        Ok(Response::new(ReviewAck {
            alert_id: request.alert_id,
            applied: self.ack_applied,
        }))
    }

    async fn register_push_target(
        &self,
        _req: Request<PushTarget>,
    ) -> Result<Response<PushAck>, Status> {
        Ok(Response::new(PushAck { ok: true }))
    }

    type StreamPendingReviewsStream = AlertStream;

    async fn stream_pending_reviews(
        &self,
        req: Request<DeviceFilter>,
    ) -> Result<Response<Self::StreamPendingReviewsStream>, Status> {
        let auth = auth_header(&req);
        let filter = req.into_inner();
        self.filters
            .lock()
            .expect("filters lock")
            .push(CapturedFilter { auth, filter });
        let events = self.events.as_ref().clone();
        Ok(Response::new(Box::pin(futures_util::stream::iter(
            events.into_iter().map(Ok),
        ))))
    }

    type FetchSegmentStream = SegmentStream;

    async fn fetch_segment(
        &self,
        _req: Request<SegmentRequest>,
    ) -> Result<Response<Self::FetchSegmentStream>, Status> {
        Ok(Response::new(Box::pin(futures_util::stream::iter([Ok(
            SegmentChunk {
                data: b"fake clip".to_vec(),
            },
        )]))))
    }
}

struct TestReviewServer {
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}

impl TestReviewServer {
    async fn spawn(review: FakeReview) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake review server");
        let addr = listener.local_addr().expect("fake review addr");
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(ReviewServer::new(review))
                .serve_with_incoming(incoming)
                .await
                .expect("fake review server serves");
        });
        Self {
            endpoint: format!("http://{addr}"),
            task,
        }
    }
}

impl Drop for TestReviewServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[test]
fn server_choice_resolves_regions_and_self_hosted() {
    assert!(resolve_endpoint("").contains("eu-west-2"));
    assert!(resolve_endpoint("cloud").contains("eu-west-2"));
    assert!(resolve_endpoint("unknown").contains("eu-west-2"));
    assert_eq!(resolve_endpoint("us"), "https://us.cloud.phbulwark.app");
    assert_eq!(
        resolve_endpoint("https://family.example.test:8443"),
        "https://family.example.test:8443"
    );

    assert_eq!(
        server_settings_initial_state(""),
        ("uk".to_string(), String::new())
    );
    assert_eq!(
        server_settings_initial_state("https://family.example.test:8443"),
        (
            "selfhosted".to_string(),
            "https://family.example.test:8443".to_string()
        )
    );
}

#[test]
fn server_inventory_merges_builtins_custom_and_legacy_url() {
    let custom = SavedServer::new("self-home", "Home server", "https://home.example.test:8443");
    let rows =
        server_inventory_for_choice("https://legacy.example.test:8443", vec![custom.clone()]);

    assert!(rows.iter().any(|s| s.id == "uk" && s.builtin));
    assert!(rows.iter().any(|s| s.id == "us" && s.builtin));
    assert!(rows.iter().any(|s| s == &custom));
    assert!(rows.iter().any(|s| {
        s.endpoint == "https://legacy.example.test:8443" && s.label == "Self-hosted"
    }));
}

#[test]
fn custom_server_inventory_normalizes_invalid_and_duplicates() {
    let rows = normalize_custom_servers(vec![
        SavedServer::new("self-a", "A", "https://a.example.test:8443"),
        SavedServer::new("self-a", "Duplicate id", "https://b.example.test:8443"),
        SavedServer::new(
            "self-c",
            "Duplicate endpoint",
            "https://a.example.test:8443",
        ),
        SavedServer::new("bad", "Bad", "ftp://bad.example.test"),
        SavedServer::new("", "Empty", "https://empty.example.test"),
    ]);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, "self-a");
    assert_eq!(rows[0].label, "A");
    assert!(!rows[0].builtin);
}

#[test]
fn custom_server_choice_resolves_by_id() {
    let server = SavedServer::new("self-home", "Home server", "https://home.example.test:8443");
    let rows = server_inventory_for_choice("", vec![server.clone()]);
    assert_eq!(server_for_choice_from("self-home", &rows), server);
    assert_eq!(
        custom_server_id(" https://home.example.test:8443 "),
        custom_server_id("https://home.example.test:8443")
    );
}

#[test]
fn server_session_keys_are_endpoint_scoped() {
    let london = server_session_key("http://london.example:8443");
    let us = server_session_key("http://us.example:8443");
    let london_again = server_session_key(" http://london.example:8443 ");

    assert_eq!(london, london_again);
    assert_ne!(london, us);
    assert_eq!(london.len(), 16);
    assert!(london.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn pair_expiry_text_is_human_readable() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    assert!(pair_expiry_text(now + 30_000).contains("expires in"));
    assert_eq!(pair_expiry_text(0), "unknown expiry");
}

#[test]
fn offline_seed_is_fake_safe_and_non_actionable() {
    let rows = seed();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|a| !a.actionable));
    assert!(rows.iter().all(|a| a.thumbnail.is_empty()));
    assert!(rows.iter().all(|a| a.segment_uri.is_none()));
    assert!(rows.iter().any(|a| a.id == "a-1001"));
    assert!(rows.iter().any(|a| a.title.contains("Possible grooming")));
}

#[test]
fn fake_alert_mapping_shows_allowed_evidence_but_never_csam() {
    let adult = Alert::from_event(fake_alert(
        "fake-adult",
        "kids-tablet",
        Category::AdultImage,
        tiny_png(),
        "blocked text snippet",
    ));
    assert_eq!(adult.title, "Blocked an adult image");
    assert!(should_show_thumbnail(&adult));
    assert!(should_show_snippet(&adult));

    let csam = Alert::from_event(fake_alert(
        "fake-csam",
        "kids-tablet",
        Category::CsamSuspected,
        tiny_png(),
        "must not render",
    ));
    assert_eq!(csam.title, "Blocked suspected illegal content");
    assert!(!can_show_evidence(csam.category));
    assert!(!should_show_thumbnail(&csam));
    assert!(!should_show_snippet(&csam));
}

#[test]
fn decision_request_and_bearer_metadata_are_stable() {
    let req = review_request_at("alert-1", "device-1", true, 123);
    assert_eq!(req.alert_id, "alert-1");
    assert_eq!(req.device_id, "device-1");
    assert_eq!(req.decision, ReviewDecision::Approve as i32);
    assert_eq!(req.scope, ReviewScope::ThisHost as i32);
    assert_eq!(req.ts, 123);

    let request = request_with_bearer(req, " token-123 ");
    assert_eq!(
        request
            .metadata()
            .get("authorization")
            .expect("authorization metadata")
            .to_str()
            .expect("metadata string"),
        "Bearer token-123"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parent_opens_live_stream_and_maps_fake_alert() {
    let fake = FakeReview::with_events(vec![fake_alert(
        "stream-alert-1",
        "kids-phone",
        Category::Grooming,
        Vec::new(),
        "move this chat elsewhere",
    )]);
    let server = TestReviewServer::spawn(fake.clone()).await;
    wait_for_server(&server.endpoint).await;

    let mut stream = open_pending_review_stream_from(&server.endpoint, "guardian-token")
        .await
        .expect("open fake review stream");
    let event = stream
        .message()
        .await
        .expect("stream message result")
        .expect("one fake alert");
    let alert = Alert::from_event(event);
    assert_eq!(alert.id, "stream-alert-1");
    assert_eq!(alert.device, "kids-phone");
    assert_eq!(alert.title, "Possible grooming detected");
    assert!(should_show_snippet(&alert));

    let filters = fake.filters.lock().expect("filters lock");
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].filter.token, "guardian-token");
    assert!(filters[0].auth.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parent_submit_decision_hits_fake_review_with_bearer_token() {
    let fake = FakeReview::with_events(Vec::new());
    let server = TestReviewServer::spawn(fake.clone()).await;
    wait_for_server(&server.endpoint).await;

    submit_decision_to(
        &server.endpoint,
        "guardian-token",
        "decision-alert-1",
        "kids-device",
        true,
    )
    .await
    .expect("submit fake decision");

    let decisions = fake.decisions.lock().expect("decisions lock");
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].auth.as_deref(), Some("Bearer guardian-token"));
    assert_eq!(decisions[0].request.alert_id, "decision-alert-1");
    assert_eq!(decisions[0].request.device_id, "kids-device");
    assert_eq!(
        decisions[0].request.decision,
        ReviewDecision::Approve as i32
    );
    assert!(decisions[0].request.ts > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parent_submit_decision_surfaces_unapplied_ack() {
    let fake = FakeReview::with_unapplied_ack();
    let server = TestReviewServer::spawn(fake).await;
    wait_for_server(&server.endpoint).await;

    let err = submit_decision_to(
        &server.endpoint,
        "guardian-token",
        "decision-alert-2",
        "kids-device",
        false,
    )
    .await
    .expect_err("unapplied ack should surface as an error");
    assert!(err.to_string().contains("did not apply"));
}

fn fake_alert(
    alert_id: &str,
    device_id: &str,
    category: Category,
    thumbnail: Vec<u8>,
    snippet: &str,
) -> AlertEvent {
    AlertEvent {
        alert_id: alert_id.to_string(),
        kind: if category == Category::Grooming {
            AlertKind::GroomingSuspected
        } else {
            AlertKind::Intervention
        } as i32,
        category: category as i32,
        severity: Severity::High as i32,
        app: "fake-chat".to_string(),
        device_id: device_id.to_string(),
        child_id: "child-1".to_string(),
        ts: 1_700_000_000_000,
        redacted_context: "Fake alert for parent e2e.".to_string(),
        evidence: Some(Evidence {
            sha256: vec![1, 2, 3, 4],
            perceptual_hash: Vec::new(),
            safe_thumbnail: thumbnail,
            text_snippet: snippet.to_string(),
            model_id: "fake-model".to_string(),
            model_version: "0".to_string(),
        }),
        ..Default::default()
    }
}

fn tiny_png() -> Vec<u8> {
    vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
}

fn auth_header<T>(req: &Request<T>) -> Option<String> {
    req.metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

async fn wait_for_server(endpoint: &str) {
    let ep = Endpoint::from_shared(endpoint.to_string())
        .expect("valid endpoint")
        .connect_timeout(Duration::from_millis(500));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match ep.connect().await {
            Ok(_) => return,
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("fake review server never came up at {endpoint}: {e}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
