//! End-to-end FamilySafety test over real in-process gRPC.
//!
//! Models the family safety-alert flow: a guardian logs in + pairs a child
//! device; the child raises an SOS; the guardian's scoped pending-review
//! stream receives the URGENT CHILD_SOS event. Staff send a region-wide safety
//! broadcast with the placeholder shared token; it reaches the same guardian
//! stream (scoping pass-through) and is listed for late-joining consoles.
//! Proves:
//!   1. RaiseSos with the pairing-minted device token is accepted; the ack
//!      reports the guardian stream it reached.
//!   2. RaiseSos with a wrong device token is Unauthenticated (no spoofed SOS).
//!   3. The CHILD_SOS event arrives on the guardian's scoped stream, CRITICAL,
//!      carrying the child's name — and no evidence/content.
//!   4. SendSafetyBroadcast with a wrong staff token is PermissionDenied; with
//!      the right one it is accepted, reaches the same stream, and
//!      ListSafetyBroadcasts returns it to an authenticated guardian (and
//!      refuses an anonymous caller).
//!
//! Every await is wrapped in a timeout so a regression can never hang CI.

use std::time::Duration;

use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::accounts_server::AccountsServer;
use bulwark_proto::v1::family_safety_client::FamilySafetyClient;
use bulwark_proto::v1::family_safety_server::FamilySafetyServer;
use bulwark_proto::v1::review_client::ReviewClient;
use bulwark_proto::v1::review_server::ReviewServer;
use bulwark_proto::v1::{
    AlertKind, CreateAccountRequest, CreatePairCodeRequest, DeviceFilter,
    ListSafetyBroadcastsRequest, LoginRequest, RedeemPairCodeRequest, SafetyBroadcast,
    SendSafetyBroadcastRequest, Severity, SosRequest,
};
use bulwark_server::accounts::{AccountStore, AccountsService};
use bulwark_server::family_safety::{FamilySafetyService, SafetyBroadcastStore};
use bulwark_server::relay::{AlertHub, ReviewService};
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Endpoint, Server};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);
const STAFF_TOKEN: &str = "e2e-staff-shared-token";

struct TestServer {
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");

        // ONE accounts store + ONE hub shared by Accounts/Review/FamilySafety,
        // exactly as service::run wires them.
        let accounts_store = AccountStore::new();
        let hub = AlertHub::new();
        let accounts = AccountsService::new(accounts_store.clone());
        let review = ReviewService::with_accounts(hub.clone(), accounts_store.clone());
        let family = FamilySafetyService::new(hub, SafetyBroadcastStore::new())
            .with_accounts(accounts_store)
            .with_staff_token(Some(STAFF_TOKEN.to_string()));

        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(AccountsServer::new(accounts))
                .add_service(ReviewServer::new(review))
                .add_service(FamilySafetyServer::new(family))
                .serve_with_incoming(incoming)
                .await
                .expect("server serves");
        });

        Self {
            endpoint: format!("http://{addr}"),
            task,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn connect_with_retry(endpoint: &str) -> Channel {
    for _ in 0..50 {
        if let Ok(ch) = Endpoint::from_shared(endpoint.to_string())
            .expect("valid endpoint")
            .connect()
            .await
        {
            return ch;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server never came up at {endpoint}");
}

/// Await with a hard timeout and unwrap a tonic result — a regression must
/// fail fast, never hang CI.
async fn timeout<T>(
    fut: impl std::future::Future<Output = Result<T, tonic::Status>>,
    what: &str,
) -> T {
    tokio::time::timeout(STEP_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("{what} timed out"))
        .unwrap_or_else(|e| panic!("{what} failed: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn child_sos_and_staff_broadcast_reach_the_guardian() {
    let server = TestServer::spawn().await;
    let channel = connect_with_retry(&server.endpoint).await;

    let mut accounts = AccountsClient::new(channel.clone());
    let mut family = FamilySafetyClient::new(channel.clone());
    let mut review = ReviewClient::new(channel.clone());

    // Guardian signs up, logs in, pairs the child device.
    timeout(
        accounts.create_account(CreateAccountRequest {
            email: "parent@example.com".into(),
            password: "password123".into(),
            display_name: "P".into(),
        }),
        "CreateAccount",
    )
    .await;
    let session = timeout(
        accounts.login(LoginRequest {
            email: "parent@example.com".into(),
            password: "password123".into(),
        }),
        "Login",
    )
    .await
    .into_inner();
    let pair = timeout(
        accounts.create_pair_code(CreatePairCodeRequest {
            token: session.token.clone(),
            child_name: "Kid".into(),
        }),
        "CreatePairCode",
    )
    .await
    .into_inner();
    let paired = timeout(
        accounts.redeem_pair_code(RedeemPairCodeRequest {
            code: pair.code,
            device_id: "kids-device-1".into(),
        }),
        "RedeemPairCode",
    )
    .await
    .into_inner();

    // Guardian opens their scoped pending-review stream.
    let mut stream = timeout(
        review.stream_pending_reviews(DeviceFilter {
            device_id: String::new(),
            token: session.token.clone(),
        }),
        "StreamPendingReviews",
    )
    .await
    .into_inner();

    // (2) A spoofed SOS (wrong device token) is rejected.
    let err = tokio::time::timeout(
        STEP_TIMEOUT,
        family.raise_sos(SosRequest {
            device_id: "kids-device-1".into(),
            device_token: "not-the-token".into(),
            ts: 1,
            client_sos_id: String::new(),
        }),
    )
    .await
    .expect("RaiseSos responds")
    .expect_err("wrong device token rejected");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // (1) The real SOS is accepted and reaches the guardian stream.
    let ack = timeout(
        family.raise_sos(SosRequest {
            device_id: "kids-device-1".into(),
            device_token: paired.device_token.clone(),
            ts: 1,
            client_sos_id: "sos-e2e-1".into(),
        }),
        "RaiseSos",
    )
    .await
    .into_inner();
    assert!(ack.delivered, "a live guardian stream took the SOS");
    assert_eq!(ack.guardian_streams_reached, 1);
    assert_eq!(ack.alert_id, "sos-e2e-1");

    // (3) URGENT, named, content-free.
    let ev = tokio::time::timeout(STEP_TIMEOUT, stream.next())
        .await
        .expect("stream yields in time")
        .expect("an item")
        .expect("ok event");
    assert_eq!(ev.kind, AlertKind::ChildSos as i32);
    assert_eq!(ev.severity, Severity::Critical as i32);
    assert_eq!(ev.device_id, "kids-device-1");
    assert!(
        ev.redacted_context.contains("Kid"),
        "carries the child's name: {}",
        ev.redacted_context
    );
    assert!(ev.evidence.is_none(), "an SOS carries no content");

    // (4) Staff broadcast: wrong token refused …
    let err = tokio::time::timeout(
        STEP_TIMEOUT,
        family.send_safety_broadcast(SendSafetyBroadcastRequest {
            staff_token: "guessed".into(),
            broadcast: Some(SafetyBroadcast {
                title: "Nope".into(),
                ..Default::default()
            }),
        }),
    )
    .await
    .expect("SendSafetyBroadcast responds")
    .expect_err("wrong staff token rejected");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // … the right token fans out (bypasses per-child scoping) and lists.
    let bcast = timeout(
        family.send_safety_broadcast(SendSafetyBroadcastRequest {
            staff_token: STAFF_TOKEN.into(),
            broadcast: Some(SafetyBroadcast {
                title: "Safety notice".into(),
                body: "A reminder from PH staff for families in this region.".into(),
                severity: Severity::High as i32,
                region: "uk".into(),
                ..Default::default()
            }),
        }),
        "SendSafetyBroadcast",
    )
    .await
    .into_inner();
    assert!(bcast.accepted);
    assert!(!bcast.broadcast_id.is_empty());
    assert_eq!(
        bcast.guardian_streams_reached, 1,
        "a broadcast reaches the scoped guardian stream"
    );

    let ev = tokio::time::timeout(STEP_TIMEOUT, stream.next())
        .await
        .expect("stream yields in time")
        .expect("an item")
        .expect("ok event");
    assert_eq!(ev.kind, AlertKind::SafetyBroadcast as i32);
    assert!(ev.redacted_context.contains("Safety notice"));

    // Anonymous List is refused in accounts mode; the guardian sees the notice.
    let err = tokio::time::timeout(
        STEP_TIMEOUT,
        family.list_safety_broadcasts(ListSafetyBroadcastsRequest::default()),
    )
    .await
    .expect("List responds")
    .expect_err("anonymous list rejected");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let listed = timeout(
        family.list_safety_broadcasts(ListSafetyBroadcastsRequest {
            token: session.token.clone(),
            ..Default::default()
        }),
        "ListSafetyBroadcasts",
    )
    .await
    .into_inner();
    assert_eq!(listed.broadcasts.len(), 1);
    assert_eq!(listed.broadcasts[0].broadcast_id, bcast.broadcast_id);
    assert_eq!(listed.broadcasts[0].issued_by, "staff-shared-token");
}
