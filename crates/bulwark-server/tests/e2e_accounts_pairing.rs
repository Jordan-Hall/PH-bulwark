//! End-to-end account/pairing tests over real in-process gRPC.
//!
//! These tests model the planned app flow:
//! guardian app selects one server, logs in, creates a child pair code; child app
//! redeems the code with its stable device id; Review streams and decisions are
//! then scoped to that child's guardians. A second test spins two independent
//! servers to prove region/self-host boundaries: tokens and pair codes are local
//! to the selected backend.

use std::time::Duration;

use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::accounts_server::AccountsServer;
use bulwark_proto::v1::alert_relay_client::AlertRelayClient;
use bulwark_proto::v1::alert_relay_server::AlertRelayServer;
use bulwark_proto::v1::review_client::ReviewClient;
use bulwark_proto::v1::review_server::ReviewServer;
use bulwark_proto::v1::{
    AlertEvent, AlertKind, Category, CreateAccountRequest, CreatePairCodeRequest, DeviceFilter,
    Evidence, ListChildrenRequest, LoginRequest, RedeemPairCodeRequest, ReviewDecision,
    ReviewRequest, ReviewScope, Severity,
};
use bulwark_server::accounts::{AccountStore, AccountsService};
use bulwark_server::relay::{AlertHub, ReviewService};
use bulwark_server::service::AlertRelayService;
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint, Server};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

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

        let store = AccountStore::new();
        let hub = AlertHub::new();
        let relay = AlertRelayService::new(hub.clone(), None);
        let review = ReviewService::with_accounts(hub, store.clone());
        let accounts = AccountsService::new(store);

        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(AccountsServer::new(accounts))
                .add_service(AlertRelayServer::new(relay))
                .add_service(ReviewServer::new(review))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_routes_alerts_and_decisions_to_assigned_guardian_only() {
    let server = TestServer::spawn().await;
    let channel = connect_with_retry(&server.endpoint).await;

    let mut accounts = AccountsClient::new(channel.clone());
    let mut relay = AlertRelayClient::new(channel.clone());
    let mut parent_review = ReviewClient::new(channel.clone());
    let mut unrelated_review = ReviewClient::new(channel.clone());

    let parent_token = create_and_login(&mut accounts, "parent@example.com").await;
    let unrelated_token = create_and_login(&mut accounts, "other@example.com").await;

    let pair = timeout(
        accounts.create_pair_code(CreatePairCodeRequest {
            token: parent_token.clone(),
            child_name: "Kid One".to_string(),
        }),
        "CreatePairCode",
    )
    .await
    .into_inner();
    assert!(!pair.code.is_empty());

    let paired = timeout(
        accounts.redeem_pair_code(RedeemPairCodeRequest {
            code: pair.code,
            device_id: "kids-device-1".to_string(),
        }),
        "RedeemPairCode",
    )
    .await
    .into_inner();
    assert!(!paired.child_id.is_empty());
    assert!(!paired.family_id.is_empty());
    assert!(
        !paired.device_token.is_empty(),
        "pairing delivers the per-device credential exactly once"
    );

    let kids = timeout(
        accounts.list_children(ListChildrenRequest {
            token: parent_token.clone(),
        }),
        "ListChildren",
    )
    .await
    .into_inner();
    assert!(kids
        .children
        .iter()
        .any(|c| c.child_id == paired.child_id && c.device_id == "kids-device-1"));

    let mut parent_stream = timeout(
        parent_review.stream_pending_reviews(DeviceFilter {
            device_id: String::new(),
            token: parent_token.clone(),
        }),
        "parent StreamPendingReviews",
    )
    .await
    .into_inner();
    let mut unrelated_stream = timeout(
        unrelated_review.stream_pending_reviews(DeviceFilter {
            device_id: String::new(),
            token: unrelated_token.clone(),
        }),
        "unrelated StreamPendingReviews",
    )
    .await
    .into_inner();

    let alert = synthetic_alert("paired-alert-1", "kids-device-1", Category::AdultImage);
    let ack = timeout(relay.raise_alert(alert), "RaiseAlert")
        .await
        .into_inner();
    assert_eq!(ack.alert_id, "paired-alert-1");
    assert!(ack.delivered, "the assigned guardian stream is live");

    let got = timeout_stream_next(&mut parent_stream, "parent receives paired alert").await;
    assert_eq!(got.alert_id, "paired-alert-1");
    assert_eq!(got.device_id, "kids-device-1");
    assert!(
        tokio::time::timeout(Duration::from_millis(250), unrelated_stream.next())
            .await
            .is_err(),
        "unassigned guardian must not receive another child's alert"
    );

    let approve = ReviewRequest {
        alert_id: "paired-alert-1".to_string(),
        decision: ReviewDecision::Approve as i32,
        device_id: "kids-device-1".to_string(),
        scope: ReviewScope::ThisHost as i32,
        ts: 2,
    };
    let approve_ack = timeout(
        parent_review.submit_decision(bearer(approve.clone(), &parent_token)),
        "parent SubmitDecision",
    )
    .await
    .into_inner();
    assert!(approve_ack.applied);

    let err = tokio::time::timeout(
        STEP_TIMEOUT,
        unrelated_review.submit_decision(bearer(approve, &unrelated_token)),
    )
    .await
    .expect("unrelated SubmitDecision did not hang")
    .expect_err("unassigned guardian cannot decide another child's alert");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_choices_are_auth_and_pairing_boundaries() {
    let london = TestServer::spawn().await;
    let us = TestServer::spawn().await;

    let london_channel = connect_with_retry(&london.endpoint).await;
    let us_channel = connect_with_retry(&us.endpoint).await;
    let mut london_accounts = AccountsClient::new(london_channel.clone());
    let mut us_accounts = AccountsClient::new(us_channel.clone());
    let mut us_review = ReviewClient::new(us_channel.clone());

    let london_token = create_and_login(&mut london_accounts, "guardian@example.com").await;
    let london_pair = timeout(
        london_accounts.create_pair_code(CreatePairCodeRequest {
            token: london_token.clone(),
            child_name: "London Kid".to_string(),
        }),
        "London CreatePairCode",
    )
    .await
    .into_inner();

    let redeem_on_us = tokio::time::timeout(
        STEP_TIMEOUT,
        us_accounts.redeem_pair_code(RedeemPairCodeRequest {
            code: london_pair.code.clone(),
            device_id: "device-cross-region".to_string(),
        }),
    )
    .await
    .expect("US RedeemPairCode did not hang")
    .expect_err("a London pair code must not redeem on the US/self-host server");
    assert_eq!(redeem_on_us.code(), tonic::Code::NotFound);

    let create_with_london_token_on_us = tokio::time::timeout(
        STEP_TIMEOUT,
        us_accounts.create_pair_code(CreatePairCodeRequest {
            token: london_token.clone(),
            child_name: "Wrong Server Kid".to_string(),
        }),
    )
    .await
    .expect("US CreatePairCode did not hang")
    .expect_err("a London session token must not authenticate to another server");
    assert_eq!(
        create_with_london_token_on_us.code(),
        tonic::Code::Unauthenticated
    );

    let stream_with_london_token_on_us = tokio::time::timeout(
        STEP_TIMEOUT,
        us_review.stream_pending_reviews(DeviceFilter {
            device_id: String::new(),
            token: london_token,
        }),
    )
    .await
    .expect("US StreamPendingReviews did not hang")
    .expect_err("review stream tokens are server-local");
    assert_eq!(
        stream_with_london_token_on_us.code(),
        tonic::Code::Unauthenticated
    );

    let us_token = create_and_login(&mut us_accounts, "guardian@example.com").await;
    let us_pair = timeout(
        us_accounts.create_pair_code(CreatePairCodeRequest {
            token: us_token,
            child_name: "US Kid".to_string(),
        }),
        "US CreatePairCode",
    )
    .await
    .into_inner();
    let us_child = timeout(
        us_accounts.redeem_pair_code(RedeemPairCodeRequest {
            code: us_pair.code,
            device_id: "us-device-1".to_string(),
        }),
        "US RedeemPairCode",
    )
    .await
    .into_inner();
    assert!(!us_child.child_id.is_empty());
}

async fn create_and_login(client: &mut AccountsClient<Channel>, email: &str) -> String {
    timeout(
        client.create_account(CreateAccountRequest {
            email: email.to_string(),
            password: "password123".to_string(),
            display_name: email.to_string(),
        }),
        "CreateAccount",
    )
    .await;
    timeout(
        client.login(LoginRequest {
            email: email.to_string(),
            password: "password123".to_string(),
        }),
        "Login",
    )
    .await
    .into_inner()
    .token
}

fn synthetic_alert(alert_id: &str, device_id: &str, category: Category) -> AlertEvent {
    AlertEvent {
        alert_id: alert_id.to_string(),
        kind: AlertKind::Intervention as i32,
        category: category as i32,
        severity: Severity::High as i32,
        app: "example.com".to_string(),
        device_id: device_id.to_string(),
        ts: 1_700_000_000_000,
        redacted_context: "[redacted] flagged image on example.com".to_string(),
        evidence: Some(Evidence {
            sha256: vec![0xde, 0xad, 0xbe, 0xef],
            perceptual_hash: Vec::new(),
            safe_thumbnail: Vec::new(),
            text_snippet: String::new(),
            model_id: "test-model".to_string(),
            model_version: "0".to_string(),
        }),
        ..Default::default()
    }
}

fn bearer<T>(msg: T, token: &str) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    let value = MetadataValue::try_from(format!("Bearer {token}")).expect("valid bearer metadata");
    req.metadata_mut().insert("authorization", value);
    req
}

async fn timeout_stream_next(stream: &mut tonic::Streaming<AlertEvent>, what: &str) -> AlertEvent {
    tokio::time::timeout(STEP_TIMEOUT, stream.next())
        .await
        .unwrap_or_else(|_| panic!("{what} timed out"))
        .expect("stream yielded an item")
        .unwrap_or_else(|e| panic!("{what} errored: {e}"))
}

async fn connect_with_retry(endpoint: &str) -> Channel {
    let ep = Endpoint::from_shared(endpoint.to_string())
        .expect("valid endpoint")
        .connect_timeout(Duration::from_millis(500));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match ep.connect().await {
            Ok(ch) => return ch,
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("server never came up at {endpoint}: {e}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn timeout<T, F>(fut: F, what: &str) -> tonic::Response<T>
where
    F: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
{
    tokio::time::timeout(STEP_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("{what} timed out"))
        .unwrap_or_else(|e| panic!("{what} failed: {e}"))
}
