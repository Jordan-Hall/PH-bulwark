//! End-to-end integration test of the guardian approve/deny loop over real
//! gRPC, in-process.
//!
//! This is the genuine wire path — not a direct method call. We assemble the
//! `AlertRelay` + `Review` tonic services from `aegis-server`'s public service
//! types (sharing one [`AlertHub`] exactly as `service::run` does for an
//! `all-in-one` node), serve them on a loopback OS-assigned port over
//! **plaintext** (no TLS — dev/test only), and drive them with the generated
//! gRPC clients from `aegis-proto`.
//!
//! It proves:
//!   1. `AlertRelay.RaiseAlert` fans a redacted alert out to a live
//!      `Review.StreamPendingReviews` subscriber (the broadcast hub works).
//!   2. `Review.SubmitDecision(APPROVE, THIS_HOST)` is applied
//!      (`ReviewAck.applied == true`) — the relay resolves the raised alert's
//!      host so the per-device allowlist can key on it.
//!   3. A CSAM-category decision is **refused** (per the allowlist rule:
//!      CSAM is never allowlistable), surfaced as a gRPC `FailedPrecondition`.
//!
//! Every await is wrapped in a timeout so the test can never hang; the client
//! retries the connect until the server has bound.

use std::time::Duration;

use aegis_proto::v1::alert_relay_client::AlertRelayClient;
use aegis_proto::v1::alert_relay_server::AlertRelayServer;
use aegis_proto::v1::review_client::ReviewClient;
use aegis_proto::v1::review_server::ReviewServer;
use aegis_proto::v1::{
    AlertEvent, AlertKind, Category, DeviceFilter, Evidence, ReviewDecision, ReviewRequest,
    ReviewScope, Severity,
};

use aegis_server::relay::{AlertHub, ReviewService};
use aegis_server::service::AlertRelayService;

use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tonic::transport::{Endpoint, Server};

/// Hard cap on every individual await so a regression can never hang CI.
const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// A synthetic, fully-redacted guardian alert. Carries ONLY the no-media fields
/// the privacy invariant permits: a hash, no thumbnail, a redacted context line.
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
            safe_thumbnail: Vec::new(), // NO media
            text_snippet: String::new(),
            model_id: "test-model".to_string(),
            model_version: "0".to_string(),
        }),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guardian_approve_deny_loop_over_grpc() {
    // --- (a) start AlertRelay + Review on 127.0.0.1 with an OS-assigned port ---
    // Bind first so we KNOW the port (port 0 = OS picks), then hand the std
    // listener to tonic via an incoming stream. One shared AlertHub backs both
    // services — the same wiring `service::run` uses for an all-in-one node.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    let hub = AlertHub::new();
    let relay = AlertRelayService::new(hub.clone(), None); // no SMTP sink: fan-out only
    let review = ReviewService::new(hub);

    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(AlertRelayServer::new(relay))
            .add_service(ReviewServer::new(review))
            .serve_with_incoming(incoming)
            .await
            .expect("server serves");
    });

    // Retry-connect loop: give the server a moment to be ready before we dial.
    let endpoint = format!("http://{addr}");
    let channel = connect_with_retry(&endpoint).await;

    let mut relay_client = AlertRelayClient::new(channel.clone());
    let mut review_client = ReviewClient::new(channel);

    // --- (b) open a StreamPendingReviews subscription with an empty filter ---
    let stream_resp = timeout(
        review_client.stream_pending_reviews(DeviceFilter::default()),
        "open StreamPendingReviews",
    )
    .await;
    let mut pending = stream_resp.into_inner();

    // The subscription must be live before we publish, or the broadcast has no
    // receiver yet. tonic returns the response once the server-side handler has
    // produced the stream (it subscribes synchronously), so the subscriber is
    // registered by the time `into_inner` returns above.

    // --- (c) RaiseAlert with a synthetic, fully-redacted AlertEvent ----------
    let alert = synthetic_alert("alert-1", "kids-tablet", Category::AdultImage);
    let ack = timeout(relay_client.raise_alert(alert.clone()), "RaiseAlert")
        .await
        .into_inner();
    assert_eq!(ack.alert_id, "alert-1");
    assert!(
        ack.delivered,
        "alert should be delivered to the live guardian stream (reached > 0)"
    );

    // --- (d) the same alert arrives on the StreamPendingReviews stream -------
    let got = tokio::time::timeout(STEP_TIMEOUT, pending.next())
        .await
        .expect("fanned-out alert did not hang")
        .expect("stream yielded an item")
        .expect("item is Ok");
    assert_eq!(
        got.alert_id, "alert-1",
        "fan-out delivered the raised alert"
    );
    assert_eq!(got.device_id, "kids-tablet");
    assert_eq!(got.category, Category::AdultImage as i32);
    // Privacy invariant: no raw media crossed the wire.
    assert!(
        got.evidence
            .as_ref()
            .map(|e| e.safe_thumbnail.is_empty())
            .unwrap_or(true),
        "redacted event must carry no media"
    );

    // --- (e) SubmitDecision(APPROVE, THIS_HOST) is applied -------------------
    let approve = ReviewRequest {
        alert_id: "alert-1".to_string(),
        decision: ReviewDecision::Approve as i32,
        device_id: "kids-tablet".to_string(),
        scope: ReviewScope::ThisHost as i32,
        ts: 2,
    };
    let approve_ack = timeout(
        review_client.submit_decision(approve),
        "SubmitDecision APPROVE",
    )
    .await
    .into_inner();
    assert_eq!(approve_ack.alert_id, "alert-1");
    assert!(
        approve_ack.applied,
        "APPROVE(THIS_HOST) of a non-CSAM alert must be applied to the allowlist"
    );

    // --- (f) a CSAM-category decision is refused (allowlist rule) ------------
    // Raise a CSAM-suspected alert, then try to APPROVE it: the allowlist refuses
    // (CSAM is never allowlistable), surfaced as a FailedPrecondition status.
    let csam = synthetic_alert("alert-csam", "kids-tablet", Category::CsamSuspected);
    let _ = timeout(relay_client.raise_alert(csam), "RaiseAlert (CSAM)")
        .await
        .into_inner();

    let approve_csam = ReviewRequest {
        alert_id: "alert-csam".to_string(),
        decision: ReviewDecision::Approve as i32,
        device_id: "kids-tablet".to_string(),
        scope: ReviewScope::ThisHost as i32,
        ts: 3,
    };
    let err = tokio::time::timeout(STEP_TIMEOUT, review_client.submit_decision(approve_csam))
        .await
        .expect("SubmitDecision (CSAM) did not hang")
        .expect_err("APPROVE of CSAM must be refused");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "CSAM approve is refused as a precondition failure (never allowlisted)"
    );

    server.abort();
}

/// Dial the server, retrying briefly until it has bound. Fails the test (rather
/// than hanging) if it never comes up within the budget.
async fn connect_with_retry(endpoint: &str) -> tonic::transport::Channel {
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

/// Await a future under [`STEP_TIMEOUT`], unwrapping the tonic `Result` so a
/// call that errors (or hangs) fails the test with a clear message.
async fn timeout<T, F>(fut: F, what: &str) -> tonic::Response<T>
where
    F: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
{
    tokio::time::timeout(STEP_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("{what} timed out"))
        .unwrap_or_else(|e| panic!("{what} failed: {e}"))
}
