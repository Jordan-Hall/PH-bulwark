//! End-to-end ChildControl test over real in-process gRPC.
//!
//! Models the parent-controlled-VPN flow: a guardian logs in, pairs a child
//! device, then sets that child's desired config (region/endpoint, filtering
//! on/off, strictness band). Proves:
//!   1. A guardian SetChildConfig applies and the server stamps version = 1.
//!   2. A NON-guardian (a second account) is PermissionDenied.
//!   3. GetChildConfig by device_id returns the current config.
//!   4. A second Set bumps the monotonic version to 2.
//!   5. StreamChildConfig with a stale `have_version` emits the current config;
//!      with an up-to-date `have_version` it does NOT re-emit (no rollback /
//!      no redundant push).
//!   6. Devices authenticate: Get/Stream with a wrong or missing
//!      `device_token` (minted at pairing, returned once) are Unauthenticated.
//!
//! Every await is wrapped in a timeout so a regression can never hang CI.

use std::time::Duration;

use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::accounts_server::AccountsServer;
use bulwark_proto::v1::child_control_client::ChildControlClient;
use bulwark_proto::v1::child_control_server::ChildControlServer;
use bulwark_proto::v1::{
    ChildConfig, ChildConfigFilter, ChildStatusRequest, CreateAccountRequest,
    CreatePairCodeRequest, FilteringProfile, LoginRequest, RedeemPairCodeRequest,
    SetChildConfigRequest,
};
use bulwark_server::accounts::{AccountStore, AccountsService};
use bulwark_server::child_control::{ChildConfigStore, ChildControlService};
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

        // ONE accounts store shared by Accounts + ChildControl (single source of
        // truth for guardian→child scoping), exactly as service::run wires it.
        let accounts_store = AccountStore::new();
        let config_store = ChildConfigStore::new();
        let accounts = AccountsService::new(accounts_store.clone());
        let child_control = ChildControlService::new(config_store, accounts_store);

        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(AccountsServer::new(accounts))
                .add_service(ChildControlServer::new(child_control))
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
async fn guardian_sets_config_child_fetches_and_streams() {
    let server = TestServer::spawn().await;
    let channel = connect_with_retry(&server.endpoint).await;

    let mut accounts = AccountsClient::new(channel.clone());
    let mut control = ChildControlClient::new(channel.clone());

    // Guardian logs in and pairs a child device.
    let parent_token = create_and_login(&mut accounts, "parent@example.com").await;
    let pair = timeout(
        accounts.create_pair_code(CreatePairCodeRequest {
            token: parent_token.clone(),
            child_name: "Kid".to_string(),
        }),
        "CreatePairCode",
    )
    .await
    .into_inner();
    let paired = timeout(
        accounts.redeem_pair_code(RedeemPairCodeRequest {
            code: pair.code,
            device_id: "kids-device-1".to_string(),
        }),
        "RedeemPairCode",
    )
    .await
    .into_inner();
    let child_id = paired.child_id;
    let device_token = paired.device_token;
    assert!(!child_id.is_empty());
    assert!(
        !device_token.is_empty(),
        "redeem returns the per-device token exactly once"
    );

    // (1) Guardian sets the child's config → version 1, audit stamped.
    let ack = timeout(
        control.set_child_config(bearer(
            SetChildConfigRequest {
                token: String::new(), // via Bearer metadata, like Review
                config: Some(desired_config(&child_id, "kids-device-1", "uk")),
            },
            &parent_token,
        )),
        "SetChildConfig",
    )
    .await
    .into_inner();
    assert!(ack.applied);
    assert_eq!(ack.config_version, 1, "first config version is 1");

    // (2) A NON-guardian cannot set this child's config.
    let intruder_token = create_and_login(&mut accounts, "intruder@example.com").await;
    let denied = tokio::time::timeout(
        STEP_TIMEOUT,
        control.set_child_config(bearer(
            SetChildConfigRequest {
                token: String::new(),
                config: Some(desired_config(&child_id, "kids-device-1", "us")),
            },
            &intruder_token,
        )),
    )
    .await
    .expect("intruder SetChildConfig did not hang")
    .expect_err("a non-guardian must not set another family's child config");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    // (3) The child fetches its current config by device id.
    let got = timeout(
        control.get_child_config(ChildConfigFilter {
            device_id: "kids-device-1".to_string(),
            have_version: 0,
            device_token: device_token.clone(),
        }),
        "GetChildConfig",
    )
    .await
    .into_inner();
    assert_eq!(got.child_id, child_id);
    assert_eq!(got.server_region, "uk");
    assert_eq!(got.config_version, 1);
    assert!(got.filtering_enabled);
    assert_eq!(got.profile, FilteringProfile::Preteen as i32);

    // (3b) Devices authenticate: a WRONG (or missing) device token cannot read
    // the config — neither one-shot nor streaming.
    let get_denied = tokio::time::timeout(
        STEP_TIMEOUT,
        control.get_child_config(ChildConfigFilter {
            device_id: "kids-device-1".to_string(),
            have_version: 0,
            device_token: "not-the-token".to_string(),
        }),
    )
    .await
    .expect("wrong-token GetChildConfig did not hang")
    .expect_err("a wrong device token must not read the config");
    assert_eq!(get_denied.code(), tonic::Code::Unauthenticated);
    let stream_denied = tokio::time::timeout(
        STEP_TIMEOUT,
        control.stream_child_config(ChildConfigFilter {
            device_id: "kids-device-1".to_string(),
            have_version: 0,
            device_token: String::new(), // missing counts as wrong for a paired device
        }),
    )
    .await
    .expect("missing-token StreamChildConfig did not hang")
    .expect_err("a missing device token must not open the config stream");
    assert_eq!(stream_denied.code(), tonic::Code::Unauthenticated);

    // (4) A second guardian Set bumps the monotonic version to 2.
    let ack2 = timeout(
        control.set_child_config(bearer(
            SetChildConfigRequest {
                token: String::new(),
                config: Some(desired_config(&child_id, "kids-device-1", "us")),
            },
            &parent_token,
        )),
        "SetChildConfig #2",
    )
    .await
    .into_inner();
    assert_eq!(ack2.config_version, 2);

    // (5a) Stream with a STALE have_version emits the current (v2) config.
    let mut stream = timeout(
        control.stream_child_config(ChildConfigFilter {
            device_id: "kids-device-1".to_string(),
            have_version: 1, // child already applied v1 → wants anything newer
            device_token: device_token.clone(),
        }),
        "StreamChildConfig (stale)",
    )
    .await
    .into_inner();
    let pushed = tokio::time::timeout(STEP_TIMEOUT, stream.next())
        .await
        .expect("stream did not hang")
        .expect("stream yielded an item")
        .expect("ok config");
    assert_eq!(
        pushed.config_version, 2,
        "stale have_version gets the newer config"
    );
    assert_eq!(pushed.server_region, "us");

    // (5b) Stream with an UP-TO-DATE have_version does NOT re-emit the current
    // config (it only fires on a strictly newer guardian change).
    let mut current_stream = timeout(
        control.stream_child_config(ChildConfigFilter {
            device_id: "kids-device-1".to_string(),
            have_version: 2, // already current → nothing to push yet
            device_token: device_token.clone(),
        }),
        "StreamChildConfig (current)",
    )
    .await
    .into_inner();
    assert!(
        tokio::time::timeout(Duration::from_millis(250), current_stream.next())
            .await
            .is_err(),
        "an up-to-date child must not receive a redundant re-push"
    );

    // (6) Applied-version ack: every Get/Stream carries have_version = the
    // version the child applied, and the server records it (the 5b stream above
    // reported v2). The guardian's status query shows desired-vs-applied.
    let st = timeout(
        control.get_child_status(bearer(
            ChildStatusRequest {
                token: String::new(),
                child_id: child_id.clone(),
            },
            &parent_token,
        )),
        "GetChildStatus",
    )
    .await
    .into_inner();
    assert_eq!(st.desired_version, 2);
    assert_eq!(
        st.applied_version, 2,
        "the child's have_version was recorded as its applied version"
    );
    assert!(st.last_report_ts > 0, "check-in time recorded");
    let desired = st
        .desired
        .expect("status echoes the guardian's desired config");
    assert_eq!(desired.server_region, "us", "echo is the LATEST set (v2)");
    assert_eq!(desired.config_version, 2);

    // A non-guardian cannot read another family's child status.
    let status_denied = tokio::time::timeout(
        STEP_TIMEOUT,
        control.get_child_status(bearer(
            ChildStatusRequest {
                token: String::new(),
                child_id: child_id.clone(),
            },
            &intruder_token,
        )),
    )
    .await
    .expect("intruder GetChildStatus did not hang")
    .expect_err("a non-guardian must not read another family's child status");
    assert_eq!(status_denied.code(), tonic::Code::PermissionDenied);
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

fn desired_config(child_id: &str, device_id: &str, region: &str) -> ChildConfig {
    ChildConfig {
        child_id: child_id.to_string(),
        device_id: device_id.to_string(),
        filtering_enabled: true,
        server_region: region.to_string(),
        server_endpoint: format!("{region}.example:8443"),
        profile: FilteringProfile::Preteen as i32,
        require_always_on: true,
        // server-stamped — ignored on input:
        config_version: 0,
        updated_ts: 0,
        updated_by: String::new(),
        filter_location: 0,
    }
}

fn bearer<T>(msg: T, token: &str) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    let value = MetadataValue::try_from(format!("Bearer {token}")).expect("valid bearer metadata");
    req.metadata_mut().insert("authorization", value);
    req
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
