//! Reusable app-workflow harness for guardian/child E2E tests.
//!
//! The helpers model product roles rather than individual RPC calls: a guardian
//! selects one backend and logs in, a child enrolls on that same backend with a
//! stable device id, and review traffic goes through the real tonic clients.

use std::future::Future;
use std::time::Duration;

use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::accounts_server::AccountsServer;
use bulwark_proto::v1::alert_relay_client::AlertRelayClient;
use bulwark_proto::v1::alert_relay_server::AlertRelayServer;
use bulwark_proto::v1::review_client::ReviewClient;
use bulwark_proto::v1::review_server::ReviewServer;
use bulwark_proto::v1::{
    AccountAck, AlertAck, AlertEvent, AlertKind, Category, Children, CreateAccountRequest,
    CreatePairCodeRequest, DeviceFilter, Evidence, ListChildrenRequest, LoginRequest, PairCode,
    PairResult, RedeemPairCodeRequest, ReviewAck, ReviewDecision, ReviewRequest, ReviewScope,
    Severity,
};
use bulwark_server::accounts::{AccountStore, AccountsService};
use bulwark_server::relay::{AlertHub, ReviewService};
use bulwark_server::service::AlertRelayService;
use tokio::net::TcpListener;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Response, Status};

pub const STEP_TIMEOUT: Duration = Duration::from_secs(5);

pub struct WorkflowServer {
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}

impl WorkflowServer {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback workflow server");
        let addr = listener.local_addr().expect("workflow server addr");

        let store = AccountStore::new();
        let hub = AlertHub::new();
        let accounts = AccountsService::new(store.clone());
        let relay = AlertRelayService::new(hub.clone(), None);
        let review = ReviewService::with_accounts(hub, store);

        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(AccountsServer::new(accounts))
                .add_service(AlertRelayServer::new(relay))
                .add_service(ReviewServer::new(review))
                .serve_with_incoming(incoming)
                .await
                .expect("workflow server serves");
        });

        let endpoint = format!("http://{addr}");
        wait_for_server(&endpoint).await;
        Self { endpoint, task }
    }

    pub async fn channel(&self) -> Channel {
        connect_with_retry(&self.endpoint).await
    }

    pub async fn raise_alert_for_child(
        &self,
        alert_id: &str,
        child: &ChildEnrollment,
        category: Category,
    ) -> AlertAck {
        let mut relay = AlertRelayClient::new(self.channel().await);
        timeout_ok(
            relay.raise_alert(synthetic_alert(alert_id, child, category)),
            "RaiseAlert",
        )
        .await
    }
}

impl Drop for WorkflowServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct GuardianApp {
    channel: Channel,
    token: Option<String>,
}

impl GuardianApp {
    pub async fn connect(server: &WorkflowServer) -> Self {
        Self {
            channel: server.channel().await,
            token: None,
        }
    }

    pub async fn connect_with_token(server: &WorkflowServer, token: String) -> Self {
        Self {
            channel: server.channel().await,
            token: Some(token),
        }
    }

    pub fn token(&self) -> &str {
        self.token
            .as_deref()
            .expect("guardian must login before token use")
    }

    pub async fn create_account(
        &self,
        email: &str,
        password: &str,
        display_name: &str,
    ) -> AccountAck {
        let mut accounts = AccountsClient::new(self.channel.clone());
        timeout_ok(
            accounts.create_account(CreateAccountRequest {
                email: email.to_string(),
                password: password.to_string(),
                display_name: display_name.to_string(),
            }),
            "CreateAccount",
        )
        .await
    }

    pub async fn login(&mut self, email: &str, password: &str) -> String {
        let mut accounts = AccountsClient::new(self.channel.clone());
        let session = timeout_ok(
            accounts.login(LoginRequest {
                email: email.to_string(),
                password: password.to_string(),
            }),
            "Login",
        )
        .await;
        self.token = Some(session.token.clone());
        session.token
    }

    pub async fn create_account_and_login(
        &mut self,
        email: &str,
        password: &str,
        display_name: &str,
    ) -> String {
        self.create_account(email, password, display_name).await;
        self.login(email, password).await
    }

    pub async fn create_pair_code(&self, child_name: &str) -> PairCode {
        self.try_create_pair_code(child_name)
            .await
            .unwrap_or_else(|e| panic!("CreatePairCode failed: {e}"))
    }

    pub async fn try_create_pair_code(&self, child_name: &str) -> Result<PairCode, Status> {
        let mut accounts = AccountsClient::new(self.channel.clone());
        timeout_result(
            accounts.create_pair_code(CreatePairCodeRequest {
                token: self.token().to_string(),
                child_name: child_name.to_string(),
            }),
            "CreatePairCode",
        )
        .await
    }

    pub async fn list_children(&self) -> Children {
        let mut accounts = AccountsClient::new(self.channel.clone());
        timeout_ok(
            accounts.list_children(ListChildrenRequest {
                token: self.token().to_string(),
            }),
            "ListChildren",
        )
        .await
    }

    pub async fn open_reviews(&self) -> tonic::Streaming<AlertEvent> {
        let mut review = ReviewClient::new(self.channel.clone());
        timeout_ok(
            review.stream_pending_reviews(DeviceFilter {
                device_id: String::new(),
                token: self.token().to_string(),
            }),
            "StreamPendingReviews",
        )
        .await
    }

    pub async fn next_review(stream: &mut tonic::Streaming<AlertEvent>, what: &str) -> AlertEvent {
        tokio::time::timeout(STEP_TIMEOUT, stream.message())
            .await
            .unwrap_or_else(|_| panic!("{what} timed out"))
            .unwrap_or_else(|e| panic!("{what} errored: {e}"))
            .unwrap_or_else(|| panic!("{what} ended before an alert arrived"))
    }

    pub async fn submit_decision(
        &self,
        alert_id: &str,
        device_id: &str,
        decision: ReviewDecision,
    ) -> ReviewAck {
        let mut review = ReviewClient::new(self.channel.clone());
        timeout_ok(
            review.submit_decision(bearer(
                ReviewRequest {
                    alert_id: alert_id.to_string(),
                    decision: decision as i32,
                    device_id: device_id.to_string(),
                    scope: ReviewScope::ThisHost as i32,
                    ts: now_ms(),
                },
                self.token(),
            )),
            "SubmitDecision",
        )
        .await
    }
}

pub struct ChildApp {
    channel: Channel,
    device_id: String,
    enrollment: Option<ChildEnrollment>,
}

impl ChildApp {
    pub async fn connect(server: &WorkflowServer, device_id: &str) -> Self {
        Self {
            channel: server.channel().await,
            device_id: device_id.to_string(),
            enrollment: None,
        }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn enrollment(&self) -> &ChildEnrollment {
        self.enrollment
            .as_ref()
            .expect("child must enroll before enrollment use")
    }

    pub async fn enroll(&mut self, code: &str) -> ChildEnrollment {
        let pair = self
            .try_enroll(code)
            .await
            .unwrap_or_else(|e| panic!("RedeemPairCode failed: {e}"));
        let enrollment = ChildEnrollment {
            child_id: pair.child_id,
            family_id: pair.family_id,
            device_id: self.device_id.clone(),
        };
        self.enrollment = Some(enrollment.clone());
        enrollment
    }

    pub async fn try_enroll(&self, code: &str) -> Result<PairResult, Status> {
        let mut accounts = AccountsClient::new(self.channel.clone());
        timeout_result(
            accounts.redeem_pair_code(RedeemPairCodeRequest {
                code: code.to_string(),
                device_id: self.device_id.clone(),
            }),
            "RedeemPairCode",
        )
        .await
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildEnrollment {
    pub child_id: String,
    pub family_id: String,
    pub device_id: String,
}

fn synthetic_alert(alert_id: &str, child: &ChildEnrollment, category: Category) -> AlertEvent {
    AlertEvent {
        alert_id: alert_id.to_string(),
        kind: if category == Category::Grooming {
            AlertKind::GroomingSuspected
        } else {
            AlertKind::Intervention
        } as i32,
        category: category as i32,
        severity: Severity::High as i32,
        app: "workflow.example".to_string(),
        device_id: child.device_id.clone(),
        child_id: child.child_id.clone(),
        family_id: child.family_id.clone(),
        ts: now_ms(),
        redacted_context: "Synthetic workflow alert with redacted context.".to_string(),
        evidence: Some(Evidence {
            sha256: vec![0xde, 0xad, 0xbe, 0xef],
            perceptual_hash: Vec::new(),
            safe_thumbnail: Vec::new(),
            text_snippet: String::new(),
            model_id: "workflow-harness".to_string(),
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

async fn timeout_ok<T, F>(fut: F, what: &str) -> T
where
    F: Future<Output = Result<Response<T>, Status>>,
{
    timeout_result(fut, what).await.unwrap_or_else(|e| {
        panic!("{what} failed: {e}");
    })
}

async fn timeout_result<T, F>(fut: F, what: &str) -> Result<T, Status>
where
    F: Future<Output = Result<Response<T>, Status>>,
{
    tokio::time::timeout(STEP_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("{what} timed out"))
        .map(Response::into_inner)
}

async fn wait_for_server(endpoint: &str) {
    let _ = connect_with_retry(endpoint).await;
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
                    panic!("workflow server never came up at {endpoint}: {e}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
