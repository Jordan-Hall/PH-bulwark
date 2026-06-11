//! End-to-end tests for the EMAIL-based password-reset path over real in-process
//! gRPC. The email path sits ALONGSIDE the saved recovery code: a guardian who
//! can't find their recovery code asks the server to email a short-lived reset
//! code, then completes ResetPassword with it.
//!
//! The mailer is backed by a CAPTURING transport — these tests NEVER touch a real
//! SMTP server. We assert:
//!   * anti-enumeration: a known and an unknown email get the SAME generic ack;
//!   * the emailed token (captured from the fake transport) resets the password;
//!   * a used token is single-use (replay denied);
//!   * repeated requests for one email are rate-limited (the inbox isn't flooded).

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use bulwark_alert::transport::{MailTransport, OutgoingMail};
use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::accounts_server::AccountsServer;
use bulwark_proto::v1::{
    CreateAccountRequest, LoginRequest, RequestPasswordResetRequest, ResetPasswordRequest,
};
use bulwark_server::accounts::{AccountStore, AccountsService};
use bulwark_server::reset_mailer::ResetMailer;
use tokio::net::TcpListener;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::Code;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// Captures every email instead of sending it — the mockable seam.
#[derive(Clone, Default)]
struct CapturingTransport {
    sent: Arc<StdMutex<Vec<OutgoingMail>>>,
}

impl CapturingTransport {
    fn sent(&self) -> Vec<OutgoingMail> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl MailTransport for CapturingTransport {
    async fn send(&self, mail: OutgoingMail) -> bulwark_alert::Result<()> {
        self.sent.lock().unwrap().push(mail);
        Ok(())
    }
}

struct TestServer {
    endpoint: String,
    transport: CapturingTransport,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        let transport = CapturingTransport::default();
        let mailer = ResetMailer::with_transport(
            Arc::new(transport.clone()),
            "PH Bulwark <noreply@home.example>",
            "PH Bulwark — your password reset code",
        );
        let accounts = AccountsService::with_mailer(AccountStore::new(), mailer);

        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(AccountsServer::new(accounts))
                .serve_with_incoming(incoming)
                .await
                .expect("server serves");
        });
        Self {
            endpoint: format!("http://{addr}"),
            transport,
            task,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Pull the latest captured reset code out of the fake transport's last email.
/// The code is the only non-whitespace line that looks like a grouped code.
fn last_reset_code(transport: &CapturingTransport) -> String {
    let sent = transport.sent();
    let last = sent.last().expect("an email was sent");
    last.email
        .body
        .lines()
        .map(str::trim)
        .find(|l| {
            !l.is_empty()
                && l.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
                && l.contains('-')
        })
        .expect("reset code line present in the email body")
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_reset_is_anti_enumeration_then_emailed_token_resets() {
    let server = TestServer::spawn().await;
    let channel = connect_with_retry(&server.endpoint).await;
    let mut accounts = AccountsClient::new(channel.clone());

    timeout(
        accounts.create_account(CreateAccountRequest {
            email: "guardian@example.com".to_string(),
            password: "firstpassword".to_string(),
            display_name: "G".to_string(),
        }),
        "CreateAccount",
    )
    .await;

    // ANTI-ENUMERATION: a known and an unknown email get the SAME generic ack.
    let known = timeout(
        accounts.request_password_reset(RequestPasswordResetRequest {
            email: "guardian@example.com".to_string(),
        }),
        "RequestPasswordReset(known)",
    )
    .await
    .into_inner();
    let unknown = timeout(
        accounts.request_password_reset(RequestPasswordResetRequest {
            email: "nobody@example.com".to_string(),
        }),
        "RequestPasswordReset(unknown)",
    )
    .await
    .into_inner();
    assert!(known.ok && unknown.ok);
    assert_eq!(
        known.detail, unknown.detail,
        "the ack must be identical for known + unknown emails"
    );
    assert!(
        known.detail.contains("If that email has an account"),
        "generic anti-enumeration ack"
    );

    // Exactly ONE email went out — to the real account, not the unknown one.
    let sent = server.transport.sent();
    assert_eq!(sent.len(), 1, "only the known email is mailed");
    assert_eq!(sent[0].to, vec!["guardian@example.com".to_string()]);

    // The EMAILED code resets the password (carried in the recovery_code field).
    let code = last_reset_code(&server.transport);
    let reset = timeout(
        accounts.reset_password(ResetPasswordRequest {
            email: "guardian@example.com".to_string(),
            recovery_code: code.clone(),
            new_password: "secondpassword".to_string(),
        }),
        "ResetPassword(emailed token)",
    )
    .await
    .into_inner();
    assert!(reset.ok);
    assert!(!reset.new_recovery_code.is_empty());

    // New password logs in; the old one is dead.
    assert!(login_ok(&mut accounts, "guardian@example.com", "secondpassword").await);
    assert_eq!(
        login_err(&mut accounts, "guardian@example.com", "firstpassword").await,
        Code::Unauthenticated
    );

    // The emailed token is single-use → replaying it is denied.
    let replay = tokio::time::timeout(
        STEP_TIMEOUT,
        accounts.reset_password(ResetPasswordRequest {
            email: "guardian@example.com".to_string(),
            recovery_code: code,
            new_password: "thirdpassword".to_string(),
        }),
    )
    .await
    .expect("reset did not hang")
    .expect_err("a consumed emailed token must not work again");
    assert_eq!(replay.code(), Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_reset_requests_are_rate_limited() {
    let server = TestServer::spawn().await;
    let channel = connect_with_retry(&server.endpoint).await;
    let mut accounts = AccountsClient::new(channel.clone());

    timeout(
        accounts.create_account(CreateAccountRequest {
            email: "rl@example.com".to_string(),
            password: "firstpassword".to_string(),
            display_name: "R".to_string(),
        }),
        "CreateAccount",
    )
    .await;

    // Hammer the request endpoint well past the per-email cap. Every call still acks
    // generically (anti-enumeration), but the number of emails sent is bounded so an
    // inbox can't be flooded.
    for _ in 0..20 {
        let ack = timeout(
            accounts.request_password_reset(RequestPasswordResetRequest {
                email: "rl@example.com".to_string(),
            }),
            "RequestPasswordReset(spam)",
        )
        .await
        .into_inner();
        assert!(ack.ok);
    }
    let sent = server.transport.sent().len();
    assert!(
        sent < 20,
        "repeated requests must be rate-limited (sent {sent} emails for 20 requests)"
    );
}

async fn login_ok(client: &mut AccountsClient<Channel>, email: &str, password: &str) -> bool {
    tokio::time::timeout(
        STEP_TIMEOUT,
        client.login(LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
        }),
    )
    .await
    .expect("login did not hang")
    .is_ok()
}

async fn login_err(client: &mut AccountsClient<Channel>, email: &str, password: &str) -> Code {
    tokio::time::timeout(
        STEP_TIMEOUT,
        client.login(LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
        }),
    )
    .await
    .expect("login did not hang")
    .expect_err("expected a login error")
    .code()
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
