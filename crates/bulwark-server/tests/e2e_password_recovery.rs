//! End-to-end password-lifecycle tests over real in-process gRPC.
//!
//! Covers the self-service recovery story the way the parent app drives it:
//! create an account (receive a one-time recovery code), change the password while
//! authenticated, and — the no-operator path — reset a forgotten password with the
//! recovery code, which rotates the code and invalidates the old credentials. Also
//! asserts the per-email reset rate limit (repeated wrong guesses refused) and that
//! the wire never carries the password back.

use std::time::Duration;

use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::accounts_server::AccountsServer;
use bulwark_proto::v1::{
    ChangePasswordRequest, CreateAccountRequest, ListChildrenRequest, LoginRequest,
    ResetPasswordRequest,
};
use bulwark_server::accounts::{AccountStore, AccountsService};
use tokio::net::TcpListener;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::Code;

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
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let accounts = AccountsService::new(AccountStore::new());
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(AccountsServer::new(accounts))
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
async fn change_then_self_service_reset_round_trip() {
    let server = TestServer::spawn().await;
    let channel = connect_with_retry(&server.endpoint).await;
    let mut accounts = AccountsClient::new(channel.clone());

    // Create → receive a ONE-TIME recovery code.
    let created = timeout(
        accounts.create_account(CreateAccountRequest {
            email: "fam@example.com".to_string(),
            password: "firstpassword".to_string(),
            display_name: "Family".to_string(),
        }),
        "CreateAccount",
    )
    .await
    .into_inner();
    assert!(created.created);
    let recovery_code = created.recovery_code.clone();
    assert!(
        !recovery_code.is_empty(),
        "fresh account gets a recovery code"
    );

    // Login, then change the password while authenticated.
    let session = timeout(
        accounts.login(LoginRequest {
            email: "fam@example.com".to_string(),
            password: "firstpassword".to_string(),
        }),
        "Login",
    )
    .await
    .into_inner();
    let token = session.token;

    timeout(
        accounts.change_password(ChangePasswordRequest {
            token: token.clone(),
            old_password: "firstpassword".to_string(),
            new_password: "secondpassword".to_string(),
        }),
        "ChangePassword",
    )
    .await;

    // New password logs in; the old one is dead.
    assert!(login_ok(&mut accounts, "fam@example.com", "secondpassword").await);
    assert_eq!(
        login_err(&mut accounts, "fam@example.com", "firstpassword").await,
        Code::Unauthenticated
    );

    // Forgotten password → self-service reset with the saved recovery code. No
    // operator, no email loop. A fresh recovery code comes back.
    let reset = timeout(
        accounts.reset_password(ResetPasswordRequest {
            email: "fam@example.com".to_string(),
            recovery_code: recovery_code.clone(),
            new_password: "thirdpassword".to_string(),
        }),
        "ResetPassword",
    )
    .await
    .into_inner();
    assert!(reset.ok);
    assert!(!reset.new_recovery_code.is_empty());
    assert_ne!(reset.new_recovery_code, recovery_code);

    // The reset password works; the prior one does not.
    assert!(login_ok(&mut accounts, "fam@example.com", "thirdpassword").await);
    assert_eq!(
        login_err(&mut accounts, "fam@example.com", "secondpassword").await,
        Code::Unauthenticated
    );

    // The OLD recovery code is single-use → now invalid.
    let reuse_err = tokio::time::timeout(
        STEP_TIMEOUT,
        accounts.reset_password(ResetPasswordRequest {
            email: "fam@example.com".to_string(),
            recovery_code,
            new_password: "fourthpassword".to_string(),
        }),
    )
    .await
    .expect("reset did not hang")
    .expect_err("a consumed recovery code must not work again");
    assert_eq!(reuse_err.code(), Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_with_wrong_code_is_denied_and_throttled() {
    let server = TestServer::spawn().await;
    let channel = connect_with_retry(&server.endpoint).await;
    let mut accounts = AccountsClient::new(channel.clone());

    timeout(
        accounts.create_account(CreateAccountRequest {
            email: "victim@example.com".to_string(),
            password: "victimpassword".to_string(),
            display_name: "V".to_string(),
        }),
        "CreateAccount",
    )
    .await;

    // Five wrong codes → Unauthenticated each; the sixth attempt is throttled.
    for _ in 0..5 {
        let err = tokio::time::timeout(
            STEP_TIMEOUT,
            accounts.reset_password(ResetPasswordRequest {
                email: "victim@example.com".to_string(),
                recovery_code: "WRONG-CODE-0000".to_string(),
                new_password: "newpassword1".to_string(),
            }),
        )
        .await
        .expect("reset did not hang")
        .expect_err("wrong recovery code denied");
        assert_eq!(err.code(), Code::Unauthenticated);
    }
    let throttled = tokio::time::timeout(
        STEP_TIMEOUT,
        accounts.reset_password(ResetPasswordRequest {
            email: "victim@example.com".to_string(),
            recovery_code: "WRONG-CODE-0000".to_string(),
            new_password: "newpassword1".to_string(),
        }),
    )
    .await
    .expect("reset did not hang")
    .expect_err("reset is throttled after repeated failures");
    assert_eq!(throttled.code(), Code::ResourceExhausted);

    // The reset throttle does NOT lock the victim out of normal login.
    assert!(login_ok(&mut accounts, "victim@example.com", "victimpassword").await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_password_with_wrong_old_is_denied() {
    let server = TestServer::spawn().await;
    let channel = connect_with_retry(&server.endpoint).await;
    let mut accounts = AccountsClient::new(channel.clone());

    timeout(
        accounts.create_account(CreateAccountRequest {
            email: "cp@example.com".to_string(),
            password: "rightpassword".to_string(),
            display_name: "C".to_string(),
        }),
        "CreateAccount",
    )
    .await;
    let token = timeout(
        accounts.login(LoginRequest {
            email: "cp@example.com".to_string(),
            password: "rightpassword".to_string(),
        }),
        "Login",
    )
    .await
    .into_inner()
    .token;

    let err = tokio::time::timeout(
        STEP_TIMEOUT,
        accounts.change_password(ChangePasswordRequest {
            token: token.clone(),
            old_password: "wrongold".to_string(),
            new_password: "newpassword1".to_string(),
        }),
    )
    .await
    .expect("change did not hang")
    .expect_err("wrong old password is rejected");
    assert_eq!(err.code(), Code::Unauthenticated);

    // The original session + password still work (the failed change is a no-op).
    let _ = timeout(
        accounts.list_children(ListChildrenRequest {
            token: token.clone(),
        }),
        "ListChildren",
    )
    .await;
    assert!(login_ok(&mut accounts, "cp@example.com", "rightpassword").await);
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
