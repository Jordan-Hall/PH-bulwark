//! End-to-end provisioning test through the `aegis_admin` executable.
//!
//! The generated-client e2e suite proves the gRPC contract. This test adds the
//! operator/app-facing layer: commands read secrets from env, target the selected
//! server endpoint, create a guardian session, mint a pair code, and redeem it
//! from the child side.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use aegis_proto::v1::accounts_server::AccountsServer;
use aegis_server::accounts::{AccountStore, AccountsService};
use tokio::net::TcpListener;
use tonic::transport::Server;

struct TestAccountsServer {
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}

impl TestAccountsServer {
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
                .expect("accounts server serves");
        });

        Self {
            endpoint: format!("http://{addr}"),
            task,
        }
    }
}

impl Drop for TestAccountsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_cli_creates_pair_code_and_child_redeems_it() {
    let server = TestAccountsServer::spawn().await;
    wait_for_server(&server.endpoint).await;

    let admin = admin_bin();
    let base_env = [("AEGIS_ADMIN_ENDPOINT", server.endpoint.as_str())];

    let created = run_admin(
        &admin,
        &["create-account", "guardian-cli@example.com", "Guardian CLI"],
        &[
            ("AEGIS_ADMIN_ENDPOINT", server.endpoint.as_str()),
            ("AEGIS_ADMIN_PASSWORD", "password123"),
        ],
    );
    assert_contains(&created, "created=true");

    let login = run_admin(
        &admin,
        &["login", "guardian-cli@example.com"],
        &[
            ("AEGIS_ADMIN_ENDPOINT", server.endpoint.as_str()),
            ("AEGIS_ADMIN_PASSWORD", "password123"),
        ],
    );
    let token = value_for(&login, "token").expect("login printed token");
    assert!(!token.is_empty());

    let pair = run_admin(
        &admin,
        &["create-pair-code", "CLI Kid"],
        &[
            ("AEGIS_ADMIN_ENDPOINT", server.endpoint.as_str()),
            ("AEGIS_GUARDIAN_TOKEN", &token),
        ],
    );
    let code = value_for(&pair, "code").expect("pair code printed");
    assert!(!code.is_empty());

    let redeemed = run_admin(
        &admin,
        &["redeem-pair-code", &code, "cli-child-device-1"],
        &base_env,
    );
    let child_id = value_for(&redeemed, "child_id").expect("redeem printed child_id");
    assert!(!child_id.is_empty());

    let children = run_admin(
        &admin,
        &["list-children"],
        &[
            ("AEGIS_ADMIN_ENDPOINT", server.endpoint.as_str()),
            ("AEGIS_GUARDIAN_TOKEN", &token),
        ],
    );
    assert_contains(&children, "device=cli-child-device-1");
}

fn admin_bin() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_aegis_admin") {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().expect("current test exe");
    let deps = exe.parent().expect("deps dir");
    let debug = deps.parent().expect("debug dir");
    debug.join(format!("aegis_admin{}", std::env::consts::EXE_SUFFIX))
}

fn run_admin(bin: &PathBuf, args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    cmd.env_remove("AEGIS_ADMIN_PASSWORD")
        .env_remove("AEGIS_GUARDIAN_TOKEN")
        .env_remove("AEGIS_CLUSTER_CA")
        .env_remove("AEGIS_ADMIN_ENDPOINT");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("spawn aegis_admin");
    if !output.status.success() {
        panic!(
            "aegis_admin {:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn value_for(output: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(|v| v.trim().to_string()))
}

fn assert_contains(output: &str, needle: &str) {
    assert!(
        output.contains(needle),
        "expected output to contain `{needle}`\nactual:\n{output}"
    );
}

async fn wait_for_server(endpoint: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tonic::transport::Endpoint::from_shared(endpoint.to_string())
            .expect("valid endpoint")
            .connect_timeout(Duration::from_millis(500))
            .connect()
            .await
        {
            Ok(_) => return,
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("accounts server never came up at {endpoint}: {e}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
