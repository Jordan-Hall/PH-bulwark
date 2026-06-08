//! `bulwark_admin` — provision parent accounts / children / guardians against a
//! running `bulwark-server`'s `Accounts` gRPC service. Closes the "RPC-only, no
//! provisioning CLI" gap from the deployment runbook.
//!
//! Talks to `BULWARK_ADMIN_ENDPOINT` (default `http://127.0.0.1:8443`); if
//! `BULWARK_CLUSTER_CA` is set it pins that CA for a TLS connection. The server
//! must be running with `BULWARK_ACCOUNTS=1` (and ideally `BULWARK_STATE_DIR` set, so
//! the provisioned accounts persist).
//!
//! Secrets are read from the environment — NEVER from argv, where they would leak
//! into `ps` output and shell history. The password comes from
//! `$BULWARK_ADMIN_PASSWORD`; the session token from `$BULWARK_GUARDIAN_TOKEN` (the
//! same var the parent app reads, set from `login`'s output).
//!
//! ```text
//! BULWARK_ADMIN_PASSWORD=… bulwark_admin create-account  <email> [display_name]
//! BULWARK_ADMIN_PASSWORD=… bulwark_admin login           <email>   # -> session token
//! BULWARK_GUARDIAN_TOKEN=… bulwark_admin add-child       <child_name> <device_id>
//! BULWARK_GUARDIAN_TOKEN=… bulwark_admin assign-guardian <child_id> <guardian_account_id>
//! BULWARK_GUARDIAN_TOKEN=… bulwark_admin list-children
//! BULWARK_GUARDIAN_TOKEN=… bulwark_admin create-pair-code <child_name>
//!                         bulwark_admin redeem-pair-code <code> <device_id>
//! ```
#![forbid(unsafe_code)]

use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::{
    AddChildRequest, AssignGuardianRequest, CreateAccountRequest, CreatePairCodeRequest,
    ListChildrenRequest, LoginRequest, RedeemPairCodeRequest,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    CreateAccount {
        email: String,
        display_name: String,
    },
    Login {
        email: String,
    },
    AddChild {
        child_name: String,
        device_id: String,
    },
    AssignGuardian {
        child_id: String,
        guardian_account_id: String,
    },
    ListChildren,
    CreatePairCode {
        child_name: String,
    },
    RedeemPairCode {
        code: String,
        device_id: String,
    },
}

fn usage() -> String {
    "usage: bulwark_admin <subcommand> ...\n  \
     create-account  <email> [display_name]   (password from $BULWARK_ADMIN_PASSWORD)\n  \
     login           <email>                  (password from $BULWARK_ADMIN_PASSWORD)\n  \
     add-child       <child_name> <device_id>           (token from $BULWARK_GUARDIAN_TOKEN)\n  \
     assign-guardian <child_id> <guardian_account_id>   (token from $BULWARK_GUARDIAN_TOKEN)\n  \
     list-children                                      (token from $BULWARK_GUARDIAN_TOKEN)\n  \
     create-pair-code <child_name>                      (token from $BULWARK_GUARDIAN_TOKEN)\n  \
     redeem-pair-code <code> <device_id>                (code is the short-lived credential)"
        .to_string()
}

/// Resolve the account password from `$BULWARK_ADMIN_PASSWORD` — never from argv
/// (which leaks into `ps`, shell history, and process listings). Pure over the
/// env value so it can be unit-tested.
fn require_password(env_val: Option<String>) -> Result<String, String> {
    match env_val {
        Some(p) if !p.is_empty() => Ok(p),
        _ => Err(
            "set the password in $BULWARK_ADMIN_PASSWORD (not on the command \
                  line — argv is visible to other processes / shell history)"
                .to_string(),
        ),
    }
}

/// Resolve the guardian session token from `$BULWARK_GUARDIAN_TOKEN` — also kept off
/// argv (a token is a bearer credential). Same env var the parent app reads. Pure.
fn require_token(env_val: Option<String>) -> Result<String, String> {
    match env_val {
        Some(t) if !t.trim().is_empty() => Ok(t.trim().to_string()),
        _ => Err(
            "set the session token in $BULWARK_GUARDIAN_TOKEN (from `login`; \
                  kept off the command line — it is a bearer credential)"
                .to_string(),
        ),
    }
}

/// Parse argv (without the program name) into a [`Cmd`]. Pure — unit-tested.
fn parse(args: &[String]) -> Result<Cmd, String> {
    let sub = args.first().map(String::as_str).ok_or_else(usage)?;
    let rest = &args[1..];
    let need = |n: usize| -> Result<(), String> {
        if rest.len() < n {
            Err(format!(
                "`{sub}` needs {n} argument(s); got {}\n{}",
                rest.len(),
                usage()
            ))
        } else {
            Ok(())
        }
    };
    match sub {
        "create-account" => {
            need(1)?;
            Ok(Cmd::CreateAccount {
                email: rest[0].clone(),
                display_name: rest.get(1).cloned().unwrap_or_default(),
            })
        }
        "login" => {
            need(1)?;
            Ok(Cmd::Login {
                email: rest[0].clone(),
            })
        }
        "add-child" => {
            need(2)?;
            Ok(Cmd::AddChild {
                child_name: rest[0].clone(),
                device_id: rest[1].clone(),
            })
        }
        "assign-guardian" => {
            need(2)?;
            Ok(Cmd::AssignGuardian {
                child_id: rest[0].clone(),
                guardian_account_id: rest[1].clone(),
            })
        }
        "list-children" => Ok(Cmd::ListChildren),
        "create-pair-code" => {
            need(1)?;
            Ok(Cmd::CreatePairCode {
                child_name: rest[0].clone(),
            })
        }
        "redeem-pair-code" => {
            need(2)?;
            Ok(Cmd::RedeemPairCode {
                code: rest[0].clone(),
                device_id: rest[1].clone(),
            })
        }
        other => Err(format!("unknown subcommand `{other}`\n{}", usage())),
    }
}

/// Connect to the Accounts service: `BULWARK_ADMIN_ENDPOINT` (default plaintext dev
/// gateway), pinning `BULWARK_CLUSTER_CA` for TLS when set.
async fn connect() -> anyhow::Result<AccountsClient<Channel>> {
    let endpoint = std::env::var("BULWARK_ADMIN_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8443".to_string());
    let mut builder = Endpoint::from_shared(endpoint)?;
    if let Ok(ca) = std::env::var("BULWARK_CLUSTER_CA") {
        if !ca.is_empty() {
            let pem = std::fs::read(&ca)?;
            let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&pem));
            builder = builder.tls_config(tls)?;
        }
    }
    Ok(AccountsClient::new(builder.connect().await?))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    // Resolve secrets (env-only) BEFORE connecting, so a missing secret fails fast
    // and never reaches the wire / a process listing.
    let password = match &cmd {
        Cmd::CreateAccount { .. } | Cmd::Login { .. } => Some(
            require_password(std::env::var("BULWARK_ADMIN_PASSWORD").ok())
                .map_err(|e| anyhow::anyhow!(e))?,
        ),
        _ => None,
    };
    let token = match &cmd {
        Cmd::AddChild { .. } | Cmd::AssignGuardian { .. } | Cmd::ListChildren => Some(
            require_token(std::env::var("BULWARK_GUARDIAN_TOKEN").ok())
                .map_err(|e| anyhow::anyhow!(e))?,
        ),
        Cmd::CreatePairCode { .. } => Some(
            require_token(std::env::var("BULWARK_GUARDIAN_TOKEN").ok())
                .map_err(|e| anyhow::anyhow!(e))?,
        ),
        Cmd::RedeemPairCode { .. } => None,
        _ => None,
    };

    let mut client = connect().await?;
    match cmd {
        Cmd::CreateAccount {
            email,
            display_name,
        } => {
            let ack = client
                .create_account(CreateAccountRequest {
                    email,
                    password: password.expect("password resolved for create-account"),
                    display_name,
                })
                .await?
                .into_inner();
            println!("account_id={}", ack.account_id);
            println!("created={}", ack.created);
            if !ack.detail.is_empty() {
                println!("{}", ack.detail);
            }
        }
        Cmd::Login { email } => {
            let s = client
                .login(LoginRequest {
                    email,
                    password: password.expect("password resolved for login"),
                })
                .await?
                .into_inner();
            println!("token={}", s.token);
            println!("account_id={}", s.account_id);
        }
        Cmd::AddChild {
            child_name,
            device_id,
        } => {
            let c = client
                .add_child(AddChildRequest {
                    token: token.expect("token resolved for add-child"),
                    child_name,
                    device_id,
                })
                .await?
                .into_inner();
            println!("child_id={}", c.child_id);
            println!("device_id={}", c.device_id);
        }
        Cmd::AssignGuardian {
            child_id,
            guardian_account_id,
        } => {
            let a = client
                .assign_guardian(AssignGuardianRequest {
                    token: token.expect("token resolved for assign-guardian"),
                    child_id,
                    guardian_account_id,
                })
                .await?
                .into_inner();
            println!("ok={}", a.ok);
            if !a.detail.is_empty() {
                println!("{}", a.detail);
            }
        }
        Cmd::ListChildren => {
            let kids = client
                .list_children(ListChildrenRequest {
                    token: token.expect("token resolved for list-children"),
                })
                .await?
                .into_inner();
            if kids.children.is_empty() {
                println!("(no children assigned to this guardian)");
            }
            for c in kids.children {
                println!(
                    "{}  name={:?}  device={}  guardians=[{}]",
                    c.child_id,
                    c.child_name,
                    c.device_id,
                    c.guardian_account_ids.join(",")
                );
            }
        }
        Cmd::CreatePairCode { child_name } => {
            let pair = client
                .create_pair_code(CreatePairCodeRequest {
                    token: token.expect("token resolved for create-pair-code"),
                    child_name,
                })
                .await?
                .into_inner();
            println!("code={}", pair.code);
            println!("expires_ts={}", pair.expires_ts);
        }
        Cmd::RedeemPairCode { code, device_id } => {
            let result = client
                .redeem_pair_code(RedeemPairCodeRequest { code, device_id })
                .await?
                .into_inner();
            println!("child_id={}", result.child_id);
            println!("family_id={}", result.family_id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_create_account_with_optional_display_name() {
        // Password is NOT taken from argv (env only) — so create-account takes
        // just the email and an optional display name.
        assert_eq!(
            parse(&v(&["create-account", "a@x.com"])).unwrap(),
            Cmd::CreateAccount {
                email: "a@x.com".into(),
                display_name: String::new(),
            }
        );
        assert_eq!(
            parse(&v(&["create-account", "a@x.com", "Alice"])).unwrap(),
            Cmd::CreateAccount {
                email: "a@x.com".into(),
                display_name: "Alice".into(),
            }
        );
    }

    #[test]
    fn rejects_missing_args_no_subcommand_and_unknown() {
        assert!(parse(&v(&["add-child", "only-name"])).is_err()); // needs name + device
        assert!(parse(&v(&["assign-guardian", "only-child"])).is_err()); // needs 2
        assert!(parse(&v(&["create-account"])).is_err()); // needs an email
        assert!(parse(&v(&["login"])).is_err()); // needs an email
        assert!(parse(&v(&["create-pair-code"])).is_err()); // needs child name
        assert!(parse(&v(&["redeem-pair-code", "ABCD1234"])).is_err()); // needs code + device
        assert!(parse(&v(&["bogus"])).is_err());
        assert!(parse(&v(&[])).is_err());
    }

    #[test]
    fn secrets_are_env_only() {
        assert_eq!(require_password(Some("pw".into())).unwrap(), "pw");
        assert!(require_password(None).is_err());
        assert!(require_password(Some(String::new())).is_err());
        assert_eq!(require_token(Some(" tok ".into())).unwrap(), "tok"); // trimmed
        assert!(require_token(None).is_err());
        assert!(require_token(Some("   ".into())).is_err()); // blank
    }

    #[test]
    fn parses_token_commands_without_token_on_argv() {
        assert_eq!(
            parse(&v(&["login", "a@x.com"])).unwrap(),
            Cmd::Login {
                email: "a@x.com".into(),
            }
        );
        // Token is from $BULWARK_GUARDIAN_TOKEN, so these take only their data args.
        assert_eq!(
            parse(&v(&["add-child", "Kid", "dev-1"])).unwrap(),
            Cmd::AddChild {
                child_name: "Kid".into(),
                device_id: "dev-1".into(),
            }
        );
        assert!(matches!(
            parse(&v(&["assign-guardian", "cid", "gid"])).unwrap(),
            Cmd::AssignGuardian { .. }
        ));
        assert_eq!(parse(&v(&["list-children"])).unwrap(), Cmd::ListChildren);
        assert_eq!(
            parse(&v(&["create-pair-code", "Kid"])).unwrap(),
            Cmd::CreatePairCode {
                child_name: "Kid".into(),
            }
        );
        assert_eq!(
            parse(&v(&["redeem-pair-code", "ABCD2345", "device-1"])).unwrap(),
            Cmd::RedeemPairCode {
                code: "ABCD2345".into(),
                device_id: "device-1".into(),
            }
        );
    }
}
