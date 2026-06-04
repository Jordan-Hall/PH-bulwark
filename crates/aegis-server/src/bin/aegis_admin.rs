//! `aegis_admin` — provision parent accounts / children / guardians against a
//! running `aegis-server`'s `Accounts` gRPC service. Closes the "RPC-only, no
//! provisioning CLI" gap from the deployment runbook.
//!
//! Talks to `AEGIS_ADMIN_ENDPOINT` (default `http://127.0.0.1:8443`); if
//! `AEGIS_CLUSTER_CA` is set it pins that CA for a TLS connection. The server
//! must be running with `AEGIS_ACCOUNTS=1` (and ideally `AEGIS_STATE_DIR` set, so
//! the provisioned accounts persist).
//!
//! The password is read from `$AEGIS_ADMIN_PASSWORD` — never passed on the command
//! line, where it would leak into `ps` output and shell history.
//!
//! ```text
//! AEGIS_ADMIN_PASSWORD=… aegis_admin create-account  <email> [display_name]
//! AEGIS_ADMIN_PASSWORD=… aegis_admin login           <email>   # -> session token
//! aegis_admin add-child       <token> <child_name> <device_id>
//! aegis_admin assign-guardian <token> <child_id> <guardian_account_id>
//! aegis_admin list-children   <token>
//! ```
#![forbid(unsafe_code)]

use aegis_proto::v1::accounts_client::AccountsClient;
use aegis_proto::v1::{
    AddChildRequest, AssignGuardianRequest, CreateAccountRequest, ListChildrenRequest, LoginRequest,
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
        token: String,
        child_name: String,
        device_id: String,
    },
    AssignGuardian {
        token: String,
        child_id: String,
        guardian_account_id: String,
    },
    ListChildren {
        token: String,
    },
}

fn usage() -> String {
    "usage: aegis_admin <subcommand> ...\n  \
     create-account  <email> [display_name]   (password from $AEGIS_ADMIN_PASSWORD)\n  \
     login           <email>                  (password from $AEGIS_ADMIN_PASSWORD)\n  \
     add-child       <token> <child_name> <device_id>\n  \
     assign-guardian <token> <child_id> <guardian_account_id>\n  \
     list-children   <token>"
        .to_string()
}

/// Resolve the account password from `$AEGIS_ADMIN_PASSWORD` — never from argv
/// (which leaks into `ps`, shell history, and process listings). Pure over the
/// env value so it can be unit-tested.
fn require_password(env_val: Option<String>) -> Result<String, String> {
    match env_val {
        Some(p) if !p.is_empty() => Ok(p),
        _ => Err(
            "set the password in $AEGIS_ADMIN_PASSWORD (not on the command \
                  line — argv is visible to other processes / shell history)"
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
            need(3)?;
            Ok(Cmd::AddChild {
                token: rest[0].clone(),
                child_name: rest[1].clone(),
                device_id: rest[2].clone(),
            })
        }
        "assign-guardian" => {
            need(3)?;
            Ok(Cmd::AssignGuardian {
                token: rest[0].clone(),
                child_id: rest[1].clone(),
                guardian_account_id: rest[2].clone(),
            })
        }
        "list-children" => {
            need(1)?;
            Ok(Cmd::ListChildren {
                token: rest[0].clone(),
            })
        }
        other => Err(format!("unknown subcommand `{other}`\n{}", usage())),
    }
}

/// Connect to the Accounts service: `AEGIS_ADMIN_ENDPOINT` (default plaintext dev
/// gateway), pinning `AEGIS_CLUSTER_CA` for TLS when set.
async fn connect() -> anyhow::Result<AccountsClient<Channel>> {
    let endpoint = std::env::var("AEGIS_ADMIN_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8443".to_string());
    let mut builder = Endpoint::from_shared(endpoint)?;
    if let Ok(ca) = std::env::var("AEGIS_CLUSTER_CA") {
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

    // Resolve the password (env-only) BEFORE connecting, so a missing password
    // fails fast and never reaches the wire / a process listing.
    let password = match &cmd {
        Cmd::CreateAccount { .. } | Cmd::Login { .. } => Some(
            require_password(std::env::var("AEGIS_ADMIN_PASSWORD").ok())
                .map_err(|e| anyhow::anyhow!(e))?,
        ),
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
            token,
            child_name,
            device_id,
        } => {
            let c = client
                .add_child(AddChildRequest {
                    token,
                    child_name,
                    device_id,
                })
                .await?
                .into_inner();
            println!("child_id={}", c.child_id);
            println!("device_id={}", c.device_id);
        }
        Cmd::AssignGuardian {
            token,
            child_id,
            guardian_account_id,
        } => {
            let a = client
                .assign_guardian(AssignGuardianRequest {
                    token,
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
        Cmd::ListChildren { token } => {
            let kids = client
                .list_children(ListChildrenRequest { token })
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
        assert!(parse(&v(&["add-child", "tok", "name"])).is_err()); // needs 3
        assert!(parse(&v(&["create-account"])).is_err()); // needs an email
        assert!(parse(&v(&["login"])).is_err()); // needs an email
        assert!(parse(&v(&["bogus"])).is_err());
        assert!(parse(&v(&[])).is_err());
    }

    #[test]
    fn require_password_is_env_only() {
        assert_eq!(require_password(Some("pw".into())).unwrap(), "pw");
        assert!(require_password(None).is_err()); // not set
        assert!(require_password(Some(String::new())).is_err()); // empty
    }

    #[test]
    fn parses_the_remaining_subcommands() {
        assert_eq!(
            parse(&v(&["login", "a@x.com"])).unwrap(),
            Cmd::Login {
                email: "a@x.com".into(),
            }
        );
        assert!(matches!(
            parse(&v(&["assign-guardian", "t", "cid", "gid"])).unwrap(),
            Cmd::AssignGuardian { .. }
        ));
        assert!(matches!(
            parse(&v(&["list-children", "t"])).unwrap(),
            Cmd::ListChildren { .. }
        ));
    }
}
