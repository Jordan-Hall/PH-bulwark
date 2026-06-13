//! `bulwark-server` binary. Role chosen by `--role lb|worker|all-in-one`
//! (or `$BULWARK_ROLE`), bind address by `$BULWARK_BIND` (default 127.0.0.1:8443).
//!
//! Single-node usage:  `bulwark-server --role all-in-one`
#![forbid(unsafe_code)]

use std::sync::Arc;

use bulwark_server::{service, AnalyzerRegistry, ServerConfig, ServerRole};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = bulwark_core::init_tracing_default();

    let role = std::env::args()
        .skip_while(|a| a != "--role")
        .nth(1)
        .or_else(|| std::env::var("BULWARK_ROLE").ok())
        .and_then(|s| ServerRole::parse(&s))
        .unwrap_or(ServerRole::AllInOne);

    let bind = std::env::var("BULWARK_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());

    // Accounts (multi-tenant guardian sessions) are OFF by default so a local/dev
    // install works with an empty token (device-scoped Review). Opt in with
    // BULWARK_ACCOUNTS=1 once guardian sessions are provisioned.
    let accounts_enabled = matches!(
        std::env::var("BULWARK_ACCOUNTS").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );

    // Durable guardian state: when BULWARK_STATE_DIR is set, accounts are persisted
    // there and reloaded on restart; unset = in-memory (dev default).
    let state_dir = std::env::var_os("BULWARK_STATE_DIR")
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);

    // Transport security: BULWARK_TLS_CERT + BULWARK_TLS_KEY (PEM file paths)
    // enable server TLS; BULWARK_TLS_CLIENT_CA additionally requires client
    // certificates (mTLS). Read at startup so a typo'd path fails the boot
    // loudly instead of silently falling back to plaintext.
    let tls_cert_pem = read_pem_env("BULWARK_TLS_CERT")?;
    let tls_key_pem = read_pem_env("BULWARK_TLS_KEY")?;
    let client_ca_pem = read_pem_env("BULWARK_TLS_CLIENT_CA")?;
    if tls_cert_pem.is_some() != tls_key_pem.is_some() {
        anyhow::bail!("BULWARK_TLS_CERT and BULWARK_TLS_KEY must be set together (PEM file paths)");
    }

    // Guardian passwords and session tokens MUST NOT cross the network in clear:
    // accounts mode without TLS refuses to start. BULWARK_ALLOW_PLAINTEXT=1 is
    // the explicit, grep-able dev override — a log warning could regress unseen.
    let allow_plaintext = matches!(
        std::env::var("BULWARK_ALLOW_PLAINTEXT").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    if accounts_enabled && tls_cert_pem.is_none() && !allow_plaintext {
        anyhow::bail!(
            "refusing to start: accounts mode (BULWARK_ACCOUNTS=1) over plaintext would send \
             guardian passwords and session tokens in clear. Set BULWARK_TLS_CERT/BULWARK_TLS_KEY \
             (PEM file paths), or BULWARK_ALLOW_PLAINTEXT=1 for local development only."
        );
    }

    // Staff admin (internal operators console): OFF by default; opt in with
    // BULWARK_STAFF=1. Same plaintext refusal as accounts mode — staff
    // passwords and TOTP codes must never cross the network in clear.
    let staff_enabled = matches!(
        std::env::var("BULWARK_STAFF").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    if staff_enabled && tls_cert_pem.is_none() && !allow_plaintext {
        anyhow::bail!(
            "refusing to start: staff mode (BULWARK_STAFF=1) over plaintext would send \
             staff passwords and TOTP codes in clear. Set BULWARK_TLS_CERT/BULWARK_TLS_KEY \
             (PEM file paths), or BULWARK_ALLOW_PLAINTEXT=1 for local development only."
        );
    }

    let cfg = ServerConfig {
        role,
        bind,
        accounts_enabled,
        state_dir,
        tls_cert_pem,
        tls_key_pem,
        client_ca_pem,
        staff_enabled,
    };

    // Text + buffered-video dispatch (image/audio stay on the device fast path /
    // future worker wiring). Video fails open without bulwark-video's `ffmpeg`.
    //
    // Retain blocked video clips for guardian replay ONLY on an all-in-one node,
    // where the parent app reads `blob://` from the same disk. A distributed
    // worker's local store is unreachable by a remote parent, so it keeps no store
    // (the child device's client pipeline retains clips there instead).
    let segment_store = matches!(role, ServerRole::AllInOne)
        .then(bulwark_video::SegmentStore::default_location)
        .and_then(|r| {
            r.map_err(|e| tracing::warn!(error = %e, "segment store unavailable; video review clips not retained server-side"))
                .ok()
        });
    let registry = AnalyzerRegistry::with_text_and_video(segment_store);

    // Cluster config from the environment (BULWARK_NODE_ID / _CLUSTER_ADDRESS /
    // _CLUSTER_SEEDS / _QUORUM_DSN / …) so a multi-node deployment (e.g. the Ansible
    // cluster playbook) can point workers at the LB's address without code changes.
    let cluster = matches!(role, ServerRole::AllInOne | ServerRole::Lb).then(|| {
        Arc::new(bulwark_cluster::Cluster::new(
            bulwark_cluster::ClusterConfig::from_env(),
        ))
    });

    // Guardian-ALERT email sink: on only when BULWARK_ALERT_FROM +
    // BULWARK_ALERT_RECIPIENTS are set (BULWARK_SMTP_HOST is the shared
    // transport — it may be set purely for the password-reset mailer, which
    // must NOT force a static alert recipient). A partial config fails at
    // startup rather than silently dropping alerts.
    let email_sink: Option<Arc<dyn bulwark_alert::AlertSink>> =
        match bulwark_alert::AlertConfig::from_env().map_err(|e| anyhow::anyhow!(e))? {
            Some(cfg) => {
                let sink =
                    bulwark_alert::EmailAlertSink::new(cfg).map_err(|e| anyhow::anyhow!(e))?;
                tracing::info!("email alert sink configured (SMTP)");
                Some(Arc::new(sink))
            }
            None => {
                tracing::info!(
                    "no guardian-alert email sink (BULWARK_ALERT_FROM/RECIPIENTS unset); \
                     password-reset mail is independent and uses BULWARK_SMTP_HOST + BULWARK_RESET_FROM"
                );
                None
            }
        };

    // DEFAULT build: the relay hub is built inside `run`; only email is wired, so
    // the default server build + host CI stay byte-identical.
    #[cfg(not(feature = "push"))]
    let (alert_sink, hub) = (email_sink, None::<bulwark_server::AlertHub>);

    // PUSH build: build the hub HERE so the UnifiedPush fan-out sink can read its
    // live push_targets at raise time; compose email + push best-effort.
    //
    // UnifiedPush needs NO server-side config (no project id, no service account,
    // no OAuth) — it just HTTP-POSTs the redacted payload to whatever guardian
    // endpoint URLs are registered. So the sink is always available under the
    // `push` feature and fans to whatever the registry currently holds (an empty
    // registry is a successful no-op).
    #[cfg(feature = "push")]
    let (alert_sink, hub) = {
        let hub = match &cfg.state_dir {
            Some(dir) => {
                bulwark_server::AlertHub::with_state_dir(dir).map_err(|e| anyhow::anyhow!(e))?
            }
            None => bulwark_server::AlertHub::new(),
        };
        let reg = Arc::new(bulwark_server::relay::HubTokenRegistry::new(hub.clone()));
        let push_sink: Arc<dyn bulwark_alert::AlertSink> = Arc::new(
            bulwark_alert::UnifiedPushFanoutSink::new(reg).map_err(|e| anyhow::anyhow!(e))?,
        );
        tracing::info!("UnifiedPush fan-out sink configured (self-hosted; no Google/Apple)");
        let combined: Option<Arc<dyn bulwark_alert::AlertSink>> = match email_sink {
            Some(e) => Some(Arc::new(bulwark_alert::CompositeSink::new(vec![e, push_sink]))),
            None => Some(push_sink),
        };
        (combined, Some(hub))
    };

    tracing::info!(?role, "starting bulwark-server");
    service::run(cfg, registry, alert_sink, cluster, hub).await
}

/// Read an env var holding a PEM **file path** into bytes. Unset/empty → `None`;
/// set-but-unreadable → an error (a bad cert path must fail the boot, never
/// silently fall back to plaintext).
fn read_pem_env(var: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            let pem = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("{var}: cannot read {}: {e}", path.display()))?;
            Ok(Some(pem))
        }
        None => Ok(None),
    }
}
