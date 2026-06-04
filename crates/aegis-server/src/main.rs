//! `aegis-server` binary. Role chosen by `--role lb|worker|all-in-one`
//! (or `$AEGIS_ROLE`), bind address by `$AEGIS_BIND` (default 127.0.0.1:8443).
//!
//! Single-node usage:  `aegis-server --role all-in-one`
#![forbid(unsafe_code)]

use std::sync::Arc;

use aegis_server::{service, AnalyzerRegistry, ServerConfig, ServerRole};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = aegis_core::init_tracing_default();

    let role = std::env::args()
        .skip_while(|a| a != "--role")
        .nth(1)
        .or_else(|| std::env::var("AEGIS_ROLE").ok())
        .and_then(|s| ServerRole::parse(&s))
        .unwrap_or(ServerRole::AllInOne);

    let bind = std::env::var("AEGIS_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());

    // Accounts (multi-tenant guardian sessions) are OFF by default so a local/dev
    // install works with an empty token (device-scoped Review). Opt in with
    // AEGIS_ACCOUNTS=1 once guardian sessions are provisioned.
    let accounts_enabled = matches!(
        std::env::var("AEGIS_ACCOUNTS").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );

    // Durable guardian state: when AEGIS_STATE_DIR is set, accounts are persisted
    // there and reloaded on restart; unset = in-memory (dev default).
    let state_dir = std::env::var_os("AEGIS_STATE_DIR")
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);

    let cfg = ServerConfig {
        role,
        bind,
        accounts_enabled,
        state_dir,
        // mTLS material is loaded from aegis-core Config in a full deployment;
        // left None here so a local single-node run works out of the box (dev).
        ..ServerConfig::default()
    };

    // Text + buffered-video dispatch (image/audio stay on the device fast path /
    // future worker wiring). Video fails open without aegis-video's `ffmpeg`.
    //
    // Retain blocked video clips for guardian replay ONLY on an all-in-one node,
    // where the parent app reads `blob://` from the same disk. A distributed
    // worker's local store is unreachable by a remote parent, so it keeps no store
    // (the child device's client pipeline retains clips there instead).
    let segment_store = matches!(role, ServerRole::AllInOne)
        .then(aegis_video::SegmentStore::default_location)
        .and_then(|r| {
            r.map_err(|e| tracing::warn!(error = %e, "segment store unavailable; video review clips not retained server-side"))
                .ok()
        });
    let registry = AnalyzerRegistry::with_text_and_video(segment_store);

    // Cluster config from the environment (AEGIS_NODE_ID / _CLUSTER_ADDRESS /
    // _CLUSTER_SEEDS / _QUORUM_DSN / …) so a multi-node deployment (e.g. the Ansible
    // cluster playbook) can point workers at the LB's address without code changes.
    let cluster = matches!(role, ServerRole::AllInOne | ServerRole::Lb).then(|| {
        Arc::new(aegis_cluster::Cluster::new(
            aegis_cluster::ClusterConfig::from_env(),
        ))
    });

    // Email sink: SMTP via env (AEGIS_SMTP_HOST + AEGIS_ALERT_FROM +
    // AEGIS_ALERT_RECIPIENTS, see AlertConfig::from_env), or None. A partial/
    // invalid config fails at startup rather than silently dropping alerts.
    let email_sink: Option<Arc<dyn aegis_alert::AlertSink>> =
        match aegis_alert::AlertConfig::from_env().map_err(|e| anyhow::anyhow!(e))? {
            Some(cfg) => {
                let sink = aegis_alert::EmailAlertSink::new(cfg).map_err(|e| anyhow::anyhow!(e))?;
                tracing::info!("email alert sink configured (SMTP)");
                Some(Arc::new(sink))
            }
            None => {
                tracing::info!("no email alert sink (AEGIS_SMTP_HOST unset)");
                None
            }
        };

    // DEFAULT build: the relay hub is built inside `run`; only email is wired, so
    // the default server build + host CI stay byte-identical.
    #[cfg(not(feature = "push"))]
    let (alert_sink, hub) = (email_sink, None::<aegis_server::AlertHub>);

    // PUSH build: build the hub HERE so the FCM fan-out sink can read its live
    // push_targets at raise time; compose email + push best-effort.
    #[cfg(feature = "push")]
    let (alert_sink, hub) = {
        let hub = match &cfg.state_dir {
            Some(dir) => {
                aegis_server::AlertHub::with_state_dir(dir).map_err(|e| anyhow::anyhow!(e))?
            }
            None => aegis_server::AlertHub::new(),
        };
        let push_sink: Option<Arc<dyn aegis_alert::AlertSink>> =
            match aegis_alert::FcmConfig::from_env().map_err(|e| anyhow::anyhow!(e))? {
                Some(fcm) => {
                    let reg = Arc::new(aegis_server::relay::HubTokenRegistry::new(hub.clone()));
                    let sink = aegis_alert::FcmFanoutSink::new(&fcm, reg)
                        .map_err(|e| anyhow::anyhow!(e))?;
                    tracing::info!("FCM push fan-out sink configured");
                    Some(Arc::new(sink))
                }
                None => {
                    tracing::info!("no FCM push sink (AEGIS_FCM_PROJECT_ID unset)");
                    None
                }
            };
        let combined: Option<Arc<dyn aegis_alert::AlertSink>> = match (email_sink, push_sink) {
            (Some(e), Some(p)) => Some(Arc::new(aegis_alert::CompositeSink::new(vec![e, p]))),
            (Some(e), None) => Some(e),
            (None, Some(p)) => Some(p),
            (None, None) => None,
        };
        (combined, Some(hub))
    };

    tracing::info!(?role, "starting aegis-server");
    service::run(cfg, registry, alert_sink, cluster, hub).await
}
