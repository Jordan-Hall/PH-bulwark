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

    let cfg = ServerConfig {
        role,
        bind,
        accounts_enabled,
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

    let cluster = matches!(role, ServerRole::AllInOne | ServerRole::Lb).then(|| {
        Arc::new(aegis_cluster::Cluster::new(
            aegis_cluster::ClusterConfig::default(),
        ))
    });

    // Alert relay e-mails the guardian when SMTP is configured via env
    // (AEGIS_SMTP_HOST + AEGIS_ALERT_FROM + AEGIS_ALERT_RECIPIENTS, see
    // aegis_alert::AlertConfig::from_env). Unset → no sink (default local run:
    // the broadcast fan-out / all-in-one client is the delivery path). A partial/
    // invalid config fails at startup rather than silently dropping alerts.
    let alert_sink: Option<Arc<dyn aegis_alert::AlertSink>> =
        match aegis_alert::AlertConfig::from_env().map_err(|e| anyhow::anyhow!(e))? {
            Some(cfg) => {
                let sink = aegis_alert::EmailAlertSink::new(cfg).map_err(|e| anyhow::anyhow!(e))?;
                tracing::info!("email alert sink configured (SMTP)");
                Some(Arc::new(sink))
            }
            None => {
                tracing::info!("no email alert sink (AEGIS_SMTP_HOST unset); fan-out only");
                None
            }
        };

    tracing::info!(?role, "starting aegis-server");
    service::run(cfg, registry, alert_sink, cluster).await
}
