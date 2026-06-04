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

    let cfg = ServerConfig {
        role,
        bind,
        // mTLS material is loaded from aegis-core Config in a full deployment;
        // left None here so a local single-node run works out of the box (dev).
        ..ServerConfig::default()
    };

    // Text + buffered-video dispatch (image/audio stay on the device fast path /
    // future worker wiring). Video fails open without aegis-video's `ffmpeg`.
    let registry = AnalyzerRegistry::with_text_and_video();

    let cluster = matches!(role, ServerRole::AllInOne | ServerRole::Lb).then(|| {
        Arc::new(aegis_cluster::Cluster::new(
            aegis_cluster::ClusterConfig::default(),
        ))
    });

    // Alert relay is wired when SMTP is configured (aegis-alert). For a bare
    // local run we serve without it; the all-in-one client raises alerts itself.
    let alert_sink: Option<Arc<dyn aegis_alert::AlertSink>> = None;

    tracing::info!(?role, "starting aegis-server");
    service::run(cfg, registry, alert_sink, cluster).await
}
