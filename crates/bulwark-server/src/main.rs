//! `bulwark-server` binary. Production mode is explicit and fail-closed.
#![forbid(unsafe_code)]

use std::sync::Arc;

use bulwark_server::{service, AnalyzerRegistry, ServerConfig, ServerRole};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = bulwark_core::init_tracing_default();

    let role = std::env::args()
        .skip_while(|arg| arg != "--role")
        .nth(1)
        .or_else(|| std::env::var("BULWARK_ROLE").ok())
        .and_then(|value| ServerRole::parse(&value))
        .unwrap_or(ServerRole::AllInOne);
    let bind = std::env::var("BULWARK_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());
    let production_mode = env_flag("BULWARK_PRODUCTION");
    let accounts_enabled = env_flag("BULWARK_ACCOUNTS");
    let staff_enabled = env_flag("BULWARK_STAFF");
    let allow_plaintext = env_flag("BULWARK_ALLOW_PLAINTEXT");
    let state_dir = std::env::var_os("BULWARK_STATE_DIR")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from);

    let tls_cert_pem = read_pem_env("BULWARK_TLS_CERT")?;
    let tls_key_pem = read_pem_env("BULWARK_TLS_KEY")?;
    let client_ca_pem = read_pem_env("BULWARK_TLS_CLIENT_CA")?;
    if tls_cert_pem.is_some() != tls_key_pem.is_some() {
        anyhow::bail!("BULWARK_TLS_CERT and BULWARK_TLS_KEY must be set together");
    }

    if (accounts_enabled || staff_enabled) && tls_cert_pem.is_none() && !allow_plaintext {
        anyhow::bail!(
            "refusing plaintext credentials: configure BULWARK_TLS_CERT/BULWARK_TLS_KEY or use BULWARK_ALLOW_PLAINTEXT=1 for local development only"
        );
    }

    if production_mode {
        if allow_plaintext {
            anyhow::bail!("BULWARK_ALLOW_PLAINTEXT is forbidden when BULWARK_PRODUCTION=1");
        }
        if role != ServerRole::AllInOne {
            anyhow::bail!(
                "production currently requires --role all-in-one; distributed ClusterControl is intentionally disabled until internal-node identity and replicated durable state are proven"
            );
        }
        if !accounts_enabled {
            anyhow::bail!("BULWARK_PRODUCTION=1 requires BULWARK_ACCOUNTS=1");
        }
        if state_dir.is_none() {
            anyhow::bail!("BULWARK_PRODUCTION=1 requires durable BULWARK_STATE_DIR");
        }
        if tls_cert_pem.is_none() || tls_key_pem.is_none() || client_ca_pem.is_none() {
            anyhow::bail!(
                "BULWARK_PRODUCTION=1 requires server TLS plus BULWARK_TLS_CLIENT_CA (mTLS)"
            );
        }
        if staff_enabled {
            anyhow::bail!(
                "BULWARK_STAFF must run on a dedicated internal listener; the guardian-facing production listener refuses the staff RPC surface"
            );
        }
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
        production_mode,
    };

    // SegmentStore::default_location is retention-disabled unless the operator
    // explicitly sets BULWARK_RETAIN_REVIEW_CLIPS=1. Alerts/evidence remain
    // hash/redaction-only by default.
    let segment_store = matches!(role, ServerRole::AllInOne)
        .then(bulwark_video::SegmentStore::default_location)
        .and_then(|result| {
            result
                .map_err(|error| {
                    tracing::warn!(%error, "review clip store unavailable; raw review retention disabled")
                })
                .ok()
        });
    let registry = AnalyzerRegistry::with_text_and_video(segment_store);

    let cluster = matches!(role, ServerRole::AllInOne | ServerRole::Lb).then(|| {
        Arc::new(bulwark_cluster::Cluster::new(
            bulwark_cluster::ClusterConfig::from_env(),
        ))
    });

    let email_sink: Option<Arc<dyn bulwark_alert::AlertSink>> =
        match bulwark_alert::AlertConfig::from_env().map_err(anyhow::Error::msg)? {
            Some(alert_cfg) => {
                let sink = bulwark_alert::EmailAlertSink::new(alert_cfg)
                    .map_err(anyhow::Error::msg)?;
                tracing::info!("guardian email alert sink configured");
                Some(Arc::new(sink))
            }
            None => {
                tracing::info!("guardian email alert sink not configured");
                None
            }
        };

    #[cfg(not(feature = "push"))]
    let (alert_sink, hub) = (email_sink, None::<bulwark_server::AlertHub>);

    #[cfg(feature = "push")]
    let (alert_sink, hub) = {
        let hub = match &cfg.state_dir {
            Some(dir) => bulwark_server::AlertHub::with_state_dir(dir)
                .map_err(anyhow::Error::from)?,
            None => bulwark_server::AlertHub::new(),
        };
        let registry = Arc::new(bulwark_server::relay::HubTokenRegistry::new(hub.clone()));
        let push_sink: Arc<dyn bulwark_alert::AlertSink> = Arc::new(
            bulwark_alert::UnifiedPushFanoutSink::new(registry).map_err(anyhow::Error::msg)?,
        );
        let combined: Option<Arc<dyn bulwark_alert::AlertSink>> = match email_sink {
            Some(email) => Some(Arc::new(bulwark_alert::CompositeSink::new(vec![
                email, push_sink,
            ]))),
            None => Some(push_sink),
        };
        (combined, Some(hub))
    };

    tracing::info!(?role, production_mode, "starting bulwark-server");
    service::run(cfg, registry, alert_sink, cluster, hub).await
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn read_pem_env(var: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match std::env::var_os(var).filter(|value| !value.is_empty()) {
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            let pem = std::fs::read(&path)
                .map_err(|error| anyhow::anyhow!("{var}: cannot read {}: {error}", path.display()))?;
            Ok(Some(pem))
        }
        None => Ok(None),
    }
}
