//! `aegis_proxy` — a runnable, browser-pointable Aegis MITM proxy.
//!
//! This is the end-to-end demo entrypoint the product brief asks for. It:
//!   1. Brings up the `aegis-net` interceptor — the hudsucker MITM proxy on
//!      `127.0.0.1:8080`, backed by the **per-install CA** (`CaManager`).
//!   2. **Writes the root CA cert to disk and PRINTS its path**, so the user can
//!      trust it (Windows: `certutil -addstore -user Root <path>`; or import it
//!      via the browser's certificate settings).
//!   3. Runs the device-side [`Pipeline`] (deterministic text rules + LOCAL NSFW
//!      image scoring) over every decrypted flow.
//!   4. For each BLOCK, prints `BLOCKED <host> <category> score=<n>` and sends a
//!      redacted [`AlertEvent`] to `AEGIS_CLUSTER_ENDPOINT` (default
//!      `http://127.0.0.1:8443`) via `AlertRelay.RaiseAlert`.
//!
//! Point your browser's HTTP/HTTPS proxy at `127.0.0.1:8080`, trust the printed
//! CA, and browse. Adult images are scored locally and blocked in-line; the alert
//! carries a small SAFE preview of what was blocked (NEVER for suspected CSAM).
//!
//! NSFW scoring is real only when built `--features onnx` with `AEGIS_NSFW_MODEL`
//! or the per-install `nsfw_model.txt` pointing at an ONNX model; otherwise it
//! fails OPEN (allows) so the default build is runnable end-to-end without a model.
#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use aegis_alert::{AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AlertSink};
use aegis_client::{ClientConfig, Pipeline};
use aegis_proto::v1::alert_relay_client::AlertRelayClient;

/// The loopback address the user points their browser proxy at.
const PROXY_LISTEN: &str = "127.0.0.1:8080";
/// Default cluster (AlertRelay) endpoint; override with `AEGIS_CLUSTER_ENDPOINT`.
const DEFAULT_CLUSTER_ENDPOINT: &str = "http://127.0.0.1:8443";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = aegis_core::init_tracing_default();

    let cluster_endpoint = std::env::var("AEGIS_CLUSTER_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_CLUSTER_ENDPOINT.to_string());

    // --- 1. Build the interceptor on the fixed loopback proxy port. -----------
    let net_cfg = aegis_net::NetConfig {
        proxy_listen: PROXY_LISTEN.to_owned(),
        ..aegis_net::NetConfig::default()
    };
    let net =
        aegis_net::NetInterceptor::new(net_cfg).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // --- 2. Persist + PRINT the CA cert path so the user can trust it. --------
    let ca_path = write_ca_cert(net.ca_cert_pem())?;
    println!("=================================================================");
    println!(" Aegis MITM proxy");
    println!(" Listening:     http://{PROXY_LISTEN}  (set this as your browser proxy)");
    println!(" Root CA cert:  {}", ca_path.display());
    println!(" CA fingerprint: {}", net.ca_fingerprint());
    println!(" Trust it (Windows):");
    println!("   certutil -addstore -user Root \"{}\"", ca_path.display());
    println!(" Cluster (alerts): {cluster_endpoint}  (AlertRelay.RaiseAlert)");
    println!("=================================================================");

    // Explicit-proxy mode: bring up ONLY the MITM proxy (install CA + spawn
    // hudsucker), skipping the TUN device + QUIC firewall (which need admin). The
    // user points their browser proxy at 127.0.0.1:8080, so no transparent
    // redirect is required.
    let net = Arc::new(net);
    net.start_proxy_only()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let interceptor: Arc<dyn aegis_net::Interceptor> = net;

    // --- 3. Build the pipeline (text rules + local NSFW image scoring). -------
    // The AlertRelay sink forwards each redacted AlertEvent to the cluster.
    let relay = Arc::new(RelaySink::new(&cluster_endpoint));
    // Retain blocked/borderline NON-CSAM video clips locally (default store
    // location) so the guardian app can replay them; video analysis runs on this
    // device (offload is a seam), so this is where local_segment_uri is set.
    let cfg = ClientConfig {
        device_id: "aegis-proxy-local".to_string(),
        cluster_endpoint: Some(cluster_endpoint.clone()),
        // Cluster mTLS for offload, from operator-provisioned PEMs (AEGIS_CLIENT_*).
        // Absent → no offload; audio fails open. Needs an https:// endpoint.
        tls: aegis_client::load_cluster_tls_from_env(),
    };
    let mut pipeline = Pipeline::new(cfg.clone())
        .with_alert(relay)
        .with_default_segment_store();
    // Offload heavy media (audio) to the cluster when an endpoint + mTLS material
    // are provisioned AND the connect succeeds; otherwise audio fails open.
    if let Some(router) = aegis_client::build_offload_router(&cfg).await {
        pipeline = pipeline.with_offload(router);
    }

    tracing::info!("aegis_proxy running — point your browser at {PROXY_LISTEN}");

    // --- 3b. Tamper heartbeat: tell the cluster we're alive + protected. If this
    // process is killed/removed the beats stop and a guardian PROTECTION_DISABLED
    // alert fires. Best-effort background task — never blocks filtering.
    {
        let probe: Box<dyn aegis_client::ProtectionProbe> = Box::new(aegis_client::DesktopProbe {
            device_id: "aegis-proxy-local".to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        });
        tokio::spawn(aegis_client::tamper::run_heartbeats(
            cluster_endpoint.clone(),
            probe,
            std::time::Duration::from_secs(120),
        ));
    }

    // --- 4. The block-reporting loop. -----------------------------------------
    let result = run_loop(&pipeline, interceptor.clone()).await;
    let _ = interceptor.shutdown().await;
    result
}

/// Pull flows, classify+score, apply decisions, and PRINT each block.
async fn run_loop(
    pipeline: &Pipeline,
    interceptor: Arc<dyn aegis_net::Interceptor>,
) -> anyhow::Result<()> {
    loop {
        match interceptor.next_flow().await {
            Ok(Some(flow)) => {
                match pipeline
                    .handle_flow_reporting(flow, interceptor.as_ref())
                    .await
                {
                    Ok(reports) => {
                        for r in reports {
                            let host = if r.host.is_empty() {
                                "<unknown>"
                            } else {
                                &r.host
                            };
                            // The line the brief asks for, on stdout.
                            println!(
                                "BLOCKED {host} {} score={:.3}",
                                category_name(r.category),
                                r.score
                            );
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "flow handling failed; failing open"),
                }
            }
            Ok(None) => break, // interceptor closed
            Err(e) => {
                tracing::warn!(error = %e, "next_flow error; stopping loop");
                break;
            }
        }
    }
    Ok(())
}

/// Write the root CA cert PEM to a stable per-user file and return its path.
/// (`%LOCALAPPDATA%\Aegis\aegis-root-ca.pem` on Windows, else the temp dir.)
fn write_ca_cert(pem: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = ca_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("creating CA dir {}: {e}", dir.display()))?;
    let path = dir.join("aegis-root-ca.pem");
    std::fs::write(&path, pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("writing CA cert {}: {e}", path.display()))?;
    Ok(path)
}

fn ca_dir() -> std::path::PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        if !local.is_empty() {
            return std::path::PathBuf::from(local).join("Aegis");
        }
    }
    std::env::temp_dir().join("aegis")
}

/// Stable, human-readable category name for the BLOCKED line.
fn category_name(c: aegis_proto::v1::Category) -> &'static str {
    use aegis_proto::v1::Category;
    match c {
        Category::Unspecified => "unspecified",
        Category::Safe => "safe",
        Category::AdultImage => "adult_image",
        Category::AdultAudio => "adult_audio",
        Category::AdultText => "adult_text",
        Category::Grooming => "grooming",
        Category::CsamSuspected => "csam_suspected",
        Category::Violence => "violence",
        Category::SelfHarm => "self_harm",
        Category::Hate => "hate",
    }
}

/// An [`AlertSink`] that relays each redacted [`AlertEvent`] to the cluster's
/// `AlertRelay.RaiseAlert` over gRPC. Connection is lazy + best-effort: if the
/// cluster is down, alerting fails (logged) but filtering continues.
struct RelaySink {
    endpoint: String,
    client: Mutex<Option<AlertRelayClient<tonic::transport::Channel>>>,
}

impl RelaySink {
    fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            client: Mutex::new(None),
        }
    }

    /// Get-or-connect the gRPC client. Reconnects on the next call if a prior
    /// connection failed (the slot stays `None`).
    async fn client(
        &self,
    ) -> Result<AlertRelayClient<tonic::transport::Channel>, tonic::transport::Error> {
        let mut slot = self.client.lock().await;
        if let Some(c) = slot.as_ref() {
            return Ok(c.clone());
        }
        let c = AlertRelayClient::connect(self.endpoint.clone()).await?;
        *slot = Some(c.clone());
        Ok(c)
    }
}

#[async_trait]
impl AlertSink for RelaySink {
    async fn raise(&self, event: AlertEvent) -> aegis_alert::Result<AlertAck> {
        let alert_id = event.alert_id.clone();
        match self.client().await {
            Ok(mut client) => match client.raise_alert(event).await {
                Ok(resp) => Ok(resp.into_inner()),
                Err(status) => {
                    tracing::warn!(%alert_id, %status, "AlertRelay.RaiseAlert failed");
                    Ok(AlertAck {
                        alert_id,
                        delivered: false,
                        deduped: false,
                        detail: format!("relay error: {status}"),
                    })
                }
            },
            Err(e) => {
                tracing::warn!(%alert_id, error = %e, "AlertRelay connect failed");
                Ok(AlertAck {
                    alert_id,
                    delivered: false,
                    deduped: false,
                    detail: format!("connect error: {e}"),
                })
            }
        }
    }

    async fn raise_batch(&self, batch: AlertBatch) -> aegis_alert::Result<AlertAckBatch> {
        let mut acks = Vec::with_capacity(batch.events.len());
        for event in batch.events {
            acks.push(self.raise(event).await?);
        }
        Ok(AlertAckBatch { acks })
    }
}
