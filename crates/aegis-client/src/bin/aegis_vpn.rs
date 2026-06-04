//! `aegis_vpn` — a runnable, **transparent VPN** entrypoint (desktop: Windows /
//! Linux / macOS).
//!
//! Unlike `aegis_proxy` (which needs each app pointed at `127.0.0.1:8080`), this
//! captures **all** traffic at layer 3 via a TUN and routes it through the same
//! MITM filter — no per-app proxy settings. It:
//!   1. Refuses to run un-elevated (TUN + default route need admin/root) and
//!      prints the exact elevation command.
//!   2. Checks the TUN driver is available (`wintun.dll` on Windows).
//!   3. Brings up the in-process MITM proxy (`aegis-net`) on `127.0.0.1:8080`,
//!      writing + printing the per-install CA to trust.
//!   4. Starts the TUN redirect (`aegis_net::run_vpn` → tun2proxy): all captured
//!      TCP → the MITM proxy, UDP NAT'd out, QUIC blocked, default route installed
//!      and restored on exit.
//!   5. Runs the device-side [`Pipeline`] (text rules + local NSFW image scoring)
//!      over every decrypted flow, printing each block and relaying a redacted
//!      [`AlertEvent`] to the cluster.
//!
//! Mobile (Android/iOS) uses the native VpnService / NetworkExtension shells, not
//! this binary.
//!
//! NSFW scoring is real only when built `--features onnx` with `AEGIS_NSFW_MODEL`
//! set; otherwise it fails OPEN so the default build runs end-to-end without a model.
#![forbid(unsafe_code)]

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("aegis_vpn: VPN mode is desktop-only (Windows/Linux/macOS). Mobile uses the native VpnService / NetworkExtension.");
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use std::sync::Arc;

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use async_trait::async_trait;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use tokio::sync::Mutex;

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use aegis_alert::{AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AlertSink};
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use aegis_client::{ClientConfig, Pipeline};
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use aegis_proto::v1::alert_relay_client::AlertRelayClient;

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
const PROXY_LISTEN: &str = "127.0.0.1:8080";
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
const DEFAULT_CLUSTER_ENDPOINT: &str = "http://127.0.0.1:8443";

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = aegis_core::init_tracing_default();

    // --- 0. Pre-flight: VPN mode needs elevation + a TUN driver. --------------
    if !aegis_net::is_elevated() {
        eprintln!("aegis_vpn needs elevation (TUN adapter + default route).");
        eprintln!(
            "Re-run as administrator/root:\n  {}",
            aegis_net::elevation_command()
        );
        std::process::exit(1);
    }
    if !aegis_net::wintun_available() {
        eprintln!("wintun.dll not found. VPN mode needs the WireGuard-signed wintun.dll");
        eprintln!("next to this exe or on PATH — download it from https://www.wintun.net/ .");
        std::process::exit(1);
    }

    let cluster_endpoint = std::env::var("AEGIS_CLUSTER_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_CLUSTER_ENDPOINT.to_string());

    // --- 1. MITM proxy (the TUN redirects captured TCP here). -----------------
    let net_cfg = aegis_net::NetConfig {
        proxy_listen: PROXY_LISTEN.to_owned(),
        ..aegis_net::NetConfig::default()
    };
    let net =
        aegis_net::NetInterceptor::new(net_cfg).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let ca_path = write_ca_cert(net.ca_cert_pem())?;
    println!("=================================================================");
    println!(" Aegis VPN (transparent, system-wide)");
    println!(" MITM proxy:    http://{PROXY_LISTEN}  (TUN redirects all TCP here)");
    println!(" Root CA cert:  {}", ca_path.display());
    println!(" CA fingerprint: {}", net.ca_fingerprint());
    println!(" Trust it (Windows):");
    println!("   certutil -addstore -user Root \"{}\"", ca_path.display());
    println!(" Cluster (alerts): {cluster_endpoint}  (AlertRelay.RaiseAlert)");
    println!("=================================================================");

    let net = Arc::new(net);
    net.start_proxy_only()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let interceptor: Arc<dyn aegis_net::Interceptor> = net;

    // --- 2. Pipeline (text rules + local NSFW image scoring). -----------------
    let relay = Arc::new(RelaySink::new(&cluster_endpoint));
    // Retain blocked/borderline NON-CSAM video clips locally for guardian replay
    // (see aegis_proxy for the rationale).
    let cfg = ClientConfig {
        device_id: "aegis-vpn-local".to_string(),
        cluster_endpoint: Some(cluster_endpoint.clone()),
        // Cluster mTLS for offload, from operator-provisioned PEMs (AEGIS_CLIENT_*).
        tls: aegis_client::load_cluster_tls_from_env(),
    };
    let mut pipeline = Pipeline::new(cfg.clone())
        .with_alert(relay)
        .with_default_segment_store();
    if let Some(router) = aegis_client::build_offload_router(&cfg).await {
        pipeline = pipeline.with_offload(router);
    }

    // Tamper heartbeat: liveness + protection status to the cluster; if this is
    // killed/removed the missed-heartbeat sweep raises a guardian alert.
    {
        let probe: Box<dyn aegis_client::ProtectionProbe> = Box::new(aegis_client::DesktopProbe {
            device_id: "aegis-vpn-local".to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        });
        tokio::spawn(aegis_client::tamper::run_heartbeats(
            cluster_endpoint.clone(),
            probe,
            std::time::Duration::from_secs(120),
        ));
    }

    // --- 3. Bring up the TUN data path (permissive smoltcp + WireGuard). ------
    let shutdown = aegis_net::CancellationToken::new();
    let vpn_token = shutdown.clone();
    let mut vpn = tokio::spawn(async move {
        aegis_net::run_vpn(aegis_net::VpnConfig::default(), vpn_token).await
    });

    println!("aegis_vpn: bringing up the transparent VPN…");

    // --- 4. Run until Ctrl-C, the flow loop ends, OR the VPN data path stops. --
    // The VPN data path is the whole point of this binary. If it returns (fails or
    // stops), we must NOT keep running as a bare proxy: the parent app reports
    // "connected" by probing the local proxy port, so a lingering proxy with no
    // TUN capturing would falsely show protection ON while nothing is filtered.
    // So a VPN-task return is a FATAL startup error — tear down and exit non-zero.
    tokio::select! {
        res = &mut vpn => {
            let _ = interceptor.shutdown().await;
            return match res {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => {
                    eprintln!("VPN data path unavailable: {e}");
                    eprintln!("Use proxy mode instead: run `aegis_proxy` (no admin), trust the CA, done.");
                    std::process::exit(1);
                }
                Err(join) => {
                    eprintln!("VPN task crashed: {join}");
                    std::process::exit(1);
                }
            };
        }
        r = run_loop(&pipeline, interceptor.clone()) => {
            if let Err(e) = r { tracing::warn!(error = %e, "flow loop ended"); }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nshutting down — restoring routing…");
        }
    }

    // Cancel the TUN data path (restores host routing on teardown), tear down proxy.
    shutdown.cancel();
    let _ = vpn.await;
    let _ = interceptor.shutdown().await;
    Ok(())
}

/// Pull flows, classify+score, apply decisions, and PRINT each block.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
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
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "next_flow error; stopping loop");
                break;
            }
        }
    }
    Ok(())
}

/// Write the root CA cert PEM to a stable per-user file and return its path.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn write_ca_cert(pem: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = ca_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("creating CA dir {}: {e}", dir.display()))?;
    let path = dir.join("aegis-root-ca.pem");
    std::fs::write(&path, pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("writing CA cert {}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn ca_dir() -> std::path::PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        if !local.is_empty() {
            return std::path::PathBuf::from(local).join("Aegis");
        }
    }
    std::env::temp_dir().join("aegis")
}

/// Stable, human-readable category name for the BLOCKED line.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
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
/// `AlertRelay.RaiseAlert`. Lazy + best-effort: a down cluster fails (logged) but
/// filtering continues.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
struct RelaySink {
    endpoint: String,
    client: Mutex<Option<AlertRelayClient<tonic::transport::Channel>>>,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
impl RelaySink {
    fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            client: Mutex::new(None),
        }
    }

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

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
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
