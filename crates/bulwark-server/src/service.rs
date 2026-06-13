//! gRPC service implementations (Analysis / Offload / AlertRelay) and the
//! role-based `run` launcher. ClusterControl is mounted from `bulwark-cluster`.
//! All links are mTLS when cert material is configured.

use std::pin::Pin;
use std::sync::Arc;

use bulwark_proto::v1::accounts_server::AccountsServer;
use bulwark_proto::v1::alert_relay_server::{AlertRelay, AlertRelayServer};
use bulwark_proto::v1::analysis_server::{Analysis, AnalysisServer};
use bulwark_proto::v1::child_control_server::ChildControlServer;
use bulwark_proto::v1::family_safety_server::FamilySafetyServer;
use bulwark_proto::v1::offload_server::{Offload, OffloadServer};
use bulwark_proto::v1::review_server::ReviewServer;
use bulwark_proto::v1::tamper_server::TamperServer;
use bulwark_proto::v1::wg_provision_server::WgProvisionServer;
use bulwark_proto::v1::{
    Action, AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AnalysisBatch, AnalysisRequest,
    Category, DeviceProfile, OffloadPolicy, RefreshOffloadRequest, Severity, Verdict, VerdictBatch,
};
use futures_util::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use crate::accounts::{AccountStore, AccountsService};
use crate::child_control::{ChildConfigStore, ChildControlService};
use crate::family_safety::{FamilySafetyService, SafetyBroadcastStore};
use crate::relay::{AlertHub, ReviewService};
use crate::tamper::{self, TamperService};
use crate::wg_provision::{WgPeerStore, WgProvisionService};
use crate::{default_offload_policy, AnalyzerRegistry, ServerConfig, ServerRole};

fn to_status(e: bulwark_core::Error) -> Status {
    Status::internal(e.to_string())
}

/// Verdict returned when no analyzer is registered for a media kind yet
/// (e.g. video before `bulwark-video` is wired). Fails *open* + logs.
fn inconclusive(request_id: String) -> Verdict {
    Verdict {
        request_id,
        // Unspecified (not Safe) so policy can distinguish "couldn't score" from
        // "scored safe" and fail-closed on the coverage gap.
        category: Category::Unspecified as i32,
        action: Action::Allow as i32,
        severity: Severity::Info as i32,
        score: 0.0,
        rationale: "no analyzer registered for this media kind".to_string(),
        evidence: None,
        grooming: None,
        worker_id: String::new(),
        latency_ms: 0,
        ..Default::default()
    }
}

#[derive(Clone)]
pub struct AnalysisService {
    registry: AnalyzerRegistry,
}

impl AnalysisService {
    pub fn new(registry: AnalyzerRegistry) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl Analysis for AnalysisService {
    async fn analyze(&self, req: Request<AnalysisRequest>) -> Result<Response<Verdict>, Status> {
        let req = req.into_inner();
        match self.registry.analyzer_for(req.media_kind) {
            Some(a) => a.analyze(req).await.map(Response::new).map_err(to_status),
            None => {
                tracing::warn!(kind = req.media_kind, "no analyzer; failing open");
                Ok(Response::new(inconclusive(req.request_id)))
            }
        }
    }

    async fn analyze_batch(
        &self,
        req: Request<AnalysisBatch>,
    ) -> Result<Response<VerdictBatch>, Status> {
        let batch = req.into_inner();
        let mut verdicts = Vec::with_capacity(batch.requests.len());
        for r in batch.requests {
            let v = match self.registry.analyzer_for(r.media_kind) {
                Some(a) => a.analyze(r).await.map_err(to_status)?,
                None => inconclusive(r.request_id),
            };
            verdicts.push(v);
        }
        Ok(Response::new(VerdictBatch { verdicts }))
    }

    type AnalyzeStreamStream =
        Pin<Box<dyn futures_core::Stream<Item = Result<Verdict, Status>> + Send + 'static>>;

    async fn analyze_stream(
        &self,
        req: Request<Streaming<AnalysisRequest>>,
    ) -> Result<Response<Self::AnalyzeStreamStream>, Status> {
        let registry = self.registry.clone();
        let inbound = req.into_inner();
        let out = inbound.then(move |item| {
            let registry = registry.clone();
            async move {
                let r = item?;
                match registry.analyzer_for(r.media_kind) {
                    Some(a) => a.analyze(r).await.map_err(to_status),
                    None => Ok(inconclusive(r.request_id)),
                }
            }
        });
        Ok(Response::new(Box::pin(out)))
    }
}

/// Caches the per-device [`DeviceProfile`] captured at `negotiate_offload` so a
/// later `refresh_offload` — which only carries fresh RTT/battery, not the device
/// capabilities — can re-derive a CONSISTENT policy instead of a hardcoded stub.
#[derive(Clone, Default)]
pub struct OffloadService {
    profiles: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, DeviceProfile>>>,
}

#[tonic::async_trait]
impl Offload for OffloadService {
    async fn negotiate_offload(
        &self,
        req: Request<DeviceProfile>,
    ) -> Result<Response<OffloadPolicy>, Status> {
        let profile = req.into_inner();
        // Cache the capabilities so a later refresh re-derives against live RTT/battery.
        if let Ok(mut cache) = self.profiles.lock() {
            cache.insert(profile.device_id.clone(), profile.clone());
        }
        Ok(Response::new(default_offload_policy(&profile)))
    }

    async fn refresh_offload(
        &self,
        req: Request<RefreshOffloadRequest>,
    ) -> Result<Response<OffloadPolicy>, Status> {
        let r = req.into_inner();
        // Re-derive from the cached device profile updated with the fresh RTT/battery,
        // so a refresh stays consistent with the original negotiate (not a fixed stub).
        let profile = self
            .profiles
            .lock()
            .ok()
            .and_then(|c| c.get(&r.device_id).cloned())
            .map(|mut p| {
                p.rtt_ms = r.rtt_ms;
                p.battery_pct = r.battery_pct;
                p
            })
            .unwrap_or_else(|| DeviceProfile {
                device_id: r.device_id.clone(),
                rtt_ms: r.rtt_ms,
                battery_pct: r.battery_pct,
                ..Default::default()
            });
        let mut policy = default_offload_policy(&profile);
        // Keep the client's existing policy id for continuity if it sent one.
        if !r.policy_id.is_empty() {
            policy.policy_id = r.policy_id;
        }
        Ok(Response::new(policy))
    }
}

/// Hosts the `AlertRelay` service. Every accepted [`AlertEvent`] is fanned out
/// to subscribed guardian clients via the shared [`AlertHub`] broadcast (which
/// `Review::StreamPendingReviews` consumes) and, when configured, also handed to
/// the `bulwark-alert` e-mail [`AlertSink`](bulwark_alert::AlertSink). The sink is
/// optional so the broadcast fan-out works even on a bare local node.
#[derive(Clone)]
pub struct AlertRelayService {
    hub: AlertHub,
    sink: Option<Arc<dyn bulwark_alert::AlertSink>>,
}

impl AlertRelayService {
    /// Build a relay that fans alerts into `hub` and, if `sink` is `Some`, also
    /// e-mails them via `bulwark-alert`.
    pub fn new(hub: AlertHub, sink: Option<Arc<dyn bulwark_alert::AlertSink>>) -> Self {
        Self { hub, sink }
    }
}

#[tonic::async_trait]
impl AlertRelay for AlertRelayService {
    async fn raise_alert(&self, req: Request<AlertEvent>) -> Result<Response<AlertAck>, Status> {
        let event = req.into_inner();

        // Fan the redacted event out to any subscribed guardian Review streams.
        let reached = self.hub.publish(event.clone());

        match &self.sink {
            // SMTP configured: dedupe/digest + e-mail, return its ack.
            Some(sink) => sink
                .raise(event)
                .await
                .map(Response::new)
                .map_err(|e| Status::internal(e.to_string())),
            // No SMTP sink: the broadcast fan-out is the delivery path. Ack as
            // delivered iff at least one guardian stream received it.
            None => Ok(Response::new(AlertAck {
                alert_id: event.alert_id,
                delivered: reached > 0,
                deduped: false,
                detail: format!("fanned out to {reached} guardian stream(s)"),
            })),
        }
    }

    async fn raise_alerts(
        &self,
        req: Request<AlertBatch>,
    ) -> Result<Response<AlertAckBatch>, Status> {
        let batch = req.into_inner();

        // Fan every event out to subscribed guardian Review streams.
        for ev in &batch.events {
            self.hub.publish(ev.clone());
        }

        match &self.sink {
            Some(sink) => sink
                .raise_batch(batch)
                .await
                .map(Response::new)
                .map_err(|e| Status::internal(e.to_string())),
            None => {
                let acks = batch
                    .events
                    .into_iter()
                    .map(|ev| AlertAck {
                        alert_id: ev.alert_id,
                        delivered: true,
                        deduped: false,
                        detail: "fanned out (no SMTP sink configured)".to_string(),
                    })
                    .collect();
                Ok(Response::new(AlertAckBatch { acks }))
            }
        }
    }
}

/// Build the tonic server for the configured role and serve until shutdown.
///
/// `cluster` and `alert_sink` are only mounted for `AllInOne`/`Lb`. mTLS is
/// enabled when the config carries cert/key/ca PEM.
pub async fn run(
    cfg: ServerConfig,
    registry: AnalyzerRegistry,
    alert_sink: Option<Arc<dyn bulwark_alert::AlertSink>>,
    cluster: Option<Arc<bulwark_cluster::Cluster>>,
    // Pre-built guardian relay hub (so main.rs can wire a push fan-out sink that
    // reads its live tokens). `None` → build one here (default / all-in-one path).
    hub: Option<AlertHub>,
) -> anyhow::Result<()> {
    use tonic::transport::Server;

    let addr = parse_bind(&cfg.bind)?;
    let mut builder = Server::builder();

    match (&cfg.tls_cert_pem, &cfg.tls_key_pem) {
        (Some(cert), Some(key)) => {
            use tonic::transport::{Certificate, Identity, ServerTlsConfig};
            let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(cert, key));
            if let Some(ca) = &cfg.client_ca_pem {
                tls = tls.client_ca_root(Certificate::from_pem(ca));
                tracing::info!("mTLS enabled (client certs required)");
            } else {
                tracing::info!("TLS enabled (server-authenticated; client certs not yet required)");
            }
            builder = builder.tls_config(tls)?;
        }
        _ => {
            tracing::warn!(
                "serving WITHOUT TLS — dev only; set BULWARK_TLS_CERT/BULWARK_TLS_KEY for any real deployment"
            );
        }
    }

    let analysis = AnalysisServer::new(AnalysisService::new(registry));
    let mut router = builder.add_service(analysis);

    // Standard gRPC health service (`grpc.health.v1.Health`) for LB / systemd /
    // k8s / `grpc_health_probe` readiness checks. The overall ("") status is
    // SERVING once we've built the router and are about to listen.
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    router = router.add_service(health_service);

    if matches!(cfg.role, ServerRole::AllInOne | ServerRole::Lb) {
        router = router.add_service(OffloadServer::new(OffloadService::default()));

        // Shared guardian relay state: the broadcast hub fans redacted alerts
        // from AlertRelay out to Review's StreamPendingReviews, and carries the
        // per-device approve-allowlist Review::SubmitDecision writes through. A
        // caller may pass a pre-built hub (so a push fan-out sink can read its
        // tokens); otherwise build one here — persisted when a state dir is set.
        let hub = match (hub, &cfg.state_dir) {
            (Some(h), _) => h,
            (None, Some(dir)) => AlertHub::with_state_dir(dir)?,
            (None, None) => AlertHub::default(),
        };

        // AlertRelay is always mounted on guardian-facing nodes (even without
        // an SMTP sink) so the broadcast fan-out path is available; the sink is
        // attached when SMTP is configured.
        router = router.add_service(AlertRelayServer::new(AlertRelayService::new(
            hub.clone(),
            alert_sink.clone(),
        )));

        // Parent accounts + per-child guardians (accounts mode): built BEFORE
        // the Tamper service so heartbeats can verify the per-device token
        // minted at pairing. The same store also scopes Review, ChildControl,
        // and the Accounts service below — one source of truth. Persisted when
        // a state dir is configured (else in-memory).
        let accounts = if cfg.accounts_enabled {
            Some(match &cfg.state_dir {
                Some(dir) => AccountStore::with_state_dir(dir)?,
                None => AccountStore::new(),
            })
        } else {
            None
        };

        // Tamper: child-device protection liveness + uninstall/disable alerts,
        // fanned out through the SAME hub (so they reach guardian Review streams,
        // scoped per child/device). A background task sweeps for devices that have
        // gone silent past the grace window and raises a missed-heartbeat alert.
        // In accounts mode, heartbeats authenticate with the pairing-minted
        // device token (legacy-enrolled devices pass the store's logged grace).
        let tamper = match &accounts {
            Some(accounts) => TamperService::new(hub.clone()).with_accounts(accounts.clone()),
            None => TamperService::new(hub.clone()),
        };
        {
            let sweeper = tamper.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                    tamper::DEFAULT_HEARTBEAT_SECS as u64,
                ));
                loop {
                    tick.tick().await;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    let fired = sweeper.sweep(now_ms);
                    if fired > 0 {
                        tracing::warn!(devices = fired, "tamper: missed-heartbeat alert(s) raised");
                    }
                }
            });
        }
        router = router.add_service(TamperServer::new(tamper));

        // FamilySafety: child SOS (URGENT guardian alert; device-token
        // authenticated in accounts mode, same gate as heartbeats) + staff
        // safety broadcasts (gated by the placeholder shared env token,
        // BULWARK_STAFF_BROADCAST_TOKEN, until the staff accounts system
        // ships). SOS fans through the SAME hub as every other alert AND the
        // email/push sink when configured; broadcasts persist under the state
        // dir so a console that connects later can still fetch the active list.
        let broadcast_store = match &cfg.state_dir {
            Some(dir) => SafetyBroadcastStore::with_state_dir(dir)?,
            None => SafetyBroadcastStore::new(),
        };
        let mut family_safety = FamilySafetyService::new(hub.clone(), broadcast_store)
            .with_alert_sink(alert_sink.clone())
            .with_staff_token_from_env();
        if let Some(accounts) = &accounts {
            family_safety = family_safety.with_accounts(accounts.clone());
        }
        router = router.add_service(FamilySafetyServer::new(family_safety));

        // Review (+ optional Accounts) depends on the deployment mode:
        //   * accounts_enabled = false (DEFAULT, single-home/dev): device-scoped
        //     Review only — a client connects with an EMPTY token and gets its
        //     device's alerts/decisions. The Accounts service is NOT mounted, so
        //     the token gate never rejects the default client.
        //   * accounts_enabled = true (productised multi-tenant): Review is scoped
        //     to a guardian session token and the Accounts service is mounted for
        //     registration/login/child/guardian management. Enable only once
        //     guardian sessions exist (else the gate rejects empty-token clients).
        //
        // Retained-clip store for FetchSegment (remote video review): all-in-one
        // re-opens the default segment store as a read handle (the registry writes
        // clips to the same location), so a guardian on a DIFFERENT device than the
        // server can pull a blocked clip. A distributed worker keeps no store.
        let review_store = matches!(cfg.role, ServerRole::AllInOne)
            .then(bulwark_video::SegmentStore::default_location)
            .and_then(|r| {
                r.map_err(|e| tracing::warn!(error = %e, "segment store unavailable; remote video review disabled"))
                    .ok()
            })
            .map(Arc::new);
        if let Some(accounts) = accounts {
            // The shared accounts store (built above, also verifying device
            // tokens for Tamper) scopes Review's pending stream/decisions AND
            // backs the Accounts service.
            router = router.add_service(ReviewServer::new(
                ReviewService::with_accounts(hub, accounts.clone())
                    .with_segment_store(review_store.clone()),
            ));
            // ChildControl (parent-set, child-applied runtime config) shares the
            // SAME accounts store so guardian→child scoping is one source of truth.
            // Persisted alongside accounts when a state dir is configured.
            let child_config = match &cfg.state_dir {
                Some(dir) => ChildConfigStore::with_state_dir(dir)?,
                None => ChildConfigStore::new(),
            };
            router = router.add_service(ChildControlServer::new(ChildControlService::new(
                child_config,
                accounts.clone(),
            )));
            // WireGuard peer provisioning (FILTER_ON_SERVER): device-token-
            // authenticated against the SAME accounts store. The handler only
            // persists the DESIRED peer set (wg_peers.json under the state
            // dir) — an on-box reconciler applies it with
            // deploy/wireguard/wg-peers.sh; the gRPC path never touches wg(8).
            // Region material comes from BULWARK_WG_* env (from_env).
            let wg_peers = match &cfg.state_dir {
                Some(dir) => WgPeerStore::with_state_dir(dir)?,
                None => WgPeerStore::new(),
            }
            .with_reserved_from_env();
            router = router.add_service(WgProvisionServer::new(WgProvisionService::from_env(
                wg_peers,
                accounts.clone(),
            )));
            // Enable the EMAIL-based password-reset path automatically when SMTP is
            // configured (BULWARK_SMTP_*). Without it, guardians self-reset with their
            // saved recovery code (from_env logs which path is active).
            router = router.add_service(AccountsServer::new(AccountsService::from_env(accounts)));
            tracing::info!(
                "accounts mode ENABLED — Review + ChildControl require a guardian session token"
            );
        } else {
            router = router.add_service(ReviewServer::new(
                ReviewService::new(hub).with_segment_store(review_store),
            ));
            tracing::info!("accounts mode disabled — device-scoped Review (legacy/dev)");
        }

        if let Some(c) = cluster {
            let svc = bulwark_cluster::service::ClusterControlService::new(c);
            router = router.add_service(
                bulwark_proto::v1::cluster_control_server::ClusterControlServer::new(svc),
            );
        }
    }

    tracing::info!(role = ?cfg.role, %cfg.bind, "bulwark-server listening");
    // Serve until a shutdown signal so in-flight gRPC calls drain cleanly on a
    // systemd/SCM/Docker stop, instead of being cut off mid-response.
    router.serve_with_shutdown(addr, shutdown_signal()).await?;
    tracing::info!("bulwark-server stopped");
    Ok(())
}

/// Parse the bind address with a clear, operator-facing error (the raw
/// `AddrParseError` doesn't say which value was wrong).
fn parse_bind(bind: &str) -> anyhow::Result<std::net::SocketAddr> {
    bind.parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address {bind:?} (BULWARK_BIND): {e}"))
}

/// Resolves when the process is asked to stop: Ctrl-C on any platform, plus
/// SIGTERM on Unix (systemd/Docker/k8s send SIGTERM). Drives graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler unavailable; Ctrl-C only");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

#[cfg(test)]
mod tests {
    use super::parse_bind;

    #[test]
    fn parse_bind_accepts_valid_and_rejects_garbage() {
        assert!(parse_bind("127.0.0.1:8443").is_ok());
        assert!(parse_bind("0.0.0.0:8443").is_ok());
        assert!(parse_bind("[::1]:8443").is_ok());
        // A clear, value-bearing error — not a bare AddrParseError.
        let err = parse_bind("not-an-addr").unwrap_err().to_string();
        assert!(err.contains("not-an-addr") && err.contains("BULWARK_BIND"));
        assert!(parse_bind("127.0.0.1").is_err()); // missing port
    }
}
