//! gRPC service implementations (Analysis / Offload / AlertRelay) and the
//! role-based `run` launcher. ClusterControl is mounted from `aegis-cluster`.
//! All links are mTLS when cert material is configured.

use std::pin::Pin;
use std::sync::Arc;

use aegis_proto::v1::accounts_server::AccountsServer;
use aegis_proto::v1::alert_relay_server::{AlertRelay, AlertRelayServer};
use aegis_proto::v1::analysis_server::{Analysis, AnalysisServer};
use aegis_proto::v1::offload_server::{Offload, OffloadServer};
use aegis_proto::v1::review_server::ReviewServer;
use aegis_proto::v1::tamper_server::TamperServer;
use aegis_proto::v1::{
    Action, AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AnalysisBatch, AnalysisRequest,
    Category, DeviceProfile, OffloadPolicy, RefreshOffloadRequest, Severity, Verdict, VerdictBatch,
};
use futures_util::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use crate::accounts::{AccountStore, AccountsService};
use crate::relay::{AlertHub, ReviewService};
use crate::tamper::{self, TamperService};
use crate::{default_offload_policy, AnalyzerRegistry, ServerConfig, ServerRole};

fn to_status(e: aegis_core::Error) -> Status {
    Status::internal(e.to_string())
}

/// Verdict returned when no analyzer is registered for a media kind yet
/// (e.g. video before `aegis-video` is wired). Fails *open* + logs.
fn inconclusive(request_id: String) -> Verdict {
    Verdict {
        request_id,
        category: Category::Safe as i32,
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

#[derive(Clone, Default)]
pub struct OffloadService;

#[tonic::async_trait]
impl Offload for OffloadService {
    async fn negotiate_offload(
        &self,
        req: Request<DeviceProfile>,
    ) -> Result<Response<OffloadPolicy>, Status> {
        Ok(Response::new(default_offload_policy(&req.into_inner())))
    }

    async fn refresh_offload(
        &self,
        req: Request<RefreshOffloadRequest>,
    ) -> Result<Response<OffloadPolicy>, Status> {
        // Minimal: keep the same policy id, refresh the TTL. A richer impl would
        // re-derive from the fresh RTT/battery in the request.
        let r = req.into_inner();
        Ok(Response::new(OffloadPolicy {
            run_text_local: true,
            ttl_secs: 300,
            policy_id: r.policy_id,
            ..Default::default()
        }))
    }
}

/// Hosts the `AlertRelay` service. Every accepted [`AlertEvent`] is fanned out
/// to subscribed guardian clients via the shared [`AlertHub`] broadcast (which
/// `Review::StreamPendingReviews` consumes) and, when configured, also handed to
/// the `aegis-alert` e-mail [`AlertSink`](aegis_alert::AlertSink). The sink is
/// optional so the broadcast fan-out works even on a bare local node.
#[derive(Clone)]
pub struct AlertRelayService {
    hub: AlertHub,
    sink: Option<Arc<dyn aegis_alert::AlertSink>>,
}

impl AlertRelayService {
    /// Build a relay that fans alerts into `hub` and, if `sink` is `Some`, also
    /// e-mails them via `aegis-alert`.
    pub fn new(hub: AlertHub, sink: Option<Arc<dyn aegis_alert::AlertSink>>) -> Self {
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
    alert_sink: Option<Arc<dyn aegis_alert::AlertSink>>,
    cluster: Option<Arc<aegis_cluster::Cluster>>,
    // Pre-built guardian relay hub (so main.rs can wire a push fan-out sink that
    // reads its live tokens). `None` → build one here (default / all-in-one path).
    hub: Option<AlertHub>,
) -> anyhow::Result<()> {
    use tonic::transport::Server;

    let addr = cfg.bind.parse()?;
    let mut builder = Server::builder();

    if let (Some(cert), Some(key), Some(ca)) =
        (&cfg.tls_cert_pem, &cfg.tls_key_pem, &cfg.client_ca_pem)
    {
        use tonic::transport::{Certificate, Identity, ServerTlsConfig};
        let identity = Identity::from_pem(cert, key);
        let tls = ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(Certificate::from_pem(ca));
        builder = builder.tls_config(tls)?;
        tracing::info!("mTLS enabled (client certs required)");
    } else {
        tracing::warn!("serving WITHOUT TLS — dev only; configure mTLS for any real deployment");
    }

    let analysis = AnalysisServer::new(AnalysisService::new(registry));
    let mut router = builder.add_service(analysis);

    if matches!(cfg.role, ServerRole::AllInOne | ServerRole::Lb) {
        router = router.add_service(OffloadServer::new(OffloadService));

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
            alert_sink,
        )));

        // Tamper: child-device protection liveness + uninstall/disable alerts,
        // fanned out through the SAME hub (so they reach guardian Review streams,
        // scoped per child/device). A background task sweeps for devices that have
        // gone silent past the grace window and raises a missed-heartbeat alert.
        let tamper = TamperService::new(hub.clone());
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

        // Review (+ optional Accounts) depends on the deployment mode:
        //   * accounts_enabled = false (DEFAULT, single-home/dev): device-scoped
        //     Review only — a client connects with an EMPTY token and gets its
        //     device's alerts/decisions. The Accounts service is NOT mounted, so
        //     the token gate never rejects the default client.
        //   * accounts_enabled = true (productised multi-tenant): Review is scoped
        //     to a guardian session token and the Accounts service is mounted for
        //     registration/login/child/guardian management. Enable only once
        //     guardian sessions exist (else the gate rejects empty-token clients).
        if cfg.accounts_enabled {
            // Parent accounts + per-child guardians: the store scopes Review's
            // pending stream/decisions AND backs the Accounts service. Persisted to
            // disk when a state dir is configured (else in-memory).
            let accounts = match &cfg.state_dir {
                Some(dir) => AccountStore::with_state_dir(dir)?,
                None => AccountStore::new(),
            };
            router = router.add_service(ReviewServer::new(ReviewService::with_accounts(
                hub,
                accounts.clone(),
            )));
            router = router.add_service(AccountsServer::new(AccountsService::new(accounts)));
            tracing::info!("accounts mode ENABLED — Review requires a guardian session token");
        } else {
            router = router.add_service(ReviewServer::new(ReviewService::new(hub)));
            tracing::info!("accounts mode disabled — device-scoped Review (legacy/dev)");
        }

        if let Some(c) = cluster {
            let svc = aegis_cluster::service::ClusterControlService::new(c);
            router = router.add_service(
                aegis_proto::v1::cluster_control_server::ClusterControlServer::new(svc),
            );
        }
    }

    tracing::info!(role = ?cfg.role, %cfg.bind, "aegis-server listening");
    router.serve(addr).await?;
    Ok(())
}
