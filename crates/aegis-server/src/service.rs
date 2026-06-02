//! gRPC service implementations (Analysis / Offload / AlertRelay) and the
//! role-based `run` launcher. ClusterControl is mounted from `aegis-cluster`.
//! All links are mTLS when cert material is configured.

use std::pin::Pin;
use std::sync::Arc;

use aegis_proto::v1::analysis_server::{Analysis, AnalysisServer};
use aegis_proto::v1::offload_server::{Offload, OffloadServer};
use aegis_proto::v1::alert_relay_server::{AlertRelay, AlertRelayServer};
use aegis_proto::v1::{
    Action, AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AnalysisBatch, AnalysisRequest,
    Category, DeviceProfile, OffloadPolicy, RefreshOffloadRequest, Severity, Verdict, VerdictBatch,
};
use futures_util::StreamExt;
use tonic::{Request, Response, Status, Streaming};

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
        let mut pol = OffloadPolicy::default();
        pol.run_text_local = true;
        pol.ttl_secs = 300;
        pol.policy_id = r.policy_id;
        Ok(Response::new(pol))
    }
}

/// Hosts the `AlertRelay` service by delegating to an `aegis-alert` sink.
#[derive(Clone)]
pub struct AlertRelayService {
    sink: Arc<dyn aegis_alert::AlertSink>,
}

impl AlertRelayService {
    pub fn new(sink: Arc<dyn aegis_alert::AlertSink>) -> Self {
        Self { sink }
    }
}

#[tonic::async_trait]
impl AlertRelay for AlertRelayService {
    async fn raise_alert(&self, req: Request<AlertEvent>) -> Result<Response<AlertAck>, Status> {
        self.sink
            .raise(req.into_inner())
            .await
            .map(Response::new)
            .map_err(|e| Status::internal(e.to_string()))
    }

    async fn raise_alerts(
        &self,
        req: Request<AlertBatch>,
    ) -> Result<Response<AlertAckBatch>, Status> {
        self.sink
            .raise_batch(req.into_inner())
            .await
            .map(Response::new)
            .map_err(|e| Status::internal(e.to_string()))
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
        if let Some(sink) = alert_sink {
            router = router.add_service(AlertRelayServer::new(AlertRelayService::new(sink)));
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
