//! gRPC service composition and authenticated device-facing handlers.

use std::pin::Pin;
use std::sync::Arc;

use bulwark_proto::v1::accounts_server::AccountsServer;
use bulwark_proto::v1::alert_relay_server::{AlertRelay, AlertRelayServer};
use bulwark_proto::v1::analysis_server::{Analysis, AnalysisServer};
use bulwark_proto::v1::child_control_server::ChildControlServer;
use bulwark_proto::v1::family_safety_server::FamilySafetyServer;
use bulwark_proto::v1::offload_server::{Offload, OffloadServer};
use bulwark_proto::v1::review_server::ReviewServer;
use bulwark_proto::v1::staff_admin_server::StaffAdminServer;
use bulwark_proto::v1::tamper_server::TamperServer;
use bulwark_proto::v1::wg_provision_server::WgProvisionServer;
use bulwark_proto::v1::{
    Action, AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AlertKind, AnalysisBatch,
    AnalysisRequest, Category, DeviceProfile, OffloadPolicy, RefreshOffloadRequest, Severity,
    Verdict, VerdictBatch,
};
use futures_util::{stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

use crate::accounts::{AccountStore, AccountsService};
use crate::auth::{authenticate_device_metadata, DevicePrincipal};
use crate::child_control::{ChildConfigStore, ChildControlService};
use crate::family_safety::{FamilySafetyService, SafetyBroadcastStore};
use crate::relay::{AlertHub, ReviewService};
use crate::review_security::{ReviewLedger, SecureReviewService};
use crate::staff::{StaffAdminService, StaffStore};
use crate::tamper::{self, TamperService};
use crate::wg_provision::{WgPeerStore, WgProvisionService};
use crate::{default_offload_policy, AnalyzerRegistry, ServerConfig, ServerRole};

#[path = "remote_vpn.rs"]
mod remote_vpn;

const ANALYSIS_BATCH_CONCURRENCY: usize = 8;

fn to_status(error: bulwark_core::Error) -> Status {
    Status::internal(error.to_string())
}

fn inconclusive(request_id: String, rationale: impl Into<String>) -> Verdict {
    Verdict {
        request_id,
        category: Category::Unspecified as i32,
        action: Action::Block as i32,
        severity: Severity::Medium as i32,
        score: 0.0,
        rationale: rationale.into(),
        evidence: None,
        grooming: None,
        worker_id: String::new(),
        latency_ms: 0,
        ..Default::default()
    }
}

fn bind_analysis_identity(
    request: &mut AnalysisRequest,
    principal: &DevicePrincipal,
) -> Result<(), Status> {
    let claimed = request.device_id.trim();
    if !claimed.is_empty() && claimed != principal.device_id {
        return Err(Status::permission_denied(
            "analysis request device_id does not match authenticated device",
        ));
    }
    request.device_id = principal.device_id.clone();
    Ok(())
}

#[derive(Clone)]
pub struct AnalysisService {
    registry: AnalyzerRegistry,
    accounts: Option<AccountStore>,
}

impl AnalysisService {
    pub fn new(registry: AnalyzerRegistry) -> Self {
        Self {
            registry,
            accounts: None,
        }
    }

    pub fn with_accounts(mut self, accounts: AccountStore) -> Self {
        self.accounts = Some(accounts);
        self
    }

    fn principal<T>(&self, request: &Request<T>) -> Result<Option<DevicePrincipal>, Status> {
        self.accounts
            .as_ref()
            .map(|accounts| authenticate_device_metadata(request, accounts))
            .transpose()
    }

    async fn dispatch(&self, request: AnalysisRequest) -> Result<Verdict, Status> {
        match self.registry.analyzer_for(request.media_kind) {
            Some(analyzer) => analyzer.analyze(request).await.map_err(to_status),
            None => Ok(inconclusive(
                request.request_id,
                "no analyzer is registered for this media kind",
            )),
        }
    }
}

#[tonic::async_trait]
impl Analysis for AnalysisService {
    async fn analyze(&self, request: Request<AnalysisRequest>) -> Result<Response<Verdict>, Status> {
        let principal = self.principal(&request)?;
        let mut request = request.into_inner();
        if let Some(principal) = &principal {
            bind_analysis_identity(&mut request, principal)?;
        }
        self.dispatch(request).await.map(Response::new)
    }

    async fn analyze_batch(
        &self,
        request: Request<AnalysisBatch>,
    ) -> Result<Response<VerdictBatch>, Status> {
        let principal = self.principal(&request)?;
        let mut requests = request.into_inner().requests;
        if let Some(principal) = &principal {
            for request in &mut requests {
                bind_analysis_identity(request, principal)?;
            }
        }

        let this = self.clone();
        let results: Vec<Result<Verdict, Status>> = stream::iter(requests)
            .map(move |request| {
                let this = this.clone();
                async move { this.dispatch(request).await }
            })
            .buffered(ANALYSIS_BATCH_CONCURRENCY)
            .collect()
            .await;
        let verdicts = results.into_iter().collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(VerdictBatch { verdicts }))
    }

    type AnalyzeStreamStream =
        Pin<Box<dyn futures_core::Stream<Item = Result<Verdict, Status>> + Send + 'static>>;

    async fn analyze_stream(
        &self,
        request: Request<Streaming<AnalysisRequest>>,
    ) -> Result<Response<Self::AnalyzeStreamStream>, Status> {
        let principal = self.principal(&request)?;
        let this = self.clone();
        let inbound = request.into_inner();
        let output = inbound.then(move |item| {
            let this = this.clone();
            let principal = principal.clone();
            async move {
                let mut request = item?;
                if let Some(principal) = &principal {
                    bind_analysis_identity(&mut request, principal)?;
                }
                this.dispatch(request).await
            }
        });
        Ok(Response::new(Box::pin(output)))
    }
}

#[derive(Clone, Default)]
pub struct OffloadService {
    profiles: Arc<std::sync::Mutex<std::collections::HashMap<String, DeviceProfile>>>,
    accounts: Option<AccountStore>,
}

impl OffloadService {
    pub fn with_accounts(mut self, accounts: AccountStore) -> Self {
        self.accounts = Some(accounts);
        self
    }

    fn principal<T>(&self, request: &Request<T>) -> Result<Option<DevicePrincipal>, Status> {
        self.accounts
            .as_ref()
            .map(|accounts| authenticate_device_metadata(request, accounts))
            .transpose()
    }
}

#[tonic::async_trait]
impl Offload for OffloadService {
    async fn negotiate_offload(
        &self,
        request: Request<DeviceProfile>,
    ) -> Result<Response<OffloadPolicy>, Status> {
        let principal = self.principal(&request)?;
        let mut profile = request.into_inner();
        if let Some(principal) = &principal {
            if !profile.device_id.trim().is_empty()
                && profile.device_id.trim() != principal.device_id
            {
                return Err(Status::permission_denied(
                    "profile device_id does not match authenticated device",
                ));
            }
            profile.device_id = principal.device_id.clone();
        }
        if let Ok(mut cache) = self.profiles.lock() {
            cache.insert(profile.device_id.clone(), profile.clone());
        }
        Ok(Response::new(default_offload_policy(&profile)))
    }

    async fn refresh_offload(
        &self,
        request: Request<RefreshOffloadRequest>,
    ) -> Result<Response<OffloadPolicy>, Status> {
        let principal = self.principal(&request)?;
        let mut refresh = request.into_inner();
        if let Some(principal) = &principal {
            if !refresh.device_id.trim().is_empty()
                && refresh.device_id.trim() != principal.device_id
            {
                return Err(Status::permission_denied(
                    "refresh device_id does not match authenticated device",
                ));
            }
            refresh.device_id = principal.device_id.clone();
        }
        let profile = self
            .profiles
            .lock()
            .ok()
            .and_then(|cache| cache.get(&refresh.device_id).cloned())
            .map(|mut profile| {
                profile.rtt_ms = refresh.rtt_ms;
                profile.battery_pct = refresh.battery_pct;
                profile
            })
            .unwrap_or_else(|| DeviceProfile {
                device_id: refresh.device_id.clone(),
                rtt_ms: refresh.rtt_ms,
                battery_pct: refresh.battery_pct,
                ..Default::default()
            });
        let mut policy = default_offload_policy(&profile);
        if !refresh.policy_id.is_empty() {
            policy.policy_id = refresh.policy_id;
        }
        Ok(Response::new(policy))
    }
}

#[derive(Clone)]
pub struct AlertRelayService {
    hub: AlertHub,
    sink: Option<Arc<dyn bulwark_alert::AlertSink>>,
    accounts: Option<AccountStore>,
    review_ledger: Option<ReviewLedger>,
}

impl AlertRelayService {
    pub fn new(hub: AlertHub, sink: Option<Arc<dyn bulwark_alert::AlertSink>>) -> Self {
        Self {
            hub,
            sink,
            accounts: None,
            review_ledger: None,
        }
    }

    pub fn with_accounts(mut self, accounts: AccountStore) -> Self {
        self.accounts = Some(accounts);
        self
    }

    pub fn with_review_ledger(mut self, review_ledger: ReviewLedger) -> Self {
        self.review_ledger = Some(review_ledger);
        self
    }

    fn principal<T>(&self, request: &Request<T>) -> Result<Option<DevicePrincipal>, Status> {
        self.accounts
            .as_ref()
            .map(|accounts| authenticate_device_metadata(request, accounts))
            .transpose()
    }

    fn bind_alert(
        mut event: AlertEvent,
        principal: Option<&DevicePrincipal>,
    ) -> Result<AlertEvent, Status> {
        if event.kind() == AlertKind::SafetyBroadcast {
            return Err(Status::permission_denied(
                "SAFETY_BROADCAST is staff-originated and cannot enter through AlertRelay",
            ));
        }
        if let Some(principal) = principal {
            if !event.device_id.trim().is_empty() && event.device_id.trim() != principal.device_id {
                return Err(Status::permission_denied(
                    "alert device_id does not match authenticated device",
                ));
            }
            event.device_id = principal.device_id.clone();
            event.child_id = principal.child_id.clone();
            event.family_id = principal.family_id.clone();
        }
        Ok(event)
    }

    async fn deliver(&self, event: AlertEvent) -> Result<AlertAck, Status> {
        if let Some(ledger) = &self.review_ledger {
            ledger
                .record(&event)
                .map_err(|error| Status::unavailable(format!("durable alert ledger: {error}")))?;
        }
        let reached = self.hub.publish(event.clone());
        match &self.sink {
            Some(sink) => {
                let mut ack = sink
                    .raise(event)
                    .await
                    .map_err(|error| Status::internal(error.to_string()))?;
                if reached > 0 && !ack.delivered {
                    ack.delivered = true;
                    ack.detail = format!(
                        "{} + fanned out to {reached} guardian stream(s)",
                        ack.detail
                    );
                }
                Ok(ack)
            }
            None => Ok(AlertAck {
                alert_id: event.alert_id,
                delivered: reached > 0,
                deduped: false,
                detail: format!("durably recorded; fanned out to {reached} guardian stream(s)"),
            }),
        }
    }
}

#[tonic::async_trait]
impl AlertRelay for AlertRelayService {
    async fn raise_alert(&self, request: Request<AlertEvent>) -> Result<Response<AlertAck>, Status> {
        let principal = self.principal(&request)?;
        let event = Self::bind_alert(request.into_inner(), principal.as_ref())?;
        self.deliver(event).await.map(Response::new)
    }

    async fn raise_alerts(
        &self,
        request: Request<AlertBatch>,
    ) -> Result<Response<AlertAckBatch>, Status> {
        let principal = self.principal(&request)?;
        let batch = request.into_inner();
        let mut acks = Vec::with_capacity(batch.events.len());
        for event in batch.events {
            let event = Self::bind_alert(event, principal.as_ref())?;
            acks.push(self.deliver(event).await?);
        }
        Ok(Response::new(AlertAckBatch { acks }))
    }
}

pub async fn run(
    cfg: ServerConfig,
    registry: AnalyzerRegistry,
    alert_sink: Option<Arc<dyn bulwark_alert::AlertSink>>,
    cluster: Option<Arc<bulwark_cluster::Cluster>>,
    hub: Option<AlertHub>,
) -> anyhow::Result<()> {
    use tonic::transport::Server;

    if cfg.production_mode {
        if !cfg.accounts_enabled || cfg.state_dir.is_none() {
            anyhow::bail!("production server requires accounts + durable state");
        }
        if cfg.tls_cert_pem.is_none() || cfg.tls_key_pem.is_none() {
            anyhow::bail!("production server requires server-authenticated TLS");
        }
        if cfg.role != ServerRole::AllInOne {
            anyhow::bail!(
                "production distributed roles are disabled until internal-node auth is complete"
            );
        }
    }

    let addr = parse_bind(&cfg.bind)?;
    let mut builder = Server::builder();
    match (&cfg.tls_cert_pem, &cfg.tls_key_pem) {
        (Some(cert), Some(key)) => {
            use tonic::transport::{Certificate, Identity, ServerTlsConfig};
            let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(cert, key));
            if let Some(ca) = &cfg.client_ca_pem {
                tls = tls.client_ca_root(Certificate::from_pem(ca));
                tracing::info!("server TLS + optional client-certificate authentication enabled");
            } else {
                tracing::info!(
                    "server TLS enabled; device/guardian authorization uses application credentials"
                );
            }
            builder = builder.tls_config(tls)?;
        }
        _ => tracing::warn!("serving without TLS; local development only"),
    }

    let accounts = if cfg.accounts_enabled {
        Some(match &cfg.state_dir {
            Some(dir) => AccountStore::with_state_dir(dir)?,
            None => AccountStore::new(),
        })
    } else {
        None
    };

    // The gRPC Analysis service and the Remote VPN region filter share analyzer
    // instances. Models/sessions therefore load once per server process.
    let mut analysis = AnalysisService::new(registry.clone());
    if let Some(accounts) = &accounts {
        analysis = analysis.with_accounts(accounts.clone());
    }
    let mut router = builder.add_service(AnalysisServer::new(analysis));

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    router = router.add_service(health_service);

    if matches!(cfg.role, ServerRole::AllInOne | ServerRole::Lb) {
        let mut offload = OffloadService::default();
        if let Some(accounts) = &accounts {
            offload = offload.with_accounts(accounts.clone());
        }
        router = router.add_service(OffloadServer::new(offload));

        let hub = match (hub, &cfg.state_dir) {
            (Some(hub), _) => hub,
            (None, Some(dir)) => AlertHub::with_state_dir(dir)?,
            (None, None) => AlertHub::default(),
        };
        if let Some(accounts) = &accounts {
            hub.attach_accounts(accounts.clone());
        }

        let review_ledger = match &cfg.state_dir {
            Some(dir) => ReviewLedger::with_state_dir(dir)?,
            None => ReviewLedger::new(),
        };
        let mut relay = AlertRelayService::new(hub.clone(), alert_sink.clone())
            .with_review_ledger(review_ledger.clone());
        if let Some(accounts) = &accounts {
            relay = relay.with_accounts(accounts.clone());
        }
        router = router.add_service(AlertRelayServer::new(relay));

        let mut tamper = TamperService::new(hub.clone());
        if let Some(accounts) = &accounts {
            tamper = tamper.with_accounts(accounts.clone());
        }
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
                        .map(|duration| duration.as_millis() as i64)
                        .unwrap_or(0);
                    let fired = sweeper.sweep(now_ms);
                    if fired > 0 {
                        tracing::warn!(devices = fired, "missed-heartbeat alerts raised");
                    }
                }
            });
        }
        router = router.add_service(TamperServer::new(tamper));

        let wg_peers = if accounts.is_some() {
            Some(
                match &cfg.state_dir {
                    Some(dir) => WgPeerStore::with_state_dir(dir)?,
                    None => WgPeerStore::new(),
                }
                .with_reserved_from_env(),
            )
        } else {
            None
        };

        let staff_store = if cfg.staff_enabled {
            let staff = match &cfg.state_dir {
                Some(dir) => StaffStore::with_state_dir(dir)?,
                None => StaffStore::new(),
            }
            .with_bootstrap_from_env();
            let mut staff_service = StaffAdminService::from_env(staff.clone());
            if let Some(accounts) = &accounts {
                staff_service = staff_service.with_accounts(accounts.clone());
                if let Some(mailer) = crate::reset_mailer::ResetMailer::from_env() {
                    staff_service = staff_service.with_reset_mailer(mailer);
                }
            }
            if let Some(dir) = &cfg.state_dir {
                staff_service = staff_service
                    .with_safety_cases(crate::safety_cases::SafetyCaseStore::with_state_dir(dir)?);
            }
            if let Some(cluster) = &cluster {
                staff_service = staff_service.with_cluster(cluster.clone());
            }
            if let Some(wg_peers) = &wg_peers {
                staff_service = staff_service.with_wg_peers(wg_peers.clone());
            }
            router = router.add_service(StaffAdminServer::new(staff_service));
            Some(staff)
        } else {
            None
        };

        let broadcast_store = match &cfg.state_dir {
            Some(dir) => SafetyBroadcastStore::with_state_dir(dir)?,
            None => SafetyBroadcastStore::new(),
        };
        let mut family_safety = FamilySafetyService::new(hub.clone(), broadcast_store)
            .with_alert_sink(alert_sink.clone())
            .with_staff_token_from_env();
        if let Some(staff) = &staff_store {
            family_safety = family_safety.with_staff_store(staff.clone());
        }
        if let Some(accounts) = &accounts {
            family_safety = family_safety.with_accounts(accounts.clone());
        }
        router = router.add_service(FamilySafetyServer::new(family_safety));

        let review_store = matches!(cfg.role, ServerRole::AllInOne)
            .then(bulwark_video::SegmentStore::default_location)
            .and_then(|result| {
                result
                    .map_err(|error| tracing::warn!(%error, "review clip store unavailable"))
                    .ok()
            })
            .map(Arc::new);

        if let Some(accounts) = accounts.clone() {
            let legacy_review = ReviewService::with_accounts(hub.clone(), accounts.clone());
            let secure_review = SecureReviewService::new(
                legacy_review,
                accounts.clone(),
                review_ledger.clone(),
            )
            .with_segment_store(review_store.clone());
            router = router.add_service(ReviewServer::new(secure_review));

            // Build the child configuration store ONCE. ChildControl,
            // WgProvision's durable authorization document and the Remote VPN
            // runtime all refer to this same authority/state directory.
            let child_config = match &cfg.state_dir {
                Some(dir) => ChildConfigStore::with_state_dir(dir)?,
                None => ChildConfigStore::new(),
            };
            router = router.add_service(ChildControlServer::new(ChildControlService::new(
                child_config.clone(),
                accounts.clone(),
            )));

            let wg_peers = wg_peers.unwrap_or_else(WgPeerStore::new);

            // Start the actual region filtering runtime BEFORE exposing the
            // provisioning RPC. Therefore a grant carrying filter_active=true
            // can only be issued after the CA, transparent ingress and analyzer
            // pipeline have initialized successfully.
            if let Some(state_dir) = cfg.state_dir.clone() {
                remote_vpn::start(remote_vpn::RemoteVpnContext {
                    registry: registry.clone(),
                    accounts: accounts.clone(),
                    child_config: child_config.clone(),
                    hub: hub.clone(),
                    review_ledger: review_ledger.clone(),
                    alert_sink: alert_sink.clone(),
                    state_dir,
                })
                .await?;
            } else if matches!(
                std::env::var("BULWARK_WG_FILTER_ACTIVE").ok().as_deref(),
                Some("1") | Some("true") | Some("yes") | Some("on")
            ) {
                anyhow::bail!("Remote VPN filtering requires durable BULWARK_STATE_DIR");
            }

            router = router.add_service(WgProvisionServer::new(WgProvisionService::from_env(
                wg_peers,
                accounts.clone(),
            )));
            router = router.add_service(AccountsServer::new(AccountsService::from_env(accounts)));
        } else {
            if cfg.production_mode {
                anyhow::bail!("production Review cannot run without accounts");
            }
            router = router.add_service(ReviewServer::new(
                ReviewService::new(hub).with_segment_store(review_store),
            ));
        }

        if cluster.is_some() {
            tracing::info!(
                "ClusterControl public mount disabled; internal control plane is isolated"
            );
        }
    }

    tracing::info!(role = ?cfg.role, %cfg.bind, production = cfg.production_mode, "bulwark-server listening");
    router.serve_with_shutdown(addr, shutdown_signal()).await?;
    tracing::info!("bulwark-server stopped");
    Ok(())
}

fn parse_bind(bind: &str) -> anyhow::Result<std::net::SocketAddr> {
    bind.parse()
        .map_err(|error| anyhow::anyhow!("invalid bind address {bind:?} (BULWARK_BIND): {error}"))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "SIGTERM handler unavailable; Ctrl-C only");
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
    use super::{inconclusive, parse_bind};
    use bulwark_proto::v1::{Action, Category};

    #[test]
    fn parse_bind_accepts_valid_and_rejects_garbage() {
        assert!(parse_bind("127.0.0.1:8443").is_ok());
        assert!(parse_bind("0.0.0.0:8443").is_ok());
        assert!(parse_bind("[::1]:8443").is_ok());
        let error = parse_bind("not-an-addr").unwrap_err().to_string();
        assert!(error.contains("not-an-addr") && error.contains("BULWARK_BIND"));
        assert!(parse_bind("127.0.0.1").is_err());
    }

    #[test]
    fn uncovered_analysis_is_never_safe_or_allowed() {
        let verdict = inconclusive("r".into(), "missing model");
        assert_eq!(verdict.category(), Category::Unspecified);
        assert_eq!(verdict.action(), Action::Block);
    }
}
