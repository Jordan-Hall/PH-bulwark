//! In-process, peer-attributed filtering for authenticated Remote VPN traffic.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bulwark_alert::AlertSink;
use bulwark_flow::{AnalysisUnit, DefaultFlowClassifier, FlowClassifier};
use bulwark_net::{InterceptDecision, Interceptor, NetConfig, NetInterceptor};
use bulwark_policy::{AgeProfile, Allowlist, Policy, PolicyContext, ReviewItem};
use bulwark_proto::v1::{
    analysis_request::Media, Action, AlertEvent, AnalysisRequest, Category, ChildConfig, Evidence,
    FilterLocation, FilteringProfile, MediaKind, ReviewDecision, ReviewScope, Severity,
    SourceChannel, Verdict,
};
use bulwark_proto::DeviceId;
use serde::Deserialize;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

use crate::accounts::AccountStore;
use crate::child_control::ChildConfigStore;
use crate::relay::AlertHub;
use crate::review_security::ReviewLedger;
use crate::AnalyzerRegistry;

const DEFAULT_TRANSPARENT_BIND: &str = "0.0.0.0:8081";
const DEFAULT_PROXY_PORT_BASE: u16 = 20_000;
const DEFAULT_ANALYSIS_TIMEOUT_MS: u64 = 900;
const DEFAULT_MAX_IN_FLIGHT: usize = 64;
const STATE_REFRESH_MS: u64 = 100;

#[derive(Clone)]
pub struct RemoteVpnContext {
    pub registry: AnalyzerRegistry,
    pub accounts: AccountStore,
    pub child_config: ChildConfigStore,
    pub hub: AlertHub,
    pub review_ledger: ReviewLedger,
    pub alert_sink: Option<Arc<dyn AlertSink>>,
    pub state_dir: PathBuf,
}

#[derive(Clone)]
struct RuntimeState {
    context: RemoteVpnContext,
    peers: Arc<RwLock<HashMap<Ipv4Addr, String>>>,
    approvals: Arc<RwLock<Allowlist>>,
    concurrency: Arc<Semaphore>,
    analysis_timeout: Duration,
}

#[derive(Debug, Deserialize, Default)]
struct PeerSnapshot {
    #[serde(default)]
    peers: Vec<PeerRow>,
}

#[derive(Debug, Deserialize)]
struct PeerRow {
    device_id: String,
    address: String,
    #[serde(default)]
    expires_ts: i64,
}

#[derive(Debug, Deserialize)]
struct AuditRow {
    device_id: String,
    alert_id: String,
    decision: i32,
    scope: i32,
    host: String,
    sha256_hex: String,
    category: i32,
    ts: i64,
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn proxy_port_base() -> anyhow::Result<u16> {
    let base = std::env::var("BULWARK_REMOTE_VPN_PROXY_PORT_BASE")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PROXY_PORT_BASE);
    if u32::from(base) + 254 > u32::from(u16::MAX) {
        anyhow::bail!("BULWARK_REMOTE_VPN_PROXY_PORT_BASE leaves no room for /24 peer slots");
    }
    Ok(base)
}

fn proxy_for_address(base: u16, address: Ipv4Addr) -> Option<SocketAddr> {
    let octet = address.octets()[3];
    (2..=254)
        .contains(&octet)
        .then(|| SocketAddr::from(([127, 0, 0, 1], base + u16::from(octet))))
}

fn analysis_timeout() -> Duration {
    Duration::from_millis(
        std::env::var("BULWARK_REMOTE_VPN_ANALYSIS_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_ANALYSIS_TIMEOUT_MS)
            .clamp(100, 5_000),
    )
}

fn max_in_flight() -> usize {
    std::env::var("BULWARK_REMOTE_VPN_MAX_IN_FLIGHT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_IN_FLIGHT)
        .min(1_024)
}

fn inspection_ca_path(state_dir: &Path) -> PathBuf {
    std::env::var_os("BULWARK_WG_INSPECTION_CA_PEM")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir.join("wg_inspection_ca.pem"))
}

fn remote_ca_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("remote-vpn-ca")
}

fn remote_net_config(state_dir: &Path, proxy: SocketAddr) -> NetConfig {
    NetConfig {
        proxy_listen: proxy.to_string(),
        ca_common_name: "PH Bulwark Remote VPN Inspection Root".to_string(),
        ca_store_dir: Some(remote_ca_dir(state_dir)),
        pinning_fail_open: false,
        flow_channel_capacity: 256,
        ..NetConfig::default()
    }
}

fn install_or_verify_region_ca(state_dir: &Path) -> anyhow::Result<()> {
    let bootstrap = NetInterceptor::new(remote_net_config(
        state_dir,
        SocketAddr::from(([127, 0, 0, 1], 0)),
    ))
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let pem = bootstrap.ca_cert_pem().as_bytes();
    let path = inspection_ca_path(state_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::read(&path) {
        Ok(existing) if existing == pem => Ok(()),
        Ok(_) => anyhow::bail!(
            "Remote VPN inspection CA at {} does not match the region keystore",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::write(&path, pem)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
            }
            tracing::info!(path = %path.display(), "Remote VPN public inspection root published");
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn active_peers(path: &Path) -> anyhow::Result<HashMap<Ipv4Addr, String>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error.into()),
    };
    let snapshot: PeerSnapshot = serde_json::from_slice(&bytes)?;
    let at = now_ms();
    let mut peers = HashMap::new();
    for row in snapshot.peers {
        if row.expires_ts <= at || row.device_id.trim().is_empty() {
            continue;
        }
        let Ok(address) = row.address.trim().parse::<Ipv4Addr>() else {
            continue;
        };
        let octets = address.octets();
        if octets[..3] != [10, 8, 0] {
            continue;
        }
        peers.insert(address, row.device_id.trim().to_string());
    }
    Ok(peers)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.trim().as_bytes();
    if bytes.is_empty() || bytes.len() & 1 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

fn load_approvals(path: &Path) -> anyhow::Result<Allowlist> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Allowlist::new()),
        Err(error) => return Err(error.into()),
    };
    let rows: Vec<AuditRow> = serde_json::from_slice(&bytes)?;
    let mut allowlist = Allowlist::new();
    for row in rows {
        let decision = ReviewDecision::try_from(row.decision).unwrap_or(ReviewDecision::Unspecified);
        let scope = ReviewScope::try_from(row.scope).unwrap_or(ReviewScope::Unspecified);
        let category = Category::try_from(row.category).unwrap_or(Category::Unspecified);
        let item = ReviewItem::new(
            DeviceId(row.device_id),
            row.alert_id,
            row.host,
            decode_hex(&row.sha256_hex).unwrap_or_default(),
            category,
        );
        let _ = allowlist.apply(&item, decision, scope, row.ts);
    }
    Ok(allowlist)
}

fn remote_config(config: &ChildConfig) -> bool {
    config.filtering_enabled && config.filter_location() == FilterLocation::FilterOnServer
}

fn age_profile(config: &ChildConfig) -> AgeProfile {
    match config.profile() {
        FilteringProfile::YoungChild => AgeProfile::YoungChild,
        FilteringProfile::Preteen => AgeProfile::PreTeen,
        FilteringProfile::Teen | FilteringProfile::Custom | FilteringProfile::Unspecified => {
            AgeProfile::Teen
        }
    }
}

fn inconclusive(request_id: String, rationale: impl Into<String>) -> Verdict {
    Verdict {
        request_id,
        category: Category::Unspecified as i32,
        action: Action::Block as i32,
        severity: Severity::High as i32,
        rationale: rationale.into(),
        ..Default::default()
    }
}

fn analysis_request(
    unit: AnalysisUnit,
    device_id: &str,
    source_channel: SourceChannel,
    request_id: String,
) -> (AnalysisRequest, Option<u64>) {
    let mut request = AnalysisRequest {
        request_id,
        source_channel: source_channel as i32,
        device_id: device_id.to_string(),
        ts: now_ms(),
        ..Default::default()
    };
    let segment_id = match unit {
        AnalysisUnit::Text(span) => {
            request.media_kind = MediaKind::Text as i32;
            request.text_span = Some(span);
            None
        }
        AnalysisUnit::Image(media) => {
            request.media_kind = MediaKind::Image as i32;
            request.media = Some(Media::InlineMedia(media));
            None
        }
        AnalysisUnit::Audio(media) => {
            request.media_kind = MediaKind::Audio as i32;
            request.media = Some(Media::InlineMedia(media));
            None
        }
        AnalysisUnit::VideoSegment {
            media,
            deadline_ms,
            segment_id,
        } => {
            request.media_kind = MediaKind::Video as i32;
            request.deadline_ms = deadline_ms;
            request.media = Some(Media::InlineMedia(media));
            segment_id
        }
    };
    (request, segment_id)
}

async fn analyze(
    registry: &AnalyzerRegistry,
    request: AnalysisRequest,
    timeout: Duration,
) -> Verdict {
    let request_id = request.request_id.clone();
    let Some(analyzer) = registry.analyzer_for(request.media_kind) else {
        return inconclusive(request_id, "no region analyzer is registered for this media kind");
    };
    match tokio::time::timeout(timeout, analyzer.analyze(request)).await {
        Ok(Ok(verdict)) if verdict.category() != Category::Unspecified => verdict,
        Ok(Ok(verdict)) => {
            let rationale = if verdict.rationale.is_empty() {
                "region analyzer returned incomplete coverage".to_string()
            } else {
                verdict.rationale
            };
            inconclusive(request_id, rationale)
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "Remote VPN analyzer failed; blocking flow");
            inconclusive(request_id, "region analysis failed")
        }
        Err(_) => inconclusive(request_id, "region analysis exceeded the decision deadline"),
    }
}

fn approved(allowlist: &Allowlist, device_id: &str, host: &str, verdict: &Verdict) -> bool {
    if matches!(
        verdict.category(),
        Category::CsamSuspected | Category::Unspecified
    ) {
        return false;
    }
    let device = DeviceId(device_id.to_string());
    let host_allowed = allowlist.is_host_allowed(&device, host);
    let hash_allowed = verdict
        .evidence
        .as_ref()
        .is_some_and(|evidence| allowlist.is_hash_allowed(&device, &evidence.sha256));
    host_allowed || hash_allowed
}

fn action_rank(action: Action) -> u8 {
    match action {
        Action::Block => 6,
        Action::Blur | Action::Mute => 5,
        Action::Warn => 4,
        Action::Log => 3,
        Action::Allow => 2,
        Action::Unspecified => 1,
    }
}

fn intercept_decision(action: Action, verdict: &Verdict) -> InterceptDecision {
    match action {
        Action::Block | Action::Unspecified => InterceptDecision::Drop,
        Action::Blur | Action::Mute if verdict.remediated_media.is_empty() => InterceptDecision::Drop,
        Action::Blur | Action::Mute => InterceptDecision::Rewrite(verdict.remediated_media.clone()),
        Action::Allow | Action::Log | Action::Warn => InterceptDecision::Forward,
    }
}

fn sanitized_evidence(category: Category, evidence: Option<Evidence>) -> Option<Evidence> {
    let mut evidence = evidence?;
    if category == Category::CsamSuspected {
        evidence.safe_thumbnail.clear();
        evidence.text_snippet.clear();
    }
    Some(evidence)
}

async fn emit_alert(
    state: &RuntimeState,
    device_id: &str,
    host: &str,
    flow_id: u64,
    unit_index: usize,
    verdict: &Verdict,
    decision: &bulwark_policy::PolicyDecision,
) {
    let Some(kind) = decision.raise_alert else {
        return;
    };
    let Some((child_id, family_id, _)) = state.context.accounts.child_for_device(device_id) else {
        return;
    };
    let category = verdict.category();
    let event = AlertEvent {
        alert_id: format!("rvpn-{device_id}-{flow_id}-{unit_index}"),
        kind: kind as i32,
        category: category as i32,
        severity: decision.severity as i32,
        app: host.to_string(),
        device_id: device_id.to_string(),
        ts: now_ms(),
        redacted_context: decision.reason.clone(),
        evidence: sanitized_evidence(category, verdict.evidence.clone()),
        child_id,
        family_id,
        local_segment_uri: if category == Category::CsamSuspected {
            String::new()
        } else {
            verdict.local_segment_uri.clone()
        },
    };

    if let Err(error) = state.context.review_ledger.record(&event) {
        tracing::error!(
            %error,
            alert_id = %event.alert_id,
            "Remote VPN alert ledger write failed; suppressing non-durable guardian notification"
        );
        return;
    }
    let reached = state.context.hub.publish(event.clone());
    if let Some(sink) = &state.context.alert_sink {
        if let Err(error) = sink.raise(event).await {
            tracing::warn!(%error, reached, "Remote VPN guardian notification sink failed");
        }
    }
}

async fn process_flow(
    address: Ipv4Addr,
    interceptor: Arc<NetInterceptor>,
    classifier: DefaultFlowClassifier,
    state: RuntimeState,
    flow: bulwark_core::CapturedFlow,
) {
    let flow_id = flow.flow_id;
    let host = flow.app_or_host.clone();
    let source_channel = flow.source_channel;
    let Some(device_id) = state
        .peers
        .read()
        .ok()
        .and_then(|peers| peers.get(&address).cloned())
    else {
        let _ = interceptor.apply(flow_id, InterceptDecision::Drop).await;
        return;
    };
    let config = match state.context.child_config.get_by_device(&device_id) {
        Ok(config) if remote_config(&config) => config,
        _ => {
            let _ = interceptor.apply(flow_id, InterceptDecision::Drop).await;
            return;
        }
    };

    let units = match classifier.classify(flow).await {
        Ok(units) => units,
        Err(error) => {
            tracing::warn!(%error, %device_id, "Remote VPN flow classification failed");
            let _ = interceptor.apply(flow_id, InterceptDecision::Drop).await;
            return;
        }
    };
    if units.is_empty() {
        let _ = interceptor.apply(flow_id, InterceptDecision::Forward).await;
        return;
    }

    let policy = Policy::default();
    let policy_context = PolicyContext::new(
        DeviceId(device_id.clone()),
        source_channel,
        age_profile(&config),
    );
    let allowlist = state
        .approvals
        .read()
        .map(|allowlist| allowlist.clone())
        .unwrap_or_default();
    let mut strongest_action = Action::Allow;
    let mut strongest_verdict = None;

    for (index, unit) in units.into_iter().enumerate() {
        let request_id = format!("rvpn-{device_id}-{flow_id}-{index}");
        let (request, segment_id) = analysis_request(unit, &device_id, source_channel, request_id);
        let verdict = analyze(&state.context.registry, request, state.analysis_timeout).await;
        let mut decision = policy.evaluate(&verdict, &policy_context);

        if approved(&allowlist, &device_id, &host, &verdict) {
            decision.action = Action::Allow;
            decision.raise_alert = None;
            decision.report = false;
            decision.reason = "guardian-approved content/host".to_string();
        } else {
            emit_alert(
                &state,
                &device_id,
                &host,
                flow_id,
                index,
                &verdict,
                &decision,
            )
            .await;
        }

        if let Some(segment_id) = segment_id {
            let rewritten = (!verdict.remediated_media.is_empty())
                .then(|| bytes::Bytes::from(verdict.remediated_media.clone()));
            if let Err(error) = classifier.apply(segment_id, decision.action, rewritten) {
                tracing::warn!(%error, %device_id, "Remote VPN video buffer release failed");
            }
        }

        if action_rank(decision.action) > action_rank(strongest_action) {
            strongest_action = decision.action;
            strongest_verdict = Some(verdict);
        }
    }

    let fallback = Verdict::default();
    let verdict = strongest_verdict.as_ref().unwrap_or(&fallback);
    if let Err(error) = interceptor
        .apply(flow_id, intercept_decision(strongest_action, verdict))
        .await
    {
        tracing::debug!(%error, %device_id, flow_id, "Remote VPN decision arrived after proxy gate closed");
    }
}

async fn slot_worker(
    address: Ipv4Addr,
    interceptor: Arc<NetInterceptor>,
    state: RuntimeState,
) {
    let classifier = DefaultFlowClassifier::with_defaults();
    loop {
        match interceptor.next_flow().await {
            Ok(Some(flow)) => {
                let Ok(permit) = state.concurrency.clone().try_acquire_owned() else {
                    let _ = interceptor.apply(flow.flow_id, InterceptDecision::Drop).await;
                    continue;
                };
                let interceptor = interceptor.clone();
                let classifier = classifier.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    process_flow(address, interceptor, classifier, state, flow).await;
                });
            }
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, %address, "Remote VPN proxy flow stream stopped");
                break;
            }
        }
    }
}

async fn start_slot(
    address: Ipv4Addr,
    base: u16,
    state: RuntimeState,
) -> anyhow::Result<Arc<NetInterceptor>> {
    let proxy = proxy_for_address(base, address)
        .ok_or_else(|| anyhow::anyhow!("invalid Remote VPN tunnel address {address}"))?;
    let interceptor = Arc::new(
        NetInterceptor::new(remote_net_config(&state.context.state_dir, proxy))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
    );
    interceptor
        .start_proxy_only()
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    tokio::spawn(slot_worker(address, interceptor.clone(), state));
    tracing::info!(%address, %proxy, "Remote VPN device inspection slot ready");
    Ok(interceptor)
}

async fn reconcile_slots(
    state: &RuntimeState,
    base: u16,
    slots: &Arc<AsyncMutex<HashMap<Ipv4Addr, Arc<NetInterceptor>>>>,
) {
    let peer_path = state.context.state_dir.join("wg_peers.json");
    let next = match active_peers(&peer_path) {
        Ok(peers) => peers,
        Err(error) => {
            tracing::error!(%error, "Remote VPN peer state unreadable; disabling all peer routing");
            HashMap::new()
        }
    };
    if let Ok(mut peers) = state.peers.write() {
        *peers = next.clone();
    }

    let wanted: HashSet<_> = next.keys().copied().collect();
    let current: Vec<_> = slots.lock().await.keys().copied().collect();
    for address in current {
        if wanted.contains(&address) {
            continue;
        }
        if let Some(interceptor) = slots.lock().await.remove(&address) {
            if let Err(error) = interceptor.shutdown().await {
                tracing::warn!(%error, %address, "Remote VPN slot shutdown failed");
            }
        }
    }

    for address in wanted {
        if slots.lock().await.contains_key(&address) {
            continue;
        }
        match start_slot(address, base, state.clone()).await {
            Ok(interceptor) => {
                slots.lock().await.insert(address, interceptor);
            }
            Err(error) => {
                tracing::error!(%error, %address, "Remote VPN inspection slot failed to start");
            }
        }
    }
}

async fn state_watcher(
    state: RuntimeState,
    base: u16,
    slots: Arc<AsyncMutex<HashMap<Ipv4Addr, Arc<NetInterceptor>>>>,
) {
    let audit_path = state.context.state_dir.join("allowlist_audit.json");
    loop {
        reconcile_slots(&state, base, &slots).await;
        let next = match load_approvals(&audit_path) {
            Ok(allowlist) => allowlist,
            Err(error) => {
                tracing::error!(%error, "guardian approval journal unreadable; clearing Remote VPN approvals");
                Allowlist::new()
            }
        };
        if let Ok(mut approvals) = state.approvals.write() {
            *approvals = next;
        }
        tokio::time::sleep(Duration::from_millis(STATE_REFRESH_MS)).await;
    }
}

#[cfg(target_os = "linux")]
pub async fn start(context: RemoteVpnContext) -> anyhow::Result<()> {
    if !env_flag("BULWARK_WG_FILTER_ACTIVE") {
        return Ok(());
    }
    std::fs::create_dir_all(&context.state_dir)?;
    install_or_verify_region_ca(&context.state_dir)?;

    let bind: SocketAddr = std::env::var("BULWARK_REMOTE_VPN_TRANSPARENT_BIND")
        .unwrap_or_else(|_| DEFAULT_TRANSPARENT_BIND.to_string())
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid BULWARK_REMOTE_VPN_TRANSPARENT_BIND: {error}"))?;
    let base = proxy_port_base()?;
    let probe = tokio::net::TcpListener::bind(bind).await?;
    drop(probe);

    let state = RuntimeState {
        context,
        peers: Arc::new(RwLock::new(HashMap::new())),
        approvals: Arc::new(RwLock::new(Allowlist::new())),
        concurrency: Arc::new(Semaphore::new(max_in_flight())),
        analysis_timeout: analysis_timeout(),
    };
    let slots = Arc::new(AsyncMutex::new(HashMap::new()));
    reconcile_slots(&state, base, &slots).await;

    let routing_peers = state.peers.clone();
    tokio::spawn(async move {
        let result = bulwark_net::vpn::transparent::run_transparent_listener_routed(
            bind,
            move |peer| {
                let IpAddr::V4(address) = peer.ip() else {
                    return None;
                };
                routing_peers
                    .read()
                    .ok()
                    .is_some_and(|peers| peers.contains_key(&address))
                    .then(|| proxy_for_address(base, address))
                    .flatten()
            },
            bulwark_net::vpn::CancellationToken::new(),
        )
        .await;
        if let Err(error) = result {
            tracing::error!(%error, "Remote VPN transparent listener stopped; redirect remains fail closed");
        }
    });
    tokio::spawn(state_watcher(state.clone(), base, slots));

    tracing::info!(
        %bind,
        proxy_port_base = base,
        analysis_timeout_ms = state.analysis_timeout.as_millis(),
        "Remote VPN region filter runtime active"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn start(_context: RemoteVpnContext) -> anyhow::Result<()> {
    if env_flag("BULWARK_WG_FILTER_ACTIVE") {
        anyhow::bail!("Remote VPN server filtering is supported only on Linux regions");
    }
    Ok(())
}
