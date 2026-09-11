//! Fast authenticated child-device uplink to the enrolled Bulwark server.
//!
//! The VPN hot path reuses one lazy HTTP/2 channel for Analysis + AlertRelay so
//! gated images/video do not pay a TCP/TLS handshake per object. Application
//! credentials are also attached as gRPC metadata, binding every device-originated
//! RPC to the pairing-minted device principal on the hardened server.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bulwark_proto::v1::alert_relay_client::AlertRelayClient;
use bulwark_proto::v1::analysis_client::AnalysisClient;
use bulwark_proto::v1::tamper_client::TamperClient;
use bulwark_proto::v1::{
    analysis_request::Media, AlertEvent, AnalysisRequest, Heartbeat, InlineMedia, MediaKind,
    ProtectionStatus, SourceChannel, Verdict,
};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

const DEVICE_ID_HEADER: &str = "x-bulwark-device-id";
const DEVICE_TOKEN_HEADER: &str = "x-bulwark-device-token";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Where, and as whom, this enrolled child device talks to the service.
#[derive(Clone, Debug, Default)]
pub struct RelayTarget {
    pub endpoint: String,
    pub device_id: String,
    pub child_id: String,
    pub family_id: String,
    pub cluster_ca: String,
    pub device_token: String,
}

#[derive(Clone)]
struct CachedChannel {
    key: String,
    channel: Channel,
}

fn target_cell() -> &'static Mutex<Option<RelayTarget>> {
    static TARGET: OnceLock<Mutex<Option<RelayTarget>>> = OnceLock::new();
    TARGET.get_or_init(|| Mutex::new(None))
}

fn channel_cell() -> &'static Mutex<Option<CachedChannel>> {
    static CHANNEL: OnceLock<Mutex<Option<CachedChannel>>> = OnceLock::new();
    CHANNEL.get_or_init(|| Mutex::new(None))
}

/// Install/refresh the enrollment target from the device config. A target without
/// a device token is retained for legacy heartbeat compatibility, but protected
/// Analysis/AlertRelay calls reject it rather than impersonating a device by ID.
pub fn set_target_from_config_json(config_json: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return;
    };
    let field = |name: &str| {
        value
            .get(name)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let endpoint = field("cluster_endpoint");
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return;
    }
    let next = RelayTarget {
        endpoint,
        device_id: field("device_id"),
        child_id: field("child_id"),
        family_id: field("family_id"),
        cluster_ca: field("cluster_ca"),
        device_token: field("device_token"),
    };
    if let Ok(mut current) = target_cell().lock() {
        let changed = current
            .as_ref()
            .map(|old| old.endpoint != next.endpoint || old.cluster_ca != next.cluster_ca)
            .unwrap_or(true);
        *current = Some(next);
        if changed {
            if let Ok(mut cached) = channel_cell().lock() {
                *cached = None;
            }
        }
    }
}

/// Snapshot the current enrolled target.
pub fn target() -> Option<RelayTarget> {
    target_cell().lock().ok().and_then(|target| target.clone())
}

fn relay_runtime() -> Option<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(1)
                .thread_name("bulwark-relay")
                .build()
                .ok()
        })
        .as_ref()
}

fn endpoint(t: &RelayTarget) -> Result<Endpoint, String> {
    let mut endpoint = Endpoint::from_shared(t.endpoint.clone())
        .map_err(|_| "relay endpoint is not valid".to_string())?
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(3))
        .tcp_nodelay(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(5));

    if t.endpoint.to_ascii_lowercase().starts_with("https://") {
        let pinned = if t.cluster_ca.trim().is_empty() {
            None
        } else {
            match std::fs::read(t.cluster_ca.trim()) {
                Ok(pem) => Some(pem),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(format!("pinned cluster CA is unreadable: {error}"));
                }
            }
        };
        let tls = match pinned {
            Some(pem) => tonic::transport::ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(pem)),
            None => tonic::transport::ClientTlsConfig::new().with_enabled_roots(),
        };
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|error| format!("TLS config: {error}"))?;
    }
    Ok(endpoint)
}

/// Reuse one multiplexed HTTP/2 channel. `connect_lazy` keeps setup off the flow
/// consumer's critical section; the first request establishes the connection and
/// subsequent image/video decisions reuse it.
fn shared_channel(t: &RelayTarget) -> Result<Channel, String> {
    let key = format!("{}\u{0}{}", t.endpoint, t.cluster_ca);
    if let Ok(cache) = channel_cell().lock() {
        if let Some(cached) = cache.as_ref().filter(|cached| cached.key == key) {
            return Ok(cached.channel.clone());
        }
    }
    let channel = endpoint(t)?.connect_lazy();
    if let Ok(mut cache) = channel_cell().lock() {
        *cache = Some(CachedChannel {
            key,
            channel: channel.clone(),
        });
    }
    Ok(channel)
}

fn authenticated_request<T>(t: &RelayTarget, message: T) -> Result<Request<T>, String> {
    if t.device_id.trim().is_empty() || t.device_token.trim().is_empty() {
        return Err("device enrollment credential is missing; re-pair this device".to_string());
    }
    let mut request = Request::new(message);
    let device_id = MetadataValue::try_from(t.device_id.as_str())
        .map_err(|_| "device id cannot be encoded as gRPC metadata".to_string())?;
    let device_token = MetadataValue::try_from(t.device_token.as_str())
        .map_err(|_| "device token cannot be encoded as gRPC metadata".to_string())?;
    request.metadata_mut().insert(DEVICE_ID_HEADER, device_id);
    request
        .metadata_mut()
        .insert(DEVICE_TOKEN_HEADER, device_token);
    Ok(request)
}

/// Score one gated image/video unit on the cluster over the already-reused
/// channel. The caller supplies a tight deadline that is also sent to the worker
/// so it can shed work instead of causing visible playback stalls.
pub async fn analyze_media(
    kind: MediaKind,
    source_channel: SourceChannel,
    mime_type: String,
    bytes: Vec<u8>,
    deadline_ms: u32,
    request_id: String,
) -> Result<Verdict, String> {
    let target = target().ok_or_else(|| "device is not enrolled with a cluster".to_string())?;
    if bytes.is_empty() {
        return Err("captured media was empty".to_string());
    }
    let channel = shared_channel(&target)?;
    let mut client = AnalysisClient::new(channel);
    let request = AnalysisRequest {
        request_id,
        media_kind: kind as i32,
        source_channel: source_channel as i32,
        device_id: target.device_id.clone(),
        ts: now_ms(),
        deadline_ms,
        media: Some(Media::InlineMedia(InlineMedia {
            data: bytes,
            mime_type,
            ..Default::default()
        })),
        ..Default::default()
    };
    let request = authenticated_request(&target, request)?;
    let timeout = Duration::from_millis(u64::from(deadline_ms.max(250)));
    tokio::time::timeout(timeout, client.analyze(request))
        .await
        .map_err(|_| "media analysis deadline exceeded".to_string())?
        .map_err(|status| format!("media analysis failed: {}", status.code()))
        .map(|response| response.into_inner())
}

async fn raise_alert(t: RelayTarget, event: AlertEvent) -> Result<(), String> {
    let mut client = AlertRelayClient::new(shared_channel(&t)?);
    let request = authenticated_request(&t, event)?;
    tokio::time::timeout(Duration::from_secs(2), client.raise_alert(request))
        .await
        .map_err(|_| "raise_alert timed out".to_string())?
        .map_err(|status| format!("raise_alert: {}", status.code()))?;
    Ok(())
}

/// Best-effort remote copy of a redacted guardian alert. The local alert queue is
/// written first by callers, so a transient server failure never removes evidence.
pub fn relay_alert_best_effort(mut event: AlertEvent) {
    let Some(target) = target() else { return };
    let Some(runtime) = relay_runtime() else { return };
    if event.device_id.is_empty() {
        event.device_id = target.device_id.clone();
    }
    if event.child_id.is_empty() {
        event.child_id = target.child_id.clone();
    }
    if event.family_id.is_empty() {
        event.family_id = target.family_id.clone();
    }
    runtime.spawn(async move {
        if let Err(error) = raise_alert(target, event).await {
            tracing::debug!(%error, "guardian alert relay failed (best effort)");
        }
    });
}

/// Content-free protection snapshot for the server liveness/tamper path.
pub fn protection_status(t: &RelayTarget, vpn_up: bool) -> ProtectionStatus {
    ProtectionStatus {
        device_id: t.device_id.clone(),
        child_id: t.child_id.clone(),
        vpn_active: vpn_up,
        platform: "android".to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        ts: now_ms(),
        ..Default::default()
    }
}

async fn send_heartbeat(t: &RelayTarget, vpn_up: bool) -> Result<u32, String> {
    let mut client = TamperClient::new(shared_channel(t)?);
    let heartbeat = Heartbeat {
        status: Some(protection_status(t, vpn_up)),
        tamper_events: Vec::new(),
        device_token: t.device_token.clone(),
    };
    let ack = tokio::time::timeout(Duration::from_secs(3), client.heartbeat(heartbeat))
        .await
        .map_err(|_| "heartbeat timed out".to_string())?
        .map_err(|status| format!("heartbeat: {}", status.code()))?
        .into_inner();
    Ok(ack.next_interval_secs)
}

/// Periodic protection heartbeat until the VPN session is cancelled.
pub async fn run_heartbeats(
    shutdown: bulwark_net::vpn::CancellationToken,
    vpn_up: Arc<AtomicBool>,
) {
    let mut interval = HEARTBEAT_INTERVAL;
    loop {
        if let Some(target) = target() {
            match send_heartbeat(&target, vpn_up.load(Ordering::Relaxed)).await {
                Ok(next) if next > 0 => interval = Duration::from_secs(u64::from(next)),
                Ok(_) => {}
                Err(error) => tracing::debug!(%error, "heartbeat failed (best effort)"),
            }
        }
        if tokio::time::timeout(interval, shutdown.cancelled())
            .await
            .is_ok()
        {
            break;
        }
    }
}

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing_and_channel_cache_key_are_stable() {
        set_target_from_config_json(
            r#"{"cluster_endpoint":"http://srv:50051","device_id":"d1","child_id":"c1","family_id":"f1","device_token":"token"}"#,
        );
        let t = target().expect("target");
        assert_eq!(t.device_id, "d1");
        assert_eq!(t.child_id, "c1");
        assert_eq!(t.device_token, "token");
        assert!(shared_channel(&t).is_ok());
        assert!(shared_channel(&t).is_ok());
    }

    #[test]
    fn protected_request_requires_pairing_credential() {
        let t = RelayTarget {
            endpoint: "http://srv".into(),
            device_id: "d".into(),
            ..Default::default()
        };
        assert!(authenticated_request(&t, ()).is_err());
    }

    #[test]
    fn protection_status_is_content_free() {
        let t = RelayTarget {
            device_id: "kids-phone".into(),
            child_id: "c1".into(),
            ..Default::default()
        };
        let status = protection_status(&t, true);
        assert_eq!(status.device_id, "kids-phone");
        assert!(status.vpn_active);
    }
}
