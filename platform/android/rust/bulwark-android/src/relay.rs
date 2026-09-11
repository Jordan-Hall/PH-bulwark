//! Authenticated Android uplink plus Remote VPN provisioning/lease renewal.
//!
//! Local VPN uses Analysis/AlertRelay over one cached HTTP/2 channel. Remote VPN
//! keeps the phone transport-only: a persistent device WireGuard identity is
//! authenticated with the pairing credential once, then a short-lived region-
//! signed VPN lease is renewed off the data hot path. Lease revocation/expiry
//! cancels the tunnel; it never silently falls back to an unfiltered route.

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
#[cfg(target_os = "android")]
use bulwark_proto::v1::wg_provision_client::WgProvisionClient;
#[cfg(target_os = "android")]
use bulwark_proto::v1::{RegisterWgPeerRequest, WgPeerGrant};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

const DEVICE_ID_HEADER: &str = "x-bulwark-device-id";
const DEVICE_TOKEN_HEADER: &str = "x-bulwark-device-token";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(target_os = "android")]
const INSPECTION_CA_BIN_HEADER: &str = "x-bulwark-inspection-ca-bin";
#[cfg(target_os = "android")]
const INSPECTION_CA_SHA256_HEADER: &str = "x-bulwark-inspection-ca-sha256";
#[cfg(target_os = "android")]
const VPN_SESSION_HEADER: &str = "x-bulwark-vpn-session";
#[cfg(target_os = "android")]
const VPN_SESSION_EXPIRES_HEADER: &str = "x-bulwark-vpn-session-expires-ms";
#[cfg(target_os = "android")]
const VPN_SESSION_RENEW_HEADER: &str = "x-bulwark-vpn-renew-after-ms";
#[cfg(target_os = "android")]
const LEASE_RETRY: Duration = Duration::from_secs(10);

/// Where, and as whom, this enrolled child device talks to the control plane.
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

/// Install/refresh the enrolled control-plane target from the VPN config JSON.
pub fn set_target_from_config_json(config_json: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return;
    };
    let field = |name: &str| {
        value
            .get(name)
            .and_then(|value| value.as_str())
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
        let channel_changed = current
            .as_ref()
            .map(|old| old.endpoint != next.endpoint || old.cluster_ca != next.cluster_ca)
            .unwrap_or(true);
        *current = Some(next);
        if channel_changed {
            if let Ok(mut cache) = channel_cell().lock() {
                *cache = None;
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

fn endpoint(target: &RelayTarget) -> Result<Endpoint, String> {
    let mut endpoint = Endpoint::from_shared(target.endpoint.clone())
        .map_err(|_| "relay endpoint is not valid".to_string())?
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(4))
        .tcp_nodelay(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(5));

    if target.endpoint.to_ascii_lowercase().starts_with("https://") {
        let pinned = if target.cluster_ca.trim().is_empty() {
            None
        } else {
            match std::fs::read(target.cluster_ca.trim()) {
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

fn shared_channel(target: &RelayTarget) -> Result<Channel, String> {
    let key = format!("{}\u{0}{}", target.endpoint, target.cluster_ca);
    if let Ok(cache) = channel_cell().lock() {
        if let Some(cached) = cache.as_ref().filter(|cached| cached.key == key) {
            return Ok(cached.channel.clone());
        }
    }
    let channel = endpoint(target)?.connect_lazy();
    if let Ok(mut cache) = channel_cell().lock() {
        *cache = Some(CachedChannel {
            key,
            channel: channel.clone(),
        });
    }
    Ok(channel)
}

fn authenticated_request<T>(target: &RelayTarget, message: T) -> Result<Request<T>, String> {
    if target.device_id.trim().is_empty() || target.device_token.trim().is_empty() {
        return Err("device enrollment credential is missing; re-pair this device".to_string());
    }
    let mut request = Request::new(message);
    let device_id = MetadataValue::try_from(target.device_id.as_str())
        .map_err(|_| "device id cannot be encoded as gRPC metadata".to_string())?;
    let device_token = MetadataValue::try_from(target.device_token.as_str())
        .map_err(|_| "device token cannot be encoded as gRPC metadata".to_string())?;
    request.metadata_mut().insert(DEVICE_ID_HEADER, device_id);
    request
        .metadata_mut()
        .insert(DEVICE_TOKEN_HEADER, device_token);
    Ok(request)
}

/// Score one protected media object over the reused cluster channel.
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
    let mut client = AnalysisClient::new(shared_channel(&target)?);
    let request = authenticated_request(
        &target,
        AnalysisRequest {
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
        },
    )?;
    tokio::time::timeout(
        Duration::from_millis(u64::from(deadline_ms.max(250))),
        client.analyze(request),
    )
    .await
    .map_err(|_| "media analysis deadline exceeded".to_string())?
    .map_err(|status| format!("media analysis failed: {}", status.code()))
    .map(|response| response.into_inner())
}

async fn raise_alert(target: RelayTarget, event: AlertEvent) -> Result<(), String> {
    let mut client = AlertRelayClient::new(shared_channel(&target)?);
    let request = authenticated_request(&target, event)?;
    tokio::time::timeout(Duration::from_secs(2), client.raise_alert(request))
        .await
        .map_err(|_| "raise_alert timed out".to_string())?
        .map_err(|status| format!("raise_alert: {}", status.code()))?;
    Ok(())
}

/// Best-effort remote copy of a redacted guardian alert.
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

/// Content-free protection snapshot for liveness/tamper monitoring.
pub fn protection_status(target: &RelayTarget, vpn_up: bool) -> ProtectionStatus {
    ProtectionStatus {
        device_id: target.device_id.clone(),
        child_id: target.child_id.clone(),
        vpn_active: vpn_up,
        platform: "android".to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        ts: now_ms(),
        ..Default::default()
    }
}

async fn send_heartbeat(target: &RelayTarget, vpn_up: bool) -> Result<u32, String> {
    let mut client = TamperClient::new(shared_channel(target)?);
    let ack = tokio::time::timeout(
        Duration::from_secs(3),
        client.heartbeat(Heartbeat {
            status: Some(protection_status(target, vpn_up)),
            tamper_events: Vec::new(),
            device_token: target.device_token.clone(),
        }),
    )
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

// ---------------------------------------------------------------------------
// Remote VPN: persistent device key + short-lived authenticated lease.
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
#[derive(Clone)]
struct PreparedServerVpn {
    provision_target: RelayTarget,
    device_id: String,
    wg_public_key: String,
    keypair: bulwark_net::vpn::wg::WgKeypair,
    grant: WgPeerGrant,
    session_token: String,
    session_expires_ms: i64,
    renew_after_ms: u64,
    inspection_ca_sha256: String,
}

#[cfg(target_os = "android")]
struct ProvisionedLease {
    grant: WgPeerGrant,
    session_token: String,
    session_expires_ms: i64,
    renew_after_ms: u64,
    inspection_ca_pem: String,
    inspection_ca_sha256: String,
}

#[cfg(target_os = "android")]
#[derive(Debug)]
struct RemoteRpcError {
    code: tonic::Code,
    detail: String,
}

#[cfg(target_os = "android")]
impl std::fmt::Display for RemoteRpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

#[cfg(target_os = "android")]
fn prepared_server_vpn_cell() -> &'static Mutex<Option<PreparedServerVpn>> {
    static PREPARED: OnceLock<Mutex<Option<PreparedServerVpn>>> = OnceLock::new();
    PREPARED.get_or_init(|| Mutex::new(None))
}

#[cfg(target_os = "android")]
fn error_json(message: impl AsRef<str>) -> String {
    serde_json::json!({"ok": false, "error": message.as_ref()}).to_string()
}

#[cfg(target_os = "android")]
fn ensure_private_dir(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)
        .map_err(|error| format!("creating Remote VPN state directory: {error}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protecting Remote VPN state directory: {error}"))
}

#[cfg(target_os = "android")]
fn load_or_create_server_vpn_keypair(
    state_dir: &std::path::Path,
) -> Result<bulwark_net::vpn::wg::WgKeypair, String> {
    use rand_core::{OsRng, RngCore};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    ensure_private_dir(state_dir)?;
    let path = state_dir.join("wireguard.key");
    let read_existing = || -> Result<bulwark_net::vpn::wg::WgKeypair, String> {
        let bytes = std::fs::read(&path)
            .map_err(|error| format!("reading Remote VPN device key: {error}"))?;
        let private: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Remote VPN device key has an invalid length".to_string())?;
        Ok(bulwark_net::vpn::wg::WgKeypair::from_private_bytes(private))
    };

    match std::fs::metadata(&path) {
        Ok(_) => return read_existing(),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("checking Remote VPN device key: {error}"));
        }
        Err(_) => {}
    }

    let mut private = [0u8; 32];
    OsRng.fill_bytes(&mut private);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(&private)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("persisting Remote VPN device key: {error}"))?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("protecting Remote VPN device key: {error}"))?;
            Ok(bulwark_net::vpn::wg::WgKeypair::from_private_bytes(private))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_existing(),
        Err(error) => Err(format!("creating Remote VPN device key: {error}")),
    }
}

#[cfg(target_os = "android")]
fn metadata_i64<T>(response: &tonic::Response<T>, name: &'static str) -> Result<i64, String> {
    response
        .metadata()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| format!("server omitted required {name} metadata"))
}

#[cfg(target_os = "android")]
async fn register_remote_peer(
    target: &RelayTarget,
    wg_public_key: &str,
    session_token: Option<&str>,
) -> Result<ProvisionedLease, RemoteRpcError> {
    let channel = endpoint(target)
        .map_err(|detail| RemoteRpcError {
            code: tonic::Code::Unavailable,
            detail,
        })?
        .connect()
        .await
        .map_err(|error| RemoteRpcError {
            code: tonic::Code::Unavailable,
            detail: format!("could not reach Remote VPN provisioner: {error}"),
        })?;
    let mut client = WgProvisionClient::new(channel);
    let mut request = Request::new(RegisterWgPeerRequest {
        device_id: target.device_id.clone(),
        device_token: if session_token.is_some() {
            String::new()
        } else {
            target.device_token.clone()
        },
        wg_public_key: wg_public_key.to_string(),
    });
    if let Some(token) = session_token {
        let value = MetadataValue::try_from(token).map_err(|_| RemoteRpcError {
            code: tonic::Code::Unauthenticated,
            detail: "Remote VPN lease token could not be encoded".to_string(),
        })?;
        request.metadata_mut().insert(VPN_SESSION_HEADER, value);
    }

    let response = tokio::time::timeout(Duration::from_secs(8), client.register_wg_peer(request))
        .await
        .map_err(|_| RemoteRpcError {
            code: tonic::Code::DeadlineExceeded,
            detail: "Remote VPN provisioning timed out".to_string(),
        })?
        .map_err(|status| RemoteRpcError {
            code: status.code(),
            detail: match status.code() {
                tonic::Code::Unauthenticated => {
                    "Remote VPN authentication was rejected; re-pair or re-authenticate this device"
                        .to_string()
                }
                tonic::Code::PermissionDenied => {
                    "the guardian no longer authorizes Remote VPN for this device".to_string()
                }
                tonic::Code::FailedPrecondition => {
                    "the selected region is not ready for authenticated Remote VPN".to_string()
                }
                _ => format!("Remote VPN provisioning failed: {}", status.code()),
            },
        })?;

    let inspection_ca = response
        .metadata()
        .get_bin(INSPECTION_CA_BIN_HEADER)
        .ok_or_else(|| RemoteRpcError {
            code: tonic::Code::FailedPrecondition,
            detail: "server did not supply its inspection CA".to_string(),
        })?
        .to_bytes()
        .map_err(|_| RemoteRpcError {
            code: tonic::Code::DataLoss,
            detail: "server inspection CA metadata was invalid".to_string(),
        })?
        .to_vec();
    let inspection_ca_pem = String::from_utf8(inspection_ca).map_err(|_| RemoteRpcError {
        code: tonic::Code::DataLoss,
        detail: "server inspection CA was not PEM text".to_string(),
    })?;
    if !inspection_ca_pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(RemoteRpcError {
            code: tonic::Code::DataLoss,
            detail: "server inspection CA is not a certificate PEM".to_string(),
        });
    }
    let inspection_ca_sha256 = response
        .metadata()
        .get(INSPECTION_CA_SHA256_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let session_token = response
        .metadata()
        .get(VPN_SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RemoteRpcError {
            code: tonic::Code::Unauthenticated,
            detail: "server did not mint a Remote VPN lease".to_string(),
        })?
        .to_string();
    let session_expires_ms = metadata_i64(&response, VPN_SESSION_EXPIRES_HEADER).map_err(|detail| {
        RemoteRpcError {
            code: tonic::Code::DataLoss,
            detail,
        }
    })?;
    let renew_after_ms = metadata_i64(&response, VPN_SESSION_RENEW_HEADER)
        .map_err(|detail| RemoteRpcError {
            code: tonic::Code::DataLoss,
            detail,
        })?
        .max(1) as u64;

    let grant = response.into_inner();
    if !grant.filter_active {
        return Err(RemoteRpcError {
            code: tonic::Code::FailedPrecondition,
            detail: "region did not confirm active server-side filtering".to_string(),
        });
    }
    Ok(ProvisionedLease {
        grant,
        session_token,
        session_expires_ms,
        renew_after_ms,
        inspection_ca_pem,
        inspection_ca_sha256,
    })
}

#[cfg(target_os = "android")]
async fn prepare_server_vpn_rpc(
    target: RelayTarget,
    state_dir: std::path::PathBuf,
) -> Result<String, String> {
    if target.device_id.trim().is_empty() || target.device_token.trim().is_empty() {
        return Err("this device is not paired with the server".to_string());
    }
    let keypair = load_or_create_server_vpn_keypair(&state_dir)?;
    let wg_public_key = data_encoding::BASE64.encode(keypair.public_key().as_bytes());
    let provisioned = register_remote_peer(&target, &wg_public_key, None)
        .await
        .map_err(|error| error.detail)?;
    let _ = wg_config_from_parts(&provisioned.grant, keypair.clone())?;

    if let Ok(mut prepared) = prepared_server_vpn_cell().lock() {
        *prepared = Some(PreparedServerVpn {
            provision_target: target.clone(),
            device_id: target.device_id.clone(),
            wg_public_key,
            keypair,
            grant: provisioned.grant.clone(),
            session_token: provisioned.session_token.clone(),
            session_expires_ms: provisioned.session_expires_ms,
            renew_after_ms: provisioned.renew_after_ms,
            inspection_ca_sha256: provisioned.inspection_ca_sha256.clone(),
        });
    }

    Ok(serde_json::json!({
        "ok": true,
        "filter_active": true,
        "assigned_address": provisioned.grant.assigned_address,
        "server_endpoint": provisioned.grant.server_endpoint,
        "keepalive_secs": provisioned.grant.keepalive_secs,
        "inspection_ca_pem": provisioned.inspection_ca_pem,
        "inspection_ca_sha256": provisioned.inspection_ca_sha256,
        "session_expires_ts": provisioned.session_expires_ms,
        "renew_after_ms": provisioned.renew_after_ms,
        "authentication": "device-bound rotating lease"
    })
    .to_string())
}

#[cfg(target_os = "android")]
fn wg_config_from_parts(
    grant: &WgPeerGrant,
    keypair: bulwark_net::vpn::wg::WgKeypair,
) -> Result<bulwark_net::vpn::wg::WgClientConfig, String> {
    let server_key = data_encoding::BASE64
        .decode(grant.server_public_key.trim().as_bytes())
        .map_err(|_| "server returned an invalid WireGuard public key".to_string())?;
    let server_key: [u8; 32] = server_key
        .try_into()
        .map_err(|_| "server WireGuard public key must be 32 bytes".to_string())?;
    let server_public_key = boringtun::x25519::PublicKey::from(server_key);
    let assigned_address = grant
        .assigned_address
        .trim()
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "server returned an invalid tunnel address".to_string())?;
    if grant.server_endpoint.trim().is_empty() {
        return Err("server returned no WireGuard endpoint".to_string());
    }
    let mut config = bulwark_net::vpn::wg::WgClientConfig::new(
        server_public_key,
        keypair,
        assigned_address,
    );
    config.server_endpoint = grant.server_endpoint.trim().to_string();
    config.persistent_keepalive_secs = u16::try_from(grant.keepalive_secs)
        .ok()
        .filter(|value| *value > 0)
        .or(Some(bulwark_net::vpn::wg::DEFAULT_KEEPALIVE_SECS));
    Ok(config)
}

#[cfg(target_os = "android")]
async fn run_server_vpn_data_path(
    tun_fd: std::os::fd::RawFd,
    config: bulwark_net::vpn::wg::WgClientConfig,
    shutdown: bulwark_net::vpn::CancellationToken,
) -> Result<(), String> {
    use bulwark_net::TunDevice;

    let tun: Arc<dyn TunDevice> = Arc::from(
        bulwark_net::open_tun_from_fd(tun_fd)
            .map_err(|error| format!("opening Android VPN fd: {error}"))?,
    );
    let poll_fd = tun
        .as_raw_fd()
        .ok_or_else(|| "Android VPN fd is not pollable".to_string())?;
    let (channels, mut pump) =
        bulwark_net::vpn::transport::run_server_filter_egress_gated(
            config,
            true,
            shutdown.clone(),
        )
        .map_err(|error| error.to_string())?;
    let failure = Arc::new(Mutex::new(None::<String>));

    let outbound_tun = tun.clone();
    let outbound_shutdown = shutdown.clone();
    let outbound_failure = failure.clone();
    let to_region = channels.to_region;
    let outbound = tokio::task::spawn_blocking(move || {
        let mut packet = vec![0u8; 65_535];
        while !outbound_shutdown.is_cancelled() {
            let mut pfd = libc::pollfd {
                fd: poll_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, 100) };
            if rc < 0 {
                if let Ok(mut slot) = outbound_failure.lock() {
                    *slot = Some(format!(
                        "polling Android VPN fd: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                outbound_shutdown.cancel();
                break;
            }
            if rc == 0 || (pfd.revents & libc::POLLIN) == 0 {
                continue;
            }
            match outbound_tun.recv(&mut packet) {
                Ok(0) => {}
                Ok(size) => {
                    if to_region.blocking_send(packet[..size].to_vec()).is_err() {
                        if !outbound_shutdown.is_cancelled() {
                            if let Ok(mut slot) = outbound_failure.lock() {
                                *slot = Some("WireGuard transport stopped accepting packets".into());
                            }
                            outbound_shutdown.cancel();
                        }
                        break;
                    }
                }
                Err(error) => {
                    if let Ok(mut slot) = outbound_failure.lock() {
                        *slot = Some(format!("reading Android VPN fd: {error}"));
                    }
                    outbound_shutdown.cancel();
                    break;
                }
            }
        }
    });

    let inbound_tun = tun.clone();
    let inbound_shutdown = shutdown.clone();
    let inbound_failure = failure.clone();
    let mut from_region = channels.from_region;
    let inbound = tokio::task::spawn_blocking(move || {
        while !inbound_shutdown.is_cancelled() {
            let Some(packet) = from_region.blocking_recv() else {
                if !inbound_shutdown.is_cancelled() {
                    if let Ok(mut slot) = inbound_failure.lock() {
                        *slot = Some("WireGuard return path closed".into());
                    }
                    inbound_shutdown.cancel();
                }
                break;
            };
            if let Err(error) = inbound_tun.send(&packet) {
                if let Ok(mut slot) = inbound_failure.lock() {
                    *slot = Some(format!("writing Android VPN fd: {error}"));
                }
                inbound_shutdown.cancel();
                break;
            }
        }
    });

    tokio::select! {
        _ = shutdown.cancelled() => {}
        result = &mut pump => {
            match result {
                Ok(Ok(())) if shutdown.is_cancelled() => {}
                Ok(Ok(())) => {
                    if let Ok(mut slot) = failure.lock() {
                        *slot = Some("WireGuard transport stopped unexpectedly".into());
                    }
                }
                Ok(Err(error)) => {
                    if let Ok(mut slot) = failure.lock() {
                        *slot = Some(format!("WireGuard transport failed: {error}"));
                    }
                }
                Err(error) => {
                    if let Ok(mut slot) = failure.lock() {
                        *slot = Some(format!("WireGuard transport task failed: {error}"));
                    }
                }
            }
            shutdown.cancel();
        }
    }

    outbound.abort();
    inbound.abort();
    failure
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .map_or(Ok(()), Err)
}

#[cfg(target_os = "android")]
fn remote_lease_failed(
    detail: &str,
    shutdown: &bulwark_net::vpn::CancellationToken,
    vpn_up: &Arc<AtomicBool>,
) {
    vpn_up.store(false, Ordering::Relaxed);
    crate::data_path_down().store(true, Ordering::Relaxed);
    tracing::error!(%detail, "Remote VPN authentication lease ended");
    crate::enqueue_protection_alert(
        "remote-vpn-auth",
        "The authenticated Remote VPN session ended or was revoked. The tunnel was stopped rather than allowing unfiltered traffic.",
    );
    shutdown.cancel();
}

#[cfg(target_os = "android")]
async fn run_remote_lease_renewal(
    prepared: PreparedServerVpn,
    shutdown: bulwark_net::vpn::CancellationToken,
    vpn_up: Arc<AtomicBool>,
) {
    let mut session_token = prepared.session_token.clone();
    let mut expires_ms = prepared.session_expires_ms;
    let mut next_wait = Duration::from_millis(prepared.renew_after_ms.max(1));

    loop {
        if expires_ms <= now_ms() {
            remote_lease_failed("Remote VPN lease expired", &shutdown, &vpn_up);
            return;
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(next_wait) => {}
        }

        match register_remote_peer(
            &prepared.provision_target,
            &prepared.wg_public_key,
            Some(&session_token),
        )
        .await
        {
            Ok(renewed) => {
                if renewed.grant.assigned_address != prepared.grant.assigned_address
                    || renewed.grant.server_public_key != prepared.grant.server_public_key
                    || renewed.grant.server_endpoint != prepared.grant.server_endpoint
                    || renewed.inspection_ca_sha256 != prepared.inspection_ca_sha256
                {
                    remote_lease_failed(
                        "Remote VPN identity changed during renewal; clean restart required",
                        &shutdown,
                        &vpn_up,
                    );
                    return;
                }
                session_token = renewed.session_token;
                expires_ms = renewed.session_expires_ms;
                next_wait = Duration::from_millis(renewed.renew_after_ms.max(1));
                tracing::debug!(expires_ms, "Remote VPN authentication lease renewed");
            }
            Err(error)
                if matches!(
                    error.code,
                    tonic::Code::Unauthenticated
                        | tonic::Code::PermissionDenied
                        | tonic::Code::FailedPrecondition
                ) =>
            {
                remote_lease_failed(&error.detail, &shutdown, &vpn_up);
                return;
            }
            Err(error) => {
                let remaining = expires_ms.saturating_sub(now_ms());
                if remaining <= 0 {
                    remote_lease_failed(&error.detail, &shutdown, &vpn_up);
                    return;
                }
                tracing::warn!(
                    error = %error,
                    remaining_ms = remaining,
                    "Remote VPN lease renewal transiently failed; retrying before expiry"
                );
                next_wait = LEASE_RETRY.min(Duration::from_millis(remaining as u64));
            }
        }
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_prepareServerVpn(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    endpoint_value: jni::objects::JString,
    device_id_value: jni::objects::JString,
    ca_path_value: jni::objects::JString,
    device_token_value: jni::objects::JString,
    state_dir_value: jni::objects::JString,
) -> jni::sys::jstring {
    crate::init_logging();
    let endpoint_value = crate::jstring_to_string(&mut env, &endpoint_value).unwrap_or_default();
    let device_id = crate::jstring_to_string(&mut env, &device_id_value).unwrap_or_default();
    let cluster_ca = crate::jstring_to_string(&mut env, &ca_path_value).unwrap_or_default();
    let device_token = crate::jstring_to_string(&mut env, &device_token_value).unwrap_or_default();
    let state_dir = crate::jstring_to_string(&mut env, &state_dir_value).unwrap_or_default();
    if state_dir.trim().is_empty() {
        return crate::string_to_jstring(
            &mut env,
            &error_json("Remote VPN state directory is missing"),
        );
    }
    let target = RelayTarget {
        endpoint: endpoint_value,
        device_id,
        cluster_ca,
        device_token,
        ..Default::default()
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => return crate::string_to_jstring(&mut env, &error_json(error.to_string())),
    };
    let json = match runtime.block_on(prepare_server_vpn_rpc(
        target,
        std::path::PathBuf::from(state_dir.trim()),
    )) {
        Ok(json) => json,
        Err(error) => error_json(error),
    };
    crate::string_to_jstring(&mut env, &json)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_startServerVpn(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    vpn_service: jni::objects::JObject,
    tun_fd: jni::sys::jint,
    config_json: jni::objects::JString,
) -> jni::sys::jlong {
    crate::init_logging();
    let config = crate::jstring_to_string(&mut env, &config_json).unwrap_or_default();
    crate::apply_profile_from_config_json(&config);
    set_target_from_config_json(&config);
    let Some(control_target) = target() else {
        return 0;
    };
    let prepared = prepared_server_vpn_cell()
        .lock()
        .ok()
        .and_then(|mut prepared| prepared.take());
    let Some(prepared) = prepared else {
        tracing::error!("Remote VPN was not authenticated/provisioned before start");
        return 0;
    };
    if prepared.device_id != control_target.device_id || prepared.session_expires_ms <= now_ms() {
        tracing::error!("Remote VPN lease does not match this device or is already expired");
        return 0;
    }
    let wg_config = match wg_config_from_parts(&prepared.grant, prepared.keypair.clone()) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "invalid Remote VPN grant");
            return 0;
        }
    };

    let vpn_service = if vpn_service.is_null() {
        None
    } else {
        env.new_global_ref(vpn_service).ok()
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(3)
        .thread_name("bulwark-remote-vpn")
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return 0,
    };
    let shutdown = bulwark_net::vpn::CancellationToken::new();
    crate::data_path_down().store(false, Ordering::Relaxed);
    let vpn_up = Arc::new(AtomicBool::new(true));
    runtime.spawn(run_heartbeats(shutdown.clone(), vpn_up.clone()));
    runtime.spawn(run_remote_lease_renewal(
        prepared.clone(),
        shutdown.clone(),
        vpn_up.clone(),
    ));

    let token = shutdown.clone();
    runtime.spawn(async move {
        if let Err(error) = run_server_vpn_data_path(
            tun_fd as std::os::fd::RawFd,
            wg_config,
            token,
        )
        .await
        {
            vpn_up.store(false, Ordering::Relaxed);
            crate::data_path_down().store(true, Ordering::Relaxed);
            tracing::error!(%error, "Remote VPN data path stopped");
            crate::enqueue_protection_alert(
                "remote-vpn-down",
                "The protected Remote VPN stopped unexpectedly. Traffic was not failed over to an unfiltered path.",
            );
        }
    });

    let session = Box::new(crate::VpnSession {
        runtime,
        shutdown,
        _vpn_service: vpn_service,
    });
    Box::into_raw(session) as jni::sys::jlong
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing_and_channel_cache_key_are_stable() {
        set_target_from_config_json(
            r#"{"cluster_endpoint":"http://srv:50051","device_id":"d1","child_id":"c1","family_id":"f1","device_token":"token"}"#,
        );
        let target = target().expect("target");
        assert_eq!(target.device_id, "d1");
        assert_eq!(target.child_id, "c1");
        assert_eq!(target.device_token, "token");
        assert!(shared_channel(&target).is_ok());
        assert!(shared_channel(&target).is_ok());
    }

    #[test]
    fn protected_request_requires_pairing_credential() {
        let target = RelayTarget {
            endpoint: "http://srv".into(),
            device_id: "d".into(),
            ..Default::default()
        };
        assert!(authenticated_request(&target, ()).is_err());
    }

    #[test]
    fn protection_status_is_content_free() {
        let target = RelayTarget {
            device_id: "kids-phone".into(),
            child_id: "c1".into(),
            ..Default::default()
        };
        let status = protection_status(&target, true);
        assert_eq!(status.device_id, "kids-phone");
        assert!(status.vpn_active);
    }
}
