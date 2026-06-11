//! Cluster relay — best-effort, CONTENT-FREE uplink to the enrolled server.
//!
//! Two RPCs, both over the exact transport pattern `fetch_child_config_rpc`
//! already uses (tonic `Endpoint`, bounded connect/request timeouts):
//!
//!   * `AlertRelay.RaiseAlert` — redacted guardian alerts (content verdicts from
//!     the flow consumer, PROTECTION_DISABLED tamper events). Fire-and-forget on
//!     a lazy single-worker runtime so it is callable from raw JNI threads
//!     (`reportTamper`) and never blocks or crashes the caller. The LOCAL alert
//!     queue (`nextAlert`) is always written first — the relay is an addition,
//!     never the only copy.
//!   * `Tamper.Heartbeat` — periodic protection liveness (vpn_active etc.),
//!     spawned on the `startVpn` runtime; the server's missed-heartbeat sweep is
//!     the backstop when this process dies.
//!
//! PRIVACY: everything sent here is category/status only — redacted policy
//! reasons, never message text or media (the AlertEvent invariant).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bulwark_proto::v1::alert_relay_client::AlertRelayClient;
use bulwark_proto::v1::tamper_client::TamperClient;
use bulwark_proto::v1::{AlertEvent, Heartbeat, ProtectionStatus};
use tonic::transport::Endpoint;

/// Where (and as whom) this device reports. Set on every `startVpn` from the
/// Kotlin deviceConfigJson; `None` until the device is enrolled.
#[derive(Clone, Debug, Default)]
pub struct RelayTarget {
    pub endpoint: String,
    pub device_id: String,
    pub child_id: String,
    pub family_id: String,
    /// Path to the pinned cluster CA PEM (`cluster_ca` in the device config —
    /// Kotlin points at `filesDir/cluster_ca.pem`, provisioned at pairing).
    /// REQUIRED for `https://` endpoints: the production regions use an on-box
    /// self-signed CA that public roots will never validate. Empty + https →
    /// the relay stays off (honest: better silent-off than connecting to an
    /// unverified server).
    pub cluster_ca: String,
}

fn target_cell() -> &'static Mutex<Option<RelayTarget>> {
    static T: OnceLock<Mutex<Option<RelayTarget>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(None))
}

/// Parse the enrolled cluster endpoint + identity out of the device-config JSON
/// (`cluster_endpoint` / `device_id` / `child_id` / `family_id`). Malformed or
/// unenrolled input leaves the relay OFF — local alerts still work (fail open).
pub fn set_target_from_config_json(config_json: &str) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return;
    };
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let endpoint = s("cluster_endpoint");
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return; // not enrolled yet (or malformed) -> relay stays off
    }
    let target = RelayTarget {
        endpoint,
        device_id: s("device_id"),
        child_id: s("child_id"),
        family_id: s("family_id"),
        cluster_ca: s("cluster_ca"),
    };
    if let Ok(mut cell) = target_cell().lock() {
        *cell = Some(target);
    }
}

/// The current relay target, if enrolled.
pub fn target() -> Option<RelayTarget> {
    target_cell().lock().ok().and_then(|t| t.clone())
}

/// Lazy single-worker runtime for fire-and-forget RPCs from JNI threads
/// (`reportTamper` has no async context). `None` if it cannot start — the relay
/// is then silently off (local alerts unaffected).
fn relay_runtime() -> Option<&'static tokio::runtime::Runtime> {
    static RT: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .thread_name("bulwark-relay")
            .build()
            .ok()
    })
    .as_ref()
}

fn endpoint_channel(t: &RelayTarget) -> Result<Endpoint, String> {
    let mut ep = Endpoint::from_shared(t.endpoint.to_string())
        .map_err(|_| "relay endpoint is not valid".to_string())?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));
    if t.endpoint
        .trim()
        .to_ascii_lowercase()
        .starts_with("https://")
    {
        // Production regions use an on-box self-signed cluster CA — public
        // webpki roots will never validate it, so the pin is REQUIRED. No pin
        // file on the device → fail here (relay stays off; local alerts +
        // the server's missed-heartbeat sweep remain the coverage).
        let pem = std::fs::read(t.cluster_ca.trim()).map_err(|e| {
            format!(
                "https relay endpoint needs the pinned cluster CA at '{}': {e}",
                t.cluster_ca
            )
        })?;
        let tls = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(pem));
        ep = ep.tls_config(tls).map_err(|e| format!("tls config: {e}"))?;
    }
    Ok(ep)
}

async fn raise_alert(t: RelayTarget, event: AlertEvent) -> Result<(), String> {
    let channel = endpoint_channel(&t)?
        .connect()
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut client = AlertRelayClient::new(channel);
    client
        .raise_alert(event)
        .await
        .map_err(|e| format!("raise_alert: {e}"))?;
    Ok(())
}

/// Best-effort `AlertRelay.RaiseAlert`: fills this device's routing identity,
/// fires on the relay runtime, NEVER blocks the caller, NEVER panics. No-op
/// until enrolled. The local queue copy must already have been written.
pub fn relay_alert_best_effort(mut event: AlertEvent) {
    let Some(t) = target() else { return };
    let Some(rt) = relay_runtime() else { return };
    if event.device_id.is_empty() {
        event.device_id = t.device_id.clone();
    }
    if event.child_id.is_empty() {
        event.child_id = t.child_id.clone();
    }
    if event.family_id.is_empty() {
        event.family_id = t.family_id.clone();
    }
    rt.spawn(async move {
        if let Err(e) = raise_alert(t, event).await {
            // Best-effort by contract: the guardian still has the local copy and
            // the cluster's missed-heartbeat sweep; debug only, never content.
            tracing::debug!(error = %e, "alert relay failed (best-effort)");
        }
    });
}

/// Default heartbeat cadence until the server tunes it via `HeartbeatAck`.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Content-free protection snapshot for this device. `vpn_up` is the live
/// data-path flag startVpn shares (flipped false if the pump exits with an
/// error). device-admin / accessibility booleans are NOT visible from this
/// runtime and are left at the proto default — the server only acts on explicit
/// `tamper_events` (which the Kotlin reports via `reportTamper`), never on
/// these booleans, so no false alerts result.
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
    let channel = endpoint_channel(t)?
        .connect()
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut client = TamperClient::new(channel);
    let hb = Heartbeat {
        status: Some(protection_status(t, vpn_up)),
        // Tamper events reach the cluster via RaiseAlert (reportTamper path);
        // sending them here too would double-alert the guardian.
        tamper_events: Vec::new(),
    };
    let ack = client
        .heartbeat(hb)
        .await
        .map_err(|e| format!("heartbeat: {e}"))?
        .into_inner();
    Ok(ack.next_interval_secs)
}

/// Periodic `Tamper.Heartbeat` until `shutdown` is cancelled. Spawned by
/// `startVpn` on the VPN runtime (the ONE heartbeat owner — no Kotlin copy).
/// Failures only log; the server's missed-heartbeat sweep covers a dead device.
pub async fn run_heartbeats(
    shutdown: bulwark_net::vpn::CancellationToken,
    vpn_up: Arc<AtomicBool>,
) {
    let mut interval = HEARTBEAT_INTERVAL;
    loop {
        if let Some(t) = target() {
            match send_heartbeat(&t, vpn_up.load(Ordering::Relaxed)).await {
                Ok(next_secs) if next_secs > 0 => {
                    interval = Duration::from_secs(u64::from(next_secs));
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "heartbeat failed (best-effort)"),
            }
        }
        // Sleep `interval`, exiting promptly on shutdown (no tokio::select! to
        // keep the dep features minimal: timeout(_, cancelled()) == cancelled).
        if tokio::time::timeout(interval, shutdown.cancelled())
            .await
            .is_ok()
        {
            break;
        }
    }
    tracing::info!("heartbeats stopped (VPN session shut down)");
}

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_target_parses_only_enrolled_configs() {
        set_target_from_config_json(r#"{"device_id":"d0"}"#); // no endpoint
        assert!(target().is_none());
        set_target_from_config_json(r#"{"cluster_endpoint":"not-a-url","device_id":"d0"}"#);
        assert!(target().is_none());

        set_target_from_config_json(
            r#"{"cluster_endpoint":"http://srv:50051","device_id":"d1","child_id":"c1","family_id":"f1","profile":"TEEN"}"#,
        );
        let t = target().expect("enrolled config sets the target");
        assert_eq!(t.endpoint, "http://srv:50051");
        assert_eq!(t.device_id, "d1");
        assert_eq!(t.child_id, "c1");
        assert_eq!(t.family_id, "f1");
    }

    #[test]
    fn protection_status_is_content_free_android() {
        let t = RelayTarget {
            endpoint: "http://srv".into(),
            device_id: "kids-phone".into(),
            child_id: "c1".into(),
            family_id: "f1".into(),
            cluster_ca: String::new(),
        };
        let s = protection_status(&t, true);
        assert_eq!(s.device_id, "kids-phone");
        assert_eq!(s.child_id, "c1");
        assert!(s.vpn_active);
        assert_eq!(s.platform, "android");
        assert!(s.ts > 0);

        let down = protection_status(&t, false);
        assert!(!down.vpn_active, "a dead pump must not claim vpn_active");
    }
}
