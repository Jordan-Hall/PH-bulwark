//! Child-side tamper / protection heartbeat reporter.
//!
//! The supervised child app periodically tells the cluster it is alive and what
//! protections are active ([`ProtectionStatus`]), plus any tamper events it saw
//! (e.g. an uninstall attempt). The cluster turns a downgrade — or the ABSENCE
//! of heartbeats (app killed / removed) — into a guardian `PROTECTION_DISABLED`
//! alert. This is the cross-platform safety net: even where removal can't be
//! prevented, it's detected.
//!
//! Reporting is best-effort: a failure NEVER affects filtering (the cluster's
//! missed-heartbeat sweep is the backstop). Carries no content — status only.

use std::time::Duration;

use aegis_proto::v1::tamper_client::TamperClient;
use aegis_proto::v1::{Heartbeat, ProtectionStatus, TamperKind};

/// Platform hook reporting the child device's protection state + tamper events.
///
/// Desktop builds report the running proxy/service as the active protection (if
/// it dies, heartbeats stop and the cluster raises a missed-heartbeat alert). The
/// Android shell wires real signals: VpnService up, device-admin active,
/// accessibility enabled, and uninstall attempts seen by the uninstall-guard.
pub trait ProtectionProbe: Send + Sync {
    /// Current protection snapshot.
    fn status(&mut self) -> ProtectionStatus;
    /// Tamper events observed since the last call (drained). Default: none.
    fn drain_tamper_events(&mut self) -> Vec<TamperKind> {
        Vec::new()
    }
}

/// Minimal probe for the desktop proxy: the running filter IS the protection.
pub struct DesktopProbe {
    pub device_id: String,
    pub app_version: String,
}

impl ProtectionProbe for DesktopProbe {
    fn status(&mut self) -> ProtectionStatus {
        ProtectionStatus {
            device_id: self.device_id.clone(),
            platform: std::env::consts::OS.to_string(),
            vpn_active: true,
            app_version: self.app_version.clone(),
            ts: now_ms(),
            ..Default::default()
        }
    }
}

/// Build a [`Heartbeat`] from a probe (snapshot status + drain tamper events).
pub fn build_heartbeat(probe: &mut dyn ProtectionProbe) -> Heartbeat {
    let status = probe.status();
    let tamper_events = probe
        .drain_tamper_events()
        .into_iter()
        .map(|k| k as i32)
        .collect();
    Heartbeat {
        status: Some(status),
        tamper_events,
    }
}

/// Periodically send heartbeats to the cluster `Tamper` service until the process
/// exits. Reconnects on error and honours the server-suggested cadence. Spawn it
/// as a background task alongside the filtering loop.
pub async fn run_heartbeats(
    endpoint: String,
    mut probe: Box<dyn ProtectionProbe>,
    initial_interval: Duration,
) {
    let mut interval = initial_interval;
    loop {
        match TamperClient::connect(endpoint.clone()).await {
            Ok(mut client) => loop {
                let hb = build_heartbeat(probe.as_mut());
                match client.heartbeat(hb).await {
                    Ok(ack) => {
                        let secs = ack.into_inner().next_interval_secs;
                        if secs > 0 {
                            interval = Duration::from_secs(secs as u64);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "tamper heartbeat failed; will reconnect");
                        break;
                    }
                }
                tokio::time::sleep(interval).await;
            },
            Err(e) => tracing::warn!(error = %e, "tamper: connect failed; retrying"),
        }
        tokio::time::sleep(interval).await;
    }
}

fn now_ms() -> i64 {
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
    fn desktop_probe_reports_active_protection() {
        let mut p = DesktopProbe {
            device_id: "kids-pc".into(),
            app_version: "0.0.0".into(),
        };
        let hb = build_heartbeat(&mut p);
        let s = hb.status.expect("status");
        assert_eq!(s.device_id, "kids-pc");
        assert!(s.vpn_active);
        assert!(hb.tamper_events.is_empty(), "no tamper on a healthy beat");
    }

    #[test]
    fn probe_tamper_events_ride_the_heartbeat_and_drain() {
        struct UninstallOnce(bool);
        impl ProtectionProbe for UninstallOnce {
            fn status(&mut self) -> ProtectionStatus {
                ProtectionStatus {
                    device_id: "kids-phone".into(),
                    ..Default::default()
                }
            }
            fn drain_tamper_events(&mut self) -> Vec<TamperKind> {
                if self.0 {
                    self.0 = false;
                    vec![TamperKind::AppUninstallAttempt]
                } else {
                    Vec::new()
                }
            }
        }
        let mut p = UninstallOnce(true);
        let first = build_heartbeat(&mut p);
        assert_eq!(
            first.tamper_events,
            vec![TamperKind::AppUninstallAttempt as i32]
        );
        // Drained: the next beat is clean.
        let second = build_heartbeat(&mut p);
        assert!(second.tamper_events.is_empty());
    }
}
