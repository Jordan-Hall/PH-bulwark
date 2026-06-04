//! Tamper service — child-device protection liveness + uninstall/disable alerts.
//!
//! The supervised child app sends periodic [`Heartbeat`]s carrying its
//! [`ProtectionStatus`]. Two things raise a guardian
//! `AlertEvent(kind = PROTECTION_DISABLED)`, fanned out through the shared
//! [`AlertHub`] (so it reaches the same guardian Review streams as every other
//! alert, scoped per child/device):
//!
//!   1. **Self-reported tamper events** — the child detected a downgrade
//!      (accessibility/VPN/device-admin turned off, or an app-removal attempt).
//!   2. **Missed heartbeats** — the device stopped checking in (app killed,
//!      offline, or uninstalled). Detected server-side by the liveness sweeper.
//!
//! This is the cross-platform safety net: even where removal can't be PREVENTED
//! (iOS, un-managed Android), it is DETECTED and reported. Carries NO content —
//! only status signals + a human-readable, redacted description.
//!
//! State is in-memory (a per-device liveness map); a clone shares it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aegis_proto::v1::{
    tamper_server::Tamper, AlertEvent, AlertKind, Category, Heartbeat, HeartbeatAck,
    ProtectionStatus, Severity, TamperKind,
};
use tonic::{Request, Response, Status};

use crate::relay::AlertHub;

/// Cadence (seconds) the server asks child devices to heartbeat at.
pub const DEFAULT_HEARTBEAT_SECS: u32 = 120;
/// How long without a heartbeat before a device is considered offline/removed
/// and a `HEARTBEAT_MISSED` alert fires. ~3 missed beats, in millis.
pub const DEFAULT_GRACE_MS: i64 = 3 * DEFAULT_HEARTBEAT_SECS as i64 * 1000;

/// What the server remembers about one child device's protection liveness.
struct DeviceLiveness {
    last_seen_ms: i64,
    platform: String,
    /// Debounce: once we've alerted that this device went silent, don't re-alert
    /// every sweep — only again after it checks back in and lapses anew.
    overdue_alerted: bool,
}

/// Shared, cloneable child-device protection tracker. Clone freely — clones share
/// the same liveness map and [`AlertHub`].
#[derive(Clone)]
pub struct TamperService {
    hub: AlertHub,
    liveness: Arc<Mutex<HashMap<String, DeviceLiveness>>>,
    grace_ms: i64,
}

impl TamperService {
    /// Track liveness and publish tamper alerts into `hub`.
    pub fn new(hub: AlertHub) -> Self {
        Self {
            hub,
            liveness: Arc::new(Mutex::new(HashMap::new())),
            grace_ms: DEFAULT_GRACE_MS,
        }
    }

    /// Override the missed-heartbeat grace window (tests / tuning).
    pub fn with_grace_ms(mut self, grace_ms: i64) -> Self {
        self.grace_ms = grace_ms;
        self
    }

    /// Record a heartbeat at `now_ms` and return the guardian alerts its
    /// self-reported tamper events warrant (does not touch the hub — the caller
    /// publishes, which keeps this unit-testable).
    fn ingest(&self, hb: &Heartbeat, now_ms: i64) -> Vec<AlertEvent> {
        let status = hb.status.clone().unwrap_or_default();
        let device_id = status.device_id.trim().to_string();
        if device_id.is_empty() {
            return Vec::new();
        }
        {
            let mut map = self.liveness.lock().expect("liveness lock");
            map.insert(
                device_id.clone(),
                DeviceLiveness {
                    last_seen_ms: now_ms,
                    platform: status.platform.clone(),
                    overdue_alerted: false, // back in touch → re-arm outage detection
                },
            );
        }
        hb.tamper_events
            .iter()
            .filter_map(|k| TamperKind::try_from(*k).ok())
            .filter(|k| *k != TamperKind::Unspecified)
            .map(|k| tamper_alert(&device_id, k, &status, now_ms))
            .collect()
    }

    /// Devices that have gone silent past the grace window get one
    /// `HEARTBEAT_MISSED` alert (debounced until they check back in). Returns the
    /// alerts to publish. Pure over `now_ms` so a test can advance the clock.
    fn overdue(&self, now_ms: i64) -> Vec<AlertEvent> {
        let mut out = Vec::new();
        let mut map = self.liveness.lock().expect("liveness lock");
        for (device_id, live) in map.iter_mut() {
            let silent_for = now_ms.saturating_sub(live.last_seen_ms);
            if silent_for >= self.grace_ms && !live.overdue_alerted {
                live.overdue_alerted = true;
                let status = ProtectionStatus {
                    device_id: device_id.clone(),
                    platform: live.platform.clone(),
                    ..Default::default()
                };
                out.push(tamper_alert(
                    device_id,
                    TamperKind::HeartbeatMissed,
                    &status,
                    now_ms,
                ));
            }
        }
        out
    }

    /// Run one liveness sweep at `now_ms`, publishing any missed-heartbeat alerts.
    /// Returns how many fired. The server spawns a task that calls this on a timer.
    pub fn sweep(&self, now_ms: i64) -> usize {
        let alerts = self.overdue(now_ms);
        let n = alerts.len();
        for ev in alerts {
            self.hub.publish(ev);
        }
        n
    }
}

#[tonic::async_trait]
impl Tamper for TamperService {
    async fn heartbeat(&self, req: Request<Heartbeat>) -> Result<Response<HeartbeatAck>, Status> {
        let hb = req.into_inner();
        if hb
            .status
            .as_ref()
            .map(|s| s.device_id.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(Status::invalid_argument(
                "heartbeat requires status.device_id",
            ));
        }
        for ev in self.ingest(&hb, now_ms()) {
            self.hub.publish(ev);
        }
        Ok(Response::new(HeartbeatAck {
            next_interval_secs: DEFAULT_HEARTBEAT_SECS,
            ok: true,
        }))
    }
}

/// Build a redacted PROTECTION_DISABLED alert for a tamper signal. Content-free:
/// a human-readable description + the device/platform only.
fn tamper_alert(
    device_id: &str,
    kind: TamperKind,
    status: &ProtectionStatus,
    now_ms: i64,
) -> AlertEvent {
    AlertEvent {
        // Stable-ish id: same device+kind within the same second dedupes.
        alert_id: format!("{device_id}-tamper-{}-{}", kind as i32, now_ms / 1000),
        kind: AlertKind::ProtectionDisabled as i32,
        category: Category::Safe as i32, // a status signal, not a content category
        severity: Severity::High as i32, // losing protection is high-priority
        app: status.platform.clone(),
        device_id: device_id.to_string(),
        // Carry the child the device belongs to when the heartbeat knew it; the
        // relay also matches on device_id, so empty is fine.
        child_id: status.child_id.clone(),
        ts: now_ms,
        redacted_context: tamper_message(kind).to_string(),
        ..Default::default()
    }
}

/// Human-readable, guardian-facing description. NO device content — status only.
fn tamper_message(kind: TamperKind) -> &'static str {
    match kind {
        TamperKind::AppUninstallAttempt => {
            "An attempt was made to remove the Aegis protection app on the child's device."
        }
        TamperKind::DeviceAdminRemoved => {
            "Device management for the Aegis app was turned off on the child's device."
        }
        TamperKind::AccessibilityDisabled => {
            "On-device monitoring (accessibility) was turned off on the child's device."
        }
        TamperKind::VpnDisabled => {
            "The filtering VPN was turned off or bypassed on the child's device."
        }
        TamperKind::HeartbeatMissed => {
            "The child's device stopped checking in (app closed, offline, or removed)."
        }
        TamperKind::SafeModeOrFactoryReset => {
            "The child's device booted into safe mode or was factory-reset."
        }
        TamperKind::Unspecified => "Protection status changed on the child's device.",
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

    fn hb(device: &str, events: Vec<TamperKind>) -> Heartbeat {
        Heartbeat {
            status: Some(ProtectionStatus {
                device_id: device.into(),
                platform: "android".into(),
                vpn_active: true,
                ..Default::default()
            }),
            tamper_events: events.into_iter().map(|k| k as i32).collect(),
        }
    }

    #[test]
    fn self_reported_tamper_event_becomes_protection_disabled_alert() {
        let svc = TamperService::new(AlertHub::new());
        let alerts = svc.ingest(&hb("kids-phone", vec![TamperKind::VpnDisabled]), 1_000);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::ProtectionDisabled as i32);
        assert_eq!(alerts[0].device_id, "kids-phone");
        assert!(alerts[0].redacted_context.contains("filtering VPN"));
        // No content ever rides a tamper alert.
        assert!(alerts[0].evidence.is_none());
    }

    #[test]
    fn a_plain_liveness_heartbeat_raises_no_alert() {
        let svc = TamperService::new(AlertHub::new());
        let alerts = svc.ingest(&hb("kids-phone", vec![]), 1_000);
        assert!(alerts.is_empty());
    }

    #[test]
    fn silent_device_raises_one_missed_heartbeat_then_debounces() {
        let svc = TamperService::new(AlertHub::new()).with_grace_ms(60_000);
        svc.ingest(&hb("kids-phone", vec![]), 0);

        // Still within grace → nothing.
        assert!(svc.overdue(30_000).is_empty());

        // Past grace → exactly one HEARTBEAT_MISSED.
        let alerts = svc.overdue(120_000);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::ProtectionDisabled as i32);
        assert!(alerts[0].redacted_context.contains("stopped checking in"));

        // Debounced: a second sweep while still silent does NOT re-alert.
        assert!(svc.overdue(200_000).is_empty());

        // It checks back in, then lapses again → a fresh alert is allowed.
        svc.ingest(&hb("kids-phone", vec![]), 210_000);
        assert!(svc.overdue(400_000).len() == 1);
    }

    #[tokio::test]
    async fn heartbeat_rpc_requires_device_id() {
        let svc = TamperService::new(AlertHub::new());
        let bad = Heartbeat {
            status: Some(ProtectionStatus::default()),
            tamper_events: vec![],
        };
        let err = svc
            .heartbeat(Request::new(bad))
            .await
            .expect_err("blank device_id rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
