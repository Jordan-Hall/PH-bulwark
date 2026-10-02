//! Child-device protection liveness and tamper reporting.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bulwark_proto::v1::{
    tamper_server::Tamper, AlertEvent, AlertKind, Category, Heartbeat, HeartbeatAck,
    ProtectionStatus, Severity, TamperKind,
};
use tonic::{Request, Response, Status};

use crate::accounts::AccountStore;
use crate::relay::AlertHub;

/// Cadence requested from supervised devices.
pub const DEFAULT_HEARTBEAT_SECS: u32 = 120;
/// Three missed heartbeats before one guardian alert is raised.
pub const DEFAULT_GRACE_MS: i64 = 3 * DEFAULT_HEARTBEAT_SECS as i64 * 1000;

struct DeviceLiveness {
    last_seen_ms: i64,
    platform: String,
    child_id: String,
    family_id: String,
    overdue_alerted: bool,
}

/// Shared protection-liveness service.
#[derive(Clone)]
pub struct TamperService {
    hub: AlertHub,
    liveness: Arc<Mutex<HashMap<String, DeviceLiveness>>>,
    grace_ms: i64,
    accounts: Option<AccountStore>,
}

impl TamperService {
    /// Build a liveness service publishing alerts into `hub`.
    pub fn new(hub: AlertHub) -> Self {
        Self {
            hub,
            liveness: Arc::new(Mutex::new(HashMap::new())),
            grace_ms: DEFAULT_GRACE_MS,
            accounts: None,
        }
    }

    /// Require pairing-minted device credentials for heartbeats.
    pub fn with_accounts(mut self, accounts: AccountStore) -> Self {
        self.accounts = Some(accounts);
        self
    }

    /// Override the missed-heartbeat grace window.
    pub fn with_grace_ms(mut self, grace_ms: i64) -> Self {
        self.grace_ms = grace_ms.max(1);
        self
    }

    fn ingest(&self, heartbeat: &Heartbeat, now_ms: i64) -> Vec<AlertEvent> {
        let mut status = heartbeat.status.clone().unwrap_or_default();
        let device_id = status.device_id.trim().to_string();
        if device_id.is_empty() {
            return Vec::new();
        }

        let mut family_id = String::new();
        if let Some(accounts) = &self.accounts {
            if let Some((child_id, authoritative_family, _)) = accounts.child_for_device(&device_id)
            {
                status.child_id = child_id;
                family_id = authoritative_family;
            }
        }

        self.liveness
            .lock()
            .expect("liveness mutex poisoned")
            .insert(
                device_id.clone(),
                DeviceLiveness {
                    last_seen_ms: now_ms,
                    platform: status.platform.clone(),
                    child_id: status.child_id.clone(),
                    family_id: family_id.clone(),
                    overdue_alerted: false,
                },
            );

        heartbeat
            .tamper_events
            .iter()
            .filter_map(|value| TamperKind::try_from(*value).ok())
            .filter(|kind| *kind != TamperKind::Unspecified)
            .map(|kind| tamper_alert(&device_id, kind, &status, &family_id, now_ms))
            .collect()
    }

    fn overdue(&self, now_ms: i64) -> Vec<AlertEvent> {
        let mut output = Vec::new();
        let mut liveness = self.liveness.lock().expect("liveness mutex poisoned");
        for (device_id, live) in liveness.iter_mut() {
            if now_ms.saturating_sub(live.last_seen_ms) < self.grace_ms || live.overdue_alerted {
                continue;
            }
            live.overdue_alerted = true;
            output.push(tamper_alert(
                device_id,
                TamperKind::HeartbeatMissed,
                &ProtectionStatus {
                    device_id: device_id.clone(),
                    child_id: live.child_id.clone(),
                    platform: live.platform.clone(),
                    ..Default::default()
                },
                &live.family_id,
                now_ms,
            ));
        }
        output
    }

    /// Run one missed-heartbeat sweep and publish newly overdue devices.
    pub fn sweep(&self, now_ms: i64) -> usize {
        let alerts = self.overdue(now_ms);
        let count = alerts.len();
        for event in alerts {
            self.hub.publish(event);
        }
        count
    }
}

#[tonic::async_trait]
impl Tamper for TamperService {
    async fn heartbeat(
        &self,
        request: Request<Heartbeat>,
    ) -> Result<Response<HeartbeatAck>, Status> {
        let heartbeat = request.into_inner();
        let device_id = heartbeat
            .status
            .as_ref()
            .map(|status| status.device_id.trim())
            .unwrap_or_default();
        if device_id.is_empty() {
            return Err(Status::invalid_argument(
                "heartbeat requires status.device_id",
            ));
        }

        if let Some(accounts) = &self.accounts {
            if !crate::auth::verify_device_token_strict(
                accounts,
                device_id,
                heartbeat.device_token.trim(),
            ) {
                return Err(Status::unauthenticated(
                    "unknown, legacy-unpaired, or invalid device credential",
                ));
            }
        }

        for event in self.ingest(&heartbeat, now_ms()) {
            self.hub.publish(event);
        }
        Ok(Response::new(HeartbeatAck {
            next_interval_secs: DEFAULT_HEARTBEAT_SECS,
            ok: true,
        }))
    }
}

fn tamper_alert(
    device_id: &str,
    kind: TamperKind,
    status: &ProtectionStatus,
    family_id: &str,
    now_ms: i64,
) -> AlertEvent {
    AlertEvent {
        alert_id: format!("{device_id}-tamper-{}-{}", kind as i32, now_ms / 1000),
        kind: AlertKind::ProtectionDisabled as i32,
        category: Category::Safe as i32,
        severity: Severity::High as i32,
        app: status.platform.clone(),
        device_id: device_id.to_string(),
        child_id: status.child_id.clone(),
        family_id: family_id.to_string(),
        ts: now_ms,
        redacted_context: tamper_message(kind).to_string(),
        ..Default::default()
    }
}

fn tamper_message(kind: TamperKind) -> &'static str {
    match kind {
        TamperKind::AppUninstallAttempt => {
            "An attempt was made to remove the Bulwark protection app on the child's device."
        }
        TamperKind::DeviceAdminRemoved => {
            "Device management for the Bulwark app was turned off on the child's device."
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
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heartbeat(device: &str, token: &str) -> Heartbeat {
        Heartbeat {
            status: Some(ProtectionStatus {
                device_id: device.into(),
                platform: "android".into(),
                vpn_active: true,
                ..Default::default()
            }),
            device_token: token.into(),
            ..Default::default()
        }
    }

    fn paired(device: &str) -> (AccountStore, String) {
        let accounts = AccountStore::new();
        accounts
            .create_account("parent@example.test", "password123", "Parent")
            .unwrap();
        let (session, _, _) = accounts
            .login("parent@example.test", "password123")
            .unwrap();
        let (code, _) = accounts.create_pair_code(&session, "Kid").unwrap();
        let (_, _, token) = accounts.redeem_pair_code(&code, device).unwrap();
        (accounts, token)
    }

    #[tokio::test]
    async fn paired_credential_is_required_in_accounts_mode() {
        let (accounts, token) = paired("device-1");
        let service = TamperService::new(AlertHub::new()).with_accounts(accounts);
        assert!(service
            .heartbeat(Request::new(heartbeat("device-1", &token)))
            .await
            .is_ok());
        assert_eq!(
            service
                .heartbeat(Request::new(heartbeat("device-1", "")))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }
}
