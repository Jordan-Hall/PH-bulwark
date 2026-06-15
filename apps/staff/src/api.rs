//! StaffAdmin gRPC client: TLS channel setup (+ optional CA pin) and the RPC
//! wrappers the console uses. Every request carries the staff bearer in its
//! `token` field (the server also accepts a Bearer metadata header). Plaintext
//! is refused so passwords + TOTP codes never cross the network in clear.

use bulwark_proto::v1::staff_admin_client::StaffAdminClient;
use bulwark_proto::v1::{
    FleetHealth, FleetHealthRequest, GuardianMeta, GuardianMetaRequest, ListSafetyCasesRequest,
    Regions, RegionsRequest, SafetyCase, SafetyCases, StaffAuditPage, StaffAuditQuery,
    StaffLoginRequest, StaffSession, TransitionSafetyCaseRequest, TriggerGuardianResetAck,
    TriggerGuardianResetRequest, UnlockGuardianAck, UnlockGuardianRequest,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use crate::session::{ca_path, staff_endpoint};

/// Build a TLS channel to the staff gateway. Pins `BULWARK_CLUSTER_CA` when set
/// (self-hosted / private CA), else trusts the public roots for `https://`.
async fn connect() -> anyhow::Result<Channel> {
    let endpoint = staff_endpoint();
    if !(endpoint.starts_with("https://")
        || endpoint.starts_with("http://127.0.0.1")
        || endpoint.starts_with("http://localhost"))
    {
        anyhow::bail!(
            "refusing plaintext to {endpoint}: staff passwords + TOTP codes must not cross the \
             network in clear. Use an https:// endpoint (BULWARK_STAFF_ENDPOINT)."
        );
    }
    let mut builder = Endpoint::from_shared(endpoint.clone())?;
    if let Some(ca) = ca_path() {
        let pem = std::fs::read(ca)?;
        let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&pem));
        builder = builder.tls_config(tls)?;
    } else if endpoint.to_ascii_lowercase().starts_with("https://") {
        builder = builder.tls_config(ClientTlsConfig::new().with_enabled_roots())?;
    }
    Ok(builder.connect().await?)
}

async fn client() -> anyhow::Result<StaffAdminClient<Channel>> {
    Ok(StaffAdminClient::new(connect().await?))
}

/// Password + mandatory TOTP → a short-TTL staff session. Wrong email / password
/// / code are indistinguishable (anti-enumeration) and throttled server-side.
pub async fn staff_login(
    email: String,
    password: String,
    totp_code: String,
) -> anyhow::Result<StaffSession> {
    let mut c = client().await?;
    let resp = c
        .staff_login(StaffLoginRequest {
            email,
            password,
            totp_code,
        })
        .await?;
    Ok(resp.into_inner())
}

/// Content-free region list (any staff role). Audited server-side.
pub async fn list_regions(token: String) -> anyhow::Result<Regions> {
    let mut c = client().await?;
    Ok(c.list_regions(RegionsRequest { token }).await?.into_inner())
}

/// Content-free per-region health (RegionInfo + per-node HealthStatus gauges).
/// Wired into the per-region node-health view in the next increment.
#[allow(dead_code)]
pub async fn get_fleet_health(token: String, region: String) -> anyhow::Result<FleetHealth> {
    let mut c = client().await?;
    Ok(c.get_fleet_health(FleetHealthRequest { token, region })
        .await?
        .into_inner())
}

/// Tamper-evident staff audit page (ADMIN only). `chain_ok` re-verifies the
/// hash chain at read time, so at-rest tampering surfaces on every query.
pub async fn query_audit(
    token: String,
    after_seq: u64,
    limit: u32,
) -> anyhow::Result<StaffAuditPage> {
    let mut c = client().await?;
    Ok(c.query_staff_audit(StaffAuditQuery {
        token,
        after_seq,
        limit,
    })
    .await?
    .into_inner())
}

// --- Guardian support (SUPPORT / ADMIN) — content-free, by email only ----------

/// Existence + state + counts for a guardian account (never content/names/ids).
pub async fn guardian_meta(token: String, email: String) -> anyhow::Result<GuardianMeta> {
    let mut c = client().await?;
    Ok(c.get_guardian_meta(GuardianMetaRequest {
        token,
        guardian_email: email,
    })
    .await?
    .into_inner())
}

/// Email the guardian a reset code (staff never see it). Anti-enumeration ack.
pub async fn trigger_reset(
    token: String,
    email: String,
) -> anyhow::Result<TriggerGuardianResetAck> {
    let mut c = client().await?;
    Ok(c.trigger_guardian_reset(TriggerGuardianResetRequest {
        token,
        guardian_email: email,
    })
    .await?
    .into_inner())
}

/// Clear a guardian's login lockout (the failed-attempt throttles).
pub async fn unlock_guardian(token: String, email: String) -> anyhow::Result<UnlockGuardianAck> {
    let mut c = client().await?;
    Ok(c.unlock_guardian_account(UnlockGuardianRequest {
        token,
        guardian_email: email,
    })
    .await?
    .into_inner())
}

// --- NCMEC safety-report queue (SAFETY_OFFICER / ADMIN) — hashes + state only ---

/// List cases (newest first). `state_filter` = 0 (UNSPECIFIED) returns all states.
pub async fn list_cases(token: String, state_filter: i32) -> anyhow::Result<SafetyCases> {
    let mut c = client().await?;
    Ok(c.list_safety_cases(ListSafetyCasesRequest {
        token,
        state_filter,
    })
    .await?
    .into_inner())
}

/// Drive ONE validated workflow transition (the server refuses invalid edges).
/// `ncmec_reference` is required only when `new_state` == REPORTED_NCMEC.
pub async fn transition_case(
    token: String,
    case_id: String,
    new_state: i32,
    ncmec_reference: String,
) -> anyhow::Result<SafetyCase> {
    let mut c = client().await?;
    Ok(c.transition_safety_case(TransitionSafetyCaseRequest {
        token,
        case_id,
        new_state,
        ncmec_reference,
    })
    .await?
    .into_inner()
    .safety_case
    .unwrap_or_default())
}
