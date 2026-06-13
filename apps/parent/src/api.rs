//! All gRPC client calls: channel setup (TLS + per-server CA pinning),
//! Accounts, Review (pending stream + decisions), ChildControl, and segments.

use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::child_control_client::ChildControlClient;
use bulwark_proto::v1::family_safety_client::FamilySafetyClient;
use bulwark_proto::v1::review_client::ReviewClient;
use bulwark_proto::v1::{
    AccountAck, AlertEvent, AlertKind, ChangePasswordRequest, Child as ProtoChild, ChildConfig,
    ChildStatusRequest, CreateAccountRequest, CreatePairCodeRequest, DeviceFilter,
    ListChildrenRequest, ListSafetyBroadcastsRequest, LoginRequest, PairCode, PushTarget,
    RequestPasswordResetAck, RequestPasswordResetRequest, ResetPasswordAck, ResetPasswordRequest,
    ReviewDecision, ReviewRequest, ReviewScope, SafetyBroadcast, Session, SetChildConfigRequest,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::Streaming;

use crate::servers::{
    cluster_ca_path_for_endpoint, cluster_endpoint, guardian_device_id, guardian_token,
};

/// Build a tonic [`Channel`] to the cluster.
///
/// * If a CA is pinned for this server (`BULWARK_CLUSTER_CA` or the per-server
///   `cluster_ca.pem`), pin it via [`ClientTlsConfig`] — for self-hosted /
///   private-CA servers whose cert public roots can't validate.
/// * Otherwise, for `https://`, trust the PUBLIC roots (the default: the cloud
///   regions serve a real Let's Encrypt cert). Plaintext `http://` is refused to
///   anything but loopback by `plaintext_allowed`.
///
/// Never panics: a bad CA path or unreachable endpoint returns `Err`, and the
/// caller falls back to OFFLINE sample data.
pub async fn connect_channel() -> anyhow::Result<Channel> {
    let endpoint = cluster_endpoint();
    let ca_path = std::env::var("BULWARK_CLUSTER_CA")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .or_else(|| {
            let path = cluster_ca_path_for_endpoint(&endpoint);
            path.exists().then(|| path.to_string_lossy().to_string())
        });
    connect_channel_to(&endpoint, ca_path.as_deref()).await
}

pub async fn connect_channel_to(endpoint: &str, ca_path: Option<&str>) -> anyhow::Result<Channel> {
    if !plaintext_allowed(endpoint) {
        anyhow::bail!(
            "refusing plaintext to {endpoint}: guardian logins and session tokens would cross \
             the network in clear. Use an https:// endpoint with its CA pinned (cluster_ca.pem \
             / BULWARK_CLUSTER_CA), or set BULWARK_ALLOW_PLAINTEXT=1 for local development only."
        );
    }
    let mut builder = Endpoint::from_shared(endpoint.to_string())?;

    if let Some(ca_path) = ca_path.filter(|p| !p.trim().is_empty()) {
        // Private-CA path (self-hosted / on-box CA): pin the provided root so the
        // cluster authenticates with a cert chaining to it.
        let ca_pem = std::fs::read(ca_path)?;
        let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca_pem));
        builder = builder.tls_config(tls)?;
    } else if endpoint.trim().to_ascii_lowercase().starts_with("https://") {
        // No pinned CA -> PUBLIC trust (the default now that the production
        // regions serve a real Let's Encrypt cert on their domain). Pinning
        // stays available above for self-hosted/private-CA setups; the SNI/
        // server name is derived from the endpoint URI authority by tonic.
        let tls = ClientTlsConfig::new().with_enabled_roots();
        builder = builder.tls_config(tls)?;
    }

    Ok(builder.connect().await?)
}

/// May the console carry guardian credentials over `endpoint`? https:// always;
/// http:// ONLY to loopback (a local dev server — nothing leaves the machine) or
/// under the explicit `BULWARK_ALLOW_PLAINTEXT=1` dev override.
fn plaintext_allowed(endpoint: &str) -> bool {
    let allow_env = matches!(
        std::env::var("BULWARK_ALLOW_PLAINTEXT").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    plaintext_allowed_for(endpoint, allow_env)
}

/// Pure core of [`plaintext_allowed`] (unit-tested without env races).
fn plaintext_allowed_for(endpoint: &str, allow_env: bool) -> bool {
    // Schemes are case-insensitive (http crate normalizes them), so the guard
    // must be too — `HTTP://` must not bypass the plaintext refusal.
    let lower = endpoint.trim().to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("http://") else {
        return true; // https:// (anything else fails in tonic with its own error)
    };
    if allow_env {
        return true;
    }
    let host_port = rest.split('/').next().unwrap_or("");
    let host = match host_port.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host_port.split(':').next().unwrap_or(""),
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub async fn accounts_client() -> anyhow::Result<AccountsClient<Channel>> {
    Ok(AccountsClient::new(connect_channel().await?))
}

pub async fn create_guardian_account(
    email: &str,
    password: &str,
    display_name: &str,
) -> anyhow::Result<AccountAck> {
    let mut client = accounts_client().await?;
    Ok(client
        .create_account(CreateAccountRequest {
            email: email.trim().to_string(),
            password: password.to_string(),
            display_name: display_name.trim().to_string(),
        })
        .await?
        .into_inner())
}

pub async fn login_guardian(email: &str, password: &str) -> anyhow::Result<Session> {
    let mut client = accounts_client().await?;
    Ok(client
        .login(LoginRequest {
            email: email.trim().to_string(),
            password: password.to_string(),
        })
        .await?
        .into_inner())
}

/// Ask the server to EMAIL a short-lived reset code to the account's address
/// (when the operator has configured SMTP). Anti-enumeration: the ack is the
/// same generic message whether or not the email has an account — never reveals
/// who's registered. The emailed code is entered into the same reset field as a
/// recovery code (the server accepts either).
pub async fn request_password_reset(email: &str) -> anyhow::Result<RequestPasswordResetAck> {
    let mut client = accounts_client().await?;
    Ok(client
        .request_password_reset(RequestPasswordResetRequest {
            email: email.trim().to_string(),
        })
        .await?
        .into_inner())
}

/// Self-service password reset with the one-time recovery code OR an emailed
/// reset code (the server accepts either). Returns the ack, which carries a
/// FRESH recovery code to save.
pub async fn reset_password_with_code(
    email: &str,
    recovery_code: &str,
    new_password: &str,
) -> anyhow::Result<ResetPasswordAck> {
    let mut client = accounts_client().await?;
    Ok(client
        .reset_password(ResetPasswordRequest {
            email: email.trim().to_string(),
            recovery_code: recovery_code.trim().to_string(),
            new_password: new_password.to_string(),
        })
        .await?
        .into_inner())
}

/// Change the signed-in guardian's password (proves the old one). Uses the saved
/// session token for this server. Invalidates the account's OTHER sessions.
pub async fn change_guardian_password(
    old_password: &str,
    new_password: &str,
) -> anyhow::Result<AccountAck> {
    let token = guardian_token();
    if token.is_empty() {
        anyhow::bail!("sign in required to change your password");
    }
    let mut client = accounts_client().await?;
    Ok(client
        .change_password(ChangePasswordRequest {
            token,
            old_password: old_password.to_string(),
            new_password: new_password.to_string(),
        })
        .await?
        .into_inner())
}

pub async fn load_children() -> anyhow::Result<Vec<ProtoChild>> {
    let token = guardian_token();
    if token.is_empty() {
        anyhow::bail!("login required for this server");
    }
    let mut client = accounts_client().await?;
    Ok(client
        .list_children(ListChildrenRequest { token })
        .await?
        .into_inner()
        .children)
}

pub async fn create_pair_code_for_child(child_name: &str) -> anyhow::Result<PairCode> {
    let token = guardian_token();
    if token.is_empty() {
        anyhow::bail!("login required for this server");
    }
    let mut client = accounts_client().await?;
    Ok(client
        .create_pair_code(CreatePairCodeRequest {
            token,
            child_name: child_name.trim().to_string(),
        })
        .await?
        .into_inner())
}

pub async fn open_pending_review_stream() -> anyhow::Result<Streaming<AlertEvent>> {
    let channel = connect_channel().await?;
    let token = guardian_token();
    open_pending_review_stream_on(channel, &token).await
}

/// Push a child's desired VPN config to `ChildControl.SetChildConfig` (the parent
/// owns the switch): region/server, filtering on/off, strictness band. Returns the
/// server-assigned monotonic `config_version`.
pub async fn set_child_config(
    child_id: &str,
    device_id: &str,
    region: &str,
    endpoint: &str,
    filtering_enabled: bool,
    profile: i32,
    filter_location: i32,
) -> anyhow::Result<u64> {
    let token = guardian_token();
    if token.is_empty() {
        anyhow::bail!("login required for this server");
    }
    let mut client = ChildControlClient::new(connect_channel().await?);
    let ack = client
        .set_child_config(SetChildConfigRequest {
            token,
            config: Some(ChildConfig {
                child_id: child_id.to_string(),
                device_id: device_id.to_string(),
                filtering_enabled,
                server_region: region.to_string(),
                server_endpoint: endpoint.to_string(),
                profile,
                require_always_on: false,
                filter_location,
                // server-stamped — ignored on input:
                config_version: 0,
                updated_ts: 0,
                updated_by: String::new(),
            }),
        })
        .await?
        .into_inner();
    Ok(ack.config_version)
}

/// Read a child's desired-vs-applied config status (`ChildControl.GetChildStatus`):
/// the latest guardian-set version, the last version the child device reported
/// applied (its config poll doubles as the ack), when it last checked in, and the
/// guardian's saved desired config document (seeds the console's draft controls).
/// Content-free. Returns (desired_version, applied_version, last_report_ts, desired).
pub async fn get_child_status(
    child_id: &str,
) -> anyhow::Result<(u64, u64, i64, Option<ChildConfig>)> {
    let token = guardian_token();
    if token.is_empty() {
        anyhow::bail!("login required for this server");
    }
    let mut client = ChildControlClient::new(connect_channel().await?);
    let status = client
        .get_child_status(ChildStatusRequest {
            token,
            child_id: child_id.to_string(),
        })
        .await?
        .into_inner();
    Ok((
        status.desired_version,
        status.applied_version,
        status.last_report_ts,
        status.desired,
    ))
}

/// Fetch the ACTIVE staff safety notices (`FamilySafety.ListSafetyBroadcasts`)
/// so a console that connects after a broadcast was issued still sees it (the
/// live stream only reaches connected consoles). Each notice is re-shaped as
/// the same SAFETY_BROADCAST AlertEvent the stream carries, so the inbox
/// renders both paths identically (deduped by id).
pub async fn list_active_safety_broadcasts() -> anyhow::Result<Vec<AlertEvent>> {
    let token = guardian_token();
    if token.is_empty() {
        anyhow::bail!("login required for this server");
    }
    let mut client = FamilySafetyClient::new(connect_channel().await?);
    let resp = client
        .list_safety_broadcasts(ListSafetyBroadcastsRequest {
            token,
            device_id: String::new(),
            device_token: String::new(),
            region: String::new(),
        })
        .await?
        .into_inner();
    Ok(resp.broadcasts.into_iter().map(broadcast_event).collect())
}

/// Mirror of the server's broadcast→AlertEvent shaping (family_safety.rs):
/// `app` carries the region scope; title+body land in the redacted context.
pub fn broadcast_event(b: SafetyBroadcast) -> AlertEvent {
    AlertEvent {
        alert_id: b.broadcast_id,
        kind: AlertKind::SafetyBroadcast as i32,
        severity: b.severity,
        app: b.region,
        ts: b.issued_ts,
        redacted_context: if b.body.is_empty() {
            b.title
        } else {
            format!("{} — {}", b.title, b.body)
        },
        ..Default::default()
    }
}

#[cfg(test)]
pub async fn open_pending_review_stream_from(
    endpoint: &str,
    token: &str,
) -> anyhow::Result<Streaming<AlertEvent>> {
    let channel = connect_channel_to(endpoint, None).await?;
    open_pending_review_stream_on(channel, token).await
}

pub async fn open_pending_review_stream_on(
    channel: Channel,
    token: &str,
) -> anyhow::Result<Streaming<AlertEvent>> {
    let mut client = ReviewClient::new(channel);
    let filter = DeviceFilter {
        device_id: String::new(),
        token: token.trim().to_string(),
    };
    Ok(client.stream_pending_reviews(filter).await?.into_inner())
}

/// Send a guardian decision for `alert_id` to `Review.SubmitDecision`.
///
/// APPROVE allowlists the host involved (`THIS_HOST`); DENY confirms the block
/// (scope ignored for DENY per the contract). Each call dials a fresh channel —
/// decisions are infrequent and this keeps the coroutine's stream channel
/// independent of one-shot RPCs.
pub async fn submit_decision(alert_id: &str, device_id: &str, approve: bool) -> anyhow::Result<()> {
    let channel = connect_channel().await?;
    let token = guardian_token();
    submit_decision_on(channel, &token, alert_id, device_id, approve).await
}

#[cfg(test)]
pub async fn submit_decision_to(
    endpoint: &str,
    token: &str,
    alert_id: &str,
    device_id: &str,
    approve: bool,
) -> anyhow::Result<()> {
    let channel = connect_channel_to(endpoint, None).await?;
    submit_decision_on(channel, token, alert_id, device_id, approve).await
}

pub async fn submit_decision_on(
    channel: Channel,
    token: &str,
    alert_id: &str,
    device_id: &str,
    approve: bool,
) -> anyhow::Result<()> {
    let mut client = ReviewClient::new(channel);

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let req = review_request_at(alert_id, device_id, approve, ts);
    let request = with_bearer(req, token);

    let ack = client.submit_decision(request).await?.into_inner();
    if !ack.applied {
        anyhow::bail!("the cluster did not apply the decision");
    }
    Ok(())
}

pub fn review_request_at(alert_id: &str, device_id: &str, approve: bool, ts: i64) -> ReviewRequest {
    let decision = if approve {
        ReviewDecision::Approve
    } else {
        ReviewDecision::Deny
    };

    ReviewRequest {
        alert_id: alert_id.to_string(),
        decision: decision as i32,
        device_id: device_id.to_string(),
        scope: ReviewScope::ThisHost as i32,
        ts,
    }
}

/// Attach `authorization: Bearer <token>` metadata to ANY request body.
///
/// In accounts mode the server requires a guardian session token on the
/// decision RPC (it scopes the approve/deny to the guardian's assigned children)
/// AND on `Review.RegisterPushTarget` (else any caller could aim the server's
/// per-alert POST at an endpoint of their choosing — SSRF / push disruption).
/// Attach the SAME guardian token the alert stream uses. A single-home /
/// no-accounts server ignores it, so an unset token still works there.
pub fn with_bearer<T>(req: T, token: &str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(req);
    let token = token.trim();
    if !token.is_empty() {
        if let Ok(val) = tonic::metadata::MetadataValue::try_from(format!("Bearer {token}")) {
            request.metadata_mut().insert("authorization", val);
        }
    }
    request
}

/// Register this Manager device's self-hosted UnifiedPush endpoint with the
/// cluster's `Review.RegisterPushTarget`, so guardian alerts can be relayed to
/// THIS device when the guardian is away from the child's device.
///
/// AUTHENTICATED: carries the guardian's existing session token as
/// `authorization: Bearer …` — the server REQUIRES it in accounts mode and the
/// registration is rejected without it (we never weaken that). The endpoint URL
/// is the guardian's own UnifiedPush distributor route (e.g. an `ntfy` topic
/// URL); the server validates it (https + public host, SSRF guard) before
/// storing it. No alert content is sent here — this is a routing handle only.
pub async fn register_push_target(endpoint: &str) -> anyhow::Result<()> {
    let token = guardian_token();
    if token.is_empty() {
        anyhow::bail!("sign in required to register notifications for this server");
    }
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        anyhow::bail!("a UnifiedPush endpoint URL is required");
    }
    let channel = connect_channel().await?;
    register_push_target_on(channel, &token, &guardian_device_id(), endpoint).await
}

pub async fn register_push_target_on(
    channel: Channel,
    token: &str,
    device_id: &str,
    endpoint: &str,
) -> anyhow::Result<()> {
    let mut client = ReviewClient::new(channel);
    let request = with_bearer(
        PushTarget {
            device_id: device_id.to_string(),
            push_endpoint: endpoint.to_string(),
            platform: push_platform().to_string(),
        },
        token,
    );
    let ack = client.register_push_target(request).await?.into_inner();
    if !ack.ok {
        anyhow::bail!("the cluster declined the push registration");
    }
    Ok(())
}

#[cfg(test)]
pub async fn register_push_target_to(
    endpoint: &str,
    token: &str,
    device_id: &str,
    push_endpoint: &str,
) -> anyhow::Result<()> {
    let channel = connect_channel_to(endpoint, None).await?;
    register_push_target_on(channel, token, device_id, push_endpoint).await
}

/// The `platform` field the server records alongside the endpoint. The Manager
/// ships native on Android and as a desktop console elsewhere; the value is
/// advisory routing metadata only.
pub fn push_platform() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else {
        "desktop"
    }
}

/// Pull a retained clip from the cluster over `Review.FetchSegment` (for a guardian
/// on a DIFFERENT device than the server — the clip isn't on local disk). Streams
/// the chunks and reassembles. Authenticated via the guardian token in accounts mode
/// (CSAM is never retained, so it can never be fetched).
pub async fn fetch_segment_remote(uri: &str) -> Result<Vec<u8>, String> {
    use bulwark_proto::v1::SegmentRequest;
    let channel = connect_channel().await.map_err(|e| e.to_string())?;
    let mut client = ReviewClient::new(channel);
    let token = guardian_token();
    let mut stream = client
        .fetch_segment(SegmentRequest {
            local_segment_uri: uri.to_string(),
            token,
        })
        .await
        .map_err(|e| e.message().to_string())?
        .into_inner();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream
        .message()
        .await
        .map_err(|e| e.message().to_string())?
    {
        bytes.extend_from_slice(&chunk.data);
    }
    if bytes.is_empty() {
        return Err("empty or unavailable segment".to_string());
    }
    Ok(bytes)
}

#[cfg(test)]
mod transport_policy_tests {
    use super::plaintext_allowed_for;

    #[test]
    fn https_is_always_allowed() {
        assert!(plaintext_allowed_for("https://uk.example:8443", false));
    }

    #[test]
    fn plaintext_loopback_is_dev_friendly() {
        assert!(plaintext_allowed_for("http://127.0.0.1:8443", false));
        assert!(plaintext_allowed_for("http://localhost:8443", false));
        assert!(plaintext_allowed_for("http://[::1]:8443", false));
    }

    #[test]
    fn plaintext_remote_requires_explicit_override() {
        assert!(!plaintext_allowed_for(
            "http://ec2-1-2-3-4.compute.amazonaws.com:8443",
            false
        ));
        assert!(!plaintext_allowed_for("http://192.168.1.10:8443", false));
        assert!(plaintext_allowed_for("http://192.168.1.10:8443", true));
        // A loopback-PREFIXED public name is still remote.
        assert!(!plaintext_allowed_for(
            "http://localhost.evil.example:8443",
            false
        ));
        // Scheme case must not bypass the refusal (http normalizes schemes).
        assert!(!plaintext_allowed_for("HTTP://192.168.1.10:8443", false));
    }
}
