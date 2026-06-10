//! All gRPC client calls: channel setup (TLS + per-server CA pinning),
//! Accounts, Review (pending stream + decisions), ChildControl, and segments.

use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::child_control_client::ChildControlClient;
use bulwark_proto::v1::review_client::ReviewClient;
use bulwark_proto::v1::{
    AccountAck, AlertEvent, Child as ProtoChild, ChildConfig, ChildStatusRequest,
    CreateAccountRequest, CreatePairCodeRequest, DeviceFilter, ListChildrenRequest, LoginRequest,
    PairCode, ReviewDecision, ReviewRequest, ReviewScope, Session, SetChildConfigRequest,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::Streaming;

use crate::servers::{cluster_ca_path_for_endpoint, cluster_endpoint, guardian_token};

/// Build a tonic [`Channel`] to the cluster.
///
/// * If `BULWARK_CLUSTER_CA` is set (path to a PEM CA cert), pin it via
///   [`ClientTlsConfig`] (tonic `tls-ring` feature). The cluster authenticates
///   itself with a cert chaining to this root.
/// * Otherwise dial in the clear — a dev/plaintext convenience only.
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
    let mut builder = Endpoint::from_shared(endpoint.to_string())?;

    if let Some(ca_path) = ca_path.filter(|p| !p.trim().is_empty()) {
        let ca_pem = std::fs::read(ca_path)?;
        let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca_pem));
        builder = builder.tls_config(tls)?;
    }

    Ok(builder.connect().await?)
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
/// applied (its config poll doubles as the ack), and when it last checked in.
/// Content-free. Returns (desired_version, applied_version, last_report_ts).
pub async fn get_child_status(child_id: &str) -> anyhow::Result<(u64, u64, i64)> {
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
    ))
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
    let request = request_with_bearer(req, token);

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

pub fn request_with_bearer(req: ReviewRequest, token: &str) -> tonic::Request<ReviewRequest> {
    // In accounts mode the server requires a guardian session token on the
    // decision RPC (it scopes the approve/deny to the guardian's assigned
    // children). Attach the SAME guardian token the alert stream uses, as
    // `authorization: Bearer <token>` metadata. A single-home / no-accounts server
    // ignores it, so an unset token still works there.
    let mut request = tonic::Request::new(req);
    let token = token.trim();
    if !token.is_empty() {
        if let Ok(val) = tonic::metadata::MetadataValue::try_from(format!("Bearer {token}")) {
            request.metadata_mut().insert("authorization", val);
        }
    }
    request
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
