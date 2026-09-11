//! The cluster-offload gRPC client (tonic, over **mTLS**).
//!
//! Every device call is authenticated twice: the TLS client certificate proves
//! transport identity and the pairing-minted device token proves enrollment.
//! The token is carried only in gRPC metadata and is never written to logs.

use std::time::Duration;

use futures_core::stream::BoxStream;
use futures_util::StreamExt;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::Request;

use bulwark_proto::v1::analysis_client::AnalysisClient;
use bulwark_proto::v1::offload_client::OffloadClient as ProtoOffloadClient;
use bulwark_proto::v1::{
    AnalysisBatch, AnalysisRequest, DeviceProfile, OffloadPolicy, RefreshOffloadRequest, Verdict,
    VerdictBatch,
};

use crate::error::{InferError, Result};

const DEVICE_ID_HEADER: &str = "x-bulwark-device-id";
const DEVICE_TOKEN_HEADER: &str = "x-bulwark-device-token";

#[derive(Clone)]
pub struct ClientTlsIdentity {
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub ca_cert_pem: Vec<u8>,
    pub server_domain: String,
}

impl std::fmt::Debug for ClientTlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTlsIdentity")
            .field("server_domain", &self.server_domain)
            .field("client_cert_pem", &"<redacted>")
            .field("client_key_pem", &"<redacted>")
            .field("ca_cert_pem", &"<redacted>")
            .finish()
    }
}

impl ClientTlsIdentity {
    fn to_tls_config(&self) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .domain_name(self.server_domain.clone())
            .ca_certificate(Certificate::from_pem(&self.ca_cert_pem))
            .identity(Identity::from_pem(
                &self.client_cert_pem,
                &self.client_key_pem,
            ))
    }
}

/// Enrollment credential attached to device-facing RPCs. The raw token is
/// intentionally private and Debug-redacted.
#[derive(Clone)]
pub struct DeviceAuth {
    device_id: String,
    device_token: String,
}

impl std::fmt::Debug for DeviceAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuth")
            .field("device_id", &self.device_id)
            .field("device_token", &"<redacted>")
            .finish()
    }
}

impl DeviceAuth {
    pub fn new(device_id: impl Into<String>, device_token: impl Into<String>) -> Result<Self> {
        let device_id = device_id.into().trim().to_string();
        let device_token = device_token.into().trim().to_string();
        if device_id.is_empty() {
            return Err(InferError::Tls("device_id is required for authenticated offload".into()).into());
        }
        if device_token.len() < 32 {
            return Err(InferError::Tls(
                "device token is missing or too short; pair this installation before offload".into(),
            )
            .into());
        }
        // Validate once here so every request can insert metadata infallibly.
        MetadataValue::try_from(device_id.as_str()).map_err(|_| {
            bulwark_core::Error::from(InferError::Tls(
                "device_id contains characters invalid in gRPC metadata".into(),
            ))
        })?;
        MetadataValue::try_from(device_token.as_str()).map_err(|_| {
            bulwark_core::Error::from(InferError::Tls(
                "device token contains characters invalid in gRPC metadata".into(),
            ))
        })?;
        Ok(Self {
            device_id,
            device_token,
        })
    }

    /// Load the enrollment credential supplied by the desktop/mobile composition
    /// root. Production device offload refuses to operate without it.
    pub fn from_env() -> Result<Self> {
        let device_id = std::env::var("BULWARK_DEVICE_ID")
            .map_err(|_| InferError::Tls("BULWARK_DEVICE_ID is not set; device is not enrolled".into()))?;
        let device_token = std::env::var("BULWARK_DEVICE_TOKEN")
            .map_err(|_| InferError::Tls("BULWARK_DEVICE_TOKEN is not set; device is not enrolled".into()))?;
        Self::new(device_id, device_token)
    }

    fn request<T>(&self, body: T) -> Result<Request<T>> {
        let mut req = Request::new(body);
        let device_id = MetadataValue::try_from(self.device_id.as_str())
            .map_err(|_| InferError::Tls("invalid device id metadata".into()))?;
        let device_token = MetadataValue::try_from(self.device_token.as_str())
            .map_err(|_| InferError::Tls("invalid device token metadata".into()))?;
        req.metadata_mut().insert(DEVICE_ID_HEADER, device_id);
        req.metadata_mut().insert(DEVICE_TOKEN_HEADER, device_token);
        Ok(req)
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

#[derive(Clone, Debug)]
pub struct OffloadClient {
    offload: ProtoOffloadClient<Channel>,
    analysis: AnalysisClient<Channel>,
    auth: DeviceAuth,
}

impl OffloadClient {
    /// Connect using mTLS and the pairing-minted device enrollment credential
    /// loaded from `BULWARK_DEVICE_ID` / `BULWARK_DEVICE_TOKEN`.
    pub async fn connect(endpoint: &str, tls: &ClientTlsIdentity) -> Result<Self> {
        let auth = DeviceAuth::from_env()?;
        Self::connect_authenticated(endpoint, tls, auth).await
    }

    pub async fn connect_authenticated(
        endpoint: &str,
        tls: &ClientTlsIdentity,
        auth: DeviceAuth,
    ) -> Result<Self> {
        let endpoint = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|e| InferError::Transport(format!("bad endpoint {endpoint:?}: {e}")))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .tls_config(tls.to_tls_config())
            .map_err(|e| InferError::Tls(format!("mTLS config: {e}")))?;
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| InferError::Transport(format!("connect failed: {e}")))?;
        Ok(Self::from_channel_authenticated(channel, auth))
    }

    pub fn from_channel_authenticated(channel: Channel, auth: DeviceAuth) -> Self {
        Self {
            offload: ProtoOffloadClient::new(channel.clone()),
            analysis: AnalysisClient::new(channel),
            auth,
        }
    }

    pub async fn negotiate_offload(&self, mut profile: DeviceProfile) -> Result<OffloadPolicy> {
        if profile.device_id.trim().is_empty() {
            profile.device_id = self.auth.device_id().to_string();
        } else if profile.device_id.trim() != self.auth.device_id() {
            return Err(InferError::Rpc("device profile identity does not match enrolled credential".into()).into());
        }
        let resp = self
            .offload
            .clone()
            .negotiate_offload(self.auth.request(profile)?)
            .await
            .map_err(|s| InferError::Rpc(format!("NegotiateOffload: {s}")))?;
        Ok(resp.into_inner())
    }

    pub async fn refresh_offload(
        &self,
        mut req: RefreshOffloadRequest,
    ) -> Result<OffloadPolicy> {
        if req.device_id.trim().is_empty() {
            req.device_id = self.auth.device_id().to_string();
        } else if req.device_id.trim() != self.auth.device_id() {
            return Err(InferError::Rpc("refresh identity does not match enrolled credential".into()).into());
        }
        let resp = self
            .offload
            .clone()
            .refresh_offload(self.auth.request(req)?)
            .await
            .map_err(|s| InferError::Rpc(format!("RefreshOffload: {s}")))?;
        Ok(resp.into_inner())
    }

    pub async fn analyze(&self, mut req: AnalysisRequest) -> Result<Verdict> {
        if req.device_id.trim().is_empty() {
            req.device_id = self.auth.device_id().to_string();
        } else if req.device_id.trim() != self.auth.device_id() {
            return Err(InferError::Rpc("analysis identity does not match enrolled credential".into()).into());
        }
        let resp = self
            .analysis
            .clone()
            .analyze(self.auth.request(req)?)
            .await
            .map_err(|s| InferError::Rpc(format!("Analyze: {s}")))?;
        Ok(resp.into_inner())
    }

    pub async fn analyze_batch(&self, mut batch: AnalysisBatch) -> Result<VerdictBatch> {
        for req in &mut batch.requests {
            if req.device_id.trim().is_empty() {
                req.device_id = self.auth.device_id().to_string();
            } else if req.device_id.trim() != self.auth.device_id() {
                return Err(InferError::Rpc("batch contains a request for another device".into()).into());
            }
        }
        let resp = self
            .analysis
            .clone()
            .analyze_batch(self.auth.request(batch)?)
            .await
            .map_err(|s| InferError::Rpc(format!("AnalyzeBatch: {s}")))?;
        Ok(resp.into_inner())
    }

    pub async fn analyze_stream(
        &self,
        requests: BoxStream<'static, AnalysisRequest>,
    ) -> Result<BoxStream<'static, Result<Verdict>>> {
        let expected = self.auth.device_id().to_string();
        let requests = requests.map(move |mut req| {
            if req.device_id.trim().is_empty() {
                req.device_id = expected.clone();
            }
            req
        });
        let resp = self
            .analysis
            .clone()
            .analyze_stream(self.auth.request(requests.boxed())?)
            .await
            .map_err(|s| InferError::Rpc(format!("AnalyzeStream: {s}")))?;

        let stream = resp.into_inner().map(|item| {
            item.map_err(|s| {
                bulwark_core::Error::from(InferError::Rpc(format!("AnalyzeStream item: {s}")))
            })
        });
        Ok(stream.boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_identity() -> ClientTlsIdentity {
        ClientTlsIdentity {
            client_cert_pem: b"PEM-CERT-MATERIAL-AAAA".to_vec(),
            client_key_pem: b"PEM-PRIVATE-MATERIAL-BBBB".to_vec(),
            ca_cert_pem: b"PEM-CA-MATERIAL-CCCC".to_vec(),
            server_domain: "cluster.local".into(),
        }
    }

    #[test]
    fn tls_identity_debug_redacts_material() {
        let shown = format!("{:?}", dummy_identity());
        assert!(shown.contains("cluster.local"));
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("PEM-CERT-MATERIAL-AAAA"));
        assert!(!shown.contains("PEM-PRIVATE-MATERIAL-BBBB"));
        assert!(!shown.contains("PEM-CA-MATERIAL-CCCC"));
    }

    #[test]
    fn device_auth_debug_redacts_token() {
        let auth = DeviceAuth::new("dev-1", "a".repeat(64)).unwrap();
        let shown = format!("{auth:?}");
        assert!(shown.contains("dev-1"));
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains(&"a".repeat(64)));
    }

    #[tokio::test]
    async fn connect_rejects_a_malformed_endpoint() {
        let auth = DeviceAuth::new("dev-1", "b".repeat(64)).unwrap();
        let err = OffloadClient::connect_authenticated("not a url", &dummy_identity(), auth)
            .await
            .unwrap_err();
        assert!(matches!(err, bulwark_core::Error::Other(_)));
    }
}
