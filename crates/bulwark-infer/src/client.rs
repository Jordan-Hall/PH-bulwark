//! Authenticated cluster-offload gRPC client.
//!
//! Every device call is authenticated twice: mTLS proves transport identity and
//! the pairing-minted device credential proves current enrollment. The enrollment
//! token is carried only in gRPC metadata and is Debug-redacted.

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

/// PEM material for the mutually authenticated device→cluster TLS connection.
#[derive(Clone)]
pub struct ClientTlsIdentity {
    /// PEM client certificate chain issued to the installation.
    pub client_cert_pem: Vec<u8>,
    /// PEM private key corresponding to `client_cert_pem`.
    pub client_key_pem: Vec<u8>,
    /// PEM CA certificate used to authenticate the cluster.
    pub ca_cert_pem: Vec<u8>,
    /// Expected TLS server name/SNI.
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

/// Pairing-minted enrollment credential attached to every device-facing RPC.
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
    /// Validate and construct an enrollment identity.
    pub fn new(device_id: impl Into<String>, device_token: impl Into<String>) -> Result<Self> {
        let device_id = device_id.into().trim().to_string();
        let device_token = device_token.into().trim().to_string();
        if device_id.is_empty() {
            return Err(
                InferError::Tls("device_id is required for authenticated offload".into()).into(),
            );
        }
        if device_token.len() < 32 {
            return Err(InferError::Tls(
                "device token is missing or too short; pair this installation before offload"
                    .into(),
            )
            .into());
        }
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

    /// Load `BULWARK_DEVICE_ID` and `BULWARK_DEVICE_TOKEN`.
    pub fn from_env() -> Result<Self> {
        let device_id = std::env::var("BULWARK_DEVICE_ID").map_err(|_| {
            InferError::Tls("BULWARK_DEVICE_ID is not set; device is not enrolled".into())
        })?;
        let device_token = std::env::var("BULWARK_DEVICE_TOKEN").map_err(|_| {
            InferError::Tls("BULWARK_DEVICE_TOKEN is not set; device is not enrolled".into())
        })?;
        Self::new(device_id, device_token)
    }

    fn request<T>(&self, body: T) -> Result<Request<T>> {
        let mut request = Request::new(body);
        let device_id = MetadataValue::try_from(self.device_id.as_str())
            .map_err(|_| InferError::Tls("invalid device id metadata".into()))?;
        let device_token = MetadataValue::try_from(self.device_token.as_str())
            .map_err(|_| InferError::Tls("invalid device token metadata".into()))?;
        request.metadata_mut().insert(DEVICE_ID_HEADER, device_id);
        request
            .metadata_mut()
            .insert(DEVICE_TOKEN_HEADER, device_token);
        Ok(request)
    }

    /// Authenticated supervised-device identifier.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

/// Shared mTLS gRPC client for Offload and Analysis services.
#[derive(Clone, Debug)]
pub struct OffloadClient {
    offload: ProtoOffloadClient<Channel>,
    analysis: AnalysisClient<Channel>,
    auth: DeviceAuth,
}

impl OffloadClient {
    /// Connect with mTLS and enrollment credentials loaded from the environment.
    pub async fn connect(endpoint: &str, tls: &ClientTlsIdentity) -> Result<Self> {
        let auth = DeviceAuth::from_env()?;
        Self::connect_authenticated(endpoint, tls, auth).await
    }

    /// Connect with an explicit enrollment identity.
    pub async fn connect_authenticated(
        endpoint: &str,
        tls: &ClientTlsIdentity,
        auth: DeviceAuth,
    ) -> Result<Self> {
        let endpoint = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|error| InferError::Transport(format!("bad endpoint {endpoint:?}: {error}")))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .tcp_nodelay(true)
            .tls_config(tls.to_tls_config())
            .map_err(|error| InferError::Tls(format!("mTLS config: {error}")))?;
        let channel = endpoint
            .connect()
            .await
            .map_err(|error| InferError::Transport(format!("connect failed: {error}")))?;
        Ok(Self::from_channel_authenticated(channel, auth))
    }

    /// Build service clients over an already authenticated shared channel.
    pub fn from_channel_authenticated(channel: Channel, auth: DeviceAuth) -> Self {
        Self {
            offload: ProtoOffloadClient::new(channel.clone()),
            analysis: AnalysisClient::new(channel),
            auth,
        }
    }

    /// Negotiate the local-vs-cluster execution policy for this enrolled device.
    pub async fn negotiate_offload(&self, mut profile: DeviceProfile) -> Result<OffloadPolicy> {
        if profile.device_id.trim().is_empty() {
            profile.device_id = self.auth.device_id().to_string();
        } else if profile.device_id.trim() != self.auth.device_id() {
            return Err(InferError::Rpc(
                "device profile identity does not match enrolled credential".into(),
            )
            .into());
        }
        self.offload
            .clone()
            .negotiate_offload(self.auth.request(profile)?)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| InferError::Rpc(format!("NegotiateOffload: {status}")).into())
    }

    /// Refresh a negotiated policy with current RTT/battery observations.
    pub async fn refresh_offload(
        &self,
        mut request: RefreshOffloadRequest,
    ) -> Result<OffloadPolicy> {
        if request.device_id.trim().is_empty() {
            request.device_id = self.auth.device_id().to_string();
        } else if request.device_id.trim() != self.auth.device_id() {
            return Err(InferError::Rpc(
                "refresh identity does not match enrolled credential".into(),
            )
            .into());
        }
        self.offload
            .clone()
            .refresh_offload(self.auth.request(request)?)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| InferError::Rpc(format!("RefreshOffload: {status}")).into())
    }

    /// Analyze one media/text unit after binding its body identity to enrollment.
    pub async fn analyze(&self, mut request: AnalysisRequest) -> Result<Verdict> {
        if request.device_id.trim().is_empty() {
            request.device_id = self.auth.device_id().to_string();
        } else if request.device_id.trim() != self.auth.device_id() {
            return Err(InferError::Rpc(
                "analysis identity does not match enrolled credential".into(),
            )
            .into());
        }
        self.analysis
            .clone()
            .analyze(self.auth.request(request)?)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| InferError::Rpc(format!("Analyze: {status}")).into())
    }

    /// Analyze a batch; every item must belong to this enrolled device.
    pub async fn analyze_batch(&self, mut batch: AnalysisBatch) -> Result<VerdictBatch> {
        for request in &mut batch.requests {
            if request.device_id.trim().is_empty() {
                request.device_id = self.auth.device_id().to_string();
            } else if request.device_id.trim() != self.auth.device_id() {
                return Err(
                    InferError::Rpc("batch contains a request for another device".into()).into(),
                );
            }
        }
        self.analysis
            .clone()
            .analyze_batch(self.auth.request(batch)?)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| InferError::Rpc(format!("AnalyzeBatch: {status}")).into())
    }

    /// Open a bidirectional live-analysis stream authenticated as this device.
    pub async fn analyze_stream(
        &self,
        requests: BoxStream<'static, AnalysisRequest>,
    ) -> Result<BoxStream<'static, Result<Verdict>>> {
        let expected = self.auth.device_id().to_string();
        let requests = requests.map(move |mut request| {
            if request.device_id.trim().is_empty() {
                request.device_id = expected.clone();
            }
            request
        });
        let response = self
            .analysis
            .clone()
            .analyze_stream(self.auth.request(requests.boxed())?)
            .await
            .map_err(|status| InferError::Rpc(format!("AnalyzeStream: {status}")))?;

        Ok(response
            .into_inner()
            .map(|item| {
                item.map_err(|status| {
                    bulwark_core::Error::from(InferError::Rpc(format!(
                        "AnalyzeStream item: {status}"
                    )))
                })
            })
            .boxed())
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
    async fn malformed_endpoint_is_rejected_before_dial() {
        let auth = DeviceAuth::new("dev-1", "b".repeat(64)).unwrap();
        let error =
            OffloadClient::connect_authenticated("not a url", &dummy_identity(), auth)
                .await
                .unwrap_err();
        assert!(matches!(error, bulwark_core::Error::Other(_)));
    }
}
