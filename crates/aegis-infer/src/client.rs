//! The cluster-offload gRPC client (tonic, over **mTLS**).
//!
//! This is the client's single door to the cluster's `Offload` and `Analysis`
//! services (`docs/design/interfaces.md`, `crates/aegis-proto/proto/aegis.proto`).
//! Every call goes over a mutually-authenticated TLS channel: the per-device
//! client identity authenticates *us* to the cluster and the cluster CA root
//! authenticates the cluster to us (architecture.md §5: mTLS on every link). We
//! **fail closed** — if the mTLS material is missing we never dial in the clear.
//!
//! Surface:
//! * [`ClientTlsIdentity`] — config-provided client cert/key + CA root.
//! * [`OffloadClient::connect`] — build the mTLS channel + service stubs.
//! * `negotiate_offload` / `refresh_offload` — the `Offload` service.
//! * `analyze` / `analyze_batch` / `analyze_stream` — the `Analysis` service.

use futures_core::stream::BoxStream;
use futures_util::StreamExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use aegis_proto::v1::analysis_client::AnalysisClient;
use aegis_proto::v1::offload_client::OffloadClient as ProtoOffloadClient;
use aegis_proto::v1::{
    AnalysisBatch, AnalysisRequest, DeviceProfile, OffloadPolicy, RefreshOffloadRequest, Verdict,
    VerdictBatch,
};

use crate::error::{InferError, Result};

/// The mTLS material the client presents and trusts, sourced from config
/// (`aegis_core::ClusterConfig.tls_dir`). The private key never appears in
/// `aegis-proto` or on the wire beyond the TLS handshake (architecture.md §5).
#[derive(Clone)]
pub struct ClientTlsIdentity {
    /// PEM-encoded client certificate chain (the per-device cert; its subject is
    /// the `device_id`).
    pub client_cert_pem: Vec<u8>,
    /// PEM-encoded client private key. Held in memory only; loaded from the OS
    /// keystore / DPAPI / Keychain by the composition root, never logged.
    pub client_key_pem: Vec<u8>,
    /// PEM-encoded CA root used to verify the cluster's server certificate.
    pub ca_cert_pem: Vec<u8>,
    /// Expected server name (SNI / cert subject) of the cluster gateway.
    pub server_domain: String,
}

impl std::fmt::Debug for ClientTlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key/cert bytes.
        f.debug_struct("ClientTlsIdentity")
            .field("server_domain", &self.server_domain)
            .field("client_cert_pem", &"<redacted>")
            .field("client_key_pem", &"<redacted>")
            .field("ca_cert_pem", &"<redacted>")
            .finish()
    }
}

impl ClientTlsIdentity {
    /// Build the tonic [`ClientTlsConfig`] for a mutually-authenticated channel:
    /// presents our client identity and pins the cluster CA root.
    fn to_tls_config(&self) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .domain_name(self.server_domain.clone())
            .ca_certificate(Certificate::from_pem(&self.ca_cert_pem))
            .identity(Identity::from_pem(&self.client_cert_pem, &self.client_key_pem))
    }
}

/// gRPC client to the cluster's `Offload` + `Analysis` services over one shared
/// mTLS channel.
#[derive(Clone)]
pub struct OffloadClient {
    offload: ProtoOffloadClient<Channel>,
    analysis: AnalysisClient<Channel>,
}

impl OffloadClient {
    /// Connect to the cluster gateway at `endpoint` (e.g. `https://host:8443`)
    /// using the supplied mTLS [`ClientTlsIdentity`]. Fails closed if the TLS
    /// material is rejected or the endpoint is unreachable.
    pub async fn connect(endpoint: &str, tls: &ClientTlsIdentity) -> Result<Self> {
        let channel = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|e| InferError::Transport(format!("bad endpoint {endpoint:?}: {e}")))?
            .tls_config(tls.to_tls_config())
            .map_err(|e| InferError::Tls(format!("mTLS config: {e}")))?
            .connect()
            .await
            .map_err(|e| InferError::Transport(format!("connect {endpoint:?}: {e}")))?;

        Ok(Self::from_channel(channel))
    }

    /// Build the service stubs over an already-established mTLS [`Channel`]
    /// (e.g. one shared with `aegis-alert`/`aegis-cluster` by the client).
    pub fn from_channel(channel: Channel) -> Self {
        Self {
            offload: ProtoOffloadClient::new(channel.clone()),
            analysis: AnalysisClient::new(channel),
        }
    }

    // ---- Offload service --------------------------------------------------

    /// `Offload.NegotiateOffload(DeviceProfile) -> OffloadPolicy`.
    pub async fn negotiate_offload(&self, profile: DeviceProfile) -> Result<OffloadPolicy> {
        let resp = self
            .offload
            .clone()
            .negotiate_offload(profile)
            .await
            .map_err(|s| InferError::Rpc(format!("NegotiateOffload: {s}")))?;
        Ok(resp.into_inner())
    }

    /// `Offload.RefreshOffload(RefreshOffloadRequest) -> OffloadPolicy`.
    pub async fn refresh_offload(&self, req: RefreshOffloadRequest) -> Result<OffloadPolicy> {
        let resp = self
            .offload
            .clone()
            .refresh_offload(req)
            .await
            .map_err(|s| InferError::Rpc(format!("RefreshOffload: {s}")))?;
        Ok(resp.into_inner())
    }

    // ---- Analysis service -------------------------------------------------

    /// `Analysis.Analyze(AnalysisRequest) -> Verdict` (single unit).
    pub async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        let resp = self
            .analysis
            .clone()
            .analyze(req)
            .await
            .map_err(|s| InferError::Rpc(format!("Analyze: {s}")))?;
        Ok(resp.into_inner())
    }

    /// `Analysis.AnalyzeBatch(AnalysisBatch) -> VerdictBatch` (sampled frames).
    pub async fn analyze_batch(&self, batch: AnalysisBatch) -> Result<VerdictBatch> {
        let resp = self
            .analysis
            .clone()
            .analyze_batch(batch)
            .await
            .map_err(|s| InferError::Rpc(format!("AnalyzeBatch: {s}")))?;
        Ok(resp.into_inner())
    }

    /// `Analysis.AnalyzeStream(stream AnalysisRequest) -> stream Verdict` (bidi,
    /// for live capture). Returns a boxed stream of verdicts.
    pub async fn analyze_stream(
        &self,
        requests: BoxStream<'static, AnalysisRequest>,
    ) -> Result<BoxStream<'static, Result<Verdict>>> {
        let resp = self
            .analysis
            .clone()
            .analyze_stream(requests)
            .await
            .map_err(|s| InferError::Rpc(format!("AnalyzeStream: {s}")))?;

        let stream = resp.into_inner().map(|item| {
            item.map_err(|s| {
                aegis_core::Error::from(InferError::Rpc(format!("AnalyzeStream item: {s}")))
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
            client_cert_pem: b"cert".to_vec(),
            client_key_pem: b"key".to_vec(),
            ca_cert_pem: b"ca".to_vec(),
            server_domain: "cluster.local".into(),
        }
    }

    #[test]
    fn tls_identity_debug_redacts_material() {
        let shown = format!("{:?}", dummy_identity());
        assert!(shown.contains("cluster.local"));
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("key"));
        assert!(!shown.contains("cert"));
    }

    #[tokio::test]
    async fn connect_rejects_a_malformed_endpoint() {
        // No network: a malformed scheme must fail at endpoint construction,
        // proving we never dial without a well-formed mTLS endpoint.
        let err = OffloadClient::connect("not a url", &dummy_identity())
            .await
            .unwrap_err();
        // Maps onto the shared error type.
        assert!(matches!(err, aegis_core::Error::Other(_)));
    }
}
