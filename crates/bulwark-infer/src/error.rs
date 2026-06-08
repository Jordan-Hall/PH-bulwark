//! Errors for `bulwark-infer`.
//!
//! Per `docs/design/interfaces.md`, the [`OffloadRouter`] trait returns
//! [`bulwark_core::Result`], so this crate funnels its failures through the shared
//! workspace [`bulwark_core::Error`] rather than inventing a parallel type. A small
//! [`InferError`] classifies the failures unique to routing/offload (transport,
//! mTLS material, no local model) and converts into the shared error via the
//! `anyhow` escape hatch — keeping the trait signature exactly as specified.
//!
//! [`OffloadRouter`]: crate::OffloadRouter

use thiserror::Error;

/// The crate-wide result alias — the shared workspace [`bulwark_core::Result`], so
/// `bulwark-infer` slots straight into the [`crate::OffloadRouter`] contract.
pub type Result<T> = bulwark_core::Result<T>;

/// Failures specific to local-vs-cluster routing and the offload client.
///
/// These are wrapped into [`bulwark_core::Error::Other`] (the `anyhow` long tail)
/// at the trait boundary so the public surface stays
/// `bulwark_core::Result<T>`. Callers that want the detail can downcast.
#[derive(Debug, Error)]
pub enum InferError {
    /// The gRPC channel to the cluster could not be built or connected
    /// (DNS, TLS handshake, endpoint unreachable).
    #[error("offload transport error: {0}")]
    Transport(String),

    /// mTLS material (client identity / CA root) was missing or unreadable.
    /// The cluster channel MUST be mutually authenticated (architecture.md §5),
    /// so we fail closed rather than dial in the clear.
    #[error("mTLS configuration error: {0}")]
    Tls(String),

    /// A unit was routed [`crate::Route::Local`] but no local [`crate::Analyzer`]
    /// is wired (e.g. the `onnx` feature is off and no fallback was supplied).
    #[error("no local analyzer available for {0:?}")]
    NoLocalAnalyzer(bulwark_proto::v1::MediaKind),

    /// The cluster returned an error status for an `Analyze`/`Offload` RPC.
    #[error("cluster rpc failed: {0}")]
    Rpc(String),

    /// No offload policy has been negotiated yet (call `negotiate` first), and
    /// no static fallback policy was configured.
    #[error("no offload policy negotiated")]
    NoPolicy,
}

impl From<InferError> for bulwark_core::Error {
    fn from(e: InferError) -> Self {
        // Map onto the shared error. There is no dedicated network variant in
        // bulwark_core::Error, so transport/rpc/tls land in the `Other` long tail
        // (preserving the message); a missing analyzer is an Ipc-class glue gap.
        match e {
            InferError::NoLocalAnalyzer(_) => bulwark_core::Error::Ipc(e.to_string()),
            other => bulwark_core::Error::Other(anyhow::anyhow!(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::MediaKind;

    #[test]
    fn infer_error_maps_into_shared_error() {
        let e: bulwark_core::Error = InferError::Transport("dial failed".into()).into();
        assert!(matches!(e, bulwark_core::Error::Other(_)));

        let e: bulwark_core::Error = InferError::NoLocalAnalyzer(MediaKind::Image).into();
        assert!(matches!(e, bulwark_core::Error::Ipc(_)));
    }
}
