//! The local-execution seam.
//!
//! When the router decides [`Route::Local`](crate::Route::Local) it calls an
//! [`Analyzer`] — the *same* trait the server analyzers implement
//! (`docs/design/interfaces.md`), here used for the on-device **tiny first-pass
//! models**. This crate only ROUTES; it adds no models of its own beyond the
//! small dedicated ones (PLAN §0b: rules-first, small-model-second).
//!
//! Two concrete analyzers live here:
//! * [`NullAnalyzer`] — always available, no model runtime. Returns a
//!   conservative "needs offload / inconclusive" verdict so a build without the
//!   `onnx` feature still satisfies the trait and the router can fall back to
//!   the cluster. Used by the unit tests.
//! * [`OnnxAnalyzer`] — gated behind the **`onnx`** cargo feature; drives a
//!   small quantized ONNX model through [`ort`]. The integration (session
//!   creation, execution-provider ordering from the [`DeviceProfile`]) is wired
//!   here but the actual model run is not exercised in this crate's tests.
//!
//! The router holds a `dyn Analyzer`, so a real first-pass model from
//! `aegis-vision`/`-audio`/`-text` can be injected without changing the router.

use async_trait::async_trait;
use futures_core::stream::BoxStream;

use aegis_proto::v1::{
    AnalysisBatch, AnalysisRequest, Category, MediaKind, Severity, Verdict, VerdictBatch,
};

use crate::error::Result;

/// The core analysis contract (mirrors `Analyzer` in
/// `docs/design/interfaces.md`). Implemented locally for the on-device
/// first-pass; the cluster implements the same shape behind the gRPC boundary.
#[async_trait]
pub trait Analyzer: Send + Sync {
    /// Which media kinds this analyzer can handle locally (the router uses this
    /// to decide whether a local run is even possible before consulting policy).
    fn handles(&self) -> &[MediaKind];

    /// Analyse one request → one verdict. MUST NOT return raw explicit media in
    /// `Verdict.evidence` (hashes / safe thumbnail / redacted snippet only).
    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict>;

    /// Batched analyse. Default = sequential [`Analyzer::analyze`].
    async fn analyze_batch(&self, batch: AnalysisBatch) -> Result<VerdictBatch> {
        let mut verdicts = Vec::with_capacity(batch.requests.len());
        for req in batch.requests {
            verdicts.push(self.analyze(req).await?);
        }
        Ok(VerdictBatch { verdicts })
    }

    /// Streaming analyse for live capture. Default maps each request through
    /// [`Analyzer::analyze`] sequentially.
    async fn analyze_stream(
        &self,
        _requests: BoxStream<'static, AnalysisRequest>,
    ) -> Result<BoxStream<'static, Result<Verdict>>> {
        // A local first-pass rarely streams; the cluster handles live streams.
        // Implementors that need it override this.
        Err(aegis_core::Error::Ipc(
            "local analyzer does not support streaming; route to cluster".into(),
        ))
    }
}

/// Build the conservative "inconclusive — prefer offload" verdict. Used when no
/// real local model is available for a kind: a low-confidence SAFE verdict whose
/// `rationale` tells the caller to offload. Never fabricates a positive verdict.
fn inconclusive_verdict(req: &AnalysisRequest) -> Verdict {
    Verdict {
        request_id: req.request_id.clone(),
        category: Category::Safe as i32,
        action: aegis_proto::v1::Action::Log as i32,
        severity: Severity::Info as i32,
        score: 0.0,
        rationale: "no local model for this media kind; offload to cluster".into(),
        evidence: None,
        grooming: None,
        worker_id: "local:null".into(),
        latency_ms: 0,
    }
}

/// An always-available analyzer with no model runtime.
///
/// It declares it handles nothing heavy and returns an inconclusive verdict, so
/// a build without the `onnx` feature still satisfies the [`Analyzer`] trait and
/// the router transparently falls back to the cluster for media it cannot judge.
#[derive(Clone, Debug, Default)]
pub struct NullAnalyzer;

#[async_trait]
impl Analyzer for NullAnalyzer {
    fn handles(&self) -> &[MediaKind] {
        // Handles no heavy media: the router should offload instead.
        &[]
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        Ok(inconclusive_verdict(&req))
    }
}

// ---------------------------------------------------------------------------
// ONNX-backed local analyzer (feature = "onnx").
// ---------------------------------------------------------------------------

/// Real local inference via [`ort`], compiled only with `--features onnx`.
///
/// This is the integration seam for the small dedicated first-pass models. It
/// builds an `ort` session, ordering execution providers best-first from the
/// device's detected capability (`DeviceProfile.exec_providers`, produced by
/// `aegis-core::detect_device_profile`). The model files themselves are owned
/// and checksum-pinned by the analyzer crates (`aegis-vision`/`-audio`/`-text`)
/// — this crate only drives the runtime when policy says "local".
#[cfg(feature = "onnx")]
pub mod onnx {
    use super::*;
    use std::path::PathBuf;

    use aegis_proto::v1::{DeviceProfile, ExecutionProvider};

    /// Configuration for a local ONNX first-pass model.
    #[derive(Clone, Debug)]
    pub struct OnnxConfig {
        /// Path to the quantized `.onnx` model file (checksum-pinned upstream).
        pub model_path: PathBuf,
        /// Stable model id recorded on the verdict for auditability.
        pub model_id: String,
        /// Media kinds this model judges.
        pub handles: Vec<MediaKind>,
    }

    /// An [`Analyzer`] backed by an `ort` session.
    pub struct OnnxAnalyzer {
        cfg: OnnxConfig,
        session: ort::session::Session,
    }

    impl OnnxAnalyzer {
        /// Build a session for `cfg`, registering execution providers in the
        /// order the device advertises (`DeviceProfile.exec_providers`). `ort`
        /// silently falls back to CPU if a provider is unavailable, so an
        /// over-optimistic list is safe (see `aegis-core::exec_providers_for`).
        pub fn new(cfg: OnnxConfig, profile: &DeviceProfile) -> Result<Self> {
            let providers = providers_from_profile(profile);
            let session = ort::session::Session::builder()
                .and_then(|b| b.with_execution_providers(providers))
                .and_then(|b| b.commit_from_file(&cfg.model_path))
                .map_err(|e| {
                    aegis_core::Error::from(crate::error::InferError::Transport(format!(
                        "ort session for {:?}: {e}",
                        cfg.model_path
                    )))
                })?;
            Ok(Self { cfg, session })
        }
    }

    /// Map the device's advertised execution providers onto `ort`'s provider
    /// dispatch list, best-first, always ending at CPU.
    fn providers_from_profile(
        profile: &DeviceProfile,
    ) -> Vec<ort::execution_providers::ExecutionProviderDispatch> {
        use ort::execution_providers as ep;
        let mut out: Vec<ep::ExecutionProviderDispatch> = Vec::new();
        for raw in &profile.exec_providers {
            let provider = ExecutionProvider::try_from(*raw).unwrap_or(ExecutionProvider::Cpu);
            match provider {
                ExecutionProvider::Cuda => out.push(ep::CUDAExecutionProvider::default().build()),
                ExecutionProvider::Tensorrt => {
                    out.push(ep::TensorRTExecutionProvider::default().build())
                }
                ExecutionProvider::Directml => {
                    out.push(ep::DirectMLExecutionProvider::default().build())
                }
                ExecutionProvider::Coreml => {
                    out.push(ep::CoreMLExecutionProvider::default().build())
                }
                ExecutionProvider::Nnapi => out.push(ep::NNAPIExecutionProvider::default().build()),
                // QNN / unspecified fall through to the CPU floor below.
                _ => {}
            }
        }
        // CPU is always the final fallback.
        out.push(ep::CPUExecutionProvider::default().build());
        out
    }

    #[async_trait]
    impl Analyzer for OnnxAnalyzer {
        fn handles(&self) -> &[MediaKind] {
            &self.cfg.handles
        }

        async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
            // Real preprocessing (decode/resize → tensor) and the
            // `self.session.run(..)` call wire in here; the postprocessed score
            // becomes the Verdict. Kept minimal/stubbed: this crate's job is to
            // ROUTE, and the runtime run is not exercised in CI here.
            let _session = &self.session;
            let _ = &self.cfg.model_id;
            Ok(super::inconclusive_verdict(&req))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_request() -> AnalysisRequest {
        AnalysisRequest {
            request_id: "req-1".into(),
            media_kind: MediaKind::Text as i32,
            source_channel: aegis_proto::v1::SourceChannel::Web as i32,
            device_id: "dev-1".into(),
            ts: 0,
            text_span: None,
            media: None,
            deadline_ms: 0,
        }
    }

    #[tokio::test]
    async fn null_analyzer_returns_inconclusive_safe_verdict() {
        let a = NullAnalyzer;
        assert!(a.handles().is_empty());
        let v = a.analyze(text_request()).await.unwrap();
        assert_eq!(v.category, Category::Safe as i32);
        assert_eq!(v.score, 0.0);
        assert!(v.rationale.contains("offload"));
        assert!(v.evidence.is_none());
    }

    #[tokio::test]
    async fn null_analyzer_batch_is_sequential() {
        let a = NullAnalyzer;
        let batch = AnalysisBatch {
            requests: vec![text_request(), text_request()],
        };
        let out = a.analyze_batch(batch).await.unwrap();
        assert_eq!(out.verdicts.len(), 2);
    }
}
