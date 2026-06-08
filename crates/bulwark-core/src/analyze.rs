//! The canonical analysis contract.
//!
//! The **one** `Analyzer` trait that every analyzer implements:
//! `bulwark-vision` / `bulwark-audio` / `bulwark-video` / `bulwark-text` /
//! `bulwark-supervision` (server-side, heavy models) and `bulwark-infer`
//! (client-side, tiny first-pass). `bulwark-server` dispatches by
//! `AnalysisRequest.media_kind` over `&dyn Analyzer`.
//!
//! Streaming is handled at the server's gRPC layer (it loops `analyze` over the
//! inbound request stream), so the trait stays small — `handles` + `analyze`
//! plus a sequential `analyze_batch` default that GPU workers can override with
//! true batching.
//!
//! Privacy invariant (typed where possible, asserted everywhere): `analyze` MUST
//! NOT return raw explicit media in `Verdict.evidence` — hashes / safe thumbnail /
//! redacted snippet only.

use crate::Result;
use async_trait::async_trait;
use bulwark_proto::v1::{AnalysisBatch, AnalysisRequest, MediaKind, Verdict, VerdictBatch};

/// One analyzer over a single media kind (or several). See module docs.
#[async_trait]
pub trait Analyzer: Send + Sync {
    /// Which media kinds this analyzer handles (the server uses it to dispatch).
    fn handles(&self) -> &[MediaKind];

    /// Analyse one request → one verdict. MUST NOT put raw explicit media in
    /// `Verdict.evidence`.
    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict>;

    /// Batched analyse (e.g. sampled video frames). Default = sequential
    /// `analyze`; GPU workers override with real batching.
    async fn analyze_batch(&self, batch: AnalysisBatch) -> Result<VerdictBatch> {
        let mut verdicts = Vec::with_capacity(batch.requests.len());
        for req in batch.requests {
            verdicts.push(self.analyze(req).await?);
        }
        Ok(VerdictBatch { verdicts })
    }
}
