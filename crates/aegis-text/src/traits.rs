//! Trait contracts this crate implements (docs/design/interfaces.md).
//!
//! interfaces.md declares the `Analyzer` and `GroomingRules` traits in terms of
//! a shared `aegis_core::Result`. Per the Wave C build constraints, `aegis-text`
//! must NOT depend on `aegis-core` (build-order coupling), so the traits are
//! mirrored here verbatim except that `aegis_core::Result<T>` is rendered as
//! `anyhow::Result<T>` — the same `Result`/`thiserror` shape the orchestrator
//! reconciles when `aegis-core` lands. Names, arguments and ownership are
//! unchanged (workflow hand-off rule #1).
//!
//! These traits are re-homed into `aegis-core` later; this module exists so the
//! crate compiles and is testable standalone in the meantime.

use async_trait::async_trait;
use futures_core::stream::BoxStream;

use aegis_proto::{AnalysisBatch, AnalysisRequest, GroomingSignal, MediaKind, TextSpan, Verdict, VerdictBatch};

use crate::state::ThreadState;

/// The core analysis contract (interfaces.md §`Analyzer`). The same trait is
/// implemented server-side by the heavy analyzers and client-side by the local
/// first-pass; `aegis-server` dispatches by `AnalysisRequest.media_kind`.
#[async_trait]
pub trait Analyzer: Send + Sync {
    /// Which media kinds this analyzer handles (server uses it to dispatch).
    fn handles(&self) -> &[MediaKind];

    /// Analyse one request → one verdict. MUST NOT return raw explicit media in
    /// `Verdict.evidence` (hashes / safe thumbnail / redacted snippet only).
    async fn analyze(&self, req: AnalysisRequest) -> anyhow::Result<Verdict>;

    /// Batched analyse. Default = sequential `analyze`.
    async fn analyze_batch(&self, batch: AnalysisBatch) -> anyhow::Result<VerdictBatch> {
        let mut verdicts = Vec::with_capacity(batch.requests.len());
        for req in batch.requests {
            verdicts.push(self.analyze(req).await?);
        }
        Ok(VerdictBatch { verdicts })
    }

    /// Streaming analyse for live capture. Returns a verdict stream.
    async fn analyze_stream(
        &self,
        requests: BoxStream<'static, AnalysisRequest>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<Verdict>>>;
}

/// aegis-text internal contract (interfaces.md): deterministic rules FIRST,
/// classifier SECOND. The rule layer is exposed so the verdict is explainable.
pub trait GroomingRules {
    /// Run the eight indicator rules + context multipliers (no model) for a
    /// span in the context of its thread, producing the explainable signal.
    fn evaluate(&self, span: &TextSpan, thread: &ThreadState) -> GroomingSignal;
}
