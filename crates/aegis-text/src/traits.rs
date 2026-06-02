//! aegis-text internal contract (docs/design/interfaces.md): the explainable
//! rule layer.
//!
//! The canonical `Analyzer` trait now lives in `aegis_core` and is implemented
//! directly in `analyzer.rs`; this module keeps only the crate-local
//! `GroomingRules` contract that exposes the deterministic rule layer so the
//! verdict stays explainable (rules FIRST, classifier SECOND).

use aegis_proto::{GroomingSignal, TextSpan};

use crate::state::ThreadState;

/// aegis-text internal contract: deterministic rules FIRST, classifier SECOND.
/// The rule layer is exposed so the verdict is explainable.
pub trait GroomingRules {
    /// Run the eight indicator rules + context multipliers (no model) for a
    /// span in the context of its thread, producing the explainable signal.
    fn evaluate(&self, span: &TextSpan, thread: &ThreadState) -> GroomingSignal;
}
