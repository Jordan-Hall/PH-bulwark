//! The in-process flow vocabulary.
//!
//! These types are now **canonical in [`aegis_core::flow`]** so `aegis-net`
//! (which produces a [`CapturedFlow`]) and `aegis-flow` (which turns it into
//! [`AnalysisUnit`]s) share ONE definition instead of duplicating it. They are
//! re-exported here unchanged for source compatibility with this crate's modules
//! and public API. See `aegis_core::flow` for the full type documentation.

pub use aegis_core::flow::{
    AnalysisUnit, CapturedFlow, FlowPayload, Header, HttpHead, InterceptDecision,
};
