//! The in-process flow vocabulary.
//!
//! These types are now **canonical in [`bulwark_core::flow`]** so `bulwark-net`
//! (which produces a [`CapturedFlow`]) and `bulwark-flow` (which turns it into
//! [`AnalysisUnit`]s) share ONE definition instead of duplicating it. They are
//! re-exported here unchanged for source compatibility with this crate's modules
//! and public API. See `bulwark_core::flow` for the full type documentation.

pub use bulwark_core::flow::{
    AnalysisUnit, CapturedFlow, FlowPayload, Header, HttpHead, InterceptDecision,
};
