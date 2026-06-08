//! Crate-local error type.
//!
//! Per the Wave C build constraints, `bulwark-text` deliberately does **not**
//! depend on `bulwark-core` (to avoid build-order coupling), so it cannot use the
//! shared `bulwark_core::Error`/`Result` that the `Analyzer` trait nominally
//! returns. We define a local [`TextError`] with `thiserror` and convert into
//! `anyhow::Error` at the trait boundary, which is the form the orchestrator
//! reconciles once `bulwark-core` lands.

use thiserror::Error;

/// Errors produced while building or running the text detector.
#[derive(Debug, Error)]
pub enum TextError {
    /// The embedded lexicon failed to parse or compile (build-time data bug).
    #[error("lexicon error: {0}")]
    Lexicon(String),

    /// The request carried no `TextSpan` (wrong `media_kind` routed here).
    #[error("analysis request had no text_span (media_kind must be TEXT)")]
    MissingTextSpan,

    /// Conversation-state (de)serialization for the thread store failed.
    #[error("thread state codec error: {0}")]
    ThreadState(String),

    /// Optional classifier backstop error (only under the `classifier` feature).
    #[error("classifier error: {0}")]
    #[allow(dead_code)] // only constructed under the `classifier` feature
    Classifier(String),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, TextError>;
