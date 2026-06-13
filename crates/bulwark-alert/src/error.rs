//! Crate-local error type.
//!
//! Per the Wave C build constraints, `bulwark-alert` does **not** depend on
//! `bulwark-core`; it carries its own `thiserror`-based error and an `anyhow`
//! escape hatch for transport/config plumbing. The public [`AlertSink`] trait
//! (see [`crate`]) is shaped identically to the contract in
//! `docs/design/interfaces.md` — only the error type differs (`AlertError`
//! here vs. `bulwark_core::Error` there). When the crates are wired together the
//! `From<AlertError>` impl is the single conversion point.
//!
//! [`AlertSink`]: crate::AlertSink

use thiserror::Error;

/// Result alias used throughout `bulwark-alert`.
pub type Result<T> = std::result::Result<T, AlertError>;

/// Everything that can go wrong raising a guardian alert.
#[derive(Debug, Error)]
pub enum AlertError {
    /// The alert event failed the redaction / safety invariant check before it
    /// could be rendered. This is a **hard stop**: we never email content that
    /// trips the C0 (forbidden-to-persist / forbidden-to-transmit) guard.
    #[error("alert rejected by safety invariant: {0}")]
    UnsafeContent(String),

    /// Configuration was missing or invalid (e.g. no recipients, blank SMTP
    /// host, or credentials not resolvable from the environment).
    #[error("alert configuration error: {0}")]
    Config(String),

    /// Rendering the human-readable email body failed.
    #[error("failed to render alert email: {0}")]
    Render(String),

    /// The underlying mail transport (SMTP today, Gmail API later) failed to
    /// build a message or deliver it.
    #[error("mail transport error: {0}")]
    Transport(String),

    /// A push-notification backend (self-hosted UnifiedPush, behind the `push`
    /// feature) failed to POST the redacted payload to the guardian endpoint.
    /// Alerting is best-effort, so callers may choose to log-and-continue on
    /// this rather than abort.
    #[cfg(feature = "push")]
    #[error("push delivery error: {0}")]
    Push(String),

    /// Catch-all for plumbing that surfaces as `anyhow::Error` (e.g. address
    /// parsing). Kept distinct so callers can still match the typed variants.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
