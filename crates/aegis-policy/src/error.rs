//! Crate-local error types.
//!
//! `aegis-policy` deliberately does **not** depend on `aegis-core` (Wave-C
//! isolation rule): a pure, deterministic policy engine should not pull in the
//! client/server plumbing crate. We therefore define our own small error type
//! over `thiserror`, and a crate-local `Result` alias.

/// Errors that can arise while loading or validating a [`crate::PolicyConfig`].
///
/// Deciding an action is **infallible** (it always yields a [`crate::PolicyDecision`],
/// failing safe), so these errors are confined to configuration handling.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// A figment provider (file / env / defaults) failed to load or merge.
    #[error("failed to load policy configuration: {0}")]
    Load(#[from] figment::Error),

    /// The merged configuration is structurally valid but semantically wrong
    /// (e.g. thresholds out of range or out of order). Carries a human-readable
    /// reason so a misconfiguration is obvious in logs.
    #[error("invalid policy configuration: {0}")]
    Invalid(String),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, PolicyError>;
