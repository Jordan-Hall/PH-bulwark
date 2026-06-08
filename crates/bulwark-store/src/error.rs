//! Store-local error type, convertible into the workspace-wide
//! [`bulwark_core::Error`] so the [`crate::Store`] trait can return
//! `bulwark_core::Result<T>` per `docs/design/interfaces.md`.
//!
//! Backend driver errors (`rusqlite`, `sqlx`) are wrapped here and then funnel
//! into [`bulwark_core::Error::Other`] via `anyhow` at the trait boundary, which
//! keeps the shared error enum coarse while preserving the underlying cause.

/// Convenience result alias for crate-internal functions.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Errors raised by the persistence layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// A backend driver (SQLite/SQLCipher or Postgres) failed.
    #[error("storage backend error: {0}")]
    Backend(String),

    /// Opening, keying, or migrating the database failed.
    #[error("storage open/migrate error: {0}")]
    Open(String),

    /// Serializing or deserializing a stored blob (e.g. `ThreadState`,
    /// `reason_codes`) failed.
    #[error("serialization error: {0}")]
    Serde(String),

    /// At-rest encryption / key handling failed (SQLCipher key, `age` export).
    #[error("encryption error: {0}")]
    Crypto(String),

    /// The tamper-evident audit hash-chain did not verify: a row was edited,
    /// deleted, or re-ordered. This is a **security-relevant** integrity fault.
    #[error("audit log integrity violation: {0}")]
    Integrity(String),

    /// A value handed to the store was invalid (e.g. negative TTL, empty id).
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

impl StoreError {
    /// Construct a backend error from any displayable driver error.
    pub fn backend(e: impl std::fmt::Display) -> Self {
        StoreError::Backend(e.to_string())
    }

    /// Construct an open/migrate error.
    pub fn open(e: impl std::fmt::Display) -> Self {
        StoreError::Open(e.to_string())
    }

    /// Construct a serialization error.
    pub fn serde(e: impl std::fmt::Display) -> Self {
        StoreError::Serde(e.to_string())
    }

    /// Construct a crypto error.
    pub fn crypto(e: impl std::fmt::Display) -> Self {
        StoreError::Crypto(e.to_string())
    }

    /// Construct an integrity (tamper-detected) error.
    pub fn integrity(e: impl std::fmt::Display) -> Self {
        StoreError::Integrity(e.to_string())
    }

    /// Construct an invalid-value error.
    pub fn invalid(e: impl std::fmt::Display) -> Self {
        StoreError::InvalidValue(e.to_string())
    }
}

/// Funnel every store error into the shared workspace error via the `Other`
/// (anyhow) variant, preserving the message + classification in its `Display`.
impl From<StoreError> for bulwark_core::Error {
    fn from(e: StoreError) -> Self {
        bulwark_core::Error::Other(anyhow::Error::new(e))
    }
}

#[cfg(feature = "sqlite")]
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Backend(e.to_string())
    }
}

#[cfg(feature = "postgres")]
impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::Backend(e.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Serde(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_error_is_distinct() {
        let e = StoreError::integrity("row 5 hash mismatch");
        assert!(matches!(e, StoreError::Integrity(_)));
        assert!(e.to_string().contains("integrity"));
    }

    #[test]
    fn converts_into_core_error() {
        let e: bulwark_core::Error = StoreError::backend("disk full").into();
        // Funnels through the catch-all Other variant.
        assert!(matches!(e, bulwark_core::Error::Other(_)));
        assert!(e.to_string().contains("disk full"));
    }
}
