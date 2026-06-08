//! Shared crate error type for Bulwark.
//!
//! Every in-process trait in [`docs/design/interfaces.md`] returns
//! [`crate::Result<T>`] so the whole workspace funnels failures through one
//! `thiserror` enum. Crates wrap their own dependency errors into one of these
//! variants (or [`Error::Other`] for the long tail) rather than inventing a
//! parallel error type.

use std::path::PathBuf;

/// The crate-wide result alias used across every Bulwark trait boundary.
pub type Result<T> = std::result::Result<T, Error>;

/// The shared Bulwark error type.
///
/// Variants are intentionally coarse: they classify a failure for the caller
/// (config vs. I/O vs. capability detection vs. a wrapped foreign error) without
/// trying to mirror every dependency's error surface. Downstream crates add
/// context via [`anyhow`] at the edges and convert into [`Error::Other`] when no
/// dedicated variant fits.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Configuration could not be loaded, merged, or deserialized.
    #[error("configuration error: {0}")]
    Config(String),

    /// A required configuration file was missing on disk.
    #[error("configuration file not found: {0}")]
    ConfigNotFound(PathBuf),

    /// Underlying I/O failure (file, socket, pipe).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Device-capability detection failed irrecoverably. Detection is otherwise
    /// best-effort and falls back to conservative defaults; this is reserved for
    /// the rare case where even that is impossible.
    #[error("device capability detection failed: {0}")]
    Detection(String),

    /// A value was outside the range the caller requires (e.g. a score that is
    /// not in `0.0..=1.0`, a port of `0`).
    #[error("invalid value: {0}")]
    InvalidValue(String),

    /// Local IPC / channel failure (used by the in-process glue layer).
    #[error("ipc error: {0}")]
    Ipc(String),

    /// Catch-all for wrapped foreign errors that have no dedicated variant.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// Convenience constructor for a configuration error from any displayable
    /// value (keeps call sites free of `.to_string()` noise).
    pub fn config(msg: impl std::fmt::Display) -> Self {
        Error::Config(msg.to_string())
    }

    /// Convenience constructor for a detection error.
    pub fn detection(msg: impl std::fmt::Display) -> Self {
        Error::Detection(msg.to_string())
    }

    /// Convenience constructor for an invalid-value error.
    pub fn invalid_value(msg: impl std::fmt::Display) -> Self {
        Error::InvalidValue(msg.to_string())
    }
}

/// Convert a `figment` extraction error into a [`Error::Config`].
impl From<figment::Error> for Error {
    fn from(e: figment::Error) -> Self {
        Error::Config(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_human_readable() {
        let e = Error::config("missing smtp host");
        assert_eq!(e.to_string(), "configuration error: missing smtp host");
    }

    #[test]
    fn io_error_converts() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "nope");
        let e: Error = io.into();
        assert!(matches!(e, Error::Io(_)));
    }

    #[test]
    fn anyhow_error_converts() {
        let e: Error = anyhow::anyhow!("boom").into();
        assert!(matches!(e, Error::Other(_)));
    }
}
