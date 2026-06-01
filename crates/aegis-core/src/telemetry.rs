//! Tracing / log subscriber setup.
//!
//! NOTE ON THE NAME: this module configures **local diagnostic logging only**.
//! Aegis ships **no telemetry** (PLAN §3) — nothing here phones home, exports
//! spans off-device, or aggregates metrics remotely. It is `tracing-subscriber`
//! wiring for the operator's own console/log file.

use serde::{Deserialize, Serialize};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// How log lines should be rendered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable, colourised text (good for a developer console).
    #[default]
    Pretty,
    /// Structured JSON (one object per line) for log shippers / files.
    Json,
}

/// Logging configuration. Lives under [`crate::Config`] so it is loadable from
/// the same TOML + env surface as everything else.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Render format.
    pub format: LogFormat,
    /// Default directive used when `RUST_LOG` / `AEGIS_LOG` is unset
    /// (e.g. `"info,aegis_net=debug"`).
    pub default_directive: String,
    /// Whether to include the target (module path) on each line.
    pub with_target: bool,
    /// Whether to include source file + line number.
    pub with_location: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            format: LogFormat::Pretty,
            default_directive: "info".to_owned(),
            with_target: true,
            with_location: false,
        }
    }
}

/// Initialise the global `tracing` subscriber from a [`LoggingConfig`].
///
/// The env filter reads `AEGIS_LOG` first, then falls back to `RUST_LOG`, then
/// to [`LoggingConfig::default_directive`]. JSON vs. pretty is chosen by
/// [`LoggingConfig::format`].
///
/// Safe to call once at process start. Returns an error (rather than panicking)
/// if a subscriber is already installed, so test harnesses and embedders can
/// recover.
pub fn init_tracing(cfg: &LoggingConfig) -> crate::Result<()> {
    let filter = EnvFilter::try_from_env("AEGIS_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .or_else(|_| EnvFilter::try_new(&cfg.default_directive))
        .map_err(|e| crate::Error::config(format!("invalid log filter: {e}")))?;

    // Build the format layer per the requested rendering. Both branches share
    // the same filter; we pick the concrete fmt layer up front to keep the
    // subscriber types monomorphic.
    let registry = tracing_subscriber::registry().with(filter);

    match cfg.format {
        LogFormat::Json => {
            let layer = fmt::layer()
                .json()
                .with_target(cfg.with_target)
                .with_file(cfg.with_location)
                .with_line_number(cfg.with_location);
            registry
                .with(layer)
                .try_init()
                .map_err(|e| crate::Error::config(format!("tracing init failed: {e}")))
        }
        LogFormat::Pretty => {
            let layer = fmt::layer()
                .with_target(cfg.with_target)
                .with_file(cfg.with_location)
                .with_line_number(cfg.with_location);
            registry
                .with(layer)
                .try_init()
                .map_err(|e| crate::Error::config(format!("tracing init failed: {e}")))
        }
    }
}

/// Convenience: initialise tracing with default (pretty, `info`) settings.
pub fn init_tracing_default() -> crate::Result<()> {
    init_tracing(&LoggingConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_logging_is_pretty_info() {
        let c = LoggingConfig::default();
        assert_eq!(c.format, LogFormat::Pretty);
        assert_eq!(c.default_directive, "info");
        assert!(c.with_target);
    }

    #[test]
    fn log_format_serde_round_trips() {
        let j = serde_json::to_string(&LogFormat::Json).unwrap();
        assert_eq!(j, "\"json\"");
        let f: LogFormat = serde_json::from_str("\"pretty\"").unwrap();
        assert_eq!(f, LogFormat::Pretty);
    }

    // We do not assert global init here: only one subscriber can be installed
    // per process and other test binaries may race it. `init_tracing` returning
    // a `Result` (not a panic) is the contract that makes it test-safe.
}
