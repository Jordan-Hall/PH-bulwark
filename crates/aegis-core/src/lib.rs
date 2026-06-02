//! # aegis-core
//!
//! The shared foundation every other Aegis crate imports: configuration,
//! the workspace-wide error type, local diagnostic logging, device-capability
//! detection, and the identifier newtypes that wrap the `aegis.v1` wire ids.
//!
//! See `docs/design/architecture.md` (this is the in-process glue that *produces*
//! a [`DeviceProfile`]) and `docs/design/interfaces.md` (every trait returns
//! [`Result`]).
//!
//! Design constraints honoured here:
//! * `#![forbid(unsafe_code)]` — no FFI lives in this crate.
//! * **No AI/ML** (PLAN §0b): device detection is pure platform probing.
//! * **No telemetry** (PLAN §3): nothing here reports off-device; the
//!   `telemetry` module is local logging only.
//!
//! ## Quick start
//! ```no_run
//! use aegis_core::{Config, init_tracing, detect_device_profile};
//!
//! # fn main() -> aegis_core::Result<()> {
//! let config = Config::load_default()?;
//! config.validate()?;
//! init_tracing(&config.logging)?;
//!
//! let profile = detect_device_profile(); // hand to aegis-infer's OffloadRouter
//! tracing::info!(platform = %profile.platform, cores = profile.cpu_cores, "device detected");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod device;
pub mod error;
pub mod flow;
pub mod ids;
pub mod telemetry;

// --- Curated public prelude: the names other crates rely on directly. ---

pub use config::{
    ClusterConfig, Config, ModelConfig, PolicyPaths, SmtpConfig, CONFIG_PATH_ENV, ENV_PREFIX,
};
pub use device::{
    detect_device_profile, detect_device_profile_with, detect_platform, exec_providers_for,
    DetectionHints,
};
pub use error::{Error, Result};
pub use flow::{AnalysisUnit, CapturedFlow, FlowPayload, Header, HttpHead, InterceptDecision};
pub use ids::{DeviceId, RequestId, ThreadId};
pub use telemetry::{init_tracing, init_tracing_default, LogFormat, LoggingConfig};

/// Re-export of the wire contract so downstream crates can `use aegis_core::proto`
/// without a separate `aegis-proto` import when they only need a few types.
pub use aegis_proto as proto;
