//! # bulwark-infer
//!
//! **Local-vs-cluster routing and mobile offload.** This is the client's single
//! decision point for *where* each analysis unit runs: the cheap, explainable
//! grooming text rules always run on-device, while heavy image/audio/video work
//! offloads to the user's own cluster on mobile / low-power devices. It is also
//! the client's single door to the cluster's `Analysis` / `Offload` gRPC
//! services over **mTLS**.
//!
//! See `docs/design/interfaces.md` (`OffloadRouter`, `Analyzer`),
//! `docs/design/architecture.md` §4 (latency budget + guard-rails), and
//! `PLAN.md` §1 (thin client, offload heavy work on mobile).
//!
//! ## What this crate does — and deliberately does NOT do
//!
//! - **It ROUTES.** The core is a pure decision table ([`policy::decide`]) over
//!   the negotiated [`OffloadPolicy`] + live RTT + cluster backpressure +
//!   battery. No models live here.
//! - **Minimal AI** (PLAN §0b). The only local execution is through the
//!   [`Analyzer`] seam, which drives the *small dedicated* first-pass models
//!   owned by `bulwark-vision`/`-audio`/`-text`. The actual ONNX run goes through
//!   [`ort`] behind the **`onnx`** cargo feature; with the feature off the
//!   router still compiles, decides, and falls back to the cluster.
//! - **mTLS only.** The [`client::OffloadClient`] fails closed: no client
//!   identity / CA root → no connection (architecture.md §5). No telemetry; the
//!   only outbound connection is to the user's own cluster.
//!
//! ## Routing decision table (summary)
//!
//! | Condition (priority order) | Route |
//! |---|---|
//! | media kind is TEXT (grooming rules cheap + explainable) | **Local** |
//! | live RTT > `max_local_rtt_ms` | **Local** |
//! | cluster `queue_depth` > `cluster_queue_backpressure` | **Local** |
//! | heavy media AND on battery below `min_battery_pct` | **Cluster** |
//! | heavy media AND policy says run-this-kind-local | **Local** |
//! | heavy media AND policy says offload | **Cluster** |
//! | (no policy yet / cluster unreachable) | **Local** (fail-safe) |
//!
//! The full table with rationale lives on [`policy`].
//!
//! ## Quick start
//! ```no_run
//! use std::sync::Arc;
//! use bulwark_infer::{DefaultOffloadRouter, OffloadRouter, NullAnalyzer};
//! use bulwark_infer::client::{OffloadClient, ClientTlsIdentity};
//! use bulwark_core::detect_device_profile;
//!
//! # async fn run(tls: ClientTlsIdentity) -> bulwark_core::Result<()> {
//! let client = OffloadClient::connect("https://gateway.local:8443", &tls).await?;
//! let router = DefaultOffloadRouter::new(Arc::new(NullAnalyzer), client);
//!
//! // Negotiate a policy from this device's detected capabilities.
//! let _policy = router.negotiate(detect_device_profile()).await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod analyzer;
pub mod client;
pub mod error;
pub mod policy;
pub mod router;

// --- Curated public prelude ---

pub use analyzer::NullAnalyzer;
pub use bulwark_core::Analyzer;
pub use client::{ClientTlsIdentity, OffloadClient};
pub use error::{InferError, Result};
pub use policy::{decide, is_heavy, LiveConditions, PolicySnapshot, Route};
pub use router::{DefaultOffloadRouter, OffloadRouter};

/// Re-export of the wire contract so downstream crates can use the proto types
/// (`DeviceProfile`, `OffloadPolicy`, `AnalysisRequest`, `Verdict`, …) without a
/// separate `bulwark-proto` import.
pub use bulwark_proto as proto;
