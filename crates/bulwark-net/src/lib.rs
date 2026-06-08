//! # bulwark-net — the interception layer (SECURITY-CRITICAL crate)
//!
//! The client data-plane's traffic-capture + decryption layer. It implements the
//! [`Interceptor`] contract (`docs/design/interfaces.md`) and owns the system's
//! single most dangerous secret: the **per-install root CA private key**
//! (`docs/security/threat-model.md` Asset 1 — the CROWN JEWEL).
//!
//! ## What it does
//! * A platform **TUN** abstraction ([`tun::TunDevice`]) — real on Windows via
//!   `wintun` (WireGuard's pre-signed driver); Linux (`tun-rs`) / Android
//!   (`VpnService`) are stubbed behind `cfg` with documented `todo!()`s.
//! * A transparent **MITM proxy** ([`proxy`]) over `hudsucker` (hyper + rustls +
//!   rcgen leaf certs) that decrypts HTTP(S) and emits flows for classification.
//! * **Per-install CA management** ([`ca`]): generates a unique root CA on first
//!   run (`rcgen`); the key is wrapped by an OS keystore ([`ca::CaKeyStore`] —
//!   DPAPI on Windows) and **never shipped, baked-in, or transmitted**.
//! * **QUIC downgrade** ([`quic`]): block UDP/443 so apps fall back to
//!   inspectable TCP.
//! * **Cert-pinning detection** ([`pinning`]): a rejected MITM handshake emits a
//!   signal to route that host to the on-device agent (OCR); **fail-open + log**
//!   by default, configurable.
//!
//! ## Crown-jewel invariants (non-negotiable — threat-model Asset 1)
//! * The CA is **per install**. There is NO shared / baked-in CA. Any attempt to
//!   load one is rejected by [`ca::reject_shared_ca`].
//! * The CA private key is **non-exportable / wrapped at rest** by the OS
//!   keystore and **never leaves the host** (no network egress of the key).
//! * A missing/unusable CA key is **fail-CLOSED** (block + alert), never a silent
//!   pass-through. A cert-pinned host is **fail-OPEN + log** (documented gap).
//! * **Uninstall removes our root from the trust store** ([`truststore::
//!   uninstall_root`]) — an orphaned root is a latent MITM backdoor.
//!
//! ## Safety / FFI policy
//! `#![forbid(unsafe_code)]` is set crate-wide. The unavoidable FFI lives in
//! exactly two modules, each of which locally re-enables `unsafe` with an
//! `#![allow(unsafe_code)]` and a `// SAFETY:` justification on **every** block:
//!   * [`ca::dpapi`] — DPAPI `CryptProtectData` / `CryptUnprotectData` via the
//!     `windows` crate, plus the trust-store cert APIs in [`truststore`].
//!   * [`tun::windows`] — loading `wintun.dll`.
//!
//! No `unsafe` leaks into the proxy / CA / interceptor logic.
//!
//! ## No AI/ML, no telemetry
//! This crate does pure protocol interception. There are no models and nothing
//! reports off-device (PLAN §0b, §3).

// `deny` (not `forbid`) at the root so the three isolated FFI modules
// (ca::dpapi, truststore, tun::windows) can locally `#![allow(unsafe_code)]`
// for audited, SAFETY-documented blocks. Unsafe stays denied everywhere else.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod ca;
pub mod config;
pub mod error;
pub mod interceptor;
pub mod pinning;
pub mod proxy;
pub mod quic;
pub mod truststore;
pub mod tun;
// VPN mode is DESKTOP (Windows/Linux/macOS) — tun2proxy-backed. Mobile uses the
// native VpnService / NetworkExtension shells instead.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub mod vpn;

// --- Curated public API -----------------------------------------------------

pub use ca::{CaKeyStore, CaManager, DevInMemoryKeyStore, KeyStoreTier};
pub use config::NetConfig;
pub use error::{NetError, Result};
pub use interceptor::{CapturedFlow, FlowPayload, InterceptDecision, Interceptor, NetInterceptor};
pub use pinning::{HostCapability, PinningRegistry, PinningSignal};
pub use proxy::{FlowReceiver, FlowSender, MitmProxy};
pub use quic::QuicDowngrade;
pub use truststore::StoreScope;
#[cfg(target_os = "android")]
pub use tun::open_tun_from_fd;
pub use tun::{open_tun, TunConfig, TunDevice};
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub use vpn::{
    elevation_command, is_elevated, run_vpn, wintun_available, CancellationToken, VpnConfig,
};

// Re-export the proto SourceChannel so downstream code can name the flow source
// without a separate bulwark-proto import.
pub use bulwark_proto::SourceChannel;
