//! VPN mode — transparent, system-wide traffic capture (Windows).
//!
//! Unlike the explicit-proxy path ([`NetInterceptor::start_proxy_only`]) — which
//! needs each app/browser pointed at `127.0.0.1:8080` — VPN mode captures **all**
//! traffic at layer 3 via a TUN, so every app is filtered with no per-app config.
//!
//! We do NOT hand-roll a userspace TCP/IP stack: the [`tun2proxy`] crate owns the
//! wintun TUN + a smoltcp netstack and **redirects captured TCP to the local MITM
//! proxy** (`http://127.0.0.1:8080`, which speaks HTTP CONNECT) while **NATing
//! UDP/other traffic** straight out so the device keeps working. `setup(true)`
//! installs the default route and **restores host routing on teardown** (the
//! no-blackhole contract). We additionally block QUIC/UDP-443 so HTTP/3 can't slip
//! past the TCP MITM.
//!
//! ## Requirements (honest)
//! * **Admin** — creating the TUN adapter + owning the default route needs
//!   elevation ([`is_elevated`]). The runnable bin refuses to start un-elevated.
//! * **`wintun.dll`** — the WireGuard-signed driver shim must be next to the exe
//!   or on PATH ([`wintun_available`]). Not vendored in-repo (see crate README).
//! * **CA trust** — HTTPS inspection still needs the per-install root trusted;
//!   TUN capture does not change that.
//!
//! ## FFI ISOLATION
//! The crate root sets `#![forbid(unsafe_code)]`. The only `unsafe` here is the
//! Windows elevation probe (`OpenProcessToken`/`GetTokenInformation`) and the
//! `wintun.dll` presence load — both localized + justified, matching the policy
//! used by `tun::windows` / `ca::dpapi` / `truststore`.
#![allow(unsafe_code)]

pub use tokio_util::sync::CancellationToken;
use tun2proxy::{ArgDns, ArgProxy, Args};

use crate::quic::QuicDowngrade;
use crate::{NetError, Result};

/// The local MITM proxy captured TCP is redirected to. It speaks HTTP CONNECT, so
/// the scheme MUST be `http` (tun2proxy's `ProxyType::Http`).
const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:8080";
/// TUN adapter name shown to the OS.
const DEFAULT_TUN_NAME: &str = "Aegis";

/// VPN-mode configuration.
#[derive(Clone, Debug)]
pub struct VpnConfig {
    /// HTTP MITM proxy URL that captured TCP is redirected to (the local hudsucker
    /// proxy). Must be an `http://` URL — the proxy speaks CONNECT.
    pub proxy_url: String,
    /// TUN adapter name.
    pub tun_name: String,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            proxy_url: DEFAULT_PROXY_URL.to_string(),
            tun_name: DEFAULT_TUN_NAME.to_string(),
        }
    }
}

impl VpnConfig {
    /// The MITM proxy URL captured TCP is sent to.
    pub fn proxy_url(&self) -> &str {
        &self.proxy_url
    }
}

/// Whether this process is privileged enough for VPN mode — **Administrator** on
/// Windows, **root** on Unix — to create the TUN adapter and own the default
/// route. The runnable bin refuses to start otherwise.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use std::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: standard Win32 token-elevation probe. We open our OWN process token
    // (TOKEN_QUERY), query TokenElevation into a stack TOKEN_ELEVATION, and close
    // the handle. All pointers reference live stack locals for the duration of the
    // synchronous calls; failures are treated as "not elevated".
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// Unix (Linux/macOS): privileged == effective uid 0 (root / `sudo`).
#[cfg(unix)]
pub fn is_elevated() -> bool {
    // SAFETY: `geteuid` takes no args, has no preconditions, and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// On Windows, whether `wintun.dll` can be loaded (it must ship next to the exe or
/// be on PATH) — a friendly pre-flight check. On Linux/macOS the OS supplies the
/// TUN device (`/dev/net/tun` / utun), so this is always true (tun2proxy opens it).
#[cfg(windows)]
pub fn wintun_available() -> bool {
    // SAFETY: `wintun::load` LoadLibrary's wintun.dll; used here purely as a
    // presence probe and the returned table is dropped immediately.
    unsafe { wintun::load() }.is_ok()
}

/// Non-Windows: the OS provides the TUN device; nothing to pre-check.
#[cfg(not(windows))]
pub fn wintun_available() -> bool {
    true
}

/// The exact command to relaunch with the privileges VPN mode needs
/// (`Start-Process -Verb RunAs` on Windows, `sudo` on Unix).
pub fn elevation_command() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "aegis_vpn".to_string());
    #[cfg(windows)]
    {
        format!("Start-Process -Verb RunAs '{exe}'")
    }
    #[cfg(not(windows))]
    {
        format!("sudo '{exe}'")
    }
}

/// Run VPN mode until `shutdown` is cancelled.
///
/// Brings up the TUN via tun2proxy, redirects captured TCP to the MITM proxy,
/// NATs other traffic out, blocks QUIC so HTTP/3 can't bypass, installs the
/// default route, and restores host routing on exit. **Requires admin +
/// `wintun.dll`** (check [`is_elevated`] / [`wintun_available`] first).
pub async fn run_vpn(cfg: VpnConfig, shutdown: CancellationToken) -> Result<()> {
    let proxy = ArgProxy::try_from(cfg.proxy_url())
        .map_err(|e| NetError::proxy(format!("invalid MITM proxy URL {}: {e}", cfg.proxy_url())))?;

    // Block QUIC/UDP-443 so HTTP/3 can't slip past the TCP MITM. Best-effort —
    // removed on exit. Empty allowlist = downgrade all QUIC to TCP.
    let quic = QuicDowngrade::new(true, Vec::new());
    if let Err(e) = quic.apply_rule() {
        tracing::warn!(error = %e, "could not apply QUIC downgrade; HTTP/3 may bypass the filter");
    }

    // tun2proxy owns the wintun TUN + smoltcp netstack. `setup(true)` installs the
    // default route and restores it on teardown; DNS over TCP keeps lookups on the
    // captured/redirected path.
    let mut args = Args::default();
    args.proxy(proxy)
        .tun(cfg.tun_name.clone())
        .dns(ArgDns::OverTcp)
        .setup(true);

    tracing::info!(
        tun = %cfg.tun_name,
        proxy = %cfg.proxy_url(),
        "VPN mode: starting tun2proxy (all TCP -> MITM, UDP NAT'd, QUIC blocked)"
    );

    let result = tun2proxy::general_run_async(args, tun2proxy::DEFAULT_MTU, false, shutdown).await;

    let _ = quic.remove_rule();
    result.map_err(|e| NetError::tun(format!("tun2proxy VPN run: {e}")))?;
    tracing::info!("VPN mode stopped; host routing restored");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_proxy_url_parses_as_http() {
        let p = ArgProxy::try_from(VpnConfig::default().proxy_url()).expect("valid proxy url");
        assert_eq!(p.proxy_type, tun2proxy::ProxyType::Http);
    }

    #[test]
    fn defaults_are_local_http_aegis_tun() {
        let c = VpnConfig::default();
        assert!(c.proxy_url.starts_with("http://127.0.0.1:"));
        assert_eq!(c.tun_name, "Aegis");
    }

    #[test]
    fn elevation_command_uses_runas() {
        assert!(elevation_command().contains("RunAs"));
    }
}
