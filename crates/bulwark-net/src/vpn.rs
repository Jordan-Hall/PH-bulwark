//! VPN mode — transparent, system-wide traffic capture.
//!
//! Unlike the explicit-proxy path ([`NetInterceptor::start_proxy_only`]) — which
//! needs each app/browser pointed at `127.0.0.1:8080` — VPN mode captures **all**
//! traffic at layer 3 via a TUN, so every app is filtered with no per-app config.
//!
//! The current permissive replacement path uses a first-party TUN abstraction plus
//! a `smoltcp` bridge scaffold. The setup/teardown and packet parser are wired,
//! but the full TCP socket pump remains fail-closed until Linux/macOS/Android
//! device testing proves it will not blackhole a supervised device. We also block
//! QUIC/UDP-443 so HTTP/3 can't slip past the TCP TLS inspection once the bridge is enabled.
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

mod netstack;

use crate::tun::{open_tun, TunConfig};
use crate::Result;

/// The local TLS-inspecting proxy captured TCP is redirected to. It speaks HTTP CONNECT, so
/// the scheme MUST be `http` (tun2proxy's `ProxyType::Http`).
const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:8080";
/// TUN adapter name shown to the OS.
const DEFAULT_TUN_NAME: &str = "Bulwark";

/// VPN-mode configuration.
#[derive(Clone, Debug)]
pub struct VpnConfig {
    /// HTTP TLS-inspecting proxy URL that captured TCP is redirected to (the local hudsucker
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
    /// The TLS-inspecting proxy URL captured TCP is sent to.
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
        .unwrap_or_else(|_| "bulwark_vpn".to_string());
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
/// Status: on unix/Android the full fd-driven pump runs inside [`netstack`]
/// (per-flow TCP terminate → CONNECT to the local TLS-inspecting proxy → splice;
/// DNS forward; QUIC drop) — host-tested, on-device validation pending. On
/// Windows (wintun) the pump deliberately still fails closed until its own
/// spike proves it will not blackhole a supervised device.
pub async fn run_vpn(cfg: VpnConfig, shutdown: CancellationToken) -> Result<()> {
    let bridge = netstack::BridgeConfig::from_vpn(&cfg)?;
    let mut tun = open_tun()?;
    let tun_cfg = TunConfig {
        name: cfg.tun_name.clone(),
        ..TunConfig::default()
    };

    let result = async {
        tun.up(&tun_cfg)?;
        tun.install_routing(&tun_cfg)?;
        netstack::run_netstack(tun.as_ref(), bridge, shutdown).await
    }
    .await;

    let teardown = tun.teardown_routing();
    let close = tun.close();

    result?;
    teardown?;
    close
}

/// Build the in-process TLS-inspecting interceptor for VPN mode (proxy on
/// `127.0.0.1:8080`, started later by [`run_android_data_path`]).
///
/// `Some(ca_dir)` → the per-install CA persists across sessions via the
/// app-sandbox [`crate::ca::FileKeyStore`] (Android passes `filesDir/ca`
/// through `startVpn`'s configJson). `None` → SESSION-ONLY in-memory CA
/// (trust + pinning learning reset every restart) — kept as a fallback and
/// logged loudly; note the in-memory tier is refused by the CA loader outside
/// tests, so on a real device a missing `ca_dir` fails the build (fail-closed
/// on the crown jewel, surfaced by the caller as a protection-status alert).
///
/// Cross-platform on purpose so HOST tests prove CA persistence (same
/// fingerprint across two builds over one directory) without a device.
pub fn build_interceptor(
    ca_dir: Option<std::path::PathBuf>,
) -> Result<std::sync::Arc<crate::NetInterceptor>> {
    use crate::ca::{CaKeyStore, DevInMemoryKeyStore, FileKeyStore};
    use crate::{NetConfig, NetInterceptor};
    use std::sync::Arc;

    let net_cfg = NetConfig {
        proxy_listen: "127.0.0.1:8080".to_string(),
        ..Default::default()
    };
    let keystore: Arc<dyn CaKeyStore> = match ca_dir {
        Some(dir) => Arc::new(FileKeyStore::new(dir)),
        None => {
            tracing::warn!(
                "no ca_dir provided: per-install CA would be SESSION-ONLY \
                 (in-memory dev keystore; refused outside tests)"
            );
            Arc::new(DevInMemoryKeyStore::new())
        }
    };
    // Serialize CA load-or-generate across in-process callers: startVpn and the
    // JNI inspectionCaPem can race on FIRST RUN, and the file keystore's key +
    // cert writes are not atomic together — an interleaving could persist a
    // mismatched key/cert pair (every minted leaf would then fail validation).
    static CA_INIT: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _ca_init = CA_INIT.lock().unwrap_or_else(|e| e.into_inner());
    Ok(Arc::new(NetInterceptor::with_keystore(net_cfg, keystore)?))
}

/// Load (or first-run generate) the per-install inspection CA for `ca_dir` and
/// return its ROOT certificate in PEM. Public material only — the private key
/// NEVER leaves the keystore (there is no path here that serializes it).
///
/// Same load path as [`build_interceptor`], so the returned root is
/// byte-identical to the CA the proxy mints leaf certs under. The Android shell
/// installs this into the device trust store (Device Owner →
/// `DevicePolicyManager.installCaCert`) so inspected HTTPS validates instead of
/// showing "connection not private". `None` ca_dir uses the in-memory dev
/// keystore (tests only; refused on a real device by the CA loader).
pub fn inspection_ca_pem(ca_dir: Option<std::path::PathBuf>) -> Result<String> {
    Ok(build_interceptor(ca_dir)?.ca_cert_pem().to_string())
}

/// Android data path: start the TLS-inspecting proxy held by `interceptor` and
/// run the transparent smoltcp pump over the `VpnService` fd, both pointed at
/// `127.0.0.1:8080`, until `shutdown` is cancelled. The JNI `startVpn` builds
/// the interceptor via [`build_interceptor`] and KEEPS a clone so a flow
/// consumer can drain `next_flow()` / answer the decision gate concurrently —
/// without that consumer, gated media stalls the 5s gate window and drops.
///
/// Coverage note: Android 7+ ignores user-installed CAs for most apps, so full
/// HTTPS decryption is limited (the on-device accessibility/OCR path covers
/// E2E/pinned apps). The proxy still mints leaf certs for inspectable flows, and
/// DNS forwarding + QUIC-downgrade + per-flow routing run regardless. Loop
/// prevention relies on the service's `addDisallowedApplication(self)`.
#[cfg(target_os = "android")]
pub async fn run_android_data_path(
    tun_fd: std::os::fd::RawFd,
    interceptor: std::sync::Arc<crate::NetInterceptor>,
    shutdown: CancellationToken,
) -> Result<()> {
    use crate::Interceptor;

    if let Err(e) = interceptor.start_proxy_only().await {
        // Tear down before returning so the flow channel closes and the
        // caller's already-spawned flow consumer exits instead of blocking on
        // `next_flow` forever (a leaked task per failed start).
        let _ = interceptor.shutdown().await;
        return Err(e);
    }

    // Transparent pump over the VpnService fd, pointed at the proxy above.
    let bridge = netstack::BridgeConfig::from_vpn(&VpnConfig::default())?;
    let tun = crate::tun::open_tun_from_fd(tun_fd)?;
    let result = netstack::run_netstack(tun.as_ref(), bridge, shutdown).await;

    // Best-effort proxy teardown (errors ignored — the runtime is going away).
    // This also closes the flow channel, ending the caller's flow consumer.
    let _ = interceptor.shutdown().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_local_http_bulwark_tun() {
        let c = VpnConfig::default();
        assert!(c.proxy_url.starts_with("http://127.0.0.1:"));
        assert_eq!(c.tun_name, "Bulwark");
    }

    #[test]
    fn build_interceptor_persists_the_ca_across_sessions() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-vpn-ca-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let first = build_interceptor(Some(dir.clone())).expect("first build");
        let fp = first.ca_fingerprint().to_string();
        drop(first);
        let second = build_interceptor(Some(dir.clone())).expect("second build");
        assert_eq!(
            second.ca_fingerprint(),
            fp,
            "the SAME per-install root must reload from disk (no per-session CA)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn elevation_command_matches_platform() {
        let cmd = elevation_command();
        // Windows elevates via PowerShell `Start-Process -Verb RunAs`; Unix via
        // `sudo`. The assertion must match the platform the test runs on (CI runs
        // `cargo test --workspace` on ubuntu).
        #[cfg(windows)]
        assert!(
            cmd.contains("RunAs"),
            "windows elevation should use RunAs: {cmd}"
        );
        #[cfg(not(windows))]
        assert!(
            cmd.starts_with("sudo "),
            "unix elevation should use sudo: {cmd}"
        );
    }
}
