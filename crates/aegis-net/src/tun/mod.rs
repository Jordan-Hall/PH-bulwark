//! Platform TUN abstraction.
//!
//! The interception layer needs a layer-3 virtual interface so OS traffic can be
//! captured and redirected to the in-process MITM proxy. Each platform offers a
//! different primitive:
//!   * **Windows** → `wintun` (WireGuard's pre-signed driver) — **real** here.
//!   * **Linux/macOS** → `tun-rs` device plumbing, with routing still fail-closed
//!     until the shared bridge is device-tested.
//!   * **Android** → `VpnService` fd handoff via JNI; routing is owned by the
//!     Android service shell.
//!
//! [`TunDevice`] is the common contract every backend implements. [`open_tun`]
//! picks the backend for the current target.
//!
//! ## Routing teardown (threat-model / interfaces.md `shutdown`)
//! The contract's [`TunDevice::close`] MUST restore the host's routing so a crash
//! or shutdown never blackholes the device's network. On Windows that means
//! dropping the adapter (wintun removes its routes); on Linux it means tearing
//! down the nftables/TPROXY rules (platform-feasibility §2 — missing `ExecStop`
//! blackholes the LAN). This is wired into the documented teardown path.

#[cfg(windows)]
pub mod windows;

/// Pure routing command builders for transparent VPN setup/teardown.
///
/// These are compiled on every host so Linux/macOS routing plans can be unit-tested
/// without mutating the machine running the tests.
pub mod routing;

#[cfg(not(windows))]
pub mod stub;

use crate::Result;

/// Configuration for bringing up a TUN device.
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Adapter name shown to the OS (e.g. "Aegis").
    pub name: String,
    /// IPv4 address assigned to the TUN interface.
    pub ipv4: std::net::Ipv4Addr,
    /// Prefix length for the IPv4 address (e.g. 24).
    pub ipv4_prefix: u8,
    /// MTU for the interface.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            name: "Aegis".to_owned(),
            ipv4: std::net::Ipv4Addr::new(10, 64, 0, 1),
            ipv4_prefix: 24,
            mtu: 1500,
        }
    }
}

/// A platform virtual network interface that yields/accepts L3 packets.
///
/// Backends are blocking at the syscall boundary; the proxy layer drives them
/// from a dedicated task / `spawn_blocking`. The trait is intentionally minimal:
/// the heavy lifting (TCP redirect → proxy) is layered above it.
pub trait TunDevice: Send + Sync {
    /// Bring the interface up with the given config (creates the adapter + sets
    /// address/MTU). Needs admin/root on every platform.
    fn up(&mut self, config: &TunConfig) -> Result<()>;

    /// Read the next inbound IP packet into `buf`, returning its length.
    fn recv(&self, buf: &mut [u8]) -> Result<usize>;

    /// Write an outbound IP packet.
    fn send(&self, packet: &[u8]) -> Result<usize>;

    /// Tear down the interface and **restore host routing**. Idempotent.
    /// Failing to do this can blackhole the device — see module docs.
    fn close(&mut self) -> Result<()>;

    /// Short backend name for logs/diagnostics ("wintun", "tun-rs", "vpnservice").
    fn backend(&self) -> &'static str;

    // --- Part-0a foundation hooks (see docs/design/vpn-data-path-plan.md) -------
    // These have default impls so Windows (`tun/windows.rs`) is UNCHANGED — wintun
    // owns its own route + ring buffer. Linux/macOS will override the routing hooks
    // (nftables / pf); Android leaves them no-ops (routing is declarative in the
    // Kotlin VpnService). NOTE: scaffolding only — the netstack bridge + per-platform
    // packet loops that consume these are not yet implemented (need device testing).

    /// Install host routing that redirects local traffic INTO this TUN, called after
    /// [`up`](Self::up) and before the packet loop. Default no-op (Windows + the
    /// smoltcp default route handle it). Linux overrides with nftables/TPROXY +
    /// fwmark, macOS with a `pf` anchor — **for v4 AND v6** or the LAN blackholes.
    fn install_routing(&mut self, _config: &TunConfig) -> Result<()> {
        Ok(())
    }

    /// Reverse exactly what [`install_routing`](Self::install_routing) added. Default
    /// no-op. **MUST be idempotent** — it runs on the crash/`ExecStop` path too, so
    /// it has to tolerate "nothing was installed" without erroring.
    fn teardown_routing(&mut self) -> Result<()> {
        Ok(())
    }

    /// Raw pollable fd for async-reactor integration on Unix/Android, so the netstack
    /// can register the device with the runtime instead of burning a blocking thread.
    /// `None` (default) on Windows/wintun, which is driven on `spawn_blocking`.
    #[cfg(unix)]
    fn as_raw_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

/// Open the platform-appropriate TUN backend (not yet `up()`).
pub fn open_tun() -> Result<Box<dyn TunDevice>> {
    #[cfg(windows)]
    {
        Ok(Box::new(windows::WintunDevice::new()?))
    }
    #[cfg(not(windows))]
    {
        stub::open_stub()
    }
}

/// Open an Android `VpnService` file descriptor as a TUN backend.
#[cfg(target_os = "android")]
pub fn open_tun_from_fd(fd: std::os::fd::RawFd) -> Result<Box<dyn TunDevice>> {
    stub::open_android_fd(fd)
}
