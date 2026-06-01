//! Platform TUN abstraction.
//!
//! The interception layer needs a layer-3 virtual interface so OS traffic can be
//! captured and redirected to the in-process MITM proxy. Each platform offers a
//! different primitive:
//!   * **Windows** → `wintun` (WireGuard's pre-signed driver) — **real** here.
//!   * **Linux/macOS** → `tun-rs` — **stubbed** (`todo!()`), documented to slot in.
//!   * **Android** → `VpnService` via JNI — **stubbed**, documented.
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
