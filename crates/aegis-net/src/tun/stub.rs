//! Non-Windows TUN backends — **STUBBED** behind `cfg`, documented to slot in.
//!
//! These compile (so the crate builds cross-platform) but their hot methods
//! `todo!()`. They are deliberately explicit, not silent no-ops: a child's
//! device must never *appear* protected while passing traffic unfiltered. Each
//! is annotated with exactly which crate + OS mechanism the real impl uses.

use crate::tun::{TunConfig, TunDevice};
use crate::{NetError, Result};

/// Pick the stub backend for the current non-Windows target. Returns an
/// `Unsupported` error rather than a fake device, so callers fail loudly until
/// the real backend lands.
pub fn open_stub() -> Result<Box<dyn TunDevice>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Ok(Box::new(TunRsStub::default()))
    }
    #[cfg(target_os = "android")]
    {
        Ok(Box::new(VpnServiceStub::default()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
    {
        Err(NetError::unsupported("no TUN backend for this target"))
    }
}

/// Linux/macOS TUN over the **`tun-rs`** crate (workspace dep `tun-rs = "2.8"`).
///
/// Real impl plan (platform-feasibility §2):
///   * `tun-rs` creates the `/dev/net/tun` interface; set address + MTU.
///   * Route LAN traffic via **nftables TPROXY + fwmark** to the proxy port.
///   * Run as a systemd service with `CAP_NET_ADMIN` / `CAP_NET_BIND_SERVICE`.
///   * `close()` MUST tear down the nft rules (add `ExecStop`) and duplicate the
///     rules for **IPv6**, or the LAN blackholes on exit.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Default)]
pub struct TunRsStub;

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TunDevice for TunRsStub {
    fn up(&mut self, _config: &TunConfig) -> Result<()> {
        // TODO(linux): create the interface with `tun-rs`, set addr/MTU, install
        // nftables TPROXY + fwmark rules redirecting TCP to the proxy port.
        todo!("Linux/macOS TUN via tun-rs + nftables TPROXY — see module docs")
    }
    fn recv(&self, _buf: &mut [u8]) -> Result<usize> {
        todo!("tun-rs packet read")
    }
    fn send(&self, _packet: &[u8]) -> Result<usize> {
        todo!("tun-rs packet write")
    }
    fn close(&mut self) -> Result<()> {
        // TODO(linux): tear down nftables rules (ExecStop) for v4 AND v6.
        todo!("restore routing: remove nftables TPROXY/fwmark rules (v4 + v6)")
    }
    fn backend(&self) -> &'static str {
        "tun-rs"
    }
}

/// Android TUN over **`VpnService`** via JNI (workspace dep `jni = "0.22"`).
///
/// Real impl plan (platform-feasibility §3):
///   * Java `VpnService` establishes the tun fd; pass it into Rust over JNI.
///   * Read/write packets on that fd.
///   * Pair with an `AccessibilityService` for E2E/pinned apps (aegis-agent) —
///     the wire MITM only covers ~30–50% of Android-7+ apps; the rest are OCR.
///   * Play Store: VPN disclosure + Data Safety (no plaintext exfil) + MASA L2.
#[cfg(target_os = "android")]
#[derive(Default)]
pub struct VpnServiceStub;

#[cfg(target_os = "android")]
impl TunDevice for VpnServiceStub {
    fn up(&mut self, _config: &TunConfig) -> Result<()> {
        todo!("Android VpnService.establish() fd handed to Rust via JNI — see module docs")
    }
    fn recv(&self, _buf: &mut [u8]) -> Result<usize> {
        todo!("read from VpnService tun fd")
    }
    fn send(&self, _packet: &[u8]) -> Result<usize> {
        todo!("write to VpnService tun fd")
    }
    fn close(&mut self) -> Result<()> {
        todo!("stop VpnService; revoke the VPN; restore connectivity")
    }
    fn backend(&self) -> &'static str {
        "vpnservice"
    }
}
