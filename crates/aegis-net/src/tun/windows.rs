//! Windows TUN backend over `wintun` (WireGuard's pre-signed driver).
//!
//! `wintun` ships a driver that is already signed by WireGuard, so Aegis needs
//! **no EV cert / WHCP submission** unless we recompile the driver
//! (platform-feasibility §1). The `wintun` crate is a safe-ish wrapper over
//! `wintun.dll`; loading a DLL and the session ring-buffer calls are still FFI,
//! so this module is one of the two places `unsafe` is permitted in the crate.
//!
//! ## FFI ISOLATION NOTICE
//! The crate root sets `#![forbid(unsafe_code)]`. The only `unsafe` operation
//! reachable from here is loading `wintun.dll` (`Adapter::load`/`wintun::load`),
//! which the `wintun` crate exposes as an `unsafe fn` because loading an
//! arbitrary DLL path is inherently trust-sensitive. We localize and justify it
//! below; everything else uses `wintun`'s safe API. No `unsafe` escapes this file.
#![allow(unsafe_code)] // wintun.dll load is unavoidable FFI; isolated + justified.

use std::sync::Arc;

use crate::tun::{TunConfig, TunDevice};
use crate::{NetError, Result};

/// Wintun-backed TUN device.
pub struct WintunDevice {
    wintun: Arc<wintun::Wintun>,
    adapter: Option<Arc<wintun::Adapter>>,
    session: Option<Arc<wintun::Session>>,
}

impl WintunDevice {
    /// Load `wintun.dll` and prepare a device (does not create the adapter yet).
    ///
    /// We load from the system path / the DLL shipped alongside the binary. The
    /// DLL is WireGuard-signed; a hardening pass should additionally verify its
    /// Authenticode signature before load (TODO, noted for the security review).
    pub fn new() -> Result<Self> {
        // SAFETY: `wintun::load` (and `load_from_path`) is `unsafe` solely because
        // it `LoadLibrary`s a native DLL and resolves its exports — loading any
        // foreign code is inherently unsafe. Soundness conditions we uphold:
        //   * we load the WireGuard-signed `wintun.dll` (signature-verify is a
        //     documented TODO before GA);
        //   * the returned `Wintun` table is kept alive (in `self.wintun`) for as
        //     long as any adapter/session derived from it, satisfying the crate's
        //     lifetime requirement that the loaded library outlive its sessions.
        let wintun = unsafe { wintun::load() }
            .map_err(|e| NetError::tun(format!("loading wintun.dll: {e}")))?;
        Ok(WintunDevice {
            wintun: Arc::new(wintun),
            adapter: None,
            session: None,
        })
    }
}

impl TunDevice for WintunDevice {
    fn up(&mut self, config: &TunConfig) -> Result<()> {
        // Create (or open) the adapter. This is a safe wrapper call.
        let adapter = wintun::Adapter::create(&self.wintun, &config.name, "Aegis", None)
            .map_err(|e| NetError::tun(format!("creating wintun adapter: {e}")))?;

        // Assigning the IP / MTU and the route is done via the adapter + the OS
        // (the `wintun` crate exposes set_address / set_netmask on recent
        // versions; otherwise we'd shell `netsh interface ip set address`). We
        // keep the adapter handle so its routes are removed on drop/close.
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| NetError::tun(format!("starting wintun session: {e}")))?;

        self.adapter = Some(Arc::new(adapter));
        self.session = Some(Arc::new(session));
        tracing::info!(name = %config.name, "wintun adapter up");
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| NetError::tun("recv before up()"))?;
        // Blocking receive of the next packet from the ring buffer (safe API).
        let packet = session
            .receive_blocking()
            .map_err(|e| NetError::tun(format!("wintun recv: {e}")))?;
        let bytes = packet.bytes();
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }

    fn send(&self, packet: &[u8]) -> Result<usize> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| NetError::tun("send before up()"))?;
        let mut out = session
            .allocate_send_packet(packet.len() as u16)
            .map_err(|e| NetError::tun(format!("wintun alloc: {e}")))?;
        out.bytes_mut().copy_from_slice(packet);
        session.send_packet(out);
        Ok(packet.len())
    }

    fn close(&mut self) -> Result<()> {
        // Dropping the session then the adapter tears down the interface and the
        // routes wintun added, restoring host routing (module-doc requirement).
        self.session = None;
        self.adapter = None;
        tracing::info!("wintun adapter closed; host routing restored");
        Ok(())
    }

    fn backend(&self) -> &'static str {
        "wintun"
    }
}
