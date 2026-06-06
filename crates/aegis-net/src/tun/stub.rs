//! Non-Windows TUN backends.
//!
//! Linux/macOS can now create and read/write a `tun-rs` device, and Android can
//! wrap the file descriptor handed over by `VpnService`. Routing still fails
//! closed until the shared TCP bridge is complete and device-tested; an
//! unbridged default route would blackhole the child device.
#![allow(unsafe_code)] // Android fd ownership requires `dup` + `SyncDevice::from_fd`.

use crate::tun::{TunConfig, TunDevice};
use crate::{NetError, Result};

/// Pick the backend for the current non-Windows target. Returns an unsupported
/// error for platforms that do not expose a TUN primitive here.
pub fn open_stub() -> Result<Box<dyn TunDevice>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Ok(Box::new(TunRsDevice::default()))
    }
    #[cfg(target_os = "android")]
    {
        Err(NetError::unsupported(
            "Android TUN requires the VpnService fd; call open_android_fd(fd)",
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
    {
        Err(NetError::unsupported("no TUN backend for this target"))
    }
}

/// Linux/macOS TUN over the `tun-rs` crate.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Default)]
pub struct TunRsDevice {
    dev: Option<tun_rs::SyncDevice>,
    installed_routing: bool,
    actual_name: Option<String>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TunRsDevice {
    fn dev(&self) -> Result<&tun_rs::SyncDevice> {
        self.dev
            .as_ref()
            .ok_or_else(|| NetError::tun("tun-rs device used before up()"))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TunDevice for TunRsDevice {
    fn up(&mut self, config: &TunConfig) -> Result<()> {
        let dev = tun_rs::DeviceBuilder::new()
            .name(&config.name)
            .ipv4(config.ipv4, config.ipv4_prefix, None)
            .mtu(config.mtu)
            .build_sync()
            .map_err(|e| NetError::tun(format!("creating tun-rs device: {e}")))?;

        self.actual_name = dev.name().ok().filter(|n| !n.is_empty());
        self.dev = Some(dev);
        tracing::info!(
            requested_name = %config.name,
            actual_name = ?self.actual_name,
            "tun-rs device up"
        );
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.dev()?
            .recv(buf)
            .map_err(|e| NetError::tun(format!("tun-rs recv: {e}")))
    }

    fn send(&self, packet: &[u8]) -> Result<usize> {
        self.dev()?
            .send(packet)
            .map_err(|e| NetError::tun(format!("tun-rs send: {e}")))
    }

    fn close(&mut self) -> Result<()> {
        let _ = self.teardown_routing();
        self.dev = None;
        self.actual_name = None;
        tracing::info!("tun-rs device closed");
        Ok(())
    }

    fn backend(&self) -> &'static str {
        "tun-rs"
    }

    fn install_routing(&mut self, _config: &TunConfig) -> Result<()> {
        Err(NetError::unsupported(
            "Linux/macOS routing is planned but disabled until the smoltcp bridge is device-tested",
        ))
    }

    fn teardown_routing(&mut self) -> Result<()> {
        if !self.installed_routing {
            return Ok(());
        }
        self.installed_routing = false;
        Ok(())
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.dev.as_ref().map(|d| d.as_raw_fd())
    }
}

/// Open an Android VpnService fd as a TUN device.
///
/// The fd is duplicated before wrapping so Rust owns and closes only its copy;
/// Kotlin's `ParcelFileDescriptor` remains responsible for the original.
#[cfg(target_os = "android")]
pub fn open_android_fd(fd: std::os::fd::RawFd) -> Result<Box<dyn TunDevice>> {
    Ok(Box::new(AndroidVpnDevice::from_fd(fd)?))
}

#[cfg(target_os = "android")]
pub struct AndroidVpnDevice {
    dev: tun_rs::SyncDevice,
}

#[cfg(target_os = "android")]
impl AndroidVpnDevice {
    fn from_fd(fd: std::os::fd::RawFd) -> Result<Self> {
        let owned = unsafe { libc::dup(fd) };
        if owned < 0 {
            return Err(NetError::tun(format!(
                "duplicating VpnService fd: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `owned` is a fresh dup of the VpnService fd. `SyncDevice` takes
        // ownership of this duplicate and closes it on drop; Kotlin still owns the
        // original `ParcelFileDescriptor` fd.
        let dev = unsafe { tun_rs::SyncDevice::from_fd(owned) }
            .map_err(|e| NetError::tun(format!("wrapping VpnService fd: {e}")))?;
        Ok(Self { dev })
    }
}

#[cfg(target_os = "android")]
impl TunDevice for AndroidVpnDevice {
    fn up(&mut self, _config: &TunConfig) -> Result<()> {
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.dev
            .recv(buf)
            .map_err(|e| NetError::tun(format!("VpnService recv: {e}")))
    }

    fn send(&self, packet: &[u8]) -> Result<usize> {
        self.dev
            .send(packet)
            .map_err(|e| NetError::tun(format!("VpnService send: {e}")))
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }

    fn backend(&self) -> &'static str {
        "vpnservice"
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        Some(self.dev.as_raw_fd())
    }
}
