//! Local protection plumbing: spawning the bundled proxy/VPN filter binaries
//! and the per-user Windows system-proxy switch (with non-Windows no-ops).

use std::cell::RefCell;
use std::process::Child;
use std::rc::Rc;
use std::time::Duration;

use crate::config::{ca_pem_path, ffmpeg_binary, nsfw_model, proxy_exe, repo_root, vpn_exe};
use crate::servers::cluster_endpoint;

// ---------------------------------------------------------------------------
// Protection control panel — fixed local plumbing
// ---------------------------------------------------------------------------

/// The local content-filtering proxy listens here; this is also the address we
/// program into the per-user Windows system proxy.
pub const PROXY_HOST: &str = "127.0.0.1";
pub const PROXY_PORT: u16 = 8080;
pub const PROXY_ADDR: &str = "127.0.0.1:8080";

// ---------------------------------------------------------------------------
// Protection control panel — process + system-proxy plumbing
// ---------------------------------------------------------------------------

/// True when the CA pem exists on disk (i.e. the proxy has a root to trust).
pub fn ca_present() -> bool {
    ca_pem_path().exists()
}

/// The one-time, no-admin command the user runs to trust the CA for their user.
pub fn ca_trust_command() -> String {
    format!(
        "certutil -addstore -user Root \"{}\"",
        ca_pem_path().display()
    )
}

/// Spawn the content-filtering proxy.
///
/// Prefers the prebuilt `bulwark_proxy.exe`; if that's missing, falls back to
/// `cargo run -p bulwark-client --features onnx --bin bulwark_proxy` from the repo
/// root. Either way the proxy gets `BULWARK_NSFW_MODEL` + `BULWARK_CLUSTER_ENDPOINT`.
/// Returns the `Child` so the caller can kill it on Disconnect / shutdown.
///
/// Blocking (it touches the filesystem and spawns a process) — call from an
/// event handler, never the render path.
/// Build the spawn `Command` for a filter binary: the bundled exe if present
/// (`exe`), else a dev `cargo run` of `bin` from the repo root. Both inherit the
/// unified cluster endpoint and — only when configured — media provisioning paths.
pub fn filter_command(exe: Option<std::path::PathBuf>, bin: &str) -> std::process::Command {
    use std::process::Command;
    let mut cmd = match exe {
        Some(path) => Command::new(path),
        None => {
            let mut c = Command::new("cargo");
            c.args([
                "run",
                "-p",
                "bulwark-client",
                "--features",
                "onnx,ffmpeg",
                "--bin",
                bin,
            ])
            .current_dir(repo_root());
            c
        }
    };
    cmd.env("BULWARK_CLUSTER_ENDPOINT", cluster_endpoint());
    if let Some(model) = nsfw_model() {
        cmd.env("BULWARK_NSFW_MODEL", model);
    }
    if let Some(ffmpeg) = ffmpeg_binary() {
        cmd.env("FFMPEG_BINARY", ffmpeg);
    }
    cmd
}

pub fn spawn_proxy() -> std::io::Result<Child> {
    filter_command(proxy_exe(), "bulwark_proxy").spawn()
}

/// Spawn the transparent-VPN binary (`bulwark_vpn.exe`). Like [`spawn_proxy`] it
/// passes the model + cluster endpoint, but VPN mode is currently disabled by
/// the VPN binary while the transparent data path is being rebuilt.
pub fn spawn_vpn() -> std::io::Result<Child> {
    filter_command(vpn_exe(), "bulwark_vpn").spawn()
}

/// Is the proxy actually accepting connections right now? This is the source of
/// truth for the status light — independent of whether *we* think we started it,
/// so an externally-started proxy (or a crashed child) is reported honestly.
///
/// Blocking up to ~300ms; call from the status coroutine, not render.
pub fn proxy_listening() -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    let addr = match (PROXY_HOST, PROXY_PORT).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return false,
        },
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

/// Turn the per-user Windows system proxy ON, pointing all traffic at our local
/// proxy. HKCU only — no admin. Best-effort notifies WinINET so already-open
/// browsers re-read the setting; new windows pick it up regardless.
#[cfg(windows)]
pub fn enable_system_proxy() -> anyhow::Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let settings = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        KEY_WRITE,
    )?;
    settings.set_value("ProxyEnable", &1u32)?;
    settings.set_value("ProxyServer", &PROXY_ADDR.to_string())?;
    // Keep loopback + intranet direct so the console's own RPCs aren't proxied.
    settings.set_value("ProxyOverride", &"<-loopback>".to_string())?;
    refresh_wininet();
    Ok(())
}

/// Turn the per-user system proxy OFF (ProxyEnable=0) and refresh WinINET.
#[cfg(windows)]
pub fn disable_system_proxy() -> anyhow::Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let settings = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        KEY_WRITE,
    )?;
    settings.set_value("ProxyEnable", &0u32)?;
    refresh_wininet();
    Ok(())
}

/// Best-effort: poke WinINET so open browsers re-read the proxy setting now.
/// Failures are ignored — new browser windows always pick up the registry value.
#[cfg(windows)]
pub fn refresh_wininet() {
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    unsafe {
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }
}

// Non-Windows stubs so the file still type-checks on other platforms (the app
// only ships on Windows/macOS, but keeping the desktop build green elsewhere is
// cheap). On non-Windows the system-proxy toggle is a documented no-op.
#[cfg(not(windows))]
pub fn enable_system_proxy() -> anyhow::Result<()> {
    anyhow::bail!("system proxy toggle is only implemented on Windows")
}
#[cfg(not(windows))]
pub fn disable_system_proxy() -> anyhow::Result<()> {
    Ok(())
}

/// Which local filter the Connect control launches.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Explicit per-user system proxy (no admin): spawns `bulwark_proxy` and points
    /// the Windows system proxy at it.
    Proxy,
    /// Transparent, system-wide TUN VPN (needs admin): spawns `bulwark_vpn`. The TUN
    /// captures everything, so no system-proxy change is made.
    Vpn,
}

impl Mode {
    /// One-line description shown under the selector.
    pub fn explain(self) -> &'static str {
        match self {
            Mode::Proxy => "Routes traffic through the local filter via the per-user system proxy. No admin needed; covers browsers + apps that honour the system proxy.",
            Mode::Vpn => "Transparent VPN mode is being rebuilt and is disabled in this build. Use Proxy mode for now.",
        }
    }
}

/// Shared handle to the spawned proxy/VPN child, stored in app state so any handler
/// (Connect/Disconnect/shutdown) can take and kill it. `Rc<RefCell<..>>` keeps
/// it single-threaded on the UI thread, which is where our handlers run.
pub type ProxyHandle = Rc<RefCell<Option<Child>>>;

/// Kill the spawned proxy child if we have one (best-effort), then drop it.
pub fn kill_proxy(handle: &ProxyHandle) {
    if let Some(mut child) = handle.borrow_mut().take() {
        let _ = child.kill();
        // Reap so we don't leave a zombie; ignore the exit status.
        let _ = child.wait();
    }
}
