//! `bulwark_svc` — the SCM-managed Bulwark Windows service (tamper resistance).
//!
//! Runs the Bulwark filter under the Windows Service Control Manager so a Standard
//! (non-admin) child user cannot stop or delete it — the install script
//! (`deploy/windows/install-bulwark-service.ps1`) locks the service DACL (`sc sdset`)
//! so Interactive/Service users get query-only access (no STOP/DELETE), while
//! LocalSystem + Administrators (the guardian) keep full control.
//!
//! ENGINE (MVP): the service is a **watchdog/supervisor** — it (re)launches
//! `bulwark_proxy.exe` and restarts it if it exits or is killed, until the SCM stops
//! the service. The child cannot permanently disable protection because they
//! cannot stop the (ACL-locked) service; any gap is also reported by the tamper
//! heartbeat.
//!
//! KNOWN REFINEMENT (documented, not in this MVP): a LocalSystem service launches
//! the child in session 0, which cannot set the *child's* per-user WinINET proxy /
//! per-user CA. The production fix is to launch `bulwark_proxy.exe` INTO the active
//! console session as the child via `WTSQueryUserToken` + `CreateProcessAsUserW`
//! (an isolated Win32 module in `bulwark-net`), or to host the in-process transparent
//! VPN once the smoltcp/boringtun data path lands (no per-session proxy needed).
//! See docs/design/tamper-protection.md §5. This MVP proves the SCM lifecycle +
//! ACL lock + watchdog; the session-launch is the next step.

#![cfg_attr(not(windows), allow(unused))]

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "bulwark_svc is Windows-only (SCM service). On Linux/macOS use the systemd \
         unit / LaunchDaemon under deploy/."
    );
}

#[cfg(windows)]
const SERVICE_NAME: &str = "BulwarkChildSafety";

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    // Hand the process to the SCM. Blocks the main thread until the service stops;
    // the SCM then calls `ffi_service_main` on a worker thread.
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_args: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %e, "bulwark_svc failed");
    }
}

#[cfg(windows)]
fn run_service() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let _ = bulwark_core::init_tracing_default();

    // Shared stop flag the SCM control handler flips and the watchdog polls.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = stop.clone();

    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_for_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    let mut running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(ServiceStatus {
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        ..running.clone()
    })?;

    status_handle.set_service_status(running.clone())?;

    // Watchdog: keep bulwark_proxy.exe alive until asked to stop. Sync std only — the
    // child has its own tokio runtime; the service needs none.
    supervise(&stop);

    // Stopping.
    status_handle.set_service_status(ServiceStatus {
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        wait_hint: Duration::from_secs(5),
        ..running.clone()
    })?;
    running.current_state = ServiceState::Stopped;
    running.controls_accepted = ServiceControlAccept::empty();
    status_handle.set_service_status(running)?;
    Ok(())
}

/// (Re)launch `bulwark_proxy.exe` and restart it if it exits, until `stop` is set.
#[cfg(windows)]
fn supervise(stop: &std::sync::atomic::AtomicBool) {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let exe = match bulwark_proxy_path() {
        Some(p) => p,
        None => {
            tracing::error!(
                "bulwark_proxy.exe not found next to bulwark_svc.exe; nothing to supervise"
            );
            return;
        }
    };

    while !stop.load(Ordering::SeqCst) {
        match std::process::Command::new(&exe).spawn() {
            Ok(mut child) => {
                tracing::info!(pid = child.id(), "bulwark_proxy started under service");
                // Poll for either a stop request or the child exiting.
                loop {
                    if stop.load(Ordering::SeqCst) {
                        let _ = child.kill();
                        let _ = child.wait();
                        return;
                    }
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            tracing::warn!(?status, "bulwark_proxy exited; will respawn");
                            break;
                        }
                        Ok(None) => std::thread::sleep(Duration::from_millis(500)),
                        Err(e) => {
                            tracing::warn!(error = %e, "wait on bulwark_proxy failed");
                            break;
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to spawn bulwark_proxy; retrying"),
        }
        // Backoff before respawn so a crash-loop doesn't spin hot.
        for _ in 0..6 {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

/// Resolve `bulwark_proxy.exe` next to this service exe (both install into the same
/// `C:\Program Files\Bulwark\` directory).
#[cfg(windows)]
fn bulwark_proxy_path() -> Option<std::path::PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let candidate = dir.join("bulwark_proxy.exe");
    candidate.exists().then_some(candidate)
}
