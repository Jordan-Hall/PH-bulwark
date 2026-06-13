//! Server-side TRANSPARENT redirect front-end (Linux only).
//!
//! On a PH Bulwark Cloud region, child traffic arrives over WireGuard (`wg0`) and
//! an `iptables ... -j REDIRECT --to-ports <p>` rule (deploy/wireguard/
//! wg-filter.sh) bends every TCP/80 + TCP/443 flow to a LOCAL port. Unlike the
//! on-device pump (which reconstructs flows from L3 packets with smoltcp), here
//! the Linux kernel has already done the L3/L4 work: we `accept()` a normal TCP
//! socket whose *original* (pre-DNAT) destination is recoverable via
//! `getsockopt(SO_ORIGINAL_DST)`. We then reuse the SAME CONNECT bridge the
//! on-device pump uses ([`super::netstack::connect_via_proxy`] +
//! [`super::netstack::splice`]) to hand the flow to the in-process hudsucker
//! TLS-inspecting proxy — so ONE engine filters both modes.
//!
//! hudsucker is an explicit/CONNECT proxy; it does NOT itself speak transparent
//! mode or read `SO_ORIGINAL_DST`. This module is the thin shim that adapts a
//! REDIRECT'd socket into the CONNECT the proxy already understands; the proxy is
//! unchanged.
//!
//! ## FFI ISOLATION
//! The only `unsafe` here is the `getsockopt(SO_ORIGINAL_DST)` recovery,
//! localized + `// SAFETY:`-documented, matching the policy used by `vpn`
//! (elevation probe), `tun::windows`, and `ca::dpapi`.

use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::{NetError, Result};

/// `SOL_IP`-level option returning the ORIGINAL destination of a connection that
/// netfilter DNAT/REDIRECT'd (`linux/netfilter_ipv4.h` `SO_ORIGINAL_DST`). Defined
/// explicitly rather than relying on a libc re-export so the value is auditable.
const SO_ORIGINAL_DST: libc::c_int = 80;

/// Run the transparent redirect front-end until `shutdown` fires.
///
/// `bind` is where the `iptables REDIRECT --to-ports` rule lands flows (e.g.
/// `0.0.0.0:8081` — NOT loopback: REDIRECT rewrites the dst to the wg0 local
/// address, so a loopback-only bind would never receive it). `proxy` is the
/// in-process hudsucker CONNECT proxy (`127.0.0.1:8080`). Each accepted flow is
/// bridged to the proxy by SYNTHESISING `CONNECT <orig-ip>:<orig-port>` — exactly
/// like the on-device pump — so every flow is TLS-inspected + content-filtered.
pub async fn run_transparent_listener(
    bind: SocketAddr,
    proxy: SocketAddr,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| NetError::proxy(format!("transparent listener bind {bind}: {e}")))?;
    tracing::info!(%bind, %proxy, "transparent redirect front-end up (server filter mode)");
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (client, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(error = %e, "transparent accept failed");
                        continue;
                    }
                };
                let orig = match original_dst(&client) {
                    Ok(d) => d,
                    Err(e) => {
                        // No recoverable original destination → we cannot know
                        // where this flow was headed, so we must NOT guess: drop
                        // it (fail-closed; never forward an unattributable flow).
                        tracing::warn!(%peer, error = %e, "no SO_ORIGINAL_DST; dropping flow");
                        continue;
                    }
                };
                let authority = format!("{}:{}", orig.ip(), orig.port());
                tokio::spawn(bridge_one(client, proxy, authority));
            }
        }
    }
    tracing::info!("transparent redirect front-end stopped");
    Ok(())
}

/// Recover the pre-REDIRECT destination of `client` via `getsockopt(SO_ORIGINAL_DST)`.
/// IPv4 only: the WG subnet (deploy/wireguard) is IPv4-only so v6 is never routed
/// here (a v6 socket would need `IP6T_SO_ORIGINAL_DST` + `sockaddr_in6`).
fn original_dst(client: &TcpStream) -> Result<SocketAddr> {
    use std::os::fd::AsRawFd;
    let fd = client.as_raw_fd();
    // SAFETY: `sockaddr_in` is plain-old-data; an all-zero value is a valid
    // (unspecified) sockaddr that `getsockopt` overwrites in full below.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into `addr` (a live,
    // correctly-sized `sockaddr_in` stack local) and updates `len` in place. `fd`
    // is owned by `client` and stays open for the whole synchronous call; no
    // pointer escapes it. A non-zero return is converted to an error below.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(NetError::proxy(format!(
            "getsockopt(SO_ORIGINAL_DST): {}",
            std::io::Error::last_os_error()
        )));
    }
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::from((ip, port)))
}

/// Bridge ONE REDIRECT'd flow to the CONNECT proxy: open `CONNECT authority` to
/// the proxy, then splice the client socket and the proxy tunnel both ways. Reuses
/// the EXACT functions the on-device pump uses, so the server path inherits the
/// same (device-validated) CONNECT-by-IP behaviour.
async fn bridge_one(mut client: TcpStream, proxy: SocketAddr, authority: String) {
    match super::netstack::connect_via_proxy(proxy, &authority).await {
        Ok(mut up) => {
            if let Err(e) = super::netstack::splice(&mut client, &mut up).await {
                tracing::debug!(%authority, error = %e, "transparent splice ended");
            }
        }
        Err(e) => tracing::debug!(%authority, error = %e, "transparent CONNECT failed"),
    }
}
