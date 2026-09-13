//! Server-side transparent REDIRECT front-end (Linux only).
//!
//! WireGuard traffic arriving on `wg0` is redirected by `wg-filter.sh` to this
//! listener. The kernel preserves the original destination (`SO_ORIGINAL_DST`).
//! We synthesize an HTTP CONNECT to a local Bulwark TLS-inspecting proxy and
//! splice bytes in both directions. No direct-to-destination fallback exists.
//!
//! Remote VPN additionally needs tenant attribution. `run_transparent_listener_routed`
//! therefore lets the region choose a local proxy slot from the authenticated
//! WireGuard peer source address. A missing mapping or unavailable proxy drops
//! the flow fail-closed instead of leaking it through the region NAT path.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::{NetError, Result};

const SO_ORIGINAL_DST: libc::c_int = 80;

/// Run the transparent listener against one fixed local inspection proxy.
pub async fn run_transparent_listener(
    bind: SocketAddr,
    proxy: SocketAddr,
    shutdown: CancellationToken,
) -> Result<()> {
    run_transparent_listener_routed(bind, move |_| Some(proxy), shutdown).await
}

/// Run the region transparent listener and choose the local inspection proxy per
/// accepted WireGuard peer.
///
/// `proxy_for_peer` receives the source socket of the REDIRECTed connection. On
/// the Remote VPN path its IP is the peer's authenticated tunnel address
/// (`10.8.0.x`). Returning `None` means the source is not an active/authorized
/// peer and the connection is dropped before any upstream dial.
pub async fn run_transparent_listener_routed<F>(
    bind: SocketAddr,
    proxy_for_peer: F,
    shutdown: CancellationToken,
) -> Result<()>
where
    F: Fn(SocketAddr) -> Option<SocketAddr> + Send + Sync + 'static,
{
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| NetError::proxy(format!("transparent listener bind {bind}: {error}")))?;
    let proxy_for_peer = Arc::new(proxy_for_peer);
    tracing::info!(%bind, "transparent redirect front-end up (Remote VPN filter mode)");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (client, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::warn!(%error, "transparent accept failed");
                        continue;
                    }
                };

                let Some(proxy) = proxy_for_peer(peer) else {
                    tracing::warn!(peer_ip = %peer.ip(), "unattributed/unauthorized Remote VPN peer; dropping flow");
                    continue;
                };

                let original = match original_dst(&client) {
                    Ok(destination) => destination,
                    Err(error) => {
                        tracing::warn!(%peer, %error, "no SO_ORIGINAL_DST; dropping flow");
                        continue;
                    }
                };
                let authority = format!("{}:{}", original.ip(), original.port());
                tokio::spawn(bridge_one(client, proxy, authority, peer));
            }
        }
    }

    tracing::info!("transparent redirect front-end stopped");
    Ok(())
}

/// Recover the pre-REDIRECT destination of a connection.
fn original_dst(client: &TcpStream) -> Result<SocketAddr> {
    use std::os::fd::AsRawFd;

    let fd = client.as_raw_fd();
    // SAFETY: `sockaddr_in` is POD and is fully overwritten by getsockopt on
    // success. The socket remains alive for the synchronous call.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `addr` is correctly sized/aligned, `len` describes that buffer,
    // and no pointer escapes the call.
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

async fn bridge_one(mut client: TcpStream, proxy: SocketAddr, authority: String, peer: SocketAddr) {
    match super::netstack::connect_via_proxy(proxy, &authority).await {
        Ok(mut upstream) => {
            if let Err(error) = super::netstack::splice(&mut client, &mut upstream).await {
                tracing::debug!(%authority, peer_ip = %peer.ip(), %error, "transparent splice ended");
            }
        }
        Err(error) => {
            // No direct fallback. If the per-peer inspection proxy is absent or
            // unhealthy, this connection dies here.
            tracing::warn!(%authority, peer_ip = %peer.ip(), %proxy, %error, "Remote VPN inspection proxy unavailable; flow dropped");
        }
    }
}
