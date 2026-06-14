//! Shared transparent-VPN bridge.
//!
//! This is the permissive replacement for the removed GPL `tun2proxy` backend.
//! On unix/Android, `run_netstack` runs the full fd-driven pump: smoltcp
//! terminates each captured TCP flow, the bridge synthesises a `CONNECT` to the
//! in-process TLS-inspecting proxy and splices bytes both ways, DNS is forwarded,
//! and QUIC/443 is dropped so HTTP/3 can't bypass the TCP inspection. The packet
//! parser, flow policy, and bridge halves are unit-tested on every host; the pump
//! itself is host-tested and awaits on-device validation. On Windows (wintun) the
//! pump stays deliberately fail-closed pending its own spike.
#![allow(dead_code)] // Non-unix builds compile the bridge halves without the pump.

use std::net::{SocketAddr, ToSocketAddrs};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet,
    Ipv4Repr, Ipv6Packet, TcpPacket, UdpPacket, UdpRepr,
};

use crate::tun::TunDevice;
use crate::{NetError, Result};

use super::VpnConfig;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Transport {
    Tcp {
        src_port: u16,
        dst_port: u16,
        syn: bool,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
    },
    Other(IpProtocol),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PacketSummary {
    src: IpAddress,
    dst: IpAddress,
    transport: Transport,
}

#[derive(Clone, Debug)]
pub(super) struct BridgeConfig {
    proxy_addr: SocketAddr,
    /// Guardian host blocklist. Only literal-IP entries can match here (the
    /// pump sees L3 packets, no names); name rules are enforced by the proxy,
    /// which every pump flow traverses anyway.
    blocklist: std::sync::Arc<crate::blocklist::HostBlocklist>,
}

impl BridgeConfig {
    pub(super) fn from_vpn(cfg: &VpnConfig) -> Result<Self> {
        Ok(Self {
            proxy_addr: parse_http_proxy_addr(cfg.proxy_url())?,
            // VpnConfig carries no NetConfig, so the pump resolves the guardian
            // blocklist from BULWARK_BLOCKLIST (the same file the proxy loads).
            // Configured-but-unreadable fails CLOSED; unset = empty.
            blocklist: std::sync::Arc::new(crate::blocklist::HostBlocklist::from_env_or(None)?),
        })
    }
}

// ---------------------------------------------------------------------------
// The live transparent VPN pump.
//
// `run_netstack` reads captured L3 packets from the TUN and drives a `smoltcp`
// netstack that TERMINATES each TCP flow on a per-flow transparent listener bound
// to the flow's ORIGINAL destination, opens an HTTP `CONNECT` tunnel to the
// in-process TLS-inspecting proxy for that destination, and splices the two — so every TCP
// flow is decrypted + content-filtered. UDP/53 DNS is forwarded to an upstream
// resolver (so the device can still resolve names) and UDP/443 QUIC is dropped
// (forcing the HTTP/3 fallback onto inspectable TCP/443).
//
// The loop is fd-driven: a single `poll(2)` waits on the TUN fd plus a self-pipe
// that the async proxy/DNS tasks poke when they have bytes to flush. That keeps the
// synchronous smoltcp core and the async (tokio) proxy/DNS halves coordinated
// without a busy-wait, and lets `poll`'s timeout tick smoltcp's timers and observe
// cancellation. It therefore lives on the unix/Android targets that hand us a
// pollable VpnService/utun fd; the Windows/wintun desktop pump is a separate spike
// and stays fail-closed below.
//
// HONEST LIMITATIONS (tracked for the on-device validation pass):
//   * IPv4 first — captured IPv6 TCP/UDP is dropped, so apps fall back to v4.
//   * Non-DNS UDP (other than QUIC/443, intentionally dropped) is dropped.
//   * Loop prevention relies on the VpnService `addDisallowedApplication(self)` so
//     our own upstream/proxy sockets bypass the TUN (already set in
//     `BulwarkVpnService`); the desktop path must exclude the proxy by route.
//   * Clean shutdown relies on `poll(2)`'s timeout ticking the loop to observe the
//     `CancellationToken` (we never block indefinitely on a bare `recv`).

/// Windows/wintun desktop pump is a separate spike; keep it fail-closed so a
/// desktop VPN run can never blackhole the host before that path is device-tested.
#[cfg(not(unix))]
pub(super) async fn run_netstack(
    _tun: &dyn TunDevice,
    cfg: BridgeConfig,
    _shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    Err(NetError::unsupported(format!(
        "transparent VPN pump is fd-driven (Android/Unix); Windows wintun pump pending (proxy {})",
        cfg.proxy_addr
    )))
}

// ---- pure helpers (host-testable; not unix-gated) --------------------------

/// Private / loopback IPv4 space. A DNS query addressed at one of these (e.g. the
/// VpnService-advertised gateway `10.0.0.1`) has no real resolver behind it, so we
/// forward it to a public resolver instead; a public address is forwarded as-is.
fn is_private_v4(o: [u8; 4]) -> bool {
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 127
}

/// Where to forward a captured DNS query whose original destination was `server`.
fn resolver_for(server: [u8; 4]) -> SocketAddr {
    let o = if is_private_v4(server) {
        [1, 1, 1, 1]
    } else {
        server
    };
    SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3])),
        53,
    )
}

/// Extract the UDP payload (the DNS message) from a captured IPv4 UDP packet.
fn v4_udp_payload(packet: &[u8]) -> Option<Vec<u8>> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    Some(udp.payload().to_vec())
}

/// Build an IPv4/UDP packet carrying `payload` from `src:src_port` to `dst:dst_port`,
/// with correct IP + UDP checksums. Used to inject a DNS *reply* straight back into
/// the TUN, sourced from the resolver address the client originally queried (so the
/// client accepts it) — sidestepping any smoltcp UDP source-address ambiguity.
fn build_dns_response_v4(
    src: [u8; 4],
    src_port: u16,
    dst: [u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let src_a = Ipv4Address::new(src[0], src[1], src[2], src[3]);
    let dst_a = Ipv4Address::new(dst[0], dst[1], dst[2], dst[3]);
    let udp_repr = UdpRepr { src_port, dst_port };
    let ip_repr = Ipv4Repr {
        src_addr: src_a,
        dst_addr: dst_a,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + payload.len(),
        hop_limit: 64,
    };
    let caps = ChecksumCapabilities::default();
    let ip_hdr_len = ip_repr.buffer_len();
    let mut buf = vec![0u8; ip_hdr_len + ip_repr.payload_len];
    // UDP into the payload region first (it doesn't touch the IP header bytes)...
    {
        let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
        udp_repr.emit(
            &mut udp_pkt,
            &IpAddress::Ipv4(src_a),
            &IpAddress::Ipv4(dst_a),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &caps,
        );
    }
    // ...then the IP header (+ its checksum) over the leading bytes.
    {
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip_repr.emit(&mut ip_pkt, &caps);
    }
    buf
}

// ---- the fd-driven pump (unix / Android) -----------------------------------

/// Per-flow proxy-channel depth (client→proxy). Bounded so a slow proxy applies
/// natural TCP backpressure (we stop draining smoltcp's recv buffer when full).
#[cfg(unix)]
const PROXY_UP_CHANNEL: usize = 32;

/// Cap on bytes buffered from the proxy awaiting the client's smoltcp send window.
#[cfg(unix)]
const TO_CLIENT_CAP: usize = 256 * 1024;

/// A self-pipe write end the async tasks poke to wake the (blocking) `poll(2)` loop.
#[cfg(unix)]
struct Waker {
    fd: std::os::fd::RawFd,
}

#[cfg(unix)]
impl Waker {
    fn wake(&self) {
        // Best-effort single byte; a full pipe (EWOULDBLOCK) already means the loop
        // has pending work queued, so dropping the extra byte is fine.
        let b = [1u8];
        let _ = unsafe { libc::write(self.fd, b.as_ptr() as *const libc::c_void, 1) };
    }
}

#[cfg(unix)]
impl Drop for Waker {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.fd);
        }
    }
}

// (`Waker` is just an owned `RawFd` (i32), so it is auto-`Send + Sync`; the
// pipe `write`/`close` are atomic and safe from any thread.)

/// One captured TCP flow being terminated by smoltcp and bridged to the proxy.
#[cfg(unix)]
struct Flow {
    handle: SocketHandle,
    /// (src, src_port, dst, dst_port) — dedups retransmitted SYNs to one listener.
    key: (Ipv4Address, u16, Ipv4Address, u16),
    /// `host:port` of the original destination, for the proxy `CONNECT`.
    authority: String,
    /// client → proxy bytes (None until the flow establishes / after client FIN).
    up_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// proxy → client bytes. BOUNDED so a stalled client (closed smoltcp send
    /// window) backpressures the proxy task's upstream reads instead of
    /// buffering an entire download in RAM on the supervised device.
    down_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    /// proxy bytes staged for smoltcp's send window.
    to_client: std::collections::VecDeque<u8>,
    /// set by the proxy task when its upstream half is finished/failed.
    proxy_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    spawned: bool,
    closing: bool,
}

/// Run the transparent pump until `shutdown` is cancelled. Must be called from a
/// multi-threaded tokio runtime (it parks a worker via `block_in_place` while the
/// proxy/DNS tasks run on the others).
#[cfg(unix)]
pub(super) async fn run_netstack(
    tun: &dyn TunDevice,
    cfg: BridgeConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let handle = tokio::runtime::Handle::current();
    tokio::task::block_in_place(move || netstack_loop(tun, &cfg, &handle, &shutdown))
}

#[cfg(unix)]
fn make_pipe() -> Result<(std::os::fd::RawFd, std::os::fd::RawFd)> {
    let mut fds = [0 as std::os::fd::RawFd; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(NetError::tun(format!(
            "VPN pump: pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    set_nonblocking(fds[0]);
    set_nonblocking(fds[1]);
    Ok((fds[0], fds[1]))
}

#[cfg(unix)]
fn set_nonblocking(fd: std::os::fd::RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

#[cfg(unix)]
fn drain_pipe(fd: std::os::fd::RawFd) {
    let mut b = [0u8; 256];
    loop {
        let n = unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, b.len()) };
        if n <= 0 {
            break;
        }
    }
}

/// One DNS reply queued for injection back into the TUN:
/// `(src_ip, src_port, dst_ip, dst_port, payload)` — sourced from the DNS
/// server address the client originally queried, back to the client.
#[cfg(unix)]
type DnsReply = ([u8; 4], u16, [u8; 4], u16, Vec<u8>);

#[cfg(unix)]
fn netstack_loop(
    tun: &dyn TunDevice,
    cfg: &BridgeConfig,
    handle: &tokio::runtime::Handle,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<()> {
    let tunfd = tun
        .as_raw_fd()
        .ok_or_else(|| NetError::tun("VPN pump: TUN exposes no pollable fd"))?;
    let mtu = 1500usize;
    let mut phy = TunPhy::new(tun, mtu);
    let mut iface = build_interface(&mut phy);
    let mut sockets = SocketSet::new(Vec::new());
    let mut flows: Vec<Flow> = Vec::new();

    let (wake_rd, wake_wr) = make_pipe()?;
    let waker = std::sync::Arc::new(Waker { fd: wake_wr });
    let (dns_tx, dns_rx) = std::sync::mpsc::channel::<DnsReply>();

    tracing::info!(proxy = %cfg.proxy_addr, "VPN pump: transparent netstack up");

    let result = (|| -> Result<()> {
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            let now = SmolInstant::now();
            let delay_ms = iface
                .poll_delay(now, &sockets)
                .map(|d| d.total_millis() as i32)
                .unwrap_or(200)
                .clamp(1, 200);
            let mut pfds = [
                libc::pollfd {
                    fd: tunfd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wake_rd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 2, delay_ms) };
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(NetError::tun(format!("VPN pump: poll: {e}")));
            }
            if pfds[1].revents & libc::POLLIN != 0 {
                drain_pipe(wake_rd);
            }
            if pfds[0].revents & libc::POLLIN != 0 {
                let mut buf = vec![0u8; mtu + 64];
                if let Ok(n) = tun.recv(&mut buf) {
                    if n > 0 {
                        handle_inbound(
                            &buf[..n],
                            &mut iface,
                            &mut phy,
                            &mut sockets,
                            &mut flows,
                            handle,
                            &waker,
                            &dns_tx,
                            &cfg.blocklist,
                        );
                    }
                }
            }
            pump_tcp_flows(&mut sockets, &mut flows, handle, cfg.proxy_addr, &waker);
            // DNS replies go straight back to the TUN with the queried source addr.
            while let Ok((s, sp, d, dp, resp)) = dns_rx.try_recv() {
                let pkt = build_dns_response_v4(s, sp, d, dp, &resp);
                let _ = tun.send(&pkt);
            }
            iface.poll(SmolInstant::now(), &mut phy, &mut sockets);
            reap_flows(&mut sockets, &mut flows);
        }
        Ok(())
    })();

    // Teardown: dropping the flows closes their channels so the proxy tasks end;
    // close the pipe read end (the Waker closes the write end on Arc drop).
    flows.clear();
    unsafe {
        let _ = libc::close(wake_rd);
    }
    tracing::info!("VPN pump: transparent netstack stopped");
    result
}

/// Classify and feed one captured inbound packet.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn handle_inbound(
    pkt: &[u8],
    iface: &mut Interface,
    phy: &mut TunPhy,
    sockets: &mut SocketSet,
    flows: &mut Vec<Flow>,
    handle: &tokio::runtime::Handle,
    waker: &std::sync::Arc<Waker>,
    dns_tx: &std::sync::mpsc::Sender<DnsReply>,
    blocklist: &crate::blocklist::HostBlocklist,
) {
    let Some(summary) = parse_packet(pkt) else {
        return;
    };
    // IPv4-first: v6 is dropped so apps fall back to v4 (documented limitation).
    let (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) = (summary.src, summary.dst) else {
        return;
    };
    match summary.transport {
        Transport::Tcp {
            src_port,
            dst_port,
            syn,
        } => {
            let key = (src, src_port, dst, dst_port);
            // Guardian blocklist (literal-IP entry): open NO listener for a
            // listed destination — smoltcp answers the staged SYN with RST, so
            // the flow is actively refused before any CONNECT/TLS. Mirrors
            // `decide()`'s FlowAction::Drop (the pure-tested policy).
            let refused =
                syn && !blocklist.is_empty() && blocklist.is_blocked(&format!("{dst}:{dst_port}"));
            if refused {
                tracing::debug!(%dst, dst_port, "guardian blocklist: TCP flow refused (RST)");
            } else if syn && !flows.iter().any(|f| f.key == key) {
                let endpoint = IpEndpoint::new(IpAddress::Ipv4(dst), dst_port);
                if let Ok(h) = open_proxy_listener(sockets, endpoint) {
                    flows.push(Flow {
                        handle: h,
                        key,
                        authority: format!("{dst}:{dst_port}"),
                        up_tx: None,
                        down_rx: None,
                        to_client: std::collections::VecDeque::new(),
                        proxy_done: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        spawned: false,
                        closing: false,
                    });
                }
            }
            phy.stage(pkt.to_vec());
            iface.poll(SmolInstant::now(), phy, sockets);
        }
        Transport::Udp { src_port, dst_port } => {
            if dst_port == QUIC_UDP_PORT {
                return; // drop QUIC -> forces inspectable TCP/443
            }
            if dst_port == 53 && pkt.len() >= 20 {
                // src/dst are at fixed IPv4 offsets regardless of options length.
                let src_o = [pkt[12], pkt[13], pkt[14], pkt[15]];
                let dst_o = [pkt[16], pkt[17], pkt[18], pkt[19]];
                if let Some(payload) = v4_udp_payload(pkt) {
                    let resolver = resolver_for(dst_o);
                    let tx = dns_tx.clone();
                    let w = waker.clone();
                    handle.spawn(dns_query(
                        payload, resolver, src_o, src_port, dst_o, dst_port, tx, w,
                    ));
                }
            }
            // other UDP dropped (documented limitation)
        }
        Transport::Other(_) => {}
    }
}

/// Move bytes between each flow's smoltcp socket and its proxy task, spawning the
/// proxy bridge on establish and closing finished flows.
#[cfg(unix)]
fn pump_tcp_flows(
    sockets: &mut SocketSet,
    flows: &mut [Flow],
    handle: &tokio::runtime::Handle,
    proxy: SocketAddr,
    waker: &std::sync::Arc<Waker>,
) {
    use std::sync::atomic::Ordering;
    for flow in flows.iter_mut() {
        let sock = sockets.get_mut::<tcp::Socket>(flow.handle);

        // On establish, open the proxy CONNECT bridge for this destination.
        if !flow.spawned && sock.state() == tcp::State::Established {
            let (up_tx, up_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(PROXY_UP_CHANNEL);
            let (down_tx, down_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
            handle.spawn(proxy_flow(
                proxy,
                flow.authority.clone(),
                up_rx,
                down_tx,
                flow.proxy_done.clone(),
                waker.clone(),
            ));
            flow.up_tx = Some(up_tx);
            flow.down_rx = Some(down_rx);
            flow.spawned = true;
        }

        // client -> proxy, only while the channel has room (else backpressure).
        if let Some(up_tx) = &flow.up_tx {
            while sock.can_recv() {
                match up_tx.try_reserve() {
                    Ok(permit) => {
                        let mut b = [0u8; 8192];
                        match sock.recv_slice(&mut b) {
                            Ok(n) if n > 0 => permit.send(b[..n].to_vec()),
                            _ => break,
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // proxy -> staging buffer (bounded).
        if let Some(down_rx) = &mut flow.down_rx {
            while flow.to_client.len() < TO_CLIENT_CAP {
                match down_rx.try_recv() {
                    Ok(v) => flow.to_client.extend(v),
                    Err(_) => break,
                }
            }
        }

        // staging buffer -> client (smoltcp send window).
        while sock.can_send() && !flow.to_client.is_empty() {
            let (head, _) = flow.to_client.as_slices();
            match sock.send_slice(head) {
                Ok(n) if n > 0 => {
                    flow.to_client.drain(..n);
                }
                _ => break,
            }
        }

        // client closed its send half -> let the proxy task see EOF upstream.
        if !sock.may_recv() && !sock.can_recv() {
            flow.up_tx = None;
        }

        // proxy finished and everything flushed -> close our half.
        if flow.proxy_done.load(Ordering::Relaxed)
            && flow.to_client.is_empty()
            && !flow.closing
            && sock.is_open()
        {
            sock.close();
            flow.closing = true;
        }
    }
}

/// Remove fully-closed flows (drops their channels -> proxy tasks end).
#[cfg(unix)]
fn reap_flows(sockets: &mut SocketSet, flows: &mut Vec<Flow>) {
    let mut dead = Vec::new();
    flows.retain(|f| {
        let open = sockets.get::<tcp::Socket>(f.handle).is_open();
        if !open {
            dead.push(f.handle);
        }
        open
    });
    for h in dead {
        sockets.remove(h);
    }
}

/// The proxy bridge for one established flow: `CONNECT` to the TLS-inspecting proxy for the
/// flow's destination, then shuttle bytes both ways via the flow's channels.
#[cfg(unix)]
async fn proxy_flow(
    proxy: SocketAddr,
    authority: String,
    mut up_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    down_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    waker: std::sync::Arc<Waker>,
) {
    use std::sync::atomic::Ordering;
    let stream = match connect_via_proxy(proxy, &authority).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(%authority, error = %e, "VPN bridge: proxy CONNECT failed");
            done.store(true, Ordering::Relaxed);
            waker.wake();
            return;
        }
    };
    let (mut rd, mut wr) = stream.into_split();
    // client -> proxy
    let up = tokio::spawn(async move {
        while let Some(chunk) = up_rx.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    // proxy -> client
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                // Bounded: this awaits when the pump's staging buffer is full,
                // which backpressures our upstream reads (no unbounded RAM).
                if down_tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
                waker.wake();
            }
        }
    }
    up.abort();
    done.store(true, Ordering::Relaxed);
    waker.wake();
}

// ===========================================================================
// No-Device-Owner host-filter pump (DNS sinkhole + TLS-SNI reset, NO decrypt)
// ===========================================================================
//
// A SIBLING of `run_netstack` for the no-Device-Owner mode. It reuses the SAME
// smoltcp termination machinery (`TunPhy`, `build_interface`, `open_proxy_listener`,
// the DNS helpers) but with a different egress and the OPPOSITE failure mode:
//   * DNS/53: parse the cleartext QNAME; a blocklisted name gets a SINKHOLE
//     `NXDOMAIN` injected back to the client; everything else is forwarded to the
//     upstream resolver exactly as the main pump does.
//   * TCP: terminate the flow, peek the cleartext TLS-SNI (`super::sni_dns`,
//     NO decryption); a blocklisted SNI host resets the flow, otherwise the flow
//     is dialed DIRECTLY to its real destination and spliced byte-for-byte.
//   * Everything that doesn't parse → fail-SAFE PASS (the accessibility filter is
//     the always-on backstop in the layered model).
//
// STATUS: compiled on CI + host-tested via `handle_host_filtered_flow` /
// `super::sni_dns`; the loop itself awaits on-device validation and is NOT yet
// wired into `run_android_data_path` (see `run_vpn_host_filter`). This mirrors
// how `vpn::wg`/`wg_pump` ship "built, no data-path integration yet".

/// Run the no-Device-Owner host-filter pump until `shutdown` is cancelled. Same
/// runtime contract as [`run_netstack`] (multi-threaded tokio; parks a worker via
/// `block_in_place`). Takes the guardian blocklist by `Arc` (names match here, via
/// DNS QNAME + TLS SNI — not just literal IPs like the decrypting pump).
#[cfg(unix)]
pub(super) async fn run_netstack_host_filter(
    tun: &dyn TunDevice,
    blocklist: std::sync::Arc<crate::blocklist::HostBlocklist>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let handle = tokio::runtime::Handle::current();
    tokio::task::block_in_place(move || host_filter_loop(tun, &blocklist, &handle, &shutdown))
}

#[cfg(unix)]
fn host_filter_loop(
    tun: &dyn TunDevice,
    blocklist: &std::sync::Arc<crate::blocklist::HostBlocklist>,
    handle: &tokio::runtime::Handle,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<()> {
    let tunfd = tun
        .as_raw_fd()
        .ok_or_else(|| NetError::tun("host-filter pump: TUN exposes no pollable fd"))?;
    let mtu = 1500usize;
    let mut phy = TunPhy::new(tun, mtu);
    let mut iface = build_interface(&mut phy);
    let mut sockets = SocketSet::new(Vec::new());
    let mut flows: Vec<Flow> = Vec::new();

    let (wake_rd, wake_wr) = make_pipe()?;
    let waker = std::sync::Arc::new(Waker { fd: wake_wr });
    let (dns_tx, dns_rx) = std::sync::mpsc::channel::<DnsReply>();

    tracing::info!(
        entries = blocklist.len(),
        "host-filter pump: no-Device-Owner DNS+SNI netstack up (no decryption)"
    );

    let result = (|| -> Result<()> {
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            let now = SmolInstant::now();
            let delay_ms = iface
                .poll_delay(now, &sockets)
                .map(|d| d.total_millis() as i32)
                .unwrap_or(200)
                .clamp(1, 200);
            let mut pfds = [
                libc::pollfd {
                    fd: tunfd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wake_rd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 2, delay_ms) };
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(NetError::tun(format!("host-filter pump: poll: {e}")));
            }
            if pfds[1].revents & libc::POLLIN != 0 {
                drain_pipe(wake_rd);
            }
            if pfds[0].revents & libc::POLLIN != 0 {
                let mut buf = vec![0u8; mtu + 64];
                if let Ok(n) = tun.recv(&mut buf) {
                    if n > 0 {
                        handle_inbound_host_filter(
                            &buf[..n],
                            &mut iface,
                            &mut phy,
                            &mut sockets,
                            &mut flows,
                            handle,
                            &waker,
                            &dns_tx,
                            blocklist,
                        );
                    }
                }
            }
            pump_host_filtered_flows(&mut sockets, &mut flows, handle, blocklist, &waker);
            while let Ok((s, sp, d, dp, resp)) = dns_rx.try_recv() {
                let pkt = build_dns_response_v4(s, sp, d, dp, &resp);
                let _ = tun.send(&pkt);
            }
            iface.poll(SmolInstant::now(), &mut phy, &mut sockets);
            reap_flows(&mut sockets, &mut flows);
        }
        Ok(())
    })();

    flows.clear();
    unsafe {
        let _ = libc::close(wake_rd);
    }
    tracing::info!("host-filter pump: no-Device-Owner netstack stopped");
    result
}

/// Classify one captured packet for the host-filter pump. TCP flows are
/// terminated for SNI gating; DNS is QNAME-checked and sinkholed if listed;
/// QUIC/443 is dropped so the browser falls back to inspectable TCP/443.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn handle_inbound_host_filter(
    pkt: &[u8],
    iface: &mut Interface,
    phy: &mut TunPhy,
    sockets: &mut SocketSet,
    flows: &mut Vec<Flow>,
    handle: &tokio::runtime::Handle,
    waker: &std::sync::Arc<Waker>,
    dns_tx: &std::sync::mpsc::Sender<DnsReply>,
    blocklist: &std::sync::Arc<crate::blocklist::HostBlocklist>,
) {
    let Some(summary) = parse_packet(pkt) else {
        return;
    };
    // IPv4-first: v6 is dropped so apps fall back to v4 (documented limitation).
    let (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) = (summary.src, summary.dst) else {
        return;
    };
    match summary.transport {
        Transport::Tcp {
            src_port,
            dst_port,
            syn,
        } => {
            // Always terminate the flow: the SNI host is only visible once the
            // handshake's first record arrives, so the gating happens in
            // `direct_flow` (no pre-CONNECT IP refusal — names, not IPs, match).
            let key = (src, src_port, dst, dst_port);
            if syn && !flows.iter().any(|f| f.key == key) {
                let endpoint = IpEndpoint::new(IpAddress::Ipv4(dst), dst_port);
                if let Ok(h) = open_proxy_listener(sockets, endpoint) {
                    flows.push(Flow {
                        handle: h,
                        key,
                        authority: format!("{dst}:{dst_port}"),
                        up_tx: None,
                        down_rx: None,
                        to_client: std::collections::VecDeque::new(),
                        proxy_done: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        spawned: false,
                        closing: false,
                    });
                }
            }
            phy.stage(pkt.to_vec());
            iface.poll(SmolInstant::now(), phy, sockets);
        }
        Transport::Udp { src_port, dst_port } => {
            if dst_port == QUIC_UDP_PORT {
                return; // drop QUIC -> forces inspectable TCP/443
            }
            if dst_port == 53 && pkt.len() >= 20 {
                let src_o = [pkt[12], pkt[13], pkt[14], pkt[15]];
                let dst_o = [pkt[16], pkt[17], pkt[18], pkt[19]];
                if let Some(payload) = v4_udp_payload(pkt) {
                    // A blocklisted QNAME is sinkholed: inject NXDOMAIN straight
                    // back to the client (no upstream query). Otherwise forward
                    // to the resolver exactly as the main pump does. Fail-SAFE:
                    // an unparsable query forwards.
                    if !blocklist.is_empty()
                        && super::sni_dns::dns_verdict(&payload, blocklist)
                            == super::sni_dns::HostVerdict::Refuse
                    {
                        if let Some(nx) = super::sni_dns::build_nxdomain_response(&payload) {
                            tracing::debug!(
                                "host filter: DNS name on guardian blocklist; NXDOMAIN sinkhole"
                            );
                            // Sourced from the queried server back to the client.
                            let _ = dns_tx.send((dst_o, dst_port, src_o, src_port, nx));
                            waker.wake();
                            return;
                        }
                    }
                    let resolver = resolver_for(dst_o);
                    let tx = dns_tx.clone();
                    let w = waker.clone();
                    handle.spawn(dns_query(
                        payload, resolver, src_o, src_port, dst_o, dst_port, tx, w,
                    ));
                }
            }
            // other UDP dropped (documented limitation)
        }
        Transport::Other(_) => {}
    }
}

/// Move bytes between each flow's smoltcp socket and its `direct_flow` task,
/// spawning the direct bridge on establish. Mirrors [`pump_tcp_flows`] but the
/// per-flow task dials the real destination directly (no proxy/CONNECT) after a
/// fail-SAFE TLS-SNI gate.
#[cfg(unix)]
fn pump_host_filtered_flows(
    sockets: &mut SocketSet,
    flows: &mut [Flow],
    handle: &tokio::runtime::Handle,
    blocklist: &std::sync::Arc<crate::blocklist::HostBlocklist>,
    waker: &std::sync::Arc<Waker>,
) {
    use std::sync::atomic::Ordering;
    for flow in flows.iter_mut() {
        let sock = sockets.get_mut::<tcp::Socket>(flow.handle);

        if !flow.spawned && sock.state() == tcp::State::Established {
            let (up_tx, up_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(PROXY_UP_CHANNEL);
            let (down_tx, down_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
            handle.spawn(direct_flow(
                flow.authority.clone(),
                blocklist.clone(),
                up_rx,
                down_tx,
                flow.proxy_done.clone(),
                waker.clone(),
            ));
            flow.up_tx = Some(up_tx);
            flow.down_rx = Some(down_rx);
            flow.spawned = true;
        }

        if let Some(up_tx) = &flow.up_tx {
            while sock.can_recv() {
                match up_tx.try_reserve() {
                    Ok(permit) => {
                        let mut b = [0u8; 8192];
                        match sock.recv_slice(&mut b) {
                            Ok(n) if n > 0 => permit.send(b[..n].to_vec()),
                            _ => break,
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        if let Some(down_rx) = &mut flow.down_rx {
            while flow.to_client.len() < TO_CLIENT_CAP {
                match down_rx.try_recv() {
                    Ok(v) => flow.to_client.extend(v),
                    Err(_) => break,
                }
            }
        }

        while sock.can_send() && !flow.to_client.is_empty() {
            let (head, _) = flow.to_client.as_slices();
            match sock.send_slice(head) {
                Ok(n) if n > 0 => {
                    flow.to_client.drain(..n);
                }
                _ => break,
            }
        }

        if !sock.may_recv() && !sock.can_recv() {
            flow.up_tx = None;
        }

        if flow.proxy_done.load(Ordering::Relaxed)
            && flow.to_client.is_empty()
            && !flow.closing
            && sock.is_open()
        {
            sock.close();
            flow.closing = true;
        }
    }
}

/// The direct bridge for one established flow in the no-Device-Owner mode.
///
/// Accumulates the opening client bytes (the TLS `ClientHello`, up to
/// [`SNI_PEEK_CAP`]) from `up_rx`, parses the cleartext SNI (NO decryption), and:
///   * a blocklisted SNI host → reset the flow (mark done, dial NOTHING);
///   * otherwise dial the REAL destination directly, REPLAY the peeked bytes, and
///     shuttle bytes both ways via the flow's channels (transparent pass-through).
///
/// Fail-SAFE: no SNI / unparsed / incomplete-then-EOF all PASS (dial direct).
/// `authority` is the captured `ip:port`; the SNI gate matches the cleartext
/// hostname inside the handshake, which an `ip:port` blocklist entry cannot,
/// so name rules apply here for real.
#[cfg(unix)]
async fn direct_flow(
    authority: String,
    blocklist: std::sync::Arc<crate::blocklist::HostBlocklist>,
    mut up_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    down_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    waker: std::sync::Arc<Waker>,
) {
    use super::sni_dns::client_hello_sni;
    use std::sync::atomic::Ordering;

    // 1. Peek the opening bytes until the SNI parses, the cap is hit, or the
    //    client stops sending — buffering them for replay.
    let mut peek: Vec<u8> = Vec::with_capacity(1024);
    let mut sni: Option<String> = None;
    while peek.len() < SNI_PEEK_CAP {
        if let Some(host) = client_hello_sni(&peek) {
            sni = Some(host);
            break;
        }
        // Not a TLS handshake → no SNI to wait for; stop peeking and pass NOW
        // (else a non-TLS request/response flow would deadlock — see
        // `handle_host_filtered_flow`).
        if !super::sni_dns::looks_like_tls_handshake(&peek) {
            break;
        }
        match up_rx.recv().await {
            Some(chunk) => peek.extend_from_slice(&chunk),
            None => break, // client closed its send half before a full hello
        }
    }
    if sni.is_none() {
        sni = client_hello_sni(&peek);
    }

    // 2. SNI verdict (fail-SAFE everywhere but an explicit blocklist match).
    let refuse = matches!(&sni, Some(host) if !blocklist.is_empty() && blocklist.is_blocked(host));
    if refuse {
        tracing::debug!(
            sni = sni.as_deref().unwrap_or("?"),
            %authority,
            "host filter: TLS-SNI on guardian blocklist; flow reset (no dial, not decrypted)"
        );
        done.store(true, Ordering::Relaxed);
        waker.wake();
        return;
    }

    // 3. Pass: dial the real destination directly (no proxy, no decryption).
    let stream = match TcpStream::connect(authority.as_str()).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(%authority, error = %e, "host filter: direct dial failed");
            done.store(true, Ordering::Relaxed);
            waker.wake();
            return;
        }
    };
    let (mut rd, mut wr) = stream.into_split();
    // client -> upstream: replay the peeked hello first, then stream the rest.
    let up = tokio::spawn(async move {
        if !peek.is_empty() && wr.write_all(&peek).await.is_err() {
            return;
        }
        while let Some(chunk) = up_rx.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    // upstream -> client
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if down_tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
                waker.wake();
            }
        }
    }
    up.abort();
    done.store(true, Ordering::Relaxed);
    waker.wake();
}

/// Forward one captured DNS query to `resolver` and return the reply 4-tuple +
/// payload to the loop (which crafts the reply packet and writes it to the TUN).
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn dns_query(
    payload: Vec<u8>,
    resolver: SocketAddr,
    client: [u8; 4],
    client_port: u16,
    server: [u8; 4],
    server_port: u16,
    resp_tx: std::sync::mpsc::Sender<DnsReply>,
    waker: std::sync::Arc<Waker>,
) {
    let sock = match tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(s) => s,
        Err(_) => return,
    };
    if sock.connect(resolver).await.is_err() || sock.send(&payload).await.is_err() {
        return;
    }
    let mut buf = vec![0u8; 2048];
    if let Ok(Ok(n)) =
        tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv(&mut buf)).await
    {
        if n > 0 {
            // Reply is sourced from the server the client queried, back to the client.
            if resp_tx
                .send((server, server_port, client, client_port, buf[..n].to_vec()))
                .is_ok()
            {
                waker.wake();
            }
        }
    }
}

fn parse_http_proxy_addr(url: &str) -> Result<SocketAddr> {
    let authority = url
        .trim()
        .strip_prefix("http://")
        .ok_or_else(|| NetError::tun("VPN proxy_url must start with http://"))?;
    let authority = authority.split('/').next().unwrap_or(authority);
    authority
        .to_socket_addrs()
        .map_err(|e| NetError::tun(format!("resolving VPN proxy_url `{url}`: {e}")))?
        .next()
        .ok_or_else(|| NetError::tun(format!("VPN proxy_url `{url}` resolved to no addresses")))
}

fn parse_packet(packet: &[u8]) -> Option<PacketSummary> {
    match IpVersion::of_packet(packet).ok()? {
        IpVersion::Ipv4 => parse_ipv4(packet),
        IpVersion::Ipv6 => parse_ipv6(packet),
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<PacketSummary> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.frag_offset() != 0 || ip.more_frags() {
        return None;
    }
    let payload = ip.payload();
    let transport = match ip.next_header() {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload).ok()?;
            Transport::Tcp {
                src_port: tcp.src_port(),
                dst_port: tcp.dst_port(),
                syn: tcp.syn(),
            }
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload).ok()?;
            Transport::Udp {
                src_port: udp.src_port(),
                dst_port: udp.dst_port(),
            }
        }
        other => Transport::Other(other),
    };
    Some(PacketSummary {
        src: IpAddress::Ipv4(ip.src_addr()),
        dst: IpAddress::Ipv4(ip.dst_addr()),
        transport,
    })
}

fn parse_ipv6(packet: &[u8]) -> Option<PacketSummary> {
    let ip = Ipv6Packet::new_checked(packet).ok()?;
    let payload = ip.payload();
    let transport = match ip.next_header() {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload).ok()?;
            Transport::Tcp {
                src_port: tcp.src_port(),
                dst_port: tcp.dst_port(),
                syn: tcp.syn(),
            }
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload).ok()?;
            Transport::Udp {
                src_port: udp.src_port(),
                dst_port: udp.dst_port(),
            }
        }
        other => Transport::Other(other),
    };
    Some(PacketSummary {
        src: IpAddress::Ipv6(ip.src_addr()),
        dst: IpAddress::Ipv6(ip.dst_addr()),
        transport,
    })
}

fn tcp_connect_authority(summary: &PacketSummary) -> Option<String> {
    let Transport::Tcp {
        dst_port,
        syn: true,
        ..
    } = summary.transport
    else {
        return None;
    };
    match summary.dst {
        IpAddress::Ipv4(addr) => Some(format!("{addr}:{dst_port}")),
        IpAddress::Ipv6(addr) => Some(format!("[{addr}]:{dst_port}")),
    }
}

/// QUIC's default UDP port. UDP to :443 is HTTP/3 — the bridge drops it so the
/// browser falls back to TCP/443, which the TLS inspection can actually inspect. Without
/// this, HTTP/3 sails straight past the content filter.
const QUIC_UDP_PORT: u16 = 443;

/// What the bridge should do with a parsed packet — the POLICY layer, independent
/// of (and testable without) the still-gated socket pump in [`run_netstack`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FlowAction {
    /// A new TCP flow (SYN): open a tunnel to the TLS-inspecting proxy via `CONNECT` to this
    /// `host:port`, so the flow is decrypted and content-filtered.
    ProxyConnect(String),
    /// Drop the packet (with a reason). Used for QUIC/UDP-443 to force the HTTP/3
    /// fallback to TCP/443 — closing the bypass where HTTP/3 evades the filter.
    Drop(&'static str),
    /// An established TCP flow, DNS, or other traffic the bridge forwards as-is.
    Forward,
}

/// Classify a parsed packet into the action the bridge must take. Pure + total;
/// this is the policy the socket pump (same module) will enforce once it lands.
fn decide(summary: &PacketSummary, blocklist: &crate::blocklist::HostBlocklist) -> FlowAction {
    match summary.transport {
        Transport::Tcp { syn: true, .. } => match tcp_connect_authority(summary) {
            Some(authority) => {
                // The pump sees L3 packets only, so `authority` is `ip:port` —
                // a literal-IP blocklist entry refuses the flow pre-CONNECT.
                // Name (SNI/Host) rules are enforced in the proxy, which every
                // pump flow traverses anyway.
                if blocklist.is_blocked(&authority) {
                    FlowAction::Drop("destination on guardian blocklist (refused pre-CONNECT)")
                } else {
                    FlowAction::ProxyConnect(authority)
                }
            }
            None => FlowAction::Forward,
        },
        Transport::Udp { dst_port, .. } if dst_port == QUIC_UDP_PORT => {
            FlowAction::Drop("QUIC/HTTP-3 (UDP/443) blocked -> forces TCP/443 for TLS inspection")
        }
        _ => FlowAction::Forward,
    }
}

// ---- proxy bridge: synthesise CONNECT → splice (the permissive tun2proxy core) ----
//
// These are the proxy-side half of the pump: once the smoltcp netstack terminates a
// captured TCP flow (the device-validated spike that remains in `run_netstack`), it
// hands the flow's byte stream to `connect_via_proxy` + `splice`. They are pure
// async over any stream so they are unit-tested here against a loopback fake proxy —
// no TUN / device needed.

/// Open a TCP tunnel to the TLS-inspecting proxy via HTTP `CONNECT authority`, so the flow is
/// decrypted + content-filtered. Returns the established stream once the proxy answers
/// 2xx. `authority` is the `host:port` from [`FlowAction::ProxyConnect`].
pub(crate) async fn connect_via_proxy(proxy: SocketAddr, authority: &str) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|e| NetError::tun(format!("VPN bridge: connect proxy {proxy}: {e}")))?;
    let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| NetError::tun(format!("VPN bridge: write CONNECT: {e}")))?;
    let status = read_connect_status(&mut stream).await?;
    if !(200..300).contains(&status) {
        return Err(NetError::tun(format!(
            "VPN bridge: proxy refused CONNECT {authority} (HTTP {status})"
        )));
    }
    Ok(stream)
}

/// Read the proxy's CONNECT response headers (up to CRLFCRLF) and return its status.
async fn read_connect_status<S: AsyncRead + Unpin>(stream: &mut S) -> Result<u16> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| NetError::tun(format!("VPN bridge: read CONNECT response: {e}")))?;
        if n == 0 {
            return Err(NetError::tun("VPN bridge: proxy closed during CONNECT"));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(NetError::tun(
                "VPN bridge: CONNECT response headers too large",
            ));
        }
    }
    parse_status_code(&buf)
}

/// Parse the HTTP status code from a response's status line (`HTTP/1.1 200 …`).
fn parse_status_code(resp: &[u8]) -> Result<u16> {
    let line = resp.split(|&b| b == b'\r').next().unwrap_or(resp);
    let line = std::str::from_utf8(line)
        .map_err(|_| NetError::tun("VPN bridge: non-UTF8 CONNECT status line"))?;
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| NetError::tun(format!("VPN bridge: malformed status line {line:?}")))
}

/// Bidirectionally splice a captured client flow and its proxy tunnel until either
/// half closes (half-close aware via `copy_bidirectional`).
pub(crate) async fn splice<A, B>(client: &mut A, proxy: &mut B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(client, proxy)
        .await
        .map(|_| ())
        .map_err(|e| NetError::tun(format!("VPN bridge: splice: {e}")))
}

// ---- platform-agnostic transparent-flow handler (accept → gate → splice) -------
//
// This is the per-flow state machine the per-OS pumps will drive once they hand us
// an already-accepted client byte stream plus its ORIGINAL destination. It is the
// forward step toward "transparent capture, no explicit proxy": the child's apps
// are NOT configured to point at a proxy — the pump captures the flow at L3 and we
// route it through the SAME in-process TLS-inspecting proxy (the filter decision
// gate) that explicit-proxy mode uses, by SYNTHESISING a `CONNECT <orig-dst>` to it.
// So transparent mode filters byte-for-byte identically to proxy mode.
//
// It is deliberately generic over the client stream (any `AsyncRead + AsyncWrite`)
// and NOT `cfg`-gated, so it compiles and is unit-tested on every host (incl. the
// Windows dev box) with loopback / `tokio::io::duplex` fakes — no TUN, no device.
//
// FAIL-CLOSED CONTRACT (sacrosanct): there is exactly one way out to the network —
// the CONNECT to the in-process gate. A blocklisted destination, an unreachable
// gate, or a gate that refuses the CONNECT all return WITHOUT splicing and WITHOUT
// ever dialing the real destination. The caller drops the client stream (the flow
// is refused). There is NO direct-to-destination fallback anywhere in this path —
// adding one would create exactly the unfiltered path this product forbids.

/// What [`handle_transparent_flow`] did with one captured flow. Returned (instead
/// of inferred from bytes) so the fail-closed invariant is directly assertable in
/// tests: every non-`Spliced` outcome means **no bytes reached the destination**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransparentFlowOutcome {
    /// The flow was routed through the filter gate and spliced both ways to
    /// completion (one half closed). This is the only outcome in which the flow's
    /// bytes ever traversed the gate to the destination.
    Spliced,
    /// The original destination is on the guardian blocklist (literal-IP match);
    /// the flow was refused **before** any CONNECT/TLS/dial. Fail-closed.
    RefusedBlocklist,
    /// The filter gate was unreachable or refused the synthesised CONNECT, so the
    /// flow was dropped with no bytes forwarded and **no direct dial attempted**.
    /// Fail-closed (the whole point: a down gate must block, never pass-through).
    GateUnavailable,
}

/// Format the original destination of a captured flow as the `CONNECT` authority
/// the in-process gate expects (`ip:port`, IPv6 bracketed). The transparent pump
/// only ever sees L3 addresses, so this is always a literal IP — name (SNI/Host)
/// rules are applied inside the gate, which every flow traverses.
pub(crate) fn transparent_flow_authority(dst: SocketAddr) -> String {
    match dst {
        SocketAddr::V4(a) => format!("{}:{}", a.ip(), a.port()),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    }
}

/// Drive ONE captured transparent flow through the filter decision gate.
///
/// `client` is the already-accepted child-side byte stream (terminated by the
/// netstack from the captured TCP flow). `dst` is its ORIGINAL destination
/// (recovered transparently, e.g. from the smoltcp listener endpoint or
/// `SO_ORIGINAL_DST`). `gate` is the in-process TLS-inspecting proxy
/// (`127.0.0.1:8080`) — the SAME filter decision gate explicit-proxy mode uses.
/// `blocklist` is the guardian host blocklist (literal-IP entries match here).
///
/// Steps (the accept → decide → dial-through-gate → splice state machine):
/// 1. **Decide.** A blocklisted destination is refused immediately
///    ([`TransparentFlowOutcome::RefusedBlocklist`]) — no CONNECT, no dial.
/// 2. **Dial through the gate.** Synthesise `CONNECT <dst>` to `gate`
///    ([`connect_via_proxy`]). If the gate is unreachable or refuses, return
///    [`TransparentFlowOutcome::GateUnavailable`] — **fail CLOSED**: the flow is
///    dropped, and the real destination is never dialed directly.
/// 3. **Splice.** On a 2xx, [`splice`] the client and the gate tunnel both ways
///    until either half closes ([`TransparentFlowOutcome::Spliced`]).
///
/// This never dials the destination directly: the gate is the only egress, so the
/// flow is filtered identically to proxy mode or it is blocked.
pub(crate) async fn handle_transparent_flow<C>(
    mut client: C,
    dst: SocketAddr,
    gate: SocketAddr,
    blocklist: &crate::blocklist::HostBlocklist,
) -> TransparentFlowOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let authority = transparent_flow_authority(dst);

    // 1. Decide. A literal-IP guardian-blocklist entry refuses the flow before any
    //    CONNECT/TLS — mirrors the pump's pre-CONNECT RST and `decide`'s Drop.
    if !blocklist.is_empty() && blocklist.is_blocked(&authority) {
        tracing::debug!(%authority, "transparent flow: destination on guardian blocklist; refused (no dial)");
        return TransparentFlowOutcome::RefusedBlocklist;
    }

    // 2. Dial through the gate (NEVER the destination directly). A failure here is
    //    fail-CLOSED: drop the flow, do not fall back to a direct connection.
    let mut tunnel = match connect_via_proxy(gate, &authority).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(%authority, error = %e, "transparent flow: gate unavailable; flow blocked (fail-closed, no direct dial)");
            return TransparentFlowOutcome::GateUnavailable;
        }
    };

    // 3. Splice client <-> gate tunnel both ways. All bytes traverse the gate, so
    //    the flow is TLS-inspected + content-filtered exactly as in proxy mode.
    if let Err(e) = splice(&mut client, &mut tunnel).await {
        tracing::debug!(%authority, error = %e, "transparent flow: splice ended");
    }
    TransparentFlowOutcome::Spliced
}

// ---- no-Device-Owner host-filtered flow (DNS+SNI, NO decryption) -----------
//
// The sibling of `handle_transparent_flow` for the **no-Device-Owner** mode: a
// content filter for an ordinary consumer phone where we CANNOT install a trust
// anchor, so we MUST NOT decrypt. There is no in-process gate/CONNECT here — the
// flow's ONLY content check is the cleartext TLS-SNI host (parsed without
// decrypting; see `super::sni_dns`). A listed host is reset; anything else is
// dialed DIRECTLY to its real destination and spliced byte-for-byte unchanged.
//
// FAIL-SAFE (deliberate, opposite of the decrypting pump's fail-CLOSED): a flow
// whose first bytes don't parse as a blocklisted ClientHello is PASSED. That is
// acceptable ONLY because the on-screen ACCESSIBILITY content filter is the
// always-on backstop in the layered model — this network layer is an early,
// cheap host block, never the sole gate. (Unlike `handle_transparent_flow`,
// which is the egress of record and therefore fail-CLOSED.)
//
// Generic over the client stream and NOT `cfg`-gated, so it is unit-tested on
// every host (incl. the Windows dev box) with `tokio::io::duplex` fakes — the
// `cfg(unix)` loop that drives it on-device cannot be compiled there.

/// What [`handle_host_filtered_flow`] did with one captured flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostFilteredOutcome {
    /// The flow's TLS-SNI host is on the guardian blocklist; it was reset before
    /// any direct dial (no bytes reached the destination).
    RefusedSni,
    /// The flow was passed: dialed directly to its real destination and spliced
    /// both ways (SNI absent / unlisted / unparsed → fail-SAFE pass).
    Passed,
    /// The direct dial to the real destination failed (host unreachable, refused,
    /// etc.). No content decision was bypassed — the destination simply could not
    /// be reached, so nothing was filtered or forwarded.
    DialFailed,
}

/// First-bytes buffer cap before we stop waiting for a complete ClientHello and
/// fail-SAFE pass the flow. Matches the parser's own cap so the two agree.
#[cfg(any(test, unix))]
const SNI_PEEK_CAP: usize = super::sni_dns::MAX_CLIENT_HELLO;

/// Drive ONE captured flow through the no-Device-Owner host filter (DNS is
/// handled separately, in the loop; this is the TCP/TLS path).
///
/// `client` is the already-accepted child-side byte stream (terminated by the
/// netstack from the captured TCP flow). `dst` is its ORIGINAL destination. We:
/// 1. **Peek** the opening client bytes (up to [`SNI_PEEK_CAP`]) WITHOUT
///    consuming them, looking for a complete TLS `ClientHello`.
/// 2. **SNI verdict.** A blocklisted SNI host → reset the flow
///    ([`HostFilteredOutcome::RefusedSni`]); NO dial, no bytes forwarded.
/// 3. **Pass.** Otherwise dial `dst` DIRECTLY (no decryption, no proxy), REPLAY
///    the peeked bytes to it, and splice both ways
///    ([`HostFilteredOutcome::Passed`]). A failed dial is
///    [`HostFilteredOutcome::DialFailed`].
///
/// Buffer-then-replay is load-bearing: the bytes consumed to read the SNI MUST
/// be forwarded to the upstream on pass, or the handshake would be truncated.
#[cfg(any(test, unix))]
pub(crate) async fn handle_host_filtered_flow<C>(
    mut client: C,
    dst: SocketAddr,
    blocklist: &crate::blocklist::HostBlocklist,
) -> HostFilteredOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    use super::sni_dns::{client_hello_sni, HostVerdict};

    // 1. Peek the opening client bytes until we can parse a SNI host, the buffer
    //    cap is hit, or the client stops sending — WITHOUT consuming them (they
    //    are replayed to the upstream on pass).
    let mut peek = Vec::with_capacity(1024);
    let mut sni: Option<String> = None;
    let mut buf = [0u8; 4096];
    while peek.len() < SNI_PEEK_CAP {
        // A complete ClientHello already yields the host → stop reading.
        if let Some(host) = client_hello_sni(&peek) {
            sni = Some(host);
            break;
        }
        // The opening bytes can't be a TLS handshake → there's no cleartext SNI to
        // wait for. Stop peeking and fail-SAFE pass NOW: a non-TLS request/response
        // protocol won't send more until the server replies, and we haven't dialed
        // the server yet — buffering further would deadlock the flow.
        if !super::sni_dns::looks_like_tls_handshake(&peek) {
            break;
        }
        match client.read(&mut buf).await {
            Ok(0) => break, // client half-closed before completing the hello
            Ok(n) => peek.extend_from_slice(&buf[..n]),
            Err(_) => break, // read error → fail-SAFE pass with what we have
        }
    }
    // One last parse in case the cap/EOF was hit exactly as the hello completed.
    if sni.is_none() {
        sni = client_hello_sni(&peek);
    }

    // 2. SNI verdict. A listed host is refused before any dial (fail-SAFE
    //    everywhere else: no SNI, unparsed, or unlisted → pass).
    let verdict = match &sni {
        Some(host) if !blocklist.is_empty() => {
            if blocklist.is_blocked(host) {
                HostVerdict::Refuse
            } else {
                HostVerdict::Pass
            }
        }
        _ => HostVerdict::Pass,
    };
    if verdict == HostVerdict::Refuse {
        tracing::debug!(
            sni = sni.as_deref().unwrap_or("?"),
            %dst,
            "host filter: TLS-SNI on guardian blocklist; flow reset (no dial, not decrypted)"
        );
        // Dropping `client` resets/closes the captured flow; nothing was dialed.
        return HostFilteredOutcome::RefusedSni;
    }

    // 3. Pass: dial the REAL destination directly (no proxy, no decryption),
    //    replay the peeked bytes, and splice the rest unchanged. NOTE: this is
    //    transparent pass-through of the *payload* — the bytes are untouched; we
    //    only terminated the L3 flow because an unprivileged VpnService cannot
    //    raw-forward IP packets (the established model in this module).
    let mut upstream = match TcpStream::connect(dst).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(%dst, error = %e, "host filter: direct dial failed");
            return HostFilteredOutcome::DialFailed;
        }
    };
    if !peek.is_empty() {
        if let Err(e) = upstream.write_all(&peek).await {
            tracing::debug!(%dst, error = %e, "host filter: replaying peeked bytes failed");
            return HostFilteredOutcome::DialFailed;
        }
    }
    if let Err(e) = splice(&mut client, &mut upstream).await {
        tracing::debug!(%dst, error = %e, "host filter: splice ended");
    }
    HostFilteredOutcome::Passed
}

// ---- smoltcp Device over the TUN (the foundation the netstack polls through) ----

/// A `smoltcp` phy device over a [`TunDevice`]. The poll loop stages one inbound
/// packet (read from the blocking TUN) before each `poll`; `receive` hands it to
/// smoltcp once. Outbound frames smoltcp produces are written straight to the TUN.
struct TunPhy<'d> {
    tun: &'d dyn TunDevice,
    mtu: usize,
    inbound: Option<Vec<u8>>,
}

impl<'d> TunPhy<'d> {
    fn new(tun: &'d dyn TunDevice, mtu: usize) -> Self {
        Self {
            tun,
            mtu,
            inbound: None,
        }
    }

    /// Stage the next inbound packet for the upcoming `poll`.
    fn stage(&mut self, packet: Vec<u8>) {
        self.inbound = Some(packet);
    }
}

impl Device for TunPhy<'_> {
    type RxToken<'a>
        = TunRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.inbound.take()?;
        Some((TunRxToken(pkt), TunTxToken { tun: self.tun }))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken { tun: self.tun })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct TunRxToken(Vec<u8>);
impl RxToken for TunRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TunTxToken<'d> {
    tun: &'d dyn TunDevice,
}
impl TxToken for TunTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.tun.send(&buf);
        r
    }
}

// ---- smoltcp interface + transparent per-flow listener (the accept side) ----

/// TCP socket buffer per flow, each direction (64 KiB).
const FLOW_BUF: usize = 64 * 1024;

/// Identity the netstack presents on the TUN: the gateway the Android
/// `VpnService` advertises (`addAddress 10.0.0.2/32`, `addDnsServer 10.0.0.1`).
/// Using `10.0.0.1` puts the client `10.0.0.2` on-link, so egress to the client
/// needs no router, and lets the default route below name OUR OWN address as the
/// any_ip gateway.
const NETSTACK_GATEWAY: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);

/// Build the smoltcp interface over `device` for TRANSPARENT capture.
///
/// `any_ip` lets the interface accept packets addressed to ANY destination (the
/// device's real traffic). But in smoltcp 0.12 `any_ip` is NOT sufficient on its
/// own: `process_ipv4` only accepts a packet to a non-local destination when a
/// route prefix resolves that destination to one of the interface's OWN
/// addresses (otherwise: "Rejecting IPv4 packet; no matching routes"). So we:
///   * give the interface the client-subnet gateway `10.0.0.1/24` as its
///     identity — the client `10.0.0.2` is then on-link for replies; and
///   * add a default IPv4 route via that same `10.0.0.1`, so EVERY captured
///     destination resolves to a local gateway and is accepted on ingress.
///
/// Without the default route the pump rejected every public-IP SYN on ingress —
/// the device had DNS (which bypasses smoltcp) but no TCP (the on-device
/// blackhole). IPv4-only by design: v6 is dropped in `handle_inbound`, so no v6
/// route is needed (it would never be consulted).
fn build_interface(device: &mut TunPhy) -> Interface {
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, device, SmolInstant::now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(NETSTACK_GATEWAY), 24));
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(NETSTACK_GATEWAY)
        .expect("fresh routes table has room for one default route");
    iface
}

/// Open a transparent TCP listener bound to the flow's ORIGINAL destination so the
/// captured SYN is accepted by smoltcp (which, with `any_ip`, answers AS that dst).
/// The accepted byte stream is then spliced to the proxy (`connect_via_proxy`).
fn open_proxy_listener(sockets: &mut SocketSet, dst: IpEndpoint) -> Result<SocketHandle> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; FLOW_BUF]),
        tcp::SocketBuffer::new(vec![0u8; FLOW_BUF]),
    );
    socket
        .listen(dst)
        .map_err(|e| NetError::tun(format!("VPN bridge: listen {dst}: {e}")))?;
    Ok(sockets.add(socket))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp_syn(dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(40u16).to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[93, 184, 216, 34]);
        p[20..22].copy_from_slice(&(49152u16).to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p[32..34].copy_from_slice(&0x5002u16.to_be_bytes());
        p
    }

    fn ipv4_udp(dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(28u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[93, 184, 216, 34]);
        p[20..22].copy_from_slice(&(49152u16).to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p[24..26].copy_from_slice(&(8u16).to_be_bytes());
        p
    }

    #[test]
    fn parses_ipv4_tcp_syn_to_connect_authority() {
        let pkt = ipv4_tcp_syn(443);
        let summary = parse_packet(&pkt).expect("valid packet");
        assert_eq!(summary.src.to_string(), "10.0.0.2");
        assert_eq!(
            tcp_connect_authority(&summary).as_deref(),
            Some("93.184.216.34:443")
        );
    }

    #[test]
    fn udp_is_not_a_connect_target() {
        let pkt = ipv4_udp(443);
        let summary = parse_packet(&pkt).expect("valid packet");
        assert!(matches!(
            summary.transport,
            Transport::Udp { dst_port: 443, .. }
        ));
        assert!(tcp_connect_authority(&summary).is_none());
    }

    /// Empty guardian blocklist for the policy tests (the default).
    fn no_blocklist() -> crate::blocklist::HostBlocklist {
        crate::blocklist::HostBlocklist::default()
    }

    #[test]
    fn tcp_syn_decides_proxy_connect() {
        let s = parse_packet(&ipv4_tcp_syn(443)).expect("valid packet");
        assert_eq!(
            decide(&s, &no_blocklist()),
            FlowAction::ProxyConnect("93.184.216.34:443".into())
        );
    }

    #[test]
    fn blocklisted_destination_ip_is_refused_pre_connect() {
        // A literal-IP guardian-blocklist entry refuses the flow before any
        // CONNECT/TLS; a non-listed destination still proxies normally.
        let s = parse_packet(&ipv4_tcp_syn(443)).expect("valid packet");
        let listed = crate::blocklist::HostBlocklist::parse("93.184.216.34");
        assert!(matches!(decide(&s, &listed), FlowAction::Drop(_)));
        let other = crate::blocklist::HostBlocklist::parse("10.9.9.9");
        assert_eq!(
            decide(&s, &other),
            FlowAction::ProxyConnect("93.184.216.34:443".into())
        );
    }

    #[test]
    fn quic_udp_443_is_dropped() {
        // HTTP/3 over QUIC must be dropped so the browser falls back to TCP/443
        // (which the TLS inspection inspects) — otherwise it bypasses the content filter.
        let s = parse_packet(&ipv4_udp(443)).expect("valid packet");
        assert!(matches!(decide(&s, &no_blocklist()), FlowAction::Drop(_)));
    }

    #[test]
    fn dns_udp_53_is_forwarded_not_dropped() {
        // Only QUIC (443) is dropped; DNS and other UDP must pass through.
        let s = parse_packet(&ipv4_udp(53)).expect("valid packet");
        assert_eq!(decide(&s, &no_blocklist()), FlowAction::Forward);
    }

    #[test]
    fn established_tcp_is_forwarded() {
        let mut pkt = ipv4_tcp_syn(443);
        pkt[32..34].copy_from_slice(&0x5010u16.to_be_bytes()); // ACK, no SYN
        let s = parse_packet(&pkt).expect("valid packet");
        assert_eq!(decide(&s, &no_blocklist()), FlowAction::Forward);
    }

    #[test]
    fn proxy_url_must_be_plain_http() {
        assert!(parse_http_proxy_addr("http://127.0.0.1:8080").is_ok());
        assert!(parse_http_proxy_addr("https://127.0.0.1:8080").is_err());
    }

    #[test]
    fn fragmented_ipv4_is_rejected() {
        // A fragmented packet has no complete L4 header → can't be a CONNECT target;
        // the bridge must not try to interpret it (and must not panic).
        let mut pkt = ipv4_tcp_syn(443);
        pkt[6] = 0x20; // set the "More Fragments" flag
        assert!(parse_packet(&pkt).is_none());
    }

    #[test]
    fn non_syn_tcp_is_not_a_connect_target() {
        // Only a SYN opens a new flow → only a SYN maps to a proxy CONNECT.
        let mut pkt = ipv4_tcp_syn(443);
        pkt[32..34].copy_from_slice(&0x5010u16.to_be_bytes()); // ACK, no SYN
        let summary = parse_packet(&pkt).expect("valid packet");
        assert!(tcp_connect_authority(&summary).is_none());
    }

    #[test]
    fn parses_connect_status_codes() {
        assert_eq!(
            parse_status_code(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap(),
            200
        );
        assert_eq!(
            parse_status_code(b"HTTP/1.1 407 Proxy Auth Required\r\n").unwrap(),
            407
        );
        assert!(parse_status_code(b"garbage").is_err());
    }

    #[tokio::test]
    async fn connect_via_proxy_completes_on_200() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            let mut req = Vec::new();
            loop {
                s.read_exact(&mut byte).await.unwrap();
                req.push(byte[0]);
                if req.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(req.starts_with(b"CONNECT example.com:443 HTTP/1.1"));
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });
        let stream = connect_via_proxy(addr, "example.com:443").await;
        assert!(stream.is_ok(), "CONNECT should succeed: {:?}", stream.err());
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn connect_via_proxy_errors_on_407() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            let mut req = Vec::new();
            while s.read(&mut byte).await.unwrap_or(0) != 0 {
                req.push(byte[0]);
                if req.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = s
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await;
        });
        assert!(connect_via_proxy(addr, "example.com:443").await.is_err());
    }

    #[tokio::test]
    async fn splice_is_bidirectional() {
        let (mut client_ext, mut client_int) = tokio::io::duplex(64);
        let (mut proxy_int, mut proxy_ext) = tokio::io::duplex(64);
        let spliced = tokio::spawn(async move {
            let _ = splice(&mut client_int, &mut proxy_int).await;
        });
        client_ext.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        proxy_ext.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        proxy_ext.write_all(b"world").await.unwrap();
        let mut back = [0u8; 5];
        client_ext.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"world");
        drop(client_ext);
        drop(proxy_ext);
        let _ = spliced.await;
    }

    // ---- handle_transparent_flow: accept → gate → splice state machine --------

    /// Spawn a one-shot fake filter gate that accepts ONE CONNECT, answers with
    /// `status_line` (e.g. `"HTTP/1.1 200 Connection established"`), and — on a 2xx
    /// — echoes whatever the client sends back to it. Returns the bound address.
    /// Models the in-process TLS-inspecting proxy closely enough to drive the flow
    /// handler end-to-end on loopback with no TUN/device.
    async fn fake_gate(status_line: &'static str) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            let mut req = Vec::new();
            while s.read(&mut byte).await.unwrap_or(0) != 0 {
                req.push(byte[0]);
                if req.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = s
                .write_all(format!("{status_line}\r\n\r\n").as_bytes())
                .await;
            if req.windows(8).any(|w| w == b"HTTP/1.1") && status_line.contains(" 2") {
                // 2xx → behave like an established tunnel: echo client bytes back.
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });
        addr
    }

    fn dst_v4() -> SocketAddr {
        SocketAddr::from(([93, 184, 216, 34], 443))
    }

    #[test]
    fn transparent_authority_formats_v4_and_v6() {
        assert_eq!(transparent_flow_authority(dst_v4()), "93.184.216.34:443");
        let v6: SocketAddr = "[2606:2800:220:1::1]:443".parse().unwrap();
        // IPv6 must be bracketed so the `host:port` split in CONNECT is unambiguous.
        assert_eq!(transparent_flow_authority(v6), "[2606:2800:220:1::1]:443");
    }

    #[tokio::test]
    async fn transparent_flow_splices_through_the_gate() {
        // Happy path: the captured client flow is routed through the gate via a
        // synthesised CONNECT, then spliced both ways — identical to proxy mode.
        let gate = fake_gate("HTTP/1.1 200 Connection established").await;
        let (mut child, server_side) = tokio::io::duplex(1024);
        let blocklist = crate::blocklist::HostBlocklist::default();
        let handler = tokio::spawn(async move {
            handle_transparent_flow(server_side, dst_v4(), gate, &blocklist).await
        });
        // Bytes the child sends reach the gate and echo back (proving the splice).
        child.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut back = [0u8; 18];
        child.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"GET / HTTP/1.1\r\n\r\n");
        drop(child); // half-close → splice finishes
        assert_eq!(handler.await.unwrap(), TransparentFlowOutcome::Spliced);
    }

    #[tokio::test]
    async fn transparent_flow_fails_closed_when_gate_unreachable() {
        // FAIL-CLOSED: with no gate listening, the flow must be dropped — NOT dialed
        // directly to the destination. We bind+drop a listener to get a port that is
        // guaranteed closed, then assert the outcome is GateUnavailable and the
        // child stream received zero bytes (nothing was forwarded anywhere).
        let throwaway = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_gate = throwaway.local_addr().unwrap();
        drop(throwaway); // port now closed → CONNECT to the gate fails fast
        let (mut child, server_side) = tokio::io::duplex(1024);
        let blocklist = crate::blocklist::HostBlocklist::default();
        let outcome = handle_transparent_flow(server_side, dst_v4(), dead_gate, &blocklist).await;
        assert_eq!(
            outcome,
            TransparentFlowOutcome::GateUnavailable,
            "an unreachable gate must FAIL CLOSED (block), never fall back to a direct dial"
        );
        // The child half saw EOF (handler dropped its end) and zero data bytes —
        // confirming no bytes were forwarded to the destination or echoed back.
        let mut buf = [0u8; 1];
        assert_eq!(
            child.read(&mut buf).await.unwrap(),
            0,
            "a blocked flow must forward no bytes"
        );
    }

    #[tokio::test]
    async fn transparent_flow_fails_closed_when_gate_refuses_connect() {
        // The gate is reachable but REFUSES the CONNECT (e.g. 407 / 403). That is
        // still fail-closed: the flow is dropped, never dialed directly.
        let gate = fake_gate("HTTP/1.1 407 Proxy Authentication Required").await;
        let (_child, server_side) = tokio::io::duplex(1024);
        let blocklist = crate::blocklist::HostBlocklist::default();
        let outcome = handle_transparent_flow(server_side, dst_v4(), gate, &blocklist).await;
        assert_eq!(
            outcome,
            TransparentFlowOutcome::GateUnavailable,
            "a gate that refuses the CONNECT must block the flow, not bypass the gate"
        );
    }

    #[tokio::test]
    async fn transparent_flow_refuses_blocklisted_destination_before_dialing() {
        // A literal-IP guardian-blocklist entry refuses the flow BEFORE any CONNECT
        // or dial. We point at a dead gate to prove the gate is never even contacted:
        // a blocklist refusal short-circuits, so the dead gate is irrelevant.
        let throwaway = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_gate = throwaway.local_addr().unwrap();
        drop(throwaway);
        let (_child, server_side) = tokio::io::duplex(1024);
        let blocklist = crate::blocklist::HostBlocklist::parse("93.184.216.34");
        let outcome = handle_transparent_flow(server_side, dst_v4(), dead_gate, &blocklist).await;
        assert_eq!(
            outcome,
            TransparentFlowOutcome::RefusedBlocklist,
            "a blocklisted destination must be refused pre-CONNECT (no dial at all)"
        );
        // A non-blocklisted destination is NOT refused here (it would try the gate).
        let (_child2, server_side2) = tokio::io::duplex(1024);
        let other = crate::blocklist::HostBlocklist::parse("10.9.9.9");
        let outcome = handle_transparent_flow(server_side2, dst_v4(), dead_gate, &other).await;
        assert_eq!(
            outcome,
            TransparentFlowOutcome::GateUnavailable,
            "an unlisted destination is routed to the gate (which here is down → fail-closed)"
        );
    }

    // ---- handle_host_filtered_flow: no-Device-Owner DNS+SNI mode (no decrypt) --

    /// Build a TLS ClientHello record carrying `sni` (mirrors the sni_dns test
    /// builder; kept local so these tests are self-contained).
    fn client_hello_record(sni: &str) -> Vec<u8> {
        let host = sni.as_bytes();
        let mut server_name = vec![0x00];
        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name.extend_from_slice(host);
        let mut sni_ext = (server_name.len() as u16).to_be_bytes().to_vec();
        sni_ext.extend_from_slice(&server_name);
        let mut extensions = 0x0000u16.to_be_bytes().to_vec();
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0xAB; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut hs = vec![0x01];
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// A one-shot fake upstream that records everything it receives and echoes it
    /// back, so a splice is observable. Returns (addr, JoinHandle<received bytes>).
    async fn fake_upstream() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got.extend_from_slice(&buf[..n]);
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            got
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn host_filter_passes_and_replays_the_clienthello_to_upstream() {
        // BUFFER-REPLAY (load-bearing): an unlisted SNI is dialed DIRECTLY and the
        // peeked ClientHello bytes are forwarded intact (not dropped after the SNI
        // read) — else the handshake would be truncated at the real server.
        let (upstream, recv) = fake_upstream().await;
        let blocklist = crate::blocklist::HostBlocklist::parse("adult.example");
        let hello = client_hello_record("safe.example");
        let (mut child, server_side) = tokio::io::duplex(8192);
        let hello_for_child = hello.clone();
        let handler = tokio::spawn(async move {
            handle_host_filtered_flow(server_side, upstream, &blocklist).await
        });
        child.write_all(&hello_for_child).await.unwrap();
        // The upstream echoes the replayed hello back to the child (proves splice).
        let mut back = vec![0u8; hello.len()];
        child.read_exact(&mut back).await.unwrap();
        assert_eq!(
            back, hello,
            "upstream must receive the ClientHello bytes intact"
        );
        drop(child); // half-close → splice ends
        assert_eq!(handler.await.unwrap(), HostFilteredOutcome::Passed);
        let got = recv.await.unwrap();
        assert!(
            got.starts_with(&hello),
            "the direct upstream must have received the replayed ClientHello first"
        );
    }

    #[tokio::test]
    async fn host_filter_refuses_blocklisted_sni_without_dialing() {
        // REFUSE = ZERO BYTES: a listed SNI host is reset before any dial. Point at
        // a closed port to prove the upstream is never contacted (a dial would
        // error, but the refusal short-circuits before we ever dial).
        let throwaway = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = throwaway.local_addr().unwrap();
        drop(throwaway);
        let blocklist = crate::blocklist::HostBlocklist::parse(".adult.example");
        let hello = client_hello_record("cdn.adult.example");
        let (mut child, server_side) = tokio::io::duplex(8192);
        let handler =
            tokio::spawn(
                async move { handle_host_filtered_flow(server_side, dead, &blocklist).await },
            );
        child.write_all(&hello).await.unwrap();
        assert_eq!(handler.await.unwrap(), HostFilteredOutcome::RefusedSni);
        // The handler dropped its end without echoing anything → child sees EOF.
        let mut buf = [0u8; 1];
        assert_eq!(
            child.read(&mut buf).await.unwrap(),
            0,
            "a refused flow must forward/echo no bytes"
        );
    }

    #[tokio::test]
    async fn host_filter_passes_non_tls_traffic_through() {
        // Plain (non-TLS) bytes carry no SNI → fail-SAFE pass: dialed directly and
        // spliced unchanged. (The accessibility filter is the backstop for content
        // this network layer can't see.)
        let (upstream, recv) = fake_upstream().await;
        let blocklist = crate::blocklist::HostBlocklist::parse("adult.example");
        let (mut child, server_side) = tokio::io::duplex(8192);
        let handler = tokio::spawn(async move {
            handle_host_filtered_flow(server_side, upstream, &blocklist).await
        });
        child
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut back = [0u8; 9];
        child.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"GET / HTT");
        drop(child);
        assert_eq!(handler.await.unwrap(), HostFilteredOutcome::Passed);
        assert!(recv.await.unwrap().starts_with(b"GET /"));
    }

    #[tokio::test]
    async fn host_filter_incomplete_hello_fails_safe_passes_without_hanging() {
        // INCOMPLETE-FOREVER: a partial ClientHello that never completes must NOT
        // hang on the peek loop — once the client half-closes, the flow fails-SAFE
        // and is dialed/spliced with whatever arrived.
        let (upstream, recv) = fake_upstream().await;
        let blocklist = crate::blocklist::HostBlocklist::parse("adult.example");
        let full = client_hello_record("adult.example"); // would be REFUSED if completed
        let partial = full[..full.len() / 2].to_vec(); // truncated mid-handshake
        let (mut child, server_side) = tokio::io::duplex(8192);
        let p = partial.clone();
        let handler = tokio::spawn(async move {
            handle_host_filtered_flow(server_side, upstream, &blocklist).await
        });
        child.write_all(&p).await.unwrap();
        child.shutdown().await.unwrap(); // half-close: no more bytes ever
                                         // Must terminate (not hang) and pass the partial bytes to the upstream.
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), handler).await;
        assert_eq!(
            outcome
                .expect("handler must not hang on an incomplete hello")
                .unwrap(),
            HostFilteredOutcome::Passed,
            "an incomplete ClientHello fails-SAFE (passes), it does not block or refuse"
        );
        let got = recv.await.unwrap();
        assert_eq!(got, partial, "the partial bytes were forwarded directly");
    }

    struct FakeTun {
        sent: std::sync::Mutex<Vec<Vec<u8>>>,
    }
    impl crate::tun::TunDevice for FakeTun {
        fn up(&mut self, _c: &crate::tun::TunConfig) -> crate::Result<()> {
            Ok(())
        }
        fn recv(&self, _b: &mut [u8]) -> crate::Result<usize> {
            Ok(0)
        }
        fn send(&self, p: &[u8]) -> crate::Result<usize> {
            self.sent.lock().unwrap().push(p.to_vec());
            Ok(p.len())
        }
        fn close(&mut self) -> crate::Result<()> {
            Ok(())
        }
        fn backend(&self) -> &'static str {
            "fake"
        }
    }

    #[test]
    fn proxy_listener_binds_to_original_dst() {
        // A captured SYN to dst:port → a smoltcp socket LISTENing on that exact dst,
        // so (with any_ip) smoltcp accepts the flow as the original server.
        let mut sockets = SocketSet::new(Vec::new());
        let dst = IpEndpoint::new(IpAddress::v4(93, 184, 216, 34), 443);
        let h = open_proxy_listener(&mut sockets, dst).expect("listener opens");
        let sock = sockets.get::<tcp::Socket>(h);
        assert_eq!(
            sock.state(),
            tcp::State::Listen,
            "socket must LISTEN on the original destination"
        );
    }

    #[test]
    fn builds_any_ip_interface_over_a_fake_tun() {
        // The interface builds over the TUN phy device without panicking; any_ip is
        // on so it will accept packets to arbitrary destinations (transparent capture).
        struct Dummy;
        impl crate::tun::TunDevice for Dummy {
            fn up(&mut self, _c: &crate::tun::TunConfig) -> crate::Result<()> {
                Ok(())
            }
            fn recv(&self, _b: &mut [u8]) -> crate::Result<usize> {
                Ok(0)
            }
            fn send(&self, p: &[u8]) -> crate::Result<usize> {
                Ok(p.len())
            }
            fn close(&mut self) -> crate::Result<()> {
                Ok(())
            }
            fn backend(&self) -> &'static str {
                "dummy"
            }
        }
        let dummy = Dummy;
        let mut phy = TunPhy::new(&dummy, 1500);
        let iface = build_interface(&mut phy);
        assert!(iface.any_ip(), "transparent capture needs any_ip enabled");
    }

    #[test]
    fn tun_phy_receives_staged_and_transmits_to_tun() {
        let fake = FakeTun {
            sent: std::sync::Mutex::new(Vec::new()),
        };
        let mut phy = TunPhy::new(&fake, 1500);
        phy.stage(vec![1, 2, 3, 4]);
        let (rx, _tx) =
            Device::receive(&mut phy, SmolInstant::from_millis(0)).expect("staged packet");
        rx.consume(|b| assert_eq!(b, &[1, 2, 3, 4]));
        // Nothing staged now → receive returns None (smoltcp drains until empty).
        assert!(Device::receive(&mut phy, SmolInstant::from_millis(0)).is_none());
        // Transmit writes the frame straight to the TUN.
        let tx = Device::transmit(&mut phy, SmolInstant::from_millis(0)).expect("tx token");
        tx.consume(3, |buf| buf.copy_from_slice(&[9, 8, 7]));
        assert_eq!(fake.sent.lock().unwrap()[0], vec![9, 8, 7]);
    }

    #[test]
    fn private_v4_ranges_are_recognised() {
        assert!(is_private_v4([10, 0, 0, 1]));
        assert!(is_private_v4([192, 168, 1, 1]));
        assert!(is_private_v4([172, 16, 0, 1]));
        assert!(is_private_v4([127, 0, 0, 1]));
        assert!(!is_private_v4([8, 8, 8, 8]));
        assert!(!is_private_v4([1, 1, 1, 1]));
    }

    #[test]
    fn dns_to_private_gateway_goes_to_public_resolver() {
        // A query to the VpnService gateway (10.0.0.1) has no real resolver behind
        // it, so it must be forwarded to the public resolver, not looped back.
        assert_eq!(resolver_for([10, 0, 0, 1]).to_string(), "1.1.1.1:53");
        // A query aimed at a real public resolver is forwarded as-is.
        assert_eq!(resolver_for([8, 8, 8, 8]).to_string(), "8.8.8.8:53");
    }

    #[test]
    fn dns_response_round_trips_through_the_parser() {
        // The crafted reply must be a valid IPv4/UDP packet the same parser accepts,
        // sourced from the queried server back to the client, ports swapped.
        let payload = b"\x12\x34\x81\x80 dns answer bytes";
        let pkt = build_dns_response_v4([8, 8, 8, 8], 53, [10, 0, 0, 2], 49152, payload);
        let summary = parse_packet(&pkt).expect("crafted reply parses");
        assert_eq!(summary.src.to_string(), "8.8.8.8");
        assert_eq!(summary.dst.to_string(), "10.0.0.2");
        assert!(matches!(
            summary.transport,
            Transport::Udp {
                src_port: 53,
                dst_port: 49152
            }
        ));
        // And the payload survives intact.
        assert_eq!(v4_udp_payload(&pkt).as_deref(), Some(&payload[..]));
    }

    #[test]
    fn v4_udp_payload_rejects_tcp() {
        // The DNS payload extractor must not mistake a TCP packet for UDP.
        let tcp = ipv4_tcp_syn(443);
        assert!(v4_udp_payload(&tcp).is_none());
    }

    /// REGRESSION (device blackhole): with `any_ip` on, smoltcp only ACCEPTS an
    /// inbound packet addressed to a non-local destination if a route prefix
    /// resolves that destination to one of the interface's own addresses
    /// (smoltcp 0.12 `process_ipv4`: "Rejecting IPv4 packet; no matching
    /// routes"). The old `build_interface` set `any_ip` but added NO route, so
    /// every captured SYN to a public IP was dropped on INGRESS — the per-flow
    /// listener never saw it and no SYN-ACK was ever emitted toward the client.
    /// DNS still worked only because it bypasses smoltcp entirely.
    ///
    /// This drives a real client SYN (10.0.0.2 -> a public dst) through the
    /// interface + listener and asserts the interface EMITS a reply addressed
    /// BACK to the client. It FAILS against `10.64.0.1/24` + no-route and PASSES
    /// once the identity is on the client subnet AND a default route makes any
    /// destination locally routable.
    #[test]
    fn captured_syn_to_public_dst_emits_synack_to_client() {
        let fake = FakeTun {
            sent: std::sync::Mutex::new(Vec::new()),
        };
        let mut phy = TunPhy::new(&fake, 1500);
        let mut iface = build_interface(&mut phy);
        let mut sockets = SocketSet::new(Vec::new());

        // Per-flow transparent listener bound to the captured destination.
        let dst = IpEndpoint::new(IpAddress::v4(93, 184, 216, 34), 443);
        let _h = open_proxy_listener(&mut sockets, dst).expect("listener opens");

        // The exact packet shape the Android TUN delivers: SYN from 10.0.0.2,
        // with valid IP + TCP checksums (smoltcp verifies them on ingress).
        let mut syn = ipv4_tcp_syn(443);
        {
            let (src, dst) = {
                let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
                (
                    IpAddress::Ipv4(ip.src_addr()),
                    IpAddress::Ipv4(ip.dst_addr()),
                )
            };
            let ihl = (syn[0] & 0x0f) as usize * 4;
            {
                let mut tcp = TcpPacket::new_unchecked(&mut syn[ihl..]);
                tcp.fill_checksum(&src, &dst);
            }
            let mut ip = Ipv4Packet::new_unchecked(&mut syn[..]);
            ip.fill_checksum();
        }
        phy.stage(syn);
        iface.poll(SmolInstant::now(), &mut phy, &mut sockets);

        // The interface must have emitted a SYN-ACK back to the client. Before
        // the fix nothing is emitted because the SYN is rejected on ingress.
        let sent = fake.sent.lock().unwrap();
        let reply = sent.iter().find_map(|p| parse_packet(p)).expect(
            "interface must emit a reply to the captured SYN (none means the SYN \
             was rejected on ingress: any_ip with no matching route)",
        );
        assert_eq!(
            reply.dst.to_string(),
            "10.0.0.2",
            "the SYN-ACK must be addressed back to the client TUN address"
        );
        assert_eq!(
            reply.src.to_string(),
            "93.184.216.34",
            "and sourced AS the original destination (transparent capture)"
        );
        assert!(
            matches!(reply.transport, Transport::Tcp { syn: true, .. }),
            "the emitted reply must be a SYN-ACK"
        );
    }

    /// Narrower invariant guarding the same regression via the public smoltcp
    /// API alone (no packet pump): `any_ip` capture requires a route prefix that
    /// names one of the interface's own addresses as its gateway, so the
    /// interface must OWN the client-subnet gateway it routes through. (The
    /// default-route half — that a public destination resolves to that gateway
    /// — is exercised end-to-end by `captured_syn_to_public_dst_emits_synack_to_client`;
    /// `Routes::lookup` is private to smoltcp so it can't be asserted directly.)
    #[test]
    fn build_interface_owns_the_client_subnet_gateway() {
        struct Dummy;
        impl crate::tun::TunDevice for Dummy {
            fn up(&mut self, _c: &crate::tun::TunConfig) -> crate::Result<()> {
                Ok(())
            }
            fn recv(&self, _b: &mut [u8]) -> crate::Result<usize> {
                Ok(0)
            }
            fn send(&self, p: &[u8]) -> crate::Result<usize> {
                Ok(p.len())
            }
            fn close(&mut self) -> crate::Result<()> {
                Ok(())
            }
            fn backend(&self) -> &'static str {
                "dummy"
            }
        }
        let dummy = Dummy;
        let mut phy = TunPhy::new(&dummy, 1500);
        let iface = build_interface(&mut phy);
        // The interface must own the client-subnet gateway 10.0.0.1 so that a
        // route naming it as via_router satisfies smoltcp's any_ip ingress gate
        // and the client 10.0.0.2 is on-link for egress.
        assert!(
            iface.has_ip_addr(IpAddress::v4(10, 0, 0, 1)),
            "interface must own the 10.0.0.1 gateway the TUN advertises"
        );
    }
}
