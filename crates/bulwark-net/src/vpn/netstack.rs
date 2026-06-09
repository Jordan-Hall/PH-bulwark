//! Shared transparent-VPN bridge scaffolding.
//!
//! This is the permissive replacement seam for the removed GPL `tun2proxy`
//! backend. The packet parser, flow policy, and the proxy bridge (synthesise
//! `CONNECT` → bidirectional `splice`) are in place and unit-tested; the smoltcp
//! TCP-termination that wires a captured TUN flow into the bridge is the remaining
//! device-validated spike, so `run_netstack` is deliberately still fail-closed.
#![allow(dead_code)] // Bridge halves are exercised by tests until the pump lands.

use std::net::{SocketAddr, ToSocketAddrs};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet,
    TcpPacket, UdpPacket,
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
}

impl BridgeConfig {
    pub(super) fn from_vpn(cfg: &VpnConfig) -> Result<Self> {
        Ok(Self {
            proxy_addr: parse_http_proxy_addr(cfg.proxy_url())?,
        })
    }
}

pub(super) async fn run_netstack(
    _tun: &dyn TunDevice,
    cfg: BridgeConfig,
    _shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    Err(NetError::unsupported(format!(
        "smoltcp TCP bridge is scaffolded but not enabled yet (proxy target {})",
        cfg.proxy_addr
    )))
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
/// browser falls back to TCP/443, which the MITM can actually inspect. Without
/// this, HTTP/3 sails straight past the content filter.
const QUIC_UDP_PORT: u16 = 443;

/// What the bridge should do with a parsed packet — the POLICY layer, independent
/// of (and testable without) the still-gated socket pump in [`run_netstack`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FlowAction {
    /// A new TCP flow (SYN): open a tunnel to the MITM proxy via `CONNECT` to this
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
fn decide(summary: &PacketSummary) -> FlowAction {
    match summary.transport {
        Transport::Tcp { syn: true, .. } => tcp_connect_authority(summary)
            .map(FlowAction::ProxyConnect)
            .unwrap_or(FlowAction::Forward),
        Transport::Udp { dst_port, .. } if dst_port == QUIC_UDP_PORT => {
            FlowAction::Drop("QUIC/HTTP-3 (UDP/443) blocked -> forces TCP/443 for MITM")
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

/// Open a TCP tunnel to the MITM proxy via HTTP `CONNECT authority`, so the flow is
/// decrypted + content-filtered. Returns the established stream once the proxy answers
/// 2xx. `authority` is the `host:port` from [`FlowAction::ProxyConnect`].
async fn connect_via_proxy(proxy: SocketAddr, authority: &str) -> Result<TcpStream> {
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
async fn splice<A, B>(client: &mut A, proxy: &mut B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(client, proxy)
        .await
        .map(|_| ())
        .map_err(|e| NetError::tun(format!("VPN bridge: splice: {e}")))
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

/// Build the smoltcp interface over `device` for TRANSPARENT capture: `any_ip` so it
/// accepts packets addressed to ANY destination (the device's real traffic), with a
/// dummy in-subnet address as the netstack's own identity.
fn build_interface(device: &mut TunPhy) -> Interface {
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, device, SmolInstant::now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 64, 0, 1), 24));
    });
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

    #[test]
    fn tcp_syn_decides_proxy_connect() {
        let s = parse_packet(&ipv4_tcp_syn(443)).expect("valid packet");
        assert_eq!(
            decide(&s),
            FlowAction::ProxyConnect("93.184.216.34:443".into())
        );
    }

    #[test]
    fn quic_udp_443_is_dropped() {
        // HTTP/3 over QUIC must be dropped so the browser falls back to TCP/443
        // (which the MITM inspects) — otherwise it bypasses the content filter.
        let s = parse_packet(&ipv4_udp(443)).expect("valid packet");
        assert!(matches!(decide(&s), FlowAction::Drop(_)));
    }

    #[test]
    fn dns_udp_53_is_forwarded_not_dropped() {
        // Only QUIC (443) is dropped; DNS and other UDP must pass through.
        let s = parse_packet(&ipv4_udp(53)).expect("valid packet");
        assert_eq!(decide(&s), FlowAction::Forward);
    }

    #[test]
    fn established_tcp_is_forwarded() {
        let mut pkt = ipv4_tcp_syn(443);
        pkt[32..34].copy_from_slice(&0x5010u16.to_be_bytes()); // ACK, no SYN
        let s = parse_packet(&pkt).expect("valid packet");
        assert_eq!(decide(&s), FlowAction::Forward);
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
}
