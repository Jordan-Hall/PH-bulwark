//! Shared transparent-VPN bridge scaffolding.
//!
//! This is the permissive replacement seam for the removed GPL `tun2proxy`
//! backend. The packet parser and flow-target logic are in place and unit-tested;
//! the full smoltcp socket pump is deliberately still fail-closed until it has
//! loopback and real-device validation.
#![allow(dead_code)] // Parser is exercised by tests until the socket pump lands.

use std::net::{SocketAddr, ToSocketAddrs};

use smoltcp::wire::{
    IpAddress, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
};

use crate::tun::TunDevice;
use crate::{NetError, Result};

use super::VpnConfig;

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
}
