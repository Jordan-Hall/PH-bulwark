use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const DEFAULT_TRANSPARENT_BIND: &str = "0.0.0.0:8081";
const HEALTH_TIMEOUT: Duration = Duration::from_millis(40);

pub(crate) fn is_ready() -> bool {
    if !matches!(
        std::env::var("BULWARK_WG_FILTER_ACTIVE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    ) {
        return false;
    }
    let bind = std::env::var("BULWARK_REMOTE_VPN_TRANSPARENT_BIND")
        .unwrap_or_else(|_| DEFAULT_TRANSPARENT_BIND.to_string());
    let Ok(bind) = bind.parse::<SocketAddr>() else {
        return false;
    };
    let probe = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), bind.port());
    TcpStream::connect_timeout(&probe, HEALTH_TIMEOUT).is_ok()
}
