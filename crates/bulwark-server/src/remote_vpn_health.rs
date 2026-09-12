//! Live Remote VPN listener readiness.
//!
//! Lease issuance reflects the running Linux listener rather than an environment
//! promise. `/proc/net/tcp*` is inspected instead of opening a synthetic
//! connection, which would otherwise enter the transparent proxy and create a
//! false original-destination failure.

#[cfg(target_os = "linux")]
pub(crate) fn is_ready() -> bool {
    if !matches!(
        std::env::var("BULWARK_WG_FILTER_ACTIVE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    ) {
        return false;
    }
    let port = std::env::var("BULWARK_REMOTE_VPN_TRANSPARENT_BIND")
        .ok()
        .and_then(|value| value.parse::<std::net::SocketAddr>().ok())
        .map(|address| address.port())
        .unwrap_or(8081);
    listening_on_port("/proc/net/tcp", port) || listening_on_port("/proc/net/tcp6", port)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn is_ready() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn listening_on_port(path: &str, port: u16) -> bool {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };
    let expected = format!("{port:04X}");
    contents.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        let _slot = fields.next();
        let Some(local) = fields.next() else {
            return false;
        };
        let _remote = fields.next();
        let Some(state) = fields.next() else {
            return false;
        };
        state.eq_ignore_ascii_case("0A")
            && local
                .rsplit_once(':')
                .is_some_and(|(_, local_port)| local_port.eq_ignore_ascii_case(&expected))
    })
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn proc_parser_requires_listen_state_and_exact_port() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-proc-tcp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tcp");
        std::fs::write(
            &path,
            "  sl  local_address rem_address   st\n   0: 00000000:1F91 00000000:0000 0A\n   1: 00000000:20FB 00000000:0000 01\n",
        )
        .unwrap();
        assert!(super::listening_on_port(path.to_str().unwrap(), 8081));
        assert!(!super::listening_on_port(path.to_str().unwrap(), 8443));
        let _ = std::fs::remove_dir_all(dir);
    }
}
