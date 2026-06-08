//! Routing command plans for transparent VPN mode.
//!
//! The real installers execute these specs only from privileged setup/teardown
//! paths. Keeping the builders pure lets Windows CI test Linux/macOS coverage
//! (v4 + v6, idempotent teardown) without mutating the host firewall.
//!
//! WIP scaffolding: the executor (`execute_plan`) is consumed by the per-platform
//! `install_routing`/`teardown_routing` impls that land with real-device testing,
//! so it reads as dead code under `-D warnings` until then.
#![allow(dead_code)]

use std::fmt;

/// Command plus arguments, with optional stdin for tools such as `pfctl -f -`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    /// Program name, resolved by the platform path (`nft`, `ip`, `pfctl`, ...).
    pub program: String,
    /// Argument vector; no shell interpolation is required.
    pub args: Vec<String>,
    /// Optional standard input.
    pub stdin: Option<String>,
}

impl CommandSpec {
    /// Construct a command spec with no stdin.
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            stdin: None,
        }
    }

    /// Attach stdin to this command.
    pub fn with_stdin(mut self, stdin: impl Into<String>) -> Self {
        self.stdin = Some(stdin.into());
        self
    }
}

impl fmt::Display for CommandSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.program, self.args.join(" "))
    }
}

/// Linux routing parameters for the nftables/TPROXY path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxRouting {
    /// nftables table name.
    pub table: String,
    /// Policy routing table id used for marked packets.
    pub route_table: u16,
    /// Firewall mark applied to packets redirected to userspace.
    pub fwmark: String,
    /// Local MITM proxy port.
    pub proxy_port: u16,
}

impl Default for LinuxRouting {
    fn default() -> Self {
        Self {
            table: "bulwark_vpn".to_string(),
            route_table: 100,
            fwmark: "0xA6315".to_string(),
            proxy_port: 8080,
        }
    }
}

/// Linux install commands: nft TPROXY plus v4/v6 policy routes for marked flows.
pub fn linux_install_plan(cfg: &LinuxRouting) -> Vec<CommandSpec> {
    let proxy = format!(":{}", cfg.proxy_port);
    let route_table = cfg.route_table.to_string();
    vec![
        CommandSpec::new("nft", ["add", "table", "inet", cfg.table.as_str()]),
        CommandSpec::new(
            "nft",
            [
                "add",
                "chain",
                "inet",
                cfg.table.as_str(),
                "prerouting",
                "{ type filter hook prerouting priority mangle ; }",
            ],
        ),
        CommandSpec::new(
            "nft",
            [
                "add",
                "rule",
                "inet",
                cfg.table.as_str(),
                "prerouting",
                "tcp",
                "tproxy",
                "to",
                proxy.as_str(),
                "meta",
                "mark",
                "set",
                cfg.fwmark.as_str(),
            ],
        ),
        CommandSpec::new(
            "ip",
            [
                "rule",
                "add",
                "fwmark",
                cfg.fwmark.as_str(),
                "table",
                route_table.as_str(),
            ],
        ),
        CommandSpec::new(
            "ip",
            [
                "-4",
                "route",
                "add",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                route_table.as_str(),
            ],
        ),
        CommandSpec::new(
            "ip",
            [
                "-6",
                "route",
                "add",
                "local",
                "::/0",
                "dev",
                "lo",
                "table",
                route_table.as_str(),
            ],
        ),
    ]
}

/// Linux teardown commands. These are intentionally tolerant when executed:
/// missing rules/tables are not fatal in the caller.
pub fn linux_teardown_plan(cfg: &LinuxRouting) -> Vec<CommandSpec> {
    let route_table = cfg.route_table.to_string();
    vec![
        CommandSpec::new(
            "ip",
            [
                "-6",
                "route",
                "del",
                "local",
                "::/0",
                "dev",
                "lo",
                "table",
                route_table.as_str(),
            ],
        ),
        CommandSpec::new(
            "ip",
            [
                "-4",
                "route",
                "del",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                route_table.as_str(),
            ],
        ),
        CommandSpec::new(
            "ip",
            [
                "rule",
                "del",
                "fwmark",
                cfg.fwmark.as_str(),
                "table",
                route_table.as_str(),
            ],
        ),
        CommandSpec::new("nft", ["delete", "table", "inet", cfg.table.as_str()]),
    ]
}

/// macOS routing parameters for the pf anchor path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacosRouting {
    /// pf anchor name.
    pub anchor: String,
    /// utun interface name assigned by the kernel.
    pub interface: String,
    /// Local MITM proxy port.
    pub proxy_port: u16,
}

impl Default for MacosRouting {
    fn default() -> Self {
        Self {
            anchor: "com.predatorhunters.bulwark".to_string(),
            interface: "utun0".to_string(),
            proxy_port: 8080,
        }
    }
}

/// pf rules installed under the Bulwark anchor. Covers IPv4 and IPv6 TCP.
pub fn macos_pf_rules(cfg: &MacosRouting) -> String {
    format!(
        "rdr pass on {iface} inet proto tcp from any to any -> 127.0.0.1 port {port}\n\
         rdr pass on {iface} inet6 proto tcp from any to any -> ::1 port {port}\n",
        iface = cfg.interface,
        port = cfg.proxy_port
    )
}

/// macOS install plan: load the anchor rules from stdin and enable pf.
pub fn macos_install_plan(cfg: &MacosRouting) -> Vec<CommandSpec> {
    vec![
        CommandSpec::new("pfctl", ["-a", cfg.anchor.as_str(), "-f", "-"])
            .with_stdin(macos_pf_rules(cfg)),
        CommandSpec::new("pfctl", ["-E"]),
    ]
}

/// macOS teardown plan: flush only the Bulwark anchor.
pub fn macos_teardown_plan(cfg: &MacosRouting) -> Vec<CommandSpec> {
    vec![CommandSpec::new(
        "pfctl",
        ["-a", cfg.anchor.as_str(), "-F", "all"],
    )]
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn execute_plan(plan: &[CommandSpec], tolerate_failure: bool) -> crate::Result<()> {
    use crate::NetError;
    use std::io::Write;
    use std::process::{Command, Stdio};

    for spec in plan {
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args);
        if spec.stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| NetError::tun(format!("spawning `{spec}`: {e}")))?;
        if let Some(stdin) = &spec.stdin {
            if let Some(mut child_stdin) = child.stdin.take() {
                child_stdin
                    .write_all(stdin.as_bytes())
                    .map_err(|e| NetError::tun(format!("writing stdin for `{spec}`: {e}")))?;
            }
        }
        let output = child
            .wait_with_output()
            .map_err(|e| NetError::tun(format!("waiting for `{spec}`: {e}")))?;
        if !output.status.success() && !tolerate_failure {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            };
            return Err(NetError::tun(format!(
                "`{spec}` failed ({}): {detail}",
                output.status
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_plan_has_ipv4_and_ipv6_local_routes() {
        let plan = linux_install_plan(&LinuxRouting::default());
        let rendered: Vec<String> = plan.iter().map(ToString::to_string).collect();
        assert!(rendered
            .iter()
            .any(|c| c.contains("nft add table inet bulwark_vpn")));
        assert!(rendered.iter().any(|c| c.contains("tproxy to :8080")));
        assert!(rendered
            .iter()
            .any(|c| c.contains("ip -4 route add local 0.0.0.0/0")));
        assert!(rendered
            .iter()
            .any(|c| c.contains("ip -6 route add local ::/0")));
    }

    #[test]
    fn linux_teardown_deletes_routes_before_table() {
        let plan = linux_teardown_plan(&LinuxRouting::default());
        assert_eq!(
            plan.last().unwrap().to_string(),
            "nft delete table inet bulwark_vpn"
        );
        assert!(plan[0].to_string().contains("ip -6 route del"));
        assert!(plan[1].to_string().contains("ip -4 route del"));
    }

    #[test]
    fn macos_pf_rules_cover_ipv4_and_ipv6() {
        let cfg = MacosRouting {
            interface: "utun9".to_string(),
            ..Default::default()
        };
        let rules = macos_pf_rules(&cfg);
        assert!(rules.contains("on utun9 inet proto tcp"));
        assert!(rules.contains("on utun9 inet6 proto tcp"));
        assert!(rules.contains("port 8080"));
    }

    #[test]
    fn macos_install_uses_anchor_stdin() {
        let plan = macos_install_plan(&MacosRouting::default());
        assert_eq!(plan[0].program, "pfctl");
        assert!(plan[0].args.contains(&"-f".to_string()));
        assert!(plan[0].stdin.as_ref().unwrap().contains("rdr pass"));
        assert_eq!(plan[1].to_string(), "pfctl -E");
    }
}
