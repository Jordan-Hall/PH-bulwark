//! QUIC / HTTP-3 downgrade.
//!
//! QUIC runs over **UDP/443** and is end-to-end encrypted with no on-path
//! decryption point, so it bypasses our TCP TLS inspection entirely. The threat model's
//! fail-safe table mandates **downgrade**: block UDP/443 so apps fall back to
//! inspectable TCP/HTTP-2 (~85–90% do — platform-feasibility §4). A small number
//! of apps won't fall back; those go on a per-app allowlist and the failure is
//! shown on the coverage dashboard.
//!
//! ## Mechanism (per platform — now wired via `std::process::Command`)
//!   * **Windows** → `netsh advfirewall firewall add rule` blocking *outbound*
//!     UDP remoteport 443. We use a stable rule name so teardown is an exact
//!     `delete rule name=...`. (A WFP in-process filter is the more robust future
//!     option; the `netsh` path is the documented, dependency-free baseline and
//!     is what we ship.)
//!   * **Linux** → `nft` if present (a dedicated `inet bulwark_quic` table with an
//!     `output` chain dropping `udp dport 443`), else fall back to `iptables`
//!     (`-A OUTPUT -p udp --dport 443 -j DROP`). Teardown deletes the table /
//!     removes the rule so we never leave UDP/443 blocked after the VPN is gone.
//!   * **macOS** → `pfctl` with a dedicated anchor (`bulwark_quic`): we load a
//!     `block drop quick out proto udp from any to any port 443` rule into the
//!     anchor and enable pf. Teardown flushes the anchor (`pfctl -a bulwark_quic
//!     -F all`) so UDP/443
//!     is never left blocked after the VPN stops. **Honest limitation:** an anchor
//!     only takes effect if the main ruleset references it (`anchor "bulwark_quic"`
//!     in `pf.conf`); the bundled VPN profile adds that directive at install. We do
//!     not rewrite `pf.conf` at teardown — flushing the anchor empties our rules
//!     without touching the system ruleset.
//!   * **Android** → `VpnService` simply does not route UDP/443 (drops it); there
//!     is no host firewall command, so this controller is a no-op there.
//!
//! The cost is a 1–3 s first-connection delay while the app retries over TCP
//! (documented; acceptable for parental control).
//!
//! No new crate: everything here shells out via [`std::process::Command`].

use crate::{NetError, Result};

/// Stable name for the firewall rule/table so add + delete refer to the same
/// object (idempotent apply, exact teardown). Greppable in `netsh`/`nft` output.
const RULE_NAME: &str = "Bulwark-QUIC-Downgrade";

/// Stable `pfctl` anchor name (macOS). pf anchor names cannot contain spaces, so
/// this uses the underscore form rather than [`RULE_NAME`]; install + teardown
/// both reference exactly this anchor.
#[cfg(any(target_os = "macos", test))]
const PF_ANCHOR: &str = "bulwark_quic";

/// QUIC downgrade controller: decides which flows to block and applies the
/// platform firewall rule blocking outbound UDP/443.
pub struct QuicDowngrade {
    enabled: bool,
    /// Hosts/apps exempt from downgrade (they don't fall back to TCP).
    allowlist: Vec<String>,
}

impl QuicDowngrade {
    /// New controller from config.
    pub fn new(enabled: bool, allowlist: Vec<String>) -> Self {
        QuicDowngrade { enabled, allowlist }
    }

    /// Should this UDP destination be blocked to force a TCP fallback?
    /// Blocks UDP/443 unless downgrade is disabled or the host is allowlisted.
    pub fn should_block_udp(&self, dst_port: u16, app_or_host: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if dst_port != 443 {
            return false; // only QUIC's well-known port; DNS/QUIC-on-other-ports untouched
        }
        !self
            .allowlist
            .iter()
            .any(|a| a.eq_ignore_ascii_case(app_or_host))
    }

    /// Apply the platform firewall rule that blocks outbound UDP/443.
    ///
    /// Idempotent: an existing rule is removed first so a restart does not stack
    /// duplicates. No-op when downgrade is disabled. Pairs with [`Self::remove_rule`].
    pub fn apply_rule(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(windows)]
        {
            // Best-effort clean slate (ignore "no rule matched" on first run),
            // then add the blocking rule.
            let _ = windows_delete_rule();
            windows_add_rule()?;
            tracing::info!(
                rule = RULE_NAME,
                "QUIC downgrade: blocking outbound UDP/443 (netsh)"
            );
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            let _ = linux_remove_rule(); // clean slate
            linux_add_rule()?;
            tracing::info!(
                rule = RULE_NAME,
                "QUIC downgrade: dropping outbound UDP/443 (nft/iptables)"
            );
            Ok(())
        }

        #[cfg(target_os = "macos")]
        {
            let _ = macos_remove_rule(); // clean slate (flush any stale anchor rules)
            macos_add_rule()?;
            // NOTE (device-validation gate): loading + enabling the anchor only
            // ENFORCES the drop if the main pf ruleset references it
            // (`anchor "bulwark_quic"` in pf.conf). The bundled VPN profile adds
            // that directive at install; until on-device validation confirms the
            // reference is live we log a warning so a "success" here is not read as
            // proof UDP/443 is actually blocked.
            tracing::warn!(
                anchor = PF_ANCHOR,
                "QUIC downgrade: anchor loaded + pf enabled; enforcement requires the \
                 bundled profile's `anchor \"bulwark_quic\"` reference (device-validated)"
            );
            Ok(())
        }

        #[cfg(target_os = "android")]
        {
            // VpnService handles UDP/443 by simply not routing it; nothing to do.
            tracing::debug!(
                "QUIC downgrade: handled by VpnService routing (no host firewall rule)"
            );
            Ok(())
        }

        #[cfg(not(any(
            windows,
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )))]
        {
            tracing::warn!("QUIC downgrade not implemented on this platform; UDP/443 NOT blocked");
            Ok(())
        }
    }

    /// Remove the QUIC-downgrade firewall rule (teardown — pairs with shutdown).
    /// Must run on shutdown so we don't leave UDP/443 blocked after the VPN is gone.
    /// Tolerant of "rule not present" (returns Ok), since teardown may run after a
    /// crash where the rule was never applied.
    pub fn remove_rule(&self) -> Result<()> {
        #[cfg(windows)]
        {
            match windows_delete_rule() {
                Ok(()) => tracing::info!(rule = RULE_NAME, "QUIC downgrade rule removed (netsh)"),
                // A missing rule is fine on teardown; log at debug and succeed.
                Err(e) => tracing::debug!("QUIC downgrade rule removal: {e} (treating as absent)"),
            }
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            match linux_remove_rule() {
                Ok(()) => tracing::info!(
                    rule = RULE_NAME,
                    "QUIC downgrade rule removed (nft/iptables)"
                ),
                Err(e) => tracing::debug!("QUIC downgrade rule removal: {e} (treating as absent)"),
            }
            Ok(())
        }

        #[cfg(target_os = "macos")]
        {
            match macos_remove_rule() {
                Ok(()) => tracing::info!(
                    anchor = PF_ANCHOR,
                    "QUIC downgrade rule removed (pfctl anchor flushed)"
                ),
                Err(e) => tracing::debug!("QUIC downgrade rule removal: {e} (treating as absent)"),
            }
            Ok(())
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            tracing::debug!("QUIC downgrade rule removal: nothing to do on this platform");
            Ok(())
        }
    }
}

/// Run a command, returning Ok on success or a `Quic` error carrying the program,
/// exit status, and captured stderr. Used by every platform path so failures are
/// uniform and never panic on the control path.
#[cfg(any(windows, target_os = "linux"))]
fn run(program: &str, args: &[&str]) -> Result<()> {
    use std::process::Command;
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| NetError::Quic(format!("spawning `{program}`: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(NetError::Quic(format!(
            "`{program} {}` failed ({}): {}",
            args.join(" "),
            output.status,
            // netsh/iptables often write the useful message to stdout, not stderr.
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            }
        )))
    }
}

// --- Windows: netsh advfirewall ---------------------------------------------

#[cfg(windows)]
fn windows_add_rule() -> Result<()> {
    // `netsh advfirewall firewall add rule name=<n> dir=out action=block
    //  protocol=UDP remoteport=443`
    run(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={RULE_NAME}"),
            "dir=out",
            "action=block",
            "protocol=UDP",
            "remoteport=443",
        ],
    )
}

#[cfg(windows)]
fn windows_delete_rule() -> Result<()> {
    run(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={RULE_NAME}"),
            "protocol=UDP",
            "remoteport=443",
        ],
    )
}

// --- Linux: nft (preferred) with iptables fallback --------------------------

#[cfg(target_os = "linux")]
fn have(program: &str) -> bool {
    use std::process::Command;
    // `<prog> --version` exits 0 when present. `Command::output` errors if the
    // binary is missing (ENOENT), which we treat as "not available".
    Command::new(program)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linux_add_rule() -> Result<()> {
    if have("nft") {
        // Dedicated table so teardown is a single `delete table`, isolated from
        // the TPROXY ruleset.
        run("nft", &["add", "table", "inet", RULE_NAME])?;
        run(
            "nft",
            &[
                "add",
                "chain",
                "inet",
                RULE_NAME,
                "output",
                "{ type filter hook output priority 0 ; }",
            ],
        )?;
        run(
            "nft",
            &[
                "add", "rule", "inet", RULE_NAME, "output", "udp", "dport", "443", "drop",
            ],
        )
    } else {
        // Fallback: append a single OUTPUT DROP rule. Teardown deletes the exact
        // same rule spec.
        run(
            "iptables",
            &["-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "DROP"],
        )
    }
}

#[cfg(target_os = "linux")]
fn linux_remove_rule() -> Result<()> {
    if have("nft") {
        // Deleting the whole table removes the chain + rule in one shot.
        run("nft", &["delete", "table", "inet", RULE_NAME])
    } else {
        run(
            "iptables",
            &["-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "DROP"],
        )
    }
}

// --- macOS: pfctl anchor ----------------------------------------------------
//
// The argv/anchor-body builders below are cfg'd `any(target_os = "macos", test)`
// so they compile + are unit-tested on this (Windows) host; only the execution
// (`macos_add_rule`/`macos_remove_rule`) is `target_os = "macos"`.

/// The pf rule body loaded into our anchor: drop all *outbound* UDP to port 443
/// (QUIC) on every interface. `quick` makes the decision final so nothing later
/// in our anchor re-allows it.
#[cfg(any(target_os = "macos", test))]
fn macos_pf_rule() -> String {
    "block drop quick out proto udp from any to any port 443\n".to_string()
}

/// argv to load the anchor rule from stdin: `pfctl -a bulwark_quic -f -`.
/// (`-f -` reads the ruleset from stdin, which we feed [`macos_pf_rule`].)
#[cfg(any(target_os = "macos", test))]
fn macos_pf_load_argv() -> Vec<String> {
    vec![
        "pfctl".to_string(),
        "-a".to_string(),
        PF_ANCHOR.to_string(),
        "-f".to_string(),
        "-".to_string(),
    ]
}

/// argv to ensure pf is enabled: `pfctl -E`. (Idempotent; `-E` is a no-op +
/// success if pf is already on, beyond a reference-count log.)
#[cfg(any(target_os = "macos", test))]
fn macos_pf_enable_argv() -> Vec<String> {
    vec!["pfctl".to_string(), "-E".to_string()]
}

/// argv to flush every rule from our anchor: `pfctl -a bulwark_quic -F all`.
/// This is the exact teardown — it empties OUR anchor only and never touches the
/// system ruleset, so UDP/443 is unblocked without disabling pf globally.
#[cfg(any(target_os = "macos", test))]
fn macos_pf_flush_argv() -> Vec<String> {
    vec![
        "pfctl".to_string(),
        "-a".to_string(),
        PF_ANCHOR.to_string(),
        "-F".to_string(),
        "all".to_string(),
    ]
}

/// Run `pfctl`, feeding `stdin_body` to its stdin when non-empty (used by the
/// `-f -` anchor load). Mirrors [`run`]'s error shape.
#[cfg(target_os = "macos")]
fn run_pfctl(argv: &[String], stdin_body: Option<&str>) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| NetError::Quic("empty pfctl command".to_string()))?;
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_body.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| NetError::Quic(format!("spawning `{program}`: {e}")))?;
    if let Some(body) = stdin_body {
        child
            .stdin
            .take()
            .ok_or_else(|| NetError::Quic("pfctl stdin unavailable".to_string()))?
            .write_all(body.as_bytes())
            .map_err(|e| NetError::Quic(format!("writing pfctl ruleset: {e}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| NetError::Quic(format!("waiting on `{program}`: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(NetError::Quic(format!(
            "`{}` failed ({}): {}",
            argv.join(" "),
            output.status,
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            }
        )))
    }
}

#[cfg(target_os = "macos")]
fn macos_add_rule() -> Result<()> {
    // Load our drop rule into the dedicated anchor, then make sure pf is on.
    run_pfctl(&macos_pf_load_argv(), Some(&macos_pf_rule()))?;
    run_pfctl(&macos_pf_enable_argv(), None)
}

#[cfg(target_os = "macos")]
fn macos_remove_rule() -> Result<()> {
    // Flush only our anchor — leaves the system ruleset + pf state intact.
    run_pfctl(&macos_pf_flush_argv(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_udp_443_by_default() {
        let q = QuicDowngrade::new(true, vec![]);
        assert!(q.should_block_udp(443, "youtube.com"));
        assert!(!q.should_block_udp(53, "youtube.com")); // not 443 → leave alone
        assert!(q.should_block_udp(443, "")); // still 443 → block (no allowlist)
    }

    #[test]
    fn allowlist_exempts_non_fallback_apps() {
        let q = QuicDowngrade::new(true, vec!["stubborn-app.example".to_owned()]);
        assert!(!q.should_block_udp(443, "stubborn-app.example"));
        assert!(!q.should_block_udp(443, "STUBBORN-APP.EXAMPLE")); // case-insensitive
        assert!(q.should_block_udp(443, "other.example"));
    }

    #[test]
    fn disabled_blocks_nothing() {
        let q = QuicDowngrade::new(false, vec![]);
        assert!(!q.should_block_udp(443, "youtube.com"));
        // No-op when disabled: returns Ok WITHOUT shelling out to netsh/nft, so
        // the unit test stays hermetic (no firewall mutation, no admin needed).
        q.apply_rule().unwrap();
    }

    // --- macOS pfctl command-construction tests (host-agnostic: the argv/rule
    // builders are cfg'd `any(target_os = "macos", test)` so they compile + run
    // on this host; runtime execution is device-validated later). ---

    #[test]
    fn macos_pf_rule_drops_outbound_udp_443() {
        let rule = macos_pf_rule();
        assert!(rule.contains("block drop"));
        assert!(rule.contains("out")); // outbound only
        assert!(rule.contains("proto udp"));
        assert!(rule.contains("port 443"));
    }

    #[test]
    fn macos_pf_load_argv_targets_our_anchor_from_stdin() {
        assert_eq!(
            macos_pf_load_argv(),
            vec!["pfctl", "-a", PF_ANCHOR, "-f", "-"]
        );
    }

    #[test]
    fn macos_pf_enable_argv_is_dash_e() {
        assert_eq!(macos_pf_enable_argv(), vec!["pfctl", "-E"]);
    }

    #[test]
    fn macos_pf_flush_argv_flushes_only_our_anchor() {
        // Teardown MUST scope to our anchor (-a PF_ANCHOR) so it never disables pf
        // globally or touches the system ruleset — UDP/443 is unblocked cleanly.
        assert_eq!(
            macos_pf_flush_argv(),
            vec!["pfctl", "-a", PF_ANCHOR, "-F", "all"]
        );
    }

    #[test]
    fn macos_anchor_name_has_no_spaces() {
        // pf anchor names cannot contain spaces (unlike the netsh RULE_NAME).
        assert!(!PF_ANCHOR.contains(' '));
    }
}
