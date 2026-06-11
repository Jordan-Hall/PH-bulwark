//! Guardian host blocklist — the earliest, cheapest "block adult websites" gate.
//!
//! A [`HostBlocklist`] is a config-loaded set of exact hostnames plus suffix
//! rules (`.example.com` / `*.example.com` match the apex and every subdomain).
//! It is consulted at two points, BEFORE any content analysis:
//!   * the TLS-inspecting proxy refuses a CONNECT / decrypted request to a
//!     listed host with the inline block page (`proxy.rs` — no tunnel opened);
//!   * the transparent VPN pump refuses a new TCP flow whose original
//!     destination IP is listed (no listener opened → smoltcp answers RST).
//!
//! Sources, in priority order: an explicit [`crate::NetConfig::blocklist_path`],
//! else the `BULWARK_BLOCKLIST` env var (a file path), else EMPTY — an empty
//! list changes no behavior. A *configured but unreadable* file is a
//! fail-CLOSED start error: a guardian's blocklist must never silently vanish.
//!
//! File format: one entry per line; `#` starts a comment; blank lines ignored;
//! entries are case-insensitive; ports / trailing dots are stripped on match.
//! `host.example` matches exactly that host; `.host.example` (or
//! `*.host.example`) matches it and any subdomain. Literal IPv4/IPv6 addresses
//! are exact entries (the pump can only match these).

use std::collections::HashSet;
use std::path::Path;

/// A parsed guardian host blocklist (exact hosts + suffix rules). Cheap to
/// share behind an `Arc`; matching is pure and allocation-light.
#[derive(Clone, Debug, Default)]
pub struct HostBlocklist {
    /// Exact (normalized) hostnames / literal IPs.
    exact: HashSet<String>,
    /// Suffix rules stored as the bare apex (`example.com` for `.example.com`),
    /// matching the apex itself and any subdomain.
    suffixes: Vec<String>,
}

/// Normalize a host for matching: trim, strip `[v6]` brackets or a single
/// trailing `:port`, drop a trailing dot, lowercase. `None` if nothing remains.
fn normalize(host: &str) -> Option<String> {
    let mut h = host.trim();
    if let Some(rest) = h.strip_prefix('[') {
        // `[v6]` or `[v6]:port` → the address between the brackets.
        h = rest.split(']').next().unwrap_or(rest);
    } else if h.matches(':').count() == 1 {
        // `host:port` → host. (A bracketless IPv6 has >1 ':' and no port.)
        h = h.split(':').next().unwrap_or(h);
    }
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    (!h.is_empty()).then_some(h)
}

impl HostBlocklist {
    /// Env var consulted when no explicit path is configured: the path of a
    /// blocklist file (one host per line, `#` comments).
    pub const ENV: &'static str = "BULWARK_BLOCKLIST";

    /// Parse blocklist text (see the module docs for the format). Unparseable
    /// lines are simply skipped — parsing is total.
    pub fn parse(text: &str) -> Self {
        let mut exact = HashSet::new();
        let mut suffixes: Vec<String> = Vec::new();
        for line in text.lines() {
            let entry = line.split('#').next().unwrap_or("").trim();
            if entry.is_empty() {
                continue;
            }
            // Guardians paste URLs: strip a scheme + path so
            // `https://adult.example/x` blocks `adult.example` (and never
            // inserts a bogus "https" entry via the port-strip in normalize).
            let entry = entry.split_once("://").map_or(entry, |(_, rest)| rest);
            let entry = entry.split('/').next().unwrap_or(entry).trim();
            if entry.is_empty() {
                continue;
            }
            if let Some(rest) = entry.strip_prefix("*.").or_else(|| entry.strip_prefix('.')) {
                if let Some(apex) = normalize(rest) {
                    suffixes.push(apex);
                }
            } else if let Some(host) = normalize(entry) {
                exact.insert(host);
            }
        }
        suffixes.sort();
        suffixes.dedup();
        HostBlocklist { exact, suffixes }
    }

    /// Load a blocklist file. Unreadable = error (fail-CLOSED at start: a
    /// configured guardian blocklist must never silently vanish).
    pub fn load(path: &Path) -> crate::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            crate::NetError::proxy(format!(
                "guardian blocklist {} unreadable (fail-closed): {e}",
                path.display()
            ))
        })?;
        let list = Self::parse(&text);
        tracing::info!(
            path = %path.display(),
            entries = list.len(),
            "guardian host blocklist loaded"
        );
        Ok(list)
    }

    /// Resolve the blocklist: explicit `path` wins, else the [`Self::ENV`] env
    /// var (a file path), else EMPTY (no behavior change).
    pub fn from_env_or(path: Option<&Path>) -> crate::Result<Self> {
        if let Some(p) = path {
            return Self::load(p);
        }
        match std::env::var(Self::ENV) {
            Ok(p) if !p.trim().is_empty() => Self::load(Path::new(p.trim())),
            _ => Ok(Self::default()),
        }
    }

    /// Whether `host` (a hostname, literal IP, `host:port`, or `[v6]:port`) is
    /// refused by this blocklist. An empty list blocks nothing.
    pub fn is_blocked(&self, host: &str) -> bool {
        if self.is_empty() {
            return false;
        }
        let Some(h) = normalize(host) else {
            return false;
        };
        if self.exact.contains(&h) {
            return true;
        }
        self.suffixes.iter().any(|apex| {
            h == *apex
                || (h.len() > apex.len()
                    && h.ends_with(apex.as_str())
                    && h.as_bytes()[h.len() - apex.len() - 1] == b'.')
        })
    }

    /// True when no rules are loaded (the default — no behavior change).
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
    }

    /// Total number of rules (exact + suffix), for logs/UI.
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_blocks_nothing() {
        let bl = HostBlocklist::default();
        assert!(bl.is_empty());
        assert!(!bl.is_blocked("adult.example"));
        assert!(!bl.is_blocked(""));
    }

    #[test]
    fn parses_comments_blanks_and_both_suffix_forms() {
        let bl = HostBlocklist::parse(
            "# guardian list\n\nAdult.Example   # exact\n.Tracker.Example\n*.cdn.example\n",
        );
        assert_eq!(bl.len(), 3);
        assert!(bl.is_blocked("adult.example"));
        assert!(bl.is_blocked("tracker.example"), "suffix matches the apex");
        assert!(bl.is_blocked("a.b.tracker.example"));
        assert!(bl.is_blocked("x.cdn.example"), "*. form is a suffix rule");
    }

    #[test]
    fn exact_entries_do_not_match_subdomains() {
        let bl = HostBlocklist::parse("adult.example");
        assert!(bl.is_blocked("adult.example"));
        assert!(!bl.is_blocked("www.adult.example"), "exact is exact");
        assert!(!bl.is_blocked("notadult.example"));
    }

    #[test]
    fn suffix_never_matches_a_lookalike_without_the_dot() {
        let bl = HostBlocklist::parse(".example.com");
        assert!(bl.is_blocked("example.com"));
        assert!(bl.is_blocked("a.example.com"));
        assert!(
            !bl.is_blocked("badexample.com"),
            "no label boundary → no match"
        );
    }

    #[test]
    fn matching_normalizes_case_port_brackets_and_trailing_dot() {
        let bl = HostBlocklist::parse("adult.example\n2001:db8::1\n93.184.216.34");
        assert!(bl.is_blocked("ADULT.Example:443"));
        assert!(bl.is_blocked("adult.example."));
        assert!(bl.is_blocked("[2001:db8::1]:443"));
        assert!(
            bl.is_blocked("93.184.216.34:443"),
            "pump-style ip:port entry"
        );
        assert!(!bl.is_blocked("93.184.216.35:443"));
    }

    #[test]
    fn pasted_urls_block_the_host_not_the_scheme() {
        let bl = HostBlocklist::parse("https://adult.example/some/path\nhttp://.tracker.example/");
        assert!(bl.is_blocked("adult.example"));
        assert!(bl.is_blocked("x.tracker.example"));
        assert!(!bl.is_blocked("https"), "scheme must never become an entry");
        assert!(!bl.is_blocked("http"));
    }

    #[test]
    fn load_missing_file_fails_closed() {
        let err = HostBlocklist::load(Path::new("Z:/definitely/not/here.txt"));
        assert!(err.is_err(), "a configured-but-unreadable list must error");
    }

    #[test]
    fn from_env_or_resolution_order() {
        // One test owns the env var (avoids parallel-test races on it).
        std::env::remove_var(HostBlocklist::ENV);
        // Unset env + no path → empty (no behavior change).
        assert!(HostBlocklist::from_env_or(None).unwrap().is_empty());

        // Env points at a real file → loaded.
        let dir = std::env::temp_dir().join(format!(
            "bulwark-blocklist-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("hosts.txt");
        std::fs::write(&file, "adult.example\n").unwrap();
        std::env::set_var(HostBlocklist::ENV, &file);
        let bl = HostBlocklist::from_env_or(None).unwrap();
        assert!(bl.is_blocked("adult.example"));

        // An explicit path WINS over the env var.
        let other = dir.join("other.txt");
        std::fs::write(&other, ".tracker.example\n").unwrap();
        let bl = HostBlocklist::from_env_or(Some(&other)).unwrap();
        assert!(bl.is_blocked("x.tracker.example"));
        assert!(!bl.is_blocked("adult.example"));

        std::env::remove_var(HostBlocklist::ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
