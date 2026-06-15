//! Staff endpoint resolution + session-token persistence. Token namespace is
//! isolated from guardians by construction (different RPC service, different
//! store, different on-disk file) — see the design doc §3.

use crate::config::app_config_dir;

/// The cluster endpoint the staff console dials. The same gateway the guardian
/// regions use, but the StaffAdmin service only answers when the server is
/// started with `BULWARK_STAFF=1`. Override with `BULWARK_STAFF_ENDPOINT`.
pub fn staff_endpoint() -> String {
    std::env::var("BULWARK_STAFF_ENDPOINT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.predatorhunters.co.uk:8443".to_string())
}

fn token_path() -> std::path::PathBuf {
    app_config_dir().join("staff_token.txt")
}

/// The saved staff bearer (env override wins, for ops/dev). Short-TTL on the
/// server (2h default) — a stale token simply fails the next call and the
/// console drops back to the login gate.
pub fn staff_token() -> String {
    std::env::var("BULWARK_STAFF_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string(token_path())
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_default()
}

pub fn save_staff_token(token: &str) -> std::io::Result<()> {
    let path = token_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, token.trim())
}

pub fn clear_staff_token() -> std::io::Result<()> {
    match std::fs::remove_file(token_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Optional pinned CA for a self-hosted / private-CA gateway (`BULWARK_CLUSTER_CA`).
/// Unset → trust the public roots (the prod regions serve a real Let's Encrypt cert).
pub fn ca_path() -> Option<String> {
    std::env::var("BULWARK_CLUSTER_CA")
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .filter(|p| std::path::Path::new(p).exists())
}
