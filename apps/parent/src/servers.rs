//! Server inventory + choice/endpoint resolution and the per-server
//! guardian-session/token files (PH Bulwark Cloud regions + self-hosted).

use serde::{Deserialize, Serialize};

use crate::config::app_config_dir;

// ---------------------------------------------------------------------------
// Connection layer
// ---------------------------------------------------------------------------

/// PH Bulwark Cloud regions: `(id, label, endpoint)`. A user picks ONE — their data
/// routes only through that country's server (no cross-region). A UK/London server
/// is offered for UK data residency; this build targets the deployed London gateway.
pub const CLOUD_REGIONS: &[(&str, &str, &str)] = &[
    (
        "uk",
        "PH Bulwark Cloud — UK (London)",
        "http://ec2-35-179-110-106.eu-west-2.compute.amazonaws.com:8443",
    ),
    (
        "us",
        "PH Bulwark Cloud — US",
        "https://us.cloud.phbulwark.app",
    ),
];
/// Default region when nothing is saved — UK first (UK data residency).
pub const DEFAULT_REGION_ID: &str = "uk";

/// Where the chosen server is persisted (one line: a region id, or a self-hosted
/// URL). Per-user config dir (Windows `%LOCALAPPDATA%\Bulwark`, else
/// `$XDG_CONFIG_HOME`/`$HOME/.config`, else temp).
pub fn server_config_path() -> std::path::PathBuf {
    app_config_dir().join("server.txt")
}

pub fn server_inventory_path() -> std::path::PathBuf {
    app_config_dir().join("servers.json")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedServer {
    pub id: String,
    pub label: String,
    pub endpoint: String,
    #[serde(default)]
    pub builtin: bool,
}

impl SavedServer {
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            endpoint: endpoint.into(),
            builtin: false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInventoryFile {
    #[serde(default)]
    servers: Vec<SavedServer>,
}

pub fn guardian_token_path() -> std::path::PathBuf {
    guardian_token_path_for_endpoint(&cluster_endpoint())
}

pub fn guardian_token_path_for_endpoint(endpoint: &str) -> std::path::PathBuf {
    session_dir_for_endpoint(endpoint).join("guardian_token.txt")
}

pub fn cluster_ca_path_for_endpoint(endpoint: &str) -> std::path::PathBuf {
    session_dir_for_endpoint(endpoint).join("cluster_ca.pem")
}

pub fn saved_token_for_endpoint(endpoint: &str) -> String {
    std::fs::read_to_string(guardian_token_path_for_endpoint(endpoint))
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .unwrap_or_default()
}

pub fn guardian_token() -> String {
    std::env::var("BULWARK_GUARDIAN_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .or_else(|| Some(saved_token_for_endpoint(&cluster_endpoint())).filter(|t| !t.is_empty()))
        .unwrap_or_default()
}

pub fn save_guardian_token(token: &str) -> std::io::Result<()> {
    let path = guardian_token_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, token.trim())
}

pub fn clear_guardian_token() -> std::io::Result<()> {
    let path = guardian_token_path();
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn session_dir_for_endpoint(endpoint: &str) -> std::path::PathBuf {
    app_config_dir()
        .join("sessions")
        .join(server_session_key(endpoint))
}

pub fn server_session_key(endpoint: &str) -> String {
    // FNV-1a: small deterministic key for local filenames; not security-sensitive.
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in endpoint.trim().as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// The raw saved choice: a region id (e.g. `uk`), a self-hosted URL, or empty.
pub fn saved_choice() -> String {
    std::fs::read_to_string(server_config_path())
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Persist the chosen server: a region id (`uk`/`us`) or a self-hosted URL.
pub fn save_server_choice(value: &str) -> std::io::Result<()> {
    let path = server_config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let v = value.trim();
    std::fs::write(path, if v.is_empty() { DEFAULT_REGION_ID } else { v })
}

pub fn builtin_servers() -> Vec<SavedServer> {
    CLOUD_REGIONS
        .iter()
        .map(|(id, label, endpoint)| SavedServer {
            id: (*id).to_string(),
            label: (*label).to_string(),
            endpoint: (*endpoint).to_string(),
            builtin: true,
        })
        .collect()
}

pub fn load_custom_servers() -> Vec<SavedServer> {
    std::fs::read_to_string(server_inventory_path())
        .ok()
        .and_then(|json| serde_json::from_str::<ServerInventoryFile>(&json).ok())
        .map(|file| normalize_custom_servers(file.servers))
        .unwrap_or_default()
}

pub fn normalize_custom_servers(servers: Vec<SavedServer>) -> Vec<SavedServer> {
    let mut out = Vec::new();
    for mut server in servers {
        server.id = server.id.trim().to_string();
        server.label = server.label.trim().to_string();
        server.endpoint = server.endpoint.trim().to_string();
        server.builtin = false;
        if server.id.is_empty() || !is_endpoint_url(&server.endpoint) {
            continue;
        }
        if out
            .iter()
            .any(|s: &SavedServer| s.id == server.id || s.endpoint == server.endpoint)
        {
            continue;
        }
        out.push(server);
    }
    out
}

pub fn save_custom_servers(servers: Vec<SavedServer>) -> std::io::Result<()> {
    let path = server_inventory_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let file = ServerInventoryFile {
        servers: normalize_custom_servers(servers),
    };
    let json = serde_json::to_string_pretty(&file).unwrap_or_else(|_| "{\"servers\":[]}".into());
    std::fs::write(path, json)
}

pub fn custom_server_id(endpoint: &str) -> String {
    format!("self-{}", server_session_key(endpoint))
}

pub fn is_endpoint_url(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("http://") || s.starts_with("https://")
}

pub fn upsert_custom_server(label: &str, endpoint: &str) -> anyhow::Result<SavedServer> {
    let endpoint = endpoint.trim();
    if !is_endpoint_url(endpoint) {
        anyhow::bail!("self-hosted endpoint must start with http:// or https://");
    }
    let id = custom_server_id(endpoint);
    let label = label.trim();
    let server = SavedServer::new(
        id.clone(),
        if label.is_empty() {
            "Self-hosted"
        } else {
            label
        },
        endpoint,
    );
    let mut servers = load_custom_servers();
    servers.retain(|s| s.id != id && s.endpoint != endpoint);
    servers.push(server.clone());
    save_custom_servers(servers)?;
    Ok(server)
}

pub fn remove_custom_server(id: &str) -> std::io::Result<()> {
    let mut servers = load_custom_servers();
    servers.retain(|s| s.id != id);
    save_custom_servers(servers)?;
    if saved_choice().trim() == id {
        save_server_choice(DEFAULT_REGION_ID)?;
    }
    Ok(())
}

pub fn server_inventory_for_choice(saved: &str, custom: Vec<SavedServer>) -> Vec<SavedServer> {
    let mut servers = builtin_servers();
    let mut custom = normalize_custom_servers(custom);
    let saved = saved.trim();
    if is_endpoint_url(saved) && !custom.iter().any(|s| s.endpoint == saved) {
        custom.push(SavedServer::new(
            custom_server_id(saved),
            "Self-hosted",
            saved,
        ));
    }
    servers.extend(custom);
    servers
}

pub fn server_inventory() -> Vec<SavedServer> {
    server_inventory_for_choice(&saved_choice(), load_custom_servers())
}

pub fn server_for_choice_from(saved: &str, inventory: &[SavedServer]) -> SavedServer {
    let saved = saved.trim();
    if is_endpoint_url(saved) {
        return inventory
            .iter()
            .find(|s| s.endpoint == saved)
            .cloned()
            .unwrap_or_else(|| SavedServer::new(custom_server_id(saved), "Self-hosted", saved));
    }
    let id = if saved.is_empty() || saved.eq_ignore_ascii_case("cloud") {
        DEFAULT_REGION_ID
    } else {
        saved
    };
    inventory
        .iter()
        .find(|s| s.id == id)
        .cloned()
        .or_else(|| {
            inventory
                .iter()
                .find(|s| s.id == DEFAULT_REGION_ID)
                .cloned()
        })
        .unwrap_or_else(|| SavedServer::new(DEFAULT_REGION_ID, "PH Bulwark Cloud", ""))
}

pub fn selected_server_id(saved: &str) -> String {
    server_for_choice_from(saved, &server_inventory()).id
}

/// Resolve a saved choice to an endpoint URL: a `http(s)://` value is a self-hosted
/// URL used as-is; otherwise it's a region id (or empty / legacy `cloud` / unknown)
/// → that region's URL, defaulting to UK.
pub fn resolve_endpoint(saved: &str) -> String {
    server_for_choice_from(saved, &server_inventory()).endpoint
}

#[cfg(test)]
pub fn server_settings_initial_state(saved: &str) -> (String, String) {
    let saved = saved.trim();
    let is_url = is_endpoint_url(saved);
    let selected = if is_url {
        "selfhosted".to_string()
    } else if saved.is_empty() || saved.eq_ignore_ascii_case("cloud") {
        DEFAULT_REGION_ID.to_string()
    } else {
        saved.to_string()
    };
    let url = if is_url {
        saved.to_string()
    } else {
        String::new()
    };
    (selected, url)
}

/// The cluster endpoint to dial: `BULWARK_CLUSTER_ENDPOINT` (advanced/ops override)
/// wins; otherwise the user's saved country / self-hosted choice (default UK). The
/// single source of truth for the console's review channel AND the filter it spawns.
pub fn cluster_endpoint() -> String {
    if let Ok(env) = std::env::var("BULWARK_CLUSTER_ENDPOINT") {
        let env = env.trim().to_string();
        if !env.is_empty() {
            return env;
        }
    }
    resolve_endpoint(&saved_choice())
}

pub fn active_server_label() -> String {
    if std::env::var("BULWARK_CLUSTER_ENDPOINT")
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return "Ops override".to_string();
    }
    let saved = saved_choice();
    let choice = if saved.trim().is_empty() {
        DEFAULT_REGION_ID
    } else {
        saved.trim()
    };
    server_label(choice)
}

pub fn server_label(choice: &str) -> String {
    server_for_choice_from(choice, &server_inventory()).label
}

/// cluster endpoint). Mirrors the child app's server list.
pub const CHILD_REGIONS: &[(&str, &str, &str)] = &[
    (
        "uk",
        "UK — London",
        "http://ec2-35-179-110-106.eu-west-2.compute.amazonaws.com:8443",
    ),
    ("us", "US cloud", "https://us.cloud.phbulwark.app"),
];
