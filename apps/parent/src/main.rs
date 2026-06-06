//! PH Bulwark Manager — the guardian console (all-Rust Dioxus UI). "aegis" is
//! the internal engineering codename; the product is Predator Hunters Bulwark.
//!
//! LEGITIMATE features only: review guardian alerts, **approve / keep-blocked**
//! flagged items, and see the honest coverage matrix. It talks to the home
//! cluster over the SAME gRPC contract the engine serves (`Review` carries the
//! pending-review stream and the approve/deny decision). There is deliberately
//! **no** device-control / screen / location / remote-command surface here —
//! Aegis is a transparent content-safety tool, not a remote-administration
//! console.
//!
//! GUARDIAN-TRANSPARENCY MODEL: the console now shows guardians the FULL flagged
//! content for review — the actual blocked text snippet (`Evidence.text_snippet`)
//! and an inline preview of the blocked media (`Evidence.safe_thumbnail`,
//! rendered as a base64 data URI) — alongside the app/device/time context. The
//! parent sees what was blocked so they can make an informed approve/deny call.
//!
//! THE ONE EXCEPTION — suspected CSAM is NEVER previewed: when
//! `category == Category::CsamSuspected` the console renders no image and no
//! snippet, even if evidence bytes/text are present. Instead it shows a notice
//! that the content is withheld and never shown or stored. Previewing
//! suspected CSAM would be illegal, so it is the single thing this UI never
//! displays; the server also refuses to approve it.
//!
//! Dioxus `desktop` feature covers Windows + macOS. The same RSX drives the
//! `mobile` (Android/iOS, experimental) and `web` targets, and bumps cleanly to
//! the 0.7/0.8 native Blitz renderer (no webview) when it ships.

use std::cell::RefCell;
use std::process::Child;
use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use aegis_proto::v1::accounts_client::AccountsClient;
use aegis_proto::v1::review_client::ReviewClient;
use aegis_proto::v1::{
    AccountAck, AlertEvent, AlertKind, Category, Child as ProtoChild, CreateAccountRequest,
    CreatePairCodeRequest, DeviceFilter, ListChildrenRequest, LoginRequest, PairCode,
    ReviewDecision, ReviewRequest, ReviewScope, Session,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::Streaming;

fn main() {
    dioxus::launch(App);
}

// ---------------------------------------------------------------------------
// Protection control panel — fixed local plumbing
// ---------------------------------------------------------------------------

/// The local content-filtering proxy listens here; this is also the address we
/// program into the per-user Windows system proxy.
const PROXY_HOST: &str = "127.0.0.1";
const PROXY_PORT: u16 = 8080;
const PROXY_ADDR: &str = "127.0.0.1:8080";

/// Locate a bundled filter binary `name` (e.g. `aegis_proxy.exe`): an explicit
/// `env_key` override first, else next to THIS executable (where a packaged
/// release ships the filter binaries beside the console). `None` → the caller
/// falls back to a dev `cargo run`. No machine-specific path is ever hard-coded.
fn sibling_exe(env_key: &str, name: &str) -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os(env_key).filter(|s| !s.is_empty()) {
        let p = std::path::PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let beside = std::env::current_exe().ok()?.parent()?.join(name);
    beside.exists().then_some(beside)
}

/// The bundled content-filtering proxy (`AEGIS_PROXY_EXE` override, else beside us).
fn proxy_exe() -> Option<std::path::PathBuf> {
    sibling_exe("AEGIS_PROXY_EXE", "aegis_proxy.exe")
}

/// The bundled transparent-VPN binary (`AEGIS_VPN_EXE` override, else beside us).
/// VPN mode captures ALL traffic via a TUN and needs Administrator; `aegis_vpn`
/// self-checks elevation and exits immediately if not elevated.
fn vpn_exe() -> Option<std::path::PathBuf> {
    sibling_exe("AEGIS_VPN_EXE", "aegis_vpn.exe")
}

/// Repo root for the dev `cargo run` fallback only: `AEGIS_REPO_ROOT` or the cwd.
fn repo_root() -> std::path::PathBuf {
    std::env::var_os("AEGIS_REPO_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()))
}

fn app_config_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|s| !s.is_empty()) {
        PathBuf::from(local).join("Aegis")
    } else if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        PathBuf::from(xdg).join("aegis")
    } else if let Some(home) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        PathBuf::from(home).join(".config/aegis")
    } else {
        std::env::temp_dir().join("aegis")
    }
}

fn config_value(name: &str) -> Option<String> {
    std::fs::read_to_string(app_config_dir().join(name))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn env_or_config(env: &str, file: &str) -> Option<String> {
    std::env::var(env)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| config_value(file))
}

/// The NSFW model path to hand the filter. Unset means the filter runs its
/// fail-open stub; we never invent a model path.
fn nsfw_model() -> Option<String> {
    env_or_config("AEGIS_NSFW_MODEL", "nsfw_model.txt")
}

/// Human-readable model status for the diagnostics panel.
fn nsfw_model_display() -> String {
    nsfw_model()
        .unwrap_or_else(|| "(unset — set AEGIS_NSFW_MODEL; filter runs fail-open)".to_string())
}

/// Optional pinned ffmpeg binary to hand the video pipeline.
fn ffmpeg_binary() -> Option<String> {
    env_or_config("FFMPEG_BINARY", "ffmpeg_binary.txt")
        .or_else(|| env_or_config("AEGIS_FFMPEG_BINARY", "ffmpeg_binary.txt"))
}

fn ffmpeg_display() -> String {
    ffmpeg_binary().unwrap_or_else(|| "(PATH lookup — set FFMPEG_BINARY if needed)".to_string())
}

// ---------------------------------------------------------------------------
// Connection layer
// ---------------------------------------------------------------------------

/// PH Bulwark Cloud regions: `(id, label, endpoint)`. A user picks ONE — their data
/// routes only through that country's server (no cross-region). A UK/London server
/// is offered for UK data residency; this build targets the deployed London gateway.
const CLOUD_REGIONS: &[(&str, &str, &str)] = &[
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
const DEFAULT_REGION_ID: &str = "uk";

/// Where the chosen server is persisted (one line: a region id, or a self-hosted
/// URL). Per-user config dir (Windows `%LOCALAPPDATA%\Aegis`, else
/// `$XDG_CONFIG_HOME`/`$HOME/.config`, else temp).
fn server_config_path() -> std::path::PathBuf {
    app_config_dir().join("server.txt")
}

fn server_inventory_path() -> std::path::PathBuf {
    app_config_dir().join("servers.json")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SavedServer {
    id: String,
    label: String,
    endpoint: String,
    #[serde(default)]
    builtin: bool,
}

impl SavedServer {
    fn new(id: impl Into<String>, label: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            endpoint: endpoint.into(),
            builtin: false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ServerInventoryFile {
    #[serde(default)]
    servers: Vec<SavedServer>,
}

fn guardian_token_path() -> std::path::PathBuf {
    guardian_token_path_for_endpoint(&cluster_endpoint())
}

fn guardian_token_path_for_endpoint(endpoint: &str) -> std::path::PathBuf {
    session_dir_for_endpoint(endpoint).join("guardian_token.txt")
}

fn cluster_ca_path_for_endpoint(endpoint: &str) -> std::path::PathBuf {
    session_dir_for_endpoint(endpoint).join("cluster_ca.pem")
}

fn saved_token_for_endpoint(endpoint: &str) -> String {
    std::fs::read_to_string(guardian_token_path_for_endpoint(endpoint))
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .unwrap_or_default()
}

fn guardian_token() -> String {
    std::env::var("AEGIS_GUARDIAN_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .or_else(|| Some(saved_token_for_endpoint(&cluster_endpoint())).filter(|t| !t.is_empty()))
        .unwrap_or_default()
}

fn save_guardian_token(token: &str) -> std::io::Result<()> {
    let path = guardian_token_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, token.trim())
}

fn clear_guardian_token() -> std::io::Result<()> {
    let path = guardian_token_path();
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn session_dir_for_endpoint(endpoint: &str) -> std::path::PathBuf {
    app_config_dir()
        .join("sessions")
        .join(server_session_key(endpoint))
}

fn server_session_key(endpoint: &str) -> String {
    // FNV-1a: small deterministic key for local filenames; not security-sensitive.
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in endpoint.trim().as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// The raw saved choice: a region id (e.g. `uk`), a self-hosted URL, or empty.
fn saved_choice() -> String {
    std::fs::read_to_string(server_config_path())
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Persist the chosen server: a region id (`uk`/`us`) or a self-hosted URL.
fn save_server_choice(value: &str) -> std::io::Result<()> {
    let path = server_config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let v = value.trim();
    std::fs::write(path, if v.is_empty() { DEFAULT_REGION_ID } else { v })
}

fn builtin_servers() -> Vec<SavedServer> {
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

fn load_custom_servers() -> Vec<SavedServer> {
    std::fs::read_to_string(server_inventory_path())
        .ok()
        .and_then(|json| serde_json::from_str::<ServerInventoryFile>(&json).ok())
        .map(|file| normalize_custom_servers(file.servers))
        .unwrap_or_default()
}

fn normalize_custom_servers(servers: Vec<SavedServer>) -> Vec<SavedServer> {
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

fn save_custom_servers(servers: Vec<SavedServer>) -> std::io::Result<()> {
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

fn custom_server_id(endpoint: &str) -> String {
    format!("self-{}", server_session_key(endpoint))
}

fn is_endpoint_url(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("http://") || s.starts_with("https://")
}

fn upsert_custom_server(label: &str, endpoint: &str) -> anyhow::Result<SavedServer> {
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

fn remove_custom_server(id: &str) -> std::io::Result<()> {
    let mut servers = load_custom_servers();
    servers.retain(|s| s.id != id);
    save_custom_servers(servers)?;
    if saved_choice().trim() == id {
        save_server_choice(DEFAULT_REGION_ID)?;
    }
    Ok(())
}

fn server_inventory_for_choice(saved: &str, custom: Vec<SavedServer>) -> Vec<SavedServer> {
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

fn server_inventory() -> Vec<SavedServer> {
    server_inventory_for_choice(&saved_choice(), load_custom_servers())
}

fn server_for_choice_from(saved: &str, inventory: &[SavedServer]) -> SavedServer {
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

fn selected_server_id(saved: &str) -> String {
    server_for_choice_from(saved, &server_inventory()).id
}

/// Resolve a saved choice to an endpoint URL: a `http(s)://` value is a self-hosted
/// URL used as-is; otherwise it's a region id (or empty / legacy `cloud` / unknown)
/// → that region's URL, defaulting to UK.
fn resolve_endpoint(saved: &str) -> String {
    server_for_choice_from(saved, &server_inventory()).endpoint
}

#[cfg(test)]
fn server_settings_initial_state(saved: &str) -> (String, String) {
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

/// The cluster endpoint to dial: `AEGIS_CLUSTER_ENDPOINT` (advanced/ops override)
/// wins; otherwise the user's saved country / self-hosted choice (default UK). The
/// single source of truth for the console's review channel AND the filter it spawns.
fn cluster_endpoint() -> String {
    if let Ok(env) = std::env::var("AEGIS_CLUSTER_ENDPOINT") {
        let env = env.trim().to_string();
        if !env.is_empty() {
            return env;
        }
    }
    resolve_endpoint(&saved_choice())
}

fn active_server_label() -> String {
    if std::env::var("AEGIS_CLUSTER_ENDPOINT")
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

fn server_label(choice: &str) -> String {
    server_for_choice_from(choice, &server_inventory()).label
}

#[derive(Clone, PartialEq)]
struct AppStatus {
    server_label: String,
    endpoint: String,
    session_key: String,
    logged_in: bool,
}

impl AppStatus {
    fn load() -> Self {
        let endpoint = cluster_endpoint();
        Self {
            server_label: active_server_label(),
            session_key: server_session_key(&endpoint),
            logged_in: !guardian_token().is_empty(),
            endpoint,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveView {
    Setup,
    Alerts,
    Children,
    Protection,
    Server,
    Coverage,
}

#[derive(Clone, PartialEq)]
struct PairCodeUi {
    child_name: String,
    code: String,
    expires_ts: i64,
}

/// Build a tonic [`Channel`] to the cluster.
///
/// * If `AEGIS_CLUSTER_CA` is set (path to a PEM CA cert), pin it via
///   [`ClientTlsConfig`] (tonic `tls-ring` feature). The cluster authenticates
///   itself with a cert chaining to this root.
/// * Otherwise dial in the clear — a dev/plaintext convenience only.
///
/// Never panics: a bad CA path or unreachable endpoint returns `Err`, and the
/// caller falls back to OFFLINE sample data.
async fn connect_channel() -> anyhow::Result<Channel> {
    let endpoint = cluster_endpoint();
    let ca_path = std::env::var("AEGIS_CLUSTER_CA")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .or_else(|| {
            let path = cluster_ca_path_for_endpoint(&endpoint);
            path.exists().then(|| path.to_string_lossy().to_string())
        });
    connect_channel_to(&endpoint, ca_path.as_deref()).await
}

async fn connect_channel_to(endpoint: &str, ca_path: Option<&str>) -> anyhow::Result<Channel> {
    let mut builder = Endpoint::from_shared(endpoint.to_string())?;

    if let Some(ca_path) = ca_path.filter(|p| !p.trim().is_empty()) {
        let ca_pem = std::fs::read(ca_path)?;
        let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca_pem));
        builder = builder.tls_config(tls)?;
    }

    Ok(builder.connect().await?)
}

async fn accounts_client() -> anyhow::Result<AccountsClient<Channel>> {
    Ok(AccountsClient::new(connect_channel().await?))
}

async fn create_guardian_account(
    email: &str,
    password: &str,
    display_name: &str,
) -> anyhow::Result<AccountAck> {
    let mut client = accounts_client().await?;
    Ok(client
        .create_account(CreateAccountRequest {
            email: email.trim().to_string(),
            password: password.to_string(),
            display_name: display_name.trim().to_string(),
        })
        .await?
        .into_inner())
}

async fn login_guardian(email: &str, password: &str) -> anyhow::Result<Session> {
    let mut client = accounts_client().await?;
    Ok(client
        .login(LoginRequest {
            email: email.trim().to_string(),
            password: password.to_string(),
        })
        .await?
        .into_inner())
}

async fn load_children() -> anyhow::Result<Vec<ProtoChild>> {
    let token = guardian_token();
    if token.is_empty() {
        anyhow::bail!("login required for this server");
    }
    let mut client = accounts_client().await?;
    Ok(client
        .list_children(ListChildrenRequest { token })
        .await?
        .into_inner()
        .children)
}

async fn create_pair_code_for_child(child_name: &str) -> anyhow::Result<PairCode> {
    let token = guardian_token();
    if token.is_empty() {
        anyhow::bail!("login required for this server");
    }
    let mut client = accounts_client().await?;
    Ok(client
        .create_pair_code(CreatePairCodeRequest {
            token,
            child_name: child_name.trim().to_string(),
        })
        .await?
        .into_inner())
}

async fn open_pending_review_stream() -> anyhow::Result<Streaming<AlertEvent>> {
    let channel = connect_channel().await?;
    let token = guardian_token();
    open_pending_review_stream_on(channel, &token).await
}

#[cfg(test)]
async fn open_pending_review_stream_from(
    endpoint: &str,
    token: &str,
) -> anyhow::Result<Streaming<AlertEvent>> {
    let channel = connect_channel_to(endpoint, None).await?;
    open_pending_review_stream_on(channel, token).await
}

async fn open_pending_review_stream_on(
    channel: Channel,
    token: &str,
) -> anyhow::Result<Streaming<AlertEvent>> {
    let mut client = ReviewClient::new(channel);
    let filter = DeviceFilter {
        device_id: String::new(),
        token: token.trim().to_string(),
    };
    Ok(client.stream_pending_reviews(filter).await?.into_inner())
}

/// A guardian-facing alert row.
///
/// Carries the full review payload: the context summary plus, for non-CSAM
/// items, the actual flagged text snippet and a safe inline media preview so the
/// guardian sees exactly what was blocked. CSAM-suspected items deliberately
/// carry no preview surfaced to the UI (see [`AlertCard`]).
#[derive(Clone, PartialEq)]
struct Alert {
    id: String,
    title: String,
    detail: String,
    device: String,
    when: String,
    /// Whether approve / keep-blocked is offered (intervention & grooming items).
    actionable: bool,
    /// The classifier category; gates the CSAM "never preview" exception.
    category: Category,
    /// Safe (blurred/cropped) preview bytes from `Evidence.safe_thumbnail`.
    /// Empty when none was provided. Never rendered for CsamSuspected.
    thumbnail: Vec<u8>,
    /// The actual flagged text from `Evidence.text_snippet` (full, not redacted
    /// to the guardian). Empty when none. Never rendered for CsamSuspected.
    snippet: String,
    /// Local `blob://<sha256>` reference to a blocked/borderline VIDEO segment
    /// retained on this node for review (`AlertEvent.local_segment_uri`). `None`
    /// when no clip. Never set/played for CsamSuspected.
    segment_uri: Option<String>,
}

impl Alert {
    /// Map a proto [`AlertEvent`] into a UI row.
    ///
    /// Carries through the `Evidence` preview fields (`safe_thumbnail`,
    /// `text_snippet`) and the `category` so the card can show the guardian the
    /// real flagged content — except for CSAM, which [`AlertCard`] never renders.
    fn from_event(ev: AlertEvent) -> Self {
        let kind = ev.kind();
        let category = ev.category();

        // Pull the preview/evidence the cluster attached, if any. These are the
        // SAFE thumbnail and the flagged text excerpt; the CSAM exception is
        // enforced at render time in AlertCard, not here, so the row always
        // honestly reflects what the event carried.
        let (thumbnail, snippet) = match ev.evidence {
            Some(ref e) => (e.safe_thumbnail.clone(), e.text_snippet.clone()),
            None => (Vec::new(), String::new()),
        };

        // Title is a plain-language summary derived from kind + category — never
        // from any raw content.
        let title = match kind {
            AlertKind::GroomingSuspected => "Possible grooming detected".to_string(),
            AlertKind::Intervention => match category {
                Category::AdultImage => "Blocked an adult image".to_string(),
                Category::AdultAudio => "Muted adult audio".to_string(),
                Category::AdultText => "Blocked adult text".to_string(),
                Category::Violence => "Blocked violent content".to_string(),
                Category::SelfHarm => "Blocked self-harm content".to_string(),
                Category::Hate => "Blocked hateful content".to_string(),
                Category::CsamSuspected => "Blocked suspected illegal content".to_string(),
                _ => "Blocked flagged content".to_string(),
            },
            AlertKind::ProtectionDisabled => "Protection changed on the device".to_string(),
            AlertKind::Unspecified => "Safety alert".to_string(),
        };

        // The redacted, safe summary the cluster prepared. If empty, fall back to
        // the app/site name only.
        let detail = if !ev.redacted_context.is_empty() {
            ev.redacted_context.clone()
        } else if !ev.app.is_empty() {
            format!("In {}.", ev.app)
        } else {
            "A flagged item (redacted summary unavailable).".to_string()
        };

        let device = if ev.device_id.is_empty() {
            "Supervised device".to_string()
        } else {
            ev.device_id.clone()
        };

        // A locally-stored video segment to review, if the cluster attached one.
        // (The store never persists CSAM, so this is always empty for CSAM; the
        // card also gates playback on category as defence in depth.)
        let segment_uri = Some(ev.local_segment_uri).filter(|s| !s.is_empty());

        Self {
            id: ev.alert_id,
            title,
            detail,
            device,
            when: format_when(ev.ts),
            // Both product triggers are actionable (guardian can approve/deny).
            actionable: true,
            category,
            thumbnail,
            snippet,
            segment_uri,
        }
    }
}

/// Render a unix-epoch-millis timestamp as a short relative string. Falls back
/// gracefully for clock skew / unset timestamps.
fn format_when(ts_millis: i64) -> String {
    if ts_millis <= 0 {
        return "just now".to_string();
    }
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(ts_millis);
    let delta_secs = (now_millis - ts_millis).max(0) / 1000;
    if delta_secs < 60 {
        "just now".to_string()
    } else if delta_secs < 3600 {
        format!("{}m ago", delta_secs / 60)
    } else if delta_secs < 86_400 {
        format!("{}h ago", delta_secs / 3600)
    } else {
        format!("{}d ago", delta_secs / 86_400)
    }
}

/// Seed data stands in as an OFFLINE fallback while the gRPC client is not
/// connected. These mirror what `Review.StreamPendingReviews` streams from the
/// cluster — all redacted, never media.
fn seed() -> Vec<Alert> {
    vec![
        Alert {
            id: "a-1001".into(),
            title: "Blocked an adult image".into(),
            detail: "On a web page.".into(),
            device: "Kids tablet".into(),
            when: "2m ago".into(),
            actionable: false,
            category: Category::AdultImage,
            // Offline sample: no real bytes to preview.
            thumbnail: Vec::new(),
            snippet: String::new(),
            segment_uri: None,
        },
        Alert {
            id: "a-1002".into(),
            title: "Possible grooming detected".into(),
            detail: "Secrecy + \u{201c}move to another app\u{201d} patterns in a chat.".into(),
            device: "Kids phone".into(),
            when: "18m ago".into(),
            actionable: false,
            category: Category::Grooming,
            thumbnail: Vec::new(),
            snippet:
                "hey don\u{2019}t tell your mum about this, let\u{2019}s talk on the other app"
                    .into(),
            segment_uri: None,
        },
    ]
}

fn nav_class(active: ActiveView, target: ActiveView) -> &'static str {
    if active == target {
        "nav-btn nav-on"
    } else {
        "nav-btn"
    }
}

fn session_status_text(status: &AppStatus) -> &'static str {
    if status.logged_in {
        "Logged in"
    } else {
        "Login needed"
    }
}

fn pair_expiry_text(ts_millis: i64) -> String {
    if ts_millis <= 0 {
        return "unknown expiry".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(ts_millis);
    let secs = (ts_millis - now).max(0) / 1000;
    if secs < 60 {
        format!("expires in {}s", secs.max(1))
    } else {
        format!("expires in {}m", secs / 60)
    }
}

#[component]
fn App() -> Element {
    let mut alerts = use_signal(seed);
    let mut offline = use_signal(|| true);
    let action_error = use_signal(|| Option::<String>::None);
    let mut active = use_signal(|| ActiveView::Setup);
    let mut status = use_signal(AppStatus::load);
    let setup_note = use_signal(|| Option::<String>::None);
    let setup_error = use_signal(|| Option::<String>::None);
    let setup_busy = use_signal(|| false);
    let mut create_account = use_signal(|| true);
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut display_name = use_signal(String::new);
    let mut child_name = use_signal(String::new);
    let pair_code = use_signal(|| Option::<PairCodeUi>::None);
    let children = use_signal(Vec::<ProtoChild>::new);
    let children_error = use_signal(|| Option::<String>::None);
    let children_busy = use_signal(|| false);

    use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
        loop {
            let mut stream = match open_pending_review_stream().await {
                Ok(stream) => stream,
                Err(_e) => {
                    offline.set(true);
                    if alerts.read().is_empty() {
                        alerts.set(seed());
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            offline.set(false);
            alerts.write().clear();

            while let Ok(Some(event)) = stream.message().await {
                let alert = Alert::from_event(event);
                let mut list = alerts.write();
                if !list.iter().any(|a| a.id == alert.id) {
                    list.insert(0, alert);
                }
            }

            offline.set(true);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    rsx! {
        style { {CSS} }
        div { class: "app",
            header { class: "topbar",
                div {
                    h1 { "PH Bulwark Manager" }
                    p { class: "sub",
                        "Transparent content-safety for managed child devices. No device control, screen capture, or hidden monitoring."
                    }
                }
                button {
                    class: "ghost",
                    onclick: move |_| status.set(AppStatus::load()),
                    "Refresh"
                }
            }

            div { class: "status-grid",
                div { class: "status-tile",
                    span { class: "status-k", "Server" }
                    span { class: "status-v", "{status().server_label}" }
                    span { class: "status-sub mono", "{status().endpoint}" }
                }
                div { class: "status-tile",
                    span { class: "status-k", "Guardian" }
                    span {
                        class: if status().logged_in { "status-v ok" } else { "status-v warn" },
                        "{session_status_text(&status())}"
                    }
                    span { class: "status-sub mono", "session {status().session_key}" }
                }
                div { class: "status-tile",
                    span { class: "status-k", "Alerts" }
                    span { class: "status-v", "{alerts.read().len()}" }
                    span { class: "status-sub",
                        if offline() { "Demo/disconnected" } else { "Live stream" }
                    }
                }
            }

            nav { class: "tabs",
                button { class: "{nav_class(active(), ActiveView::Setup)}", onclick: move |_| active.set(ActiveView::Setup), "Setup" }
                button { class: "{nav_class(active(), ActiveView::Alerts)}", onclick: move |_| active.set(ActiveView::Alerts), "Alerts" }
                button { class: "{nav_class(active(), ActiveView::Children)}", onclick: move |_| active.set(ActiveView::Children), "Children" }
                button { class: "{nav_class(active(), ActiveView::Protection)}", onclick: move |_| active.set(ActiveView::Protection), "Protection" }
                button { class: "{nav_class(active(), ActiveView::Server)}", onclick: move |_| active.set(ActiveView::Server), "Server" }
                button { class: "{nav_class(active(), ActiveView::Coverage)}", onclick: move |_| active.set(ActiveView::Coverage), "Coverage" }
            }

            if offline() {
                div { class: "banner", "Demo mode — sample alerts are shown until a live guardian session connects." }
            }

            if let Some(err) = action_error() {
                div { class: "err", "Couldn't send your decision: {err}" }
            }

            match active() {
                ActiveView::Setup => rsx! {
                    section { class: "panel",
                        div { class: "panel-head",
                            h2 { "Family setup" }
                            p { class: "sub", "Choose the backend, sign in on that backend, then create a child pairing code." }
                        }
                        div { class: "steps",
                            div { class: "step done",
                                span { class: "step-no", "1" }
                                div {
                                    div { class: "ttl", "Server selected" }
                                    div { class: "meta mono", "{status().endpoint}" }
                                }
                            }
                            div { class: if status().logged_in { "step done" } else { "step" },
                                span { class: "step-no", "2" }
                                div {
                                    div { class: "ttl", "Guardian account" }
                                    div { class: "meta", "{session_status_text(&status())} for {status().server_label}" }
                                }
                            }
                            div { class: if pair_code().is_some() { "step done" } else { "step" },
                                span { class: "step-no", "3" }
                                div {
                                    div { class: "ttl", "Child pairing" }
                                    div { class: "meta", "Generate a short code, then enter it on the child device." }
                                }
                            }
                        }

                        div { class: "two-col",
                            div { class: "box",
                                h3 { "Guardian sign-in" }
                                div { class: "seg",
                                    button {
                                        class: if create_account() { "seg-btn seg-on" } else { "seg-btn" },
                                        onclick: move |_| create_account.set(true),
                                        "Create"
                                    }
                                    button {
                                        class: if !create_account() { "seg-btn seg-on" } else { "seg-btn" },
                                        onclick: move |_| create_account.set(false),
                                        "Login"
                                    }
                                }
                                label { class: "field",
                                    span { "Email" }
                                    input {
                                        r#type: "email",
                                        placeholder: "guardian@example.com",
                                        value: "{email}",
                                        oninput: move |e| email.set(e.value()),
                                    }
                                }
                                if create_account() {
                                    label { class: "field",
                                        span { "Display name" }
                                        input {
                                            r#type: "text",
                                            placeholder: "Guardian",
                                            value: "{display_name}",
                                            oninput: move |e| display_name.set(e.value()),
                                        }
                                    }
                                }
                                label { class: "field",
                                    span { "Password" }
                                    input {
                                        r#type: "password",
                                        placeholder: "Password",
                                        value: "{password}",
                                        oninput: move |e| password.set(e.value()),
                                    }
                                }
                                button {
                                    class: "primary",
                                    disabled: setup_busy(),
                                    onclick: move |_| {
                                        let email_value = email().trim().to_string();
                                        let password_value = password();
                                        let display_value = display_name().trim().to_string();
                                        let should_create = create_account();
                                        let mut setup_busy = setup_busy;
                                        let mut setup_error = setup_error;
                                        let mut setup_note = setup_note;
                                        let mut status = status;
                                        setup_busy.set(true);
                                        setup_error.set(None);
                                        setup_note.set(None);
                                        spawn(async move {
                                            let result: anyhow::Result<String> = async {
                                                if email_value.is_empty() || password_value.is_empty() {
                                                    anyhow::bail!("email and password are required");
                                                }
                                                if should_create {
                                                    let _ = create_guardian_account(&email_value, &password_value, &display_value).await?;
                                                }
                                                let session = login_guardian(&email_value, &password_value).await?;
                                                save_guardian_token(&session.token)?;
                                                Ok(session.account_id)
                                            }.await;
                                            match result {
                                                Ok(account_id) => {
                                                    status.set(AppStatus::load());
                                                    setup_note.set(Some(format!("Signed in as account {account_id}.")));
                                                }
                                                Err(e) => setup_error.set(Some(e.to_string())),
                                            }
                                            setup_busy.set(false);
                                        });
                                    },
                                    if setup_busy() { "Working..." } else if create_account() { "Create and login" } else { "Login" }
                                }
                                if status().logged_in {
                                    button {
                                        class: "ghost danger-link",
                                        onclick: move |_| {
                                            let mut status = status;
                                            let mut setup_note = setup_note;
                                            let mut setup_error = setup_error;
                                            match clear_guardian_token() {
                                                Ok(()) => {
                                                    status.set(AppStatus::load());
                                                    setup_note.set(Some("Signed out for this server.".to_string()));
                                                }
                                                Err(e) => setup_error.set(Some(format!("Couldn't sign out: {e}"))),
                                            }
                                        },
                                        "Sign out on this server"
                                    }
                                }
                            }

                            div { class: "box",
                                h3 { "Add child" }
                                label { class: "field",
                                    span { "Child display name" }
                                    input {
                                        r#type: "text",
                                        placeholder: "Kid",
                                        value: "{child_name}",
                                        oninput: move |e| child_name.set(e.value()),
                                    }
                                }
                                button {
                                    class: "primary",
                                    disabled: setup_busy() || !status().logged_in,
                                    onclick: move |_| {
                                        let name = child_name().trim().to_string();
                                        let mut setup_busy = setup_busy;
                                        let mut setup_error = setup_error;
                                        let mut setup_note = setup_note;
                                        let mut pair_code = pair_code;
                                        setup_busy.set(true);
                                        setup_error.set(None);
                                        setup_note.set(None);
                                        spawn(async move {
                                            let result: anyhow::Result<PairCodeUi> = async {
                                                if name.is_empty() {
                                                    anyhow::bail!("child name is required");
                                                }
                                                let pair = create_pair_code_for_child(&name).await?;
                                                Ok(PairCodeUi {
                                                    child_name: name,
                                                    code: pair.code,
                                                    expires_ts: pair.expires_ts,
                                                })
                                            }.await;
                                            match result {
                                                Ok(pair) => {
                                                    setup_note.set(Some("Pair code created. Enter it on the child device using the same server.".to_string()));
                                                    pair_code.set(Some(pair));
                                                }
                                                Err(e) => setup_error.set(Some(e.to_string())),
                                            }
                                            setup_busy.set(false);
                                        });
                                    },
                                    "Generate pair code"
                                }
                                if !status().logged_in {
                                    div { class: "hint", "Login first; sessions are separate for each server." }
                                }
                                if let Some(pair) = pair_code() {
                                    div { class: "pair-code",
                                        div { class: "meta", "Pair code for {pair.child_name}" }
                                        div { class: "code mono", "{pair.code}" }
                                        div { class: "meta", "{pair_expiry_text(pair.expires_ts)}" }
                                    }
                                }
                            }
                        }

                        if let Some(note) = setup_note() {
                            div { class: "ok-note", "{note}" }
                        }
                        if let Some(err) = setup_error() {
                            div { class: "err", "{err}" }
                        }
                    }
                },
                ActiveView::Alerts => rsx! {
                    section { class: "panel",
                        div { class: "panel-head",
                            h2 { "Alert inbox" }
                            p { class: "sub",
                                if offline() { "Demo alerts are non-actionable samples." } else { "Live alerts from children assigned to this guardian." }
                            }
                        }
                        if alerts.read().is_empty() {
                            p { class: "empty", "All clear — no alerts right now." }
                        }
                        for a in alerts.read().clone().into_iter() {
                            AlertCard {
                                key: "{a.id}",
                                alert: a.clone(),
                                on_decide: {
                                    let cb_id = a.id.clone();
                                    let cb_device = a.device.clone();
                                    move |approve: bool| {
                                        let id = cb_id.clone();
                                        let device = cb_device.clone();
                                        let mut alerts = alerts;
                                        let mut action_error = action_error;
                                        let removed: Option<Alert> = {
                                            let mut list = alerts.write();
                                            let idx = list.iter().position(|x| x.id == id);
                                            idx.map(|i| list.remove(i))
                                        };
                                        action_error.set(None);
                                        spawn(async move {
                                            if let Err(e) = submit_decision(&id, &device, approve).await {
                                                if let Some(row) = removed {
                                                    let mut list = alerts.write();
                                                    if !list.iter().any(|x| x.id == row.id) {
                                                        list.insert(0, row);
                                                    }
                                                }
                                                action_error.set(Some(e.to_string()));
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    }
                },
                ActiveView::Children => rsx! {
                    section { class: "panel",
                        div { class: "panel-head split",
                            div {
                                h2 { "Children" }
                                p { class: "sub", "Children assigned to the logged-in guardian on this server." }
                            }
                            button {
                                class: "primary",
                                disabled: children_busy() || !status().logged_in,
                                onclick: move |_| {
                                    let mut children = children;
                                    let mut children_busy = children_busy;
                                    let mut children_error = children_error;
                                    children_busy.set(true);
                                    children_error.set(None);
                                    spawn(async move {
                                        match load_children().await {
                                            Ok(rows) => children.set(rows),
                                            Err(e) => children_error.set(Some(e.to_string())),
                                        }
                                        children_busy.set(false);
                                    });
                                },
                                if children_busy() { "Loading..." } else { "Load children" }
                            }
                        }
                        if !status().logged_in {
                            div { class: "banner", "Login on this server to see children and create pair codes." }
                        }
                        if let Some(err) = children_error() {
                            div { class: "err", "{err}" }
                        }
                        if children.read().is_empty() {
                            p { class: "empty", "No children loaded yet." }
                        }
                        for child in children.read().clone().into_iter() {
                            div { class: "child-row", key: "{child.child_id}",
                                div {
                                    div { class: "ttl", "{child.child_name}" }
                                    div { class: "meta mono", "device {child.device_id}" }
                                }
                                div { class: "meta mono", "guardians {child.guardian_account_ids.len()}" }
                            }
                        }
                    }
                },
                ActiveView::Protection => rsx! {
                    ProtectionPanel {}
                },
                ActiveView::Server => rsx! {
                    ServerSettingsPanel {
                        on_saved: move |_| status.set(AppStatus::load())
                    }
                },
                ActiveView::Coverage => rsx! {
                    section { class: "panel",
                        h2 { "Coverage" }
                        CoverageMatrix {}
                    }
                },
            }
        }
    }
}

/// Send a guardian decision for `alert_id` to `Review.SubmitDecision`.
///
/// APPROVE allowlists the host involved (`THIS_HOST`); DENY confirms the block
/// (scope ignored for DENY per the contract). Each call dials a fresh channel —
/// decisions are infrequent and this keeps the coroutine's stream channel
/// independent of one-shot RPCs.
async fn submit_decision(alert_id: &str, device_id: &str, approve: bool) -> anyhow::Result<()> {
    let channel = connect_channel().await?;
    let token = guardian_token();
    submit_decision_on(channel, &token, alert_id, device_id, approve).await
}

#[cfg(test)]
async fn submit_decision_to(
    endpoint: &str,
    token: &str,
    alert_id: &str,
    device_id: &str,
    approve: bool,
) -> anyhow::Result<()> {
    let channel = connect_channel_to(endpoint, None).await?;
    submit_decision_on(channel, token, alert_id, device_id, approve).await
}

async fn submit_decision_on(
    channel: Channel,
    token: &str,
    alert_id: &str,
    device_id: &str,
    approve: bool,
) -> anyhow::Result<()> {
    let mut client = ReviewClient::new(channel);

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let req = review_request_at(alert_id, device_id, approve, ts);
    let request = request_with_bearer(req, token);

    let ack = client.submit_decision(request).await?.into_inner();
    if !ack.applied {
        anyhow::bail!("the cluster did not apply the decision");
    }
    Ok(())
}

fn review_request_at(alert_id: &str, device_id: &str, approve: bool, ts: i64) -> ReviewRequest {
    let decision = if approve {
        ReviewDecision::Approve
    } else {
        ReviewDecision::Deny
    };

    ReviewRequest {
        alert_id: alert_id.to_string(),
        decision: decision as i32,
        device_id: device_id.to_string(),
        scope: ReviewScope::ThisHost as i32,
        ts,
    }
}

fn request_with_bearer(req: ReviewRequest, token: &str) -> tonic::Request<ReviewRequest> {
    // In accounts mode the server requires a guardian session token on the
    // decision RPC (it scopes the approve/deny to the guardian's assigned
    // children). Attach the SAME guardian token the alert stream uses, as
    // `authorization: Bearer <token>` metadata. A single-home / no-accounts server
    // ignores it, so an unset token still works there.
    let mut request = tonic::Request::new(req);
    let token = token.trim();
    if !token.is_empty() {
        if let Ok(val) = tonic::metadata::MetadataValue::try_from(format!("Bearer {token}")) {
            request.metadata_mut().insert("authorization", val);
        }
    }
    request
}

// ---------------------------------------------------------------------------
// Protection control panel — process + system-proxy plumbing
// ---------------------------------------------------------------------------

/// Path to the per-install root CA the proxy uses to decrypt HTTPS. We don't
/// install it (that's a one-time `certutil` the user runs); we only report
/// whether it has been generated, and surface the trust command if needed.
fn ca_pem_path() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_default();
    std::path::Path::new(&base)
        .join("Aegis")
        .join("aegis-root-ca.pem")
}

/// True when the CA pem exists on disk (i.e. the proxy has a root to trust).
fn ca_present() -> bool {
    ca_pem_path().exists()
}

/// The one-time, no-admin command the user runs to trust the CA for their user.
fn ca_trust_command() -> String {
    format!(
        "certutil -addstore -user Root \"{}\"",
        ca_pem_path().display()
    )
}

/// Spawn the content-filtering proxy.
///
/// Prefers the prebuilt `aegis_proxy.exe`; if that's missing, falls back to
/// `cargo run -p aegis-client --features onnx --bin aegis_proxy` from the repo
/// root. Either way the proxy gets `AEGIS_NSFW_MODEL` + `AEGIS_CLUSTER_ENDPOINT`.
/// Returns the `Child` so the caller can kill it on Disconnect / shutdown.
///
/// Blocking (it touches the filesystem and spawns a process) — call from an
/// event handler, never the render path.
/// Build the spawn `Command` for a filter binary: the bundled exe if present
/// (`exe`), else a dev `cargo run` of `bin` from the repo root. Both inherit the
/// unified cluster endpoint and — only when configured — media provisioning paths.
fn filter_command(exe: Option<std::path::PathBuf>, bin: &str) -> std::process::Command {
    use std::process::Command;
    let mut cmd = match exe {
        Some(path) => Command::new(path),
        None => {
            let mut c = Command::new("cargo");
            c.args([
                "run",
                "-p",
                "aegis-client",
                "--features",
                "onnx,ffmpeg",
                "--bin",
                bin,
            ])
            .current_dir(repo_root());
            c
        }
    };
    cmd.env("AEGIS_CLUSTER_ENDPOINT", cluster_endpoint());
    if let Some(model) = nsfw_model() {
        cmd.env("AEGIS_NSFW_MODEL", model);
    }
    if let Some(ffmpeg) = ffmpeg_binary() {
        cmd.env("FFMPEG_BINARY", ffmpeg);
    }
    cmd
}

fn spawn_proxy() -> std::io::Result<Child> {
    filter_command(proxy_exe(), "aegis_proxy").spawn()
}

/// Spawn the transparent-VPN binary (`aegis_vpn.exe`). Like [`spawn_proxy`] it
/// passes the model + cluster endpoint, but VPN mode is currently disabled by
/// the VPN binary while the transparent data path is being rebuilt.
fn spawn_vpn() -> std::io::Result<Child> {
    filter_command(vpn_exe(), "aegis_vpn").spawn()
}

/// Is the proxy actually accepting connections right now? This is the source of
/// truth for the status light — independent of whether *we* think we started it,
/// so an externally-started proxy (or a crashed child) is reported honestly.
///
/// Blocking up to ~300ms; call from the status coroutine, not render.
fn proxy_listening() -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    let addr = match (PROXY_HOST, PROXY_PORT).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return false,
        },
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

/// Turn the per-user Windows system proxy ON, pointing all traffic at our local
/// proxy. HKCU only — no admin. Best-effort notifies WinINET so already-open
/// browsers re-read the setting; new windows pick it up regardless.
#[cfg(windows)]
fn enable_system_proxy() -> anyhow::Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let settings = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        KEY_WRITE,
    )?;
    settings.set_value("ProxyEnable", &1u32)?;
    settings.set_value("ProxyServer", &PROXY_ADDR.to_string())?;
    // Keep loopback + intranet direct so the console's own RPCs aren't proxied.
    settings.set_value("ProxyOverride", &"<-loopback>".to_string())?;
    refresh_wininet();
    Ok(())
}

/// Turn the per-user system proxy OFF (ProxyEnable=0) and refresh WinINET.
#[cfg(windows)]
fn disable_system_proxy() -> anyhow::Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let settings = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        KEY_WRITE,
    )?;
    settings.set_value("ProxyEnable", &0u32)?;
    refresh_wininet();
    Ok(())
}

/// Best-effort: poke WinINET so open browsers re-read the proxy setting now.
/// Failures are ignored — new browser windows always pick up the registry value.
#[cfg(windows)]
fn refresh_wininet() {
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    unsafe {
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }
}

// Non-Windows stubs so the file still type-checks on other platforms (the app
// only ships on Windows/macOS, but keeping the desktop build green elsewhere is
// cheap). On non-Windows the system-proxy toggle is a documented no-op.
#[cfg(not(windows))]
fn enable_system_proxy() -> anyhow::Result<()> {
    anyhow::bail!("system proxy toggle is only implemented on Windows")
}
#[cfg(not(windows))]
fn disable_system_proxy() -> anyhow::Result<()> {
    Ok(())
}

/// Which local filter the Connect control launches.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Explicit per-user system proxy (no admin): spawns `aegis_proxy` and points
    /// the Windows system proxy at it.
    Proxy,
    /// Transparent, system-wide TUN VPN (needs admin): spawns `aegis_vpn`. The TUN
    /// captures everything, so no system-proxy change is made.
    Vpn,
}

impl Mode {
    /// One-line description shown under the selector.
    fn explain(self) -> &'static str {
        match self {
            Mode::Proxy => "Routes traffic through the local filter via the per-user system proxy. No admin needed; covers browsers + apps that honour the system proxy.",
            Mode::Vpn => "Transparent VPN mode is being rebuilt and is disabled in this build. Use Proxy mode for now.",
        }
    }
}

/// Shared handle to the spawned proxy/VPN child, stored in app state so any handler
/// (Connect/Disconnect/shutdown) can take and kill it. `Rc<RefCell<..>>` keeps
/// it single-threaded on the UI thread, which is where our handlers run.
type ProxyHandle = Rc<RefCell<Option<Child>>>;

/// Kill the spawned proxy child if we have one (best-effort), then drop it.
fn kill_proxy(handle: &ProxyHandle) {
    if let Some(mut child) = handle.borrow_mut().take() {
        let _ = child.kill();
        // Reap so we don't leave a zombie; ignore the exit status.
        let _ = child.wait();
    }
}

#[component]
fn ProtectionPanel() -> Element {
    // Live truth from the 2s poll: is the proxy port actually accepting TCP?
    let mut connected = use_signal(|| false);
    // Whether the per-install CA pem exists (refreshed by the same poll).
    let mut ca_trusted = use_signal(ca_present);
    // Transient inline error from a failed Connect/Disconnect.
    let control_error = use_signal(|| Option::<String>::None);
    // True while a Connect/Disconnect action is in flight (debounce the button).
    let busy = use_signal(|| false);
    // Which filter the Connect control launches (Proxy = no admin, default).
    let mode = use_signal(|| Mode::Proxy);
    // True once WE turned the per-user system proxy ON (proxy mode only), so
    // Disconnect clears it iff we set it and VPN mode never touches it.
    let proxy_set = use_signal(|| false);

    // The spawned proxy process, shared across handlers. use_signal stores it so
    // the same Rc survives re-renders; we never read it on the render path.
    let proxy: Signal<ProxyHandle> = use_signal(|| Rc::new(RefCell::new(Option::<Child>::None)));

    // Live status poll: every ~2s probe the port (source of truth) and re-check
    // the CA file. Heavy/blocking work runs inside the async task, off render.
    use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
        loop {
            let listening = proxy_listening();
            if connected() != listening {
                connected.set(listening);
            }
            let ca = ca_present();
            if ca_trusted() != ca {
                ca_trusted.set(ca);
            }
            // Dioxus desktop runs on tokio; this yields without blocking the UI.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    // Best-effort cleanup when the panel is torn down (app close). Dioxus 0.6
    // has no first-class window-close hook on the desktop renderer, so we lean on
    // use_drop: it runs when the component unmounts, which on a single-window app
    // happens at shutdown. We kill the child and clear the system proxy so a
    // closed window never leaves the machine proxied. (Hard kills, e.g. Task
    // Manager, can't be caught — documented limitation; Disconnect is the
    // guaranteed clean path.)
    use_drop(move || {
        // `proxy` is a Copy `Signal`, captured directly by this `move` closure.
        kill_proxy(&proxy());
        let _ = disable_system_proxy();
    });

    rsx! {
        section { class: "protect",
            div { class: "protect-head",
                div {
                    span {
                        class: if connected() { "dot dot-on" } else { "dot dot-off" },
                    }
                    span { class: "protect-state",
                        if connected() { "Protection on" } else { "Protection off" }
                    }
                }
                button {
                    class: if connected() { "disconnect" } else { "connect" },
                    disabled: busy(),
                    onclick: move |_| {
                        // Snapshot state we need inside the (sync) handler.
                        let want_connect = !connected();
                        let selected_mode = mode();
                        let proxy_handle = proxy();
                        let mut control_error = control_error;
                        let mut busy = busy;
                        let mut connected = connected;
                        let mut proxy_set = proxy_set;

                        busy.set(true);
                        control_error.set(None);

                        if want_connect {
                            // 1) Spawn the chosen filter and stash the Child for kill.
                            let spawned = match selected_mode {
                                Mode::Proxy => spawn_proxy(),
                                Mode::Vpn => spawn_vpn(),
                            };
                            match spawned {
                                Ok(child) => {
                                    *proxy_handle.borrow_mut() = Some(child);
                                }
                                Err(e) => {
                                    let what = match selected_mode {
                                        Mode::Proxy => "the proxy",
                                        Mode::Vpn => "the VPN",
                                    };
                                    control_error
                                        .set(Some(format!("Couldn't start {what}: {e}")));
                                    busy.set(false);
                                    return;
                                }
                            }
                            match selected_mode {
                                // Proxy mode: flip the per-user system proxy ON.
                                Mode::Proxy => {
                                    if let Err(e) = enable_system_proxy() {
                                        control_error.set(Some(format!(
                                            "Started proxy but couldn't set system proxy: {e}"
                                        )));
                                    } else {
                                        proxy_set.set(true);
                                    }
                                }
                                // VPN mode: no system-proxy change. aegis_vpn exits
                                // fast if not elevated — detect that and hint admin.
                                Mode::Vpn => {
                                    let probe = proxy_handle.clone();
                                    let mut probe_err = control_error;
                                    let mut probe_connected = connected;
                                    spawn(async move {
                                        tokio::time::sleep(Duration::from_secs(2)).await;
                                        let exited = match probe.borrow_mut().as_mut() {
                                            Some(c) => matches!(c.try_wait(), Ok(Some(_))),
                                            None => false,
                                        };
                                        if exited {
                                            kill_proxy(&probe);
                                            probe_err.set(Some(
                                                "VPN mode is disabled in this build while the transparent data path is being rebuilt. \
                                                 Use Proxy mode, or connect the London WireGuard tunnel outside PH Bulwark."
                                                    .to_string(),
                                            ));
                                            probe_connected.set(false);
                                        }
                                    });
                                }
                            }
                        } else {
                            // Disconnect: kill the child; clear the system proxy
                            // only if WE set it (proxy mode). VPN never touched it.
                            kill_proxy(&proxy_handle);
                            if proxy_set() {
                                if let Err(e) = disable_system_proxy() {
                                    control_error.set(Some(format!(
                                        "Couldn't clear the system proxy: {e}"
                                    )));
                                }
                                proxy_set.set(false);
                            }
                            // Reflect "off" immediately; the poll confirms within 2s.
                            connected.set(false);
                        }

                        busy.set(false);
                    },
                    if busy() {
                        "Working…"
                    } else if connected() {
                        "Disconnect"
                    } else {
                        "Connect"
                    }
                }
            }

            div { class: "mode-sel",
                button {
                    class: if mode() == Mode::Proxy { "mode-opt mode-on" } else { "mode-opt" },
                    disabled: busy() || connected(),
                    onclick: move |_| { let mut mode = mode; mode.set(Mode::Proxy); },
                    "Proxy (no admin)"
                }
                button {
                    // DISABLED until the permissive smoltcp/WireGuard data path lands
                    // — `run_vpn` currently fails closed, so offering VPN mode would
                    // only produce an error. The onclick is retained (keeps the
                    // `Mode::Vpn` variant constructed) but the button can't be clicked.
                    class: "mode-opt",
                    disabled: true,
                    title: "Transparent VPN is being rebuilt on a permissive netstack — use Proxy for now",
                    onclick: move |_| { let mut mode = mode; mode.set(Mode::Vpn); },
                    "VPN (coming soon)"
                }
            }
            div { class: "mode-explain", "{mode().explain()}" }

            if let Some(err) = control_error() {
                div { class: "err", "{err}" }
            }

            div { class: "protect-grid",
                div { class: "pg-row",
                    span { class: "pg-k", "Status" }
                    span { class: "pg-v",
                        if connected() {
                            span { class: "ok", "Connected" }
                        } else {
                            span { class: "off", "Off" }
                        }
                    }
                }
                div { class: "pg-row",
                    span { class: "pg-k", "Proxy address" }
                    span { class: "pg-v mono", "{PROXY_ADDR}" }
                }
                div { class: "pg-row",
                    span { class: "pg-k", "Per-install CA" }
                    span { class: "pg-v",
                        if ca_trusted() {
                            span { class: "ok", "Present" }
                        } else {
                            span { class: "off", "Missing" }
                        }
                    }
                }
                div { class: "pg-row",
                    span { class: "pg-k", "NSFW model" }
                    span { class: "pg-v mono", {nsfw_model_display()} }
                }
                div { class: "pg-row",
                    span { class: "pg-k", "ffmpeg" }
                    span { class: "pg-v mono", {ffmpeg_display()} }
                }
            }

            if !ca_trusted() {
                div { class: "ca-hint",
                    "To decrypt HTTPS, trust the per-install CA once (no admin):"
                    div { class: "mono ca-cmd", "{ca_trust_command()}" }
                }
            }
        }
    }
}

/// Server / country picker: choose which PH Bulwark Cloud region (your data routes
/// only through that country) or self-host. Persisted; drives the console's review
/// channel AND the filter it spawns. `AEGIS_CLUSTER_ENDPOINT` overrides for ops use.
#[component]
fn ServerSettings() -> Element {
    rsx! {
        ServerSettingsPanel { on_saved: move |_| {} }
    }
}

#[component]
fn ServerSettingsPanel(on_saved: EventHandler<()>) -> Element {
    let saved = saved_choice();
    let mut inventory = use_signal(server_inventory);
    let mut selected = use_signal(|| selected_server_id(&saved));
    let mut custom_label = use_signal(String::new);
    let mut custom_url = use_signal(String::new);
    let mut note = use_signal(|| Option::<String>::None);
    let rows = inventory.read().clone();

    rsx! {
        section {
            h2 { "Server / country" }
            p { class: "sub",
                "Pick the one backend this guardian session should use. Each server keeps its own saved login token."
            }

            div { class: "server-list",
                for server in rows.into_iter() {
                    div {
                        class: if selected() == server.id { "server-row server-active" } else { "server-row" },
                        key: "{server.id}",
                        label { class: "server-main",
                            input {
                                r#type: "radio",
                                name: "srv",
                                checked: selected() == server.id,
                                onclick: {
                                    let id = server.id.clone();
                                    move |_| selected.set(id.clone())
                                },
                            }
                            div {
                                div { class: "ttl", "{server.label}" }
                                div { class: "meta mono", "{server.endpoint}" }
                                div { class: "server-badges",
                                    span { class: "badge", if server.builtin { "Cloud" } else { "Self-hosted" } }
                                    span {
                                        class: if saved_token_for_endpoint(&server.endpoint).is_empty() { "badge badge-warn" } else { "badge badge-ok" },
                                        if saved_token_for_endpoint(&server.endpoint).is_empty() { "No session" } else { "Session saved" }
                                    }
                                    span {
                                        class: if cluster_ca_path_for_endpoint(&server.endpoint).exists() { "badge badge-ok" } else { "badge" },
                                        if cluster_ca_path_for_endpoint(&server.endpoint).exists() { "CA pinned" } else { "Default trust" }
                                    }
                                }
                            }
                        }
                        if !server.builtin {
                            button {
                                class: "ghost danger-link small-btn",
                                onclick: {
                                    let id = server.id.clone();
                                    move |_| {
                                        match remove_custom_server(&id) {
                                            Ok(()) => {
                                                if selected() == id {
                                                    selected.set(DEFAULT_REGION_ID.to_string());
                                                }
                                                inventory.set(server_inventory());
                                                on_saved.call(());
                                                note.set(Some("Removed self-hosted server.".to_string()));
                                            }
                                            Err(e) => note.set(Some(format!("Couldn't remove server: {e}"))),
                                        }
                                    }
                                },
                                "Remove"
                            }
                        }
                    }
                }
            }

            button {
                class: "approve",
                onclick: move |_| {
                    let choice = selected();
                    match save_server_choice(&choice) {
                        Ok(()) => {
                            on_saved.call(());
                            note.set(Some("Saved — this server now has its own guardian session.".to_string()));
                        }
                        Err(e) => note.set(Some(format!("Couldn't save: {e}"))),
                    }
                },
                "Save server"
            }

            div { class: "box add-server",
                h3 { "Add self-hosted server" }
                label { class: "field",
                    span { "Name" }
                    input {
                        r#type: "text",
                        placeholder: "Home server",
                        value: "{custom_label}",
                        oninput: move |e| custom_label.set(e.value()),
                    }
                }
                label { class: "field",
                    span { "Endpoint" }
                    input {
                        r#type: "text",
                        placeholder: "https://your-server:8443",
                        value: "{custom_url}",
                        oninput: move |e| custom_url.set(e.value()),
                    }
                }
                button {
                    class: "primary",
                    onclick: move |_| {
                        match upsert_custom_server(&custom_label(), &custom_url()) {
                            Ok(server) => {
                                if let Err(e) = save_server_choice(&server.id) {
                                    note.set(Some(format!("Saved server, but couldn't make it active: {e}")));
                                } else {
                                    selected.set(server.id.clone());
                                    on_saved.call(());
                                    note.set(Some(format!("Added {} and made it active.", server.label)));
                                }
                                inventory.set(server_inventory());
                            }
                            Err(e) => note.set(Some(e.to_string())),
                        }
                    },
                    "Add and use"
                }
                div { class: "hint",
                    "For a private CA, place it at "
                    span { class: "mono", "sessions/<server-session>/cluster_ca.pem" }
                    " after adding the server."
                }
            }

            if let Some(n) = note() {
                div { class: "seg-note", "{n}" }
            }
        }
    }
}

fn can_show_evidence(category: Category) -> bool {
    category != Category::CsamSuspected
}

fn should_show_thumbnail(alert: &Alert) -> bool {
    can_show_evidence(alert.category) && !alert.thumbnail.is_empty()
}

fn should_show_snippet(alert: &Alert) -> bool {
    can_show_evidence(alert.category) && !alert.snippet.is_empty()
}

#[component]
fn AlertCard(alert: Alert, on_decide: EventHandler<bool>) -> Element {
    // THE CSAM EXCEPTION. Suspected CSAM is illegal to view, so this UI shows
    // NEITHER the image NOR the text snippet, regardless of what the event
    // carried. Everything else (intervention blocks, grooming) shows the
    // guardian the real flagged content for an informed decision.
    let is_csam = alert.category == Category::CsamSuspected;

    // Build the inline image data URI only for non-CSAM items that actually
    // carried preview bytes. `image_data_uri` sniffs the format and base64s it.
    let preview_uri: Option<String> = if should_show_thumbnail(&alert) {
        Some(image_data_uri(&alert.thumbnail))
    } else {
        None
    };

    // The actual flagged text — shown in full to the guardian, except for CSAM.
    let show_snippet = should_show_snippet(&alert);

    rsx! {
        div { class: "card",
            div { class: "ttl", "{alert.title}" }
            div { class: "meta", "{alert.device} \u{00b7} {alert.when}" }
            p { class: "detail", "{alert.detail}" }

            if is_csam {
                // No image, no snippet — withheld notice only (never displayed/stored).
                div { class: "csam",
                    "Preview withheld — suspected illegal content is blocked and is never shown or stored."
                }
            } else {
                if let Some(seg) = alert.segment_uri.clone() {
                    SegmentPlayer { uri: seg }
                }
                if let Some(uri) = preview_uri {
                    div { class: "preview",
                        div { class: "preview-label", "Preview of what was blocked:" }
                        img { class: "thumb", src: "{uri}", alt: "Safe preview of the blocked content" }
                    }
                }
                if show_snippet {
                    div { class: "snippet",
                        div { class: "snippet-label", "What was blocked:" }
                        p { class: "snippet-text", "{alert.snippet}" }
                    }
                }
            }

            if alert.actionable {
                div { class: "row",
                    button { class: "approve", onclick: move |_| on_decide.call(true), "Approve" }
                    button { class: "deny", onclick: move |_| on_decide.call(false), "Keep blocked" }
                }
            }
        }
    }
}

/// Plays a blocked video segment for guardian review. The `blob://<sha>` URI is
/// resolved from the per-user segment store on disk (`%LOCALAPPDATA%/Aegis/
/// segments/<sha>.blob`, written by `aegis-video::SegmentStore`) when the parent is
/// co-located with the server; otherwise it falls back to pulling the clip from the
/// cluster over `Review.FetchSegment`. Bytes are shown via a data URI in the desktop
/// webview's `<video>`. The caller only mounts this for NON-CSAM alerts (CSAM is
/// never stored/served, so it would not exist anyway — defence in depth).
#[component]
fn SegmentPlayer(uri: String) -> Element {
    let mut data_uri = use_signal(|| Option::<String>::None);
    let mut load_err = use_signal(|| Option::<String>::None);

    use_effect(move || {
        let uri = uri.clone();
        spawn(async move {
            // Local disk first (co-located parent); fall back to the cluster over
            // Review.FetchSegment for a guardian on a DIFFERENT device than the server.
            let bytes = match load_segment_from_disk(&uri) {
                Ok(Some(b)) => Some(b),
                Ok(None) => match fetch_segment_remote(&uri).await {
                    Ok(b) => Some(b),
                    Err(e) => {
                        load_err.set(Some(format!("not on disk; cluster fetch failed: {e}")));
                        None
                    }
                },
                Err(e) => {
                    load_err.set(Some(e));
                    None
                }
            };
            if let Some(b) = bytes {
                // Sniff the container — clips may be MP4/fMP4, DASH .m4s, HLS .ts, or
                // WebM; a hard-coded MP4 MIME breaks playback when it's something else.
                let mime = sniff_video_mime(&b);
                data_uri.set(Some(format!("data:{};base64,{}", mime, base64_encode(&b))));
            }
        });
    });

    rsx! {
        div { class: "player",
            div { class: "preview-label", "Blocked video segment (review):" }
            if let Some(src) = data_uri() {
                video { class: "vid", controls: true, src: "{src}" }
            } else if let Some(err) = load_err() {
                div { class: "seg-note", "Segment unavailable — {err}" }
            } else {
                div { class: "seg-note", "Loading segment…" }
            }
        }
    }
}

/// Resolve a `blob://<sha256>` URI to the per-user segment store path and read
/// the bytes. `Ok(None)` = missing/purged; `Err` = malformed URI or read error.
fn load_segment_from_disk(uri: &str) -> Result<Option<Vec<u8>>, String> {
    let sha = uri
        .strip_prefix("blob://")
        .ok_or_else(|| "not a blob:// URI".to_string())?;
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("malformed segment id".to_string());
    }
    let path = segments_dir().join(format!("{sha}.blob"));
    match std::fs::read(&path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Pull a retained clip from the cluster over `Review.FetchSegment` (for a guardian
/// on a DIFFERENT device than the server — the clip isn't on local disk). Streams
/// the chunks and reassembles. Authenticated via the guardian token in accounts mode
/// (CSAM is never retained, so it can never be fetched).
async fn fetch_segment_remote(uri: &str) -> Result<Vec<u8>, String> {
    use aegis_proto::v1::SegmentRequest;
    let channel = connect_channel().await.map_err(|e| e.to_string())?;
    let mut client = ReviewClient::new(channel);
    let token = guardian_token();
    let mut stream = client
        .fetch_segment(SegmentRequest {
            local_segment_uri: uri.to_string(),
            token,
        })
        .await
        .map_err(|e| e.message().to_string())?
        .into_inner();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream
        .message()
        .await
        .map_err(|e| e.message().to_string())?
    {
        bytes.extend_from_slice(&chunk.data);
    }
    if bytes.is_empty() {
        return Err("empty or unavailable segment".to_string());
    }
    Ok(bytes)
}

/// The per-user segment store directory. MUST mirror
/// `aegis_video::store::default_segments_dir()` exactly — the child writes blobs
/// there; this lean parent UI deliberately does NOT depend on `aegis-video` (it
/// would drag the whole video/vision/ONNX tree into the desktop app), so the
/// resolution is duplicated here. Keep the two in sync: Windows `%LOCALAPPDATA%`,
/// then `$XDG_DATA_HOME`, then `$HOME/.local/share`, else the temp dir.
fn segments_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|s| !s.is_empty()) {
        return PathBuf::from(local).join("Aegis").join("segments");
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|s| !s.is_empty()) {
        return PathBuf::from(xdg).join("aegis").join("segments");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        return PathBuf::from(home).join(".local/share/aegis/segments");
    }
    std::env::temp_dir().join("aegis-segments")
}

// ---------------------------------------------------------------------------
// Inline image preview helpers (no heavy deps — hand-rolled base64 + sniff)
// ---------------------------------------------------------------------------

/// Build a `data:` URI for inline `<img src=...>` rendering from raw image
/// bytes, sniffing the format from magic bytes (JPEG default).
fn image_data_uri(bytes: &[u8]) -> String {
    let mime = sniff_image_mime(bytes);
    format!("data:{};base64,{}", mime, base64_encode(bytes))
}

/// Best-effort image MIME sniff from leading magic bytes. Defaults to
/// `image/jpeg` (the common safe-thumbnail format) when nothing matches.
fn sniff_image_mime(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 8 && bytes[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        "image/png"
    } else if bytes.len() >= 6 && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a") {
        "image/gif"
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        // JPEG (FF D8 FF) and everything else default to jpeg.
        "image/jpeg"
    }
}

/// Best-effort video-container MIME sniff for a stored review clip. The segment
/// store keeps bytes as-is, so a clip may be MP4/fMP4, DASH `.m4s`, HLS `.ts`, or
/// WebM. Defaults to `video/mp4` (the common case) when nothing matches.
fn sniff_video_mime(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 8 && (&bytes[4..8] == b"ftyp" || &bytes[4..8] == b"styp") {
        // ISO-BMFF: MP4, fragmented MP4, and DASH `.m4s` all carry a ftyp/styp box.
        "video/mp4"
    } else if bytes.len() >= 4 && bytes[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        // EBML header → WebM / Matroska.
        "video/webm"
    } else if bytes.len() >= 4 && &bytes[..4] == b"OggS" {
        "video/ogg"
    } else if bytes.len() > 188 && bytes[0] == 0x47 && bytes[188] == 0x47 {
        // MPEG-TS (HLS `.ts`): 188-byte packets, each starting with the 0x47 sync.
        "video/mp2t"
    } else {
        "video/mp4"
    }
}

/// Minimal standard-alphabet base64 encoder (RFC 4648, with `=` padding).
/// Hand-rolled so the console needs no extra dependency for the data URI.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[component]
fn CoverageMatrix() -> Element {
    let rows = [
        (
            "Web (browsers)",
            "Filtered",
            "HTTPS decrypted via the per-install CA",
        ),
        (
            "Video / live streams",
            "Filtered",
            "Buffered, sampled, block/blur/mute",
        ),
        (
            "WhatsApp / Signal / Messenger (E2E)",
            "On-device only",
            "Network can't read; on-device text check",
        ),
        (
            "iPhone / iPad",
            "Content filter only",
            "Apple forbids message/screen access to apps",
        ),
    ];
    rsx! {
        table { class: "cov",
            thead { tr { th { "App / surface" } th { "Status" } th { "How" } } }
            tbody {
                for (app, status, how) in rows.iter() {
                    tr { td { "{app}" } td { "{status}" } td { class: "how", "{how}" } }
                }
            }
        }
    }
}

const CSS: &str = r#"
    body { margin: 0; font-family: system-ui, sans-serif; background: #10110f; color: #eceee8; }
    .app, .wrap { max-width: 1120px; margin: 0 auto; padding: 24px; }
    .topbar { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 18px; }
    h1 { font-size: 22px; margin: 0 0 4px; }
    .sub { color: #9aa0ad; margin: 0 0 20px; font-size: 13px; }
    h2 { font-size: 16px; margin: 0 0 8px; color: #d9ddd2; }
    h3 { font-size: 14px; margin: 0 0 12px; color: #d9ddd2; }
    .status-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin-bottom: 12px; }
    .status-tile { background: #171912; border: 1px solid #2a2e22; border-radius: 8px; padding: 12px; min-width: 0; }
    .status-k { display: block; color: #9aa0ad; font-size: 11px; text-transform: uppercase; margin-bottom: 4px; }
    .status-v { display: block; font-weight: 700; font-size: 16px; }
    .status-sub { display: block; color: #8b917f; margin-top: 4px; font-size: 12px; overflow-wrap: anywhere; }
    .warn { color: #e8c36b; }
    .tabs { display: flex; gap: 6px; flex-wrap: wrap; margin: 10px 0 16px; border-bottom: 1px solid #292d24; padding-bottom: 8px; }
    .nav-btn { background: transparent; color: #aeb5a6; border: 1px solid transparent; border-radius: 8px; padding: 8px 11px; }
    .nav-on { background: #1f2b21; color: #e8f3df; border-color: #38533a; }
    .panel { margin: 0 0 18px; }
    .panel-head { margin-bottom: 12px; }
    .panel-head.split { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
    .steps { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 0 0 14px; }
    .step { display: flex; gap: 10px; align-items: flex-start; border: 1px solid #2a2e22; border-radius: 8px; padding: 10px; background: #151711; }
    .step.done { border-color: #3d5c3f; background: #172018; }
    .step-no { display: inline-grid; place-items: center; flex: 0 0 auto; width: 22px; height: 22px; border-radius: 999px; background: #2f6f3e; color: #eaffea; font-weight: 700; font-size: 12px; }
    .two-col { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .box, .status-card { background: #171912; border: 1px solid #2a2e22; border-radius: 8px; padding: 14px; }
    .seg { display: inline-flex; gap: 4px; background: #11140f; border: 1px solid #292d24; border-radius: 8px; padding: 3px; margin-bottom: 12px; }
    .seg-btn { background: transparent; color: #aeb5a6; padding: 6px 10px; }
    .seg-on { background: #2a3b2b; color: #e8f3df; }
    .field { display: grid; gap: 5px; margin-bottom: 10px; color: #aeb5a6; font-size: 12px; }
    input.url, .field input { width: 100%; box-sizing: border-box; background: #0e100d; border: 1px solid #30362b; color: #eceee8; border-radius: 8px; padding: 9px 10px; font: inherit; }
    .primary, .ghost { font-weight: 600; }
    .primary { background: #2f6f3e; color: #eaffea; }
    .ghost { background: #20241d; color: #d9ddd2; border: 1px solid #343b30; }
    .danger-link { color: #ffd7d7; margin-top: 8px; }
    .hint { color: #9aa0ad; font-size: 12px; margin-top: 8px; }
    .pair-code { margin-top: 12px; background: #11140f; border: 1px dashed #566347; border-radius: 8px; padding: 12px; }
    .code { color: #e8f3df; font-size: 28px; font-weight: 800; letter-spacing: 0; margin: 4px 0; }
    .ok-note { background: #162318; border: 1px solid #36583a; color: #cdefd0; border-radius: 8px; padding: 9px 12px; font-size: 12px; margin-top: 12px; }
    .child-row { display: flex; justify-content: space-between; align-items: center; gap: 12px; border: 1px solid #2a2e22; border-radius: 8px; padding: 12px; margin-bottom: 8px; background: #151711; }
    .server-list { display: grid; gap: 8px; margin-bottom: 12px; }
    .server-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; border: 1px solid #2a2e22; border-radius: 8px; padding: 12px; background: #151711; }
    .server-active { border-color: #3d5c3f; background: #172018; }
    .server-main { display: flex; align-items: flex-start; gap: 10px; flex: 1; min-width: 0; margin: 0; }
    .server-main input { margin-top: 3px; flex: 0 0 auto; }
    .server-badges { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
    .badge { display: inline-flex; align-items: center; border: 1px solid #343b30; color: #aeb5a6; border-radius: 999px; padding: 2px 8px; font-size: 11px; }
    .badge-ok { border-color: #36583a; color: #cdefd0; background: #162318; }
    .badge-warn { border-color: #4a3f17; color: #e8d9a0; background: #2a2410; }
    .add-server { margin-top: 12px; }
    .small-btn { padding: 5px 10px; font-size: 12px; flex: 0 0 auto; }
    .banner { background: #2a2410; border: 1px solid #4a3f17; color: #e8d9a0; border-radius: 8px; padding: 8px 12px; font-size: 12px; margin-bottom: 14px; }
    .err { background: #3a1c1c; border: 1px solid #5a2a2a; color: #ffd7d7; border-radius: 8px; padding: 8px 12px; font-size: 12px; margin-bottom: 14px; }
    .card { background: #171912; border: 1px solid #2a2e22; border-radius: 8px; padding: 14px; margin-bottom: 10px; }
    .ttl { font-weight: 600; }
    .meta { color: #8b91a0; font-size: 12px; margin: 2px 0 8px; }
    .detail { margin: 0 0 10px; font-size: 14px; }
    .preview { margin: 0 0 10px; }
    .preview-label { color: #8b91a0; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; margin-bottom: 5px; }
    .thumb { display: block; max-width: 320px; width: 100%; height: auto; border-radius: 8px; border: 1px solid #232733; }
    .snippet { background: #12151c; border: 1px solid #232733; border-left: 3px solid #6f5a2f; border-radius: 8px; padding: 8px 12px; margin: 0 0 10px; }
    .snippet-label { color: #8b91a0; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; margin-bottom: 4px; }
    .snippet-text { margin: 0; font-size: 14px; white-space: pre-wrap; word-break: break-word; color: #e6e8ee; }
    .csam { background: #2a1414; border: 1px solid #5a2a2a; color: #ffd7d7; border-radius: 8px; padding: 10px 12px; font-size: 13px; margin: 0 0 10px; }
    .row { display: flex; gap: 8px; }
    button { border: 0; border-radius: 8px; padding: 7px 14px; font-size: 13px; cursor: pointer; }
    .approve { background: #2f6f3e; color: #eaffea; }
    .deny { background: #6f2f2f; color: #ffeaea; }
    .empty { color: #8b91a0; }
    table.cov { width: 100%; border-collapse: collapse; font-size: 13px; }
    .cov th, .cov td { text-align: left; padding: 8px; border-bottom: 1px solid #232733; }
    .cov .how { color: #9aa0ad; }
    .protect { background: #141821; border: 1px solid #232733; border-radius: 12px; padding: 16px; margin: 0 0 18px; }
    .protect-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .protect-state { font-weight: 600; font-size: 15px; }
    .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; vertical-align: middle; }
    .dot-on { background: #36c75f; box-shadow: 0 0 8px #36c75f88; }
    .dot-off { background: #5a606e; }
    .connect { background: #2f6f3e; color: #eaffea; font-weight: 600; padding: 9px 20px; }
    .disconnect { background: #6f2f2f; color: #ffeaea; font-weight: 600; padding: 9px 20px; }
    button:disabled { opacity: .6; cursor: default; }
    .protect-grid { margin-top: 14px; display: grid; grid-template-columns: 1fr; gap: 6px; }
    .pg-row { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; padding: 4px 0; border-bottom: 1px solid #1c212b; }
    .pg-k { color: #8b91a0; }
    .pg-v { text-align: right; word-break: break-all; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    .ok { color: #6fe39a; }
    .off { color: #9aa0ad; }
    .mode-sel { display: flex; gap: 8px; margin-top: 14px; }
    .mode-opt { background: #12151c; color: #c8ccd6; border: 1px solid #232733; font-weight: 500; padding: 7px 14px; }
    .mode-on { background: #1f2a3a; color: #dce7ff; border-color: #3a5170; box-shadow: 0 0 0 1px #3a5170; }
    .mode-explain { margin-top: 8px; color: #9aa0ad; font-size: 12px; }
    .player { margin: 0 0 10px; }
    .player .vid { display: block; max-width: 360px; width: 100%; height: auto; border-radius: 8px; border: 1px solid #232733; background: #000; }
    .player .seg-note { color: #8b91a0; font-size: 12px; padding: 8px 0; }
    .ca-hint { margin-top: 12px; background: #12151c; border: 1px solid #232733; border-radius: 8px; padding: 10px 12px; font-size: 12px; color: #c8ccd6; }
    .ca-cmd { margin-top: 6px; padding: 8px; background: #0c0e13; border-radius: 6px; word-break: break-all; user-select: all; }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use aegis_proto::v1::review_server::{Review, ReviewServer};
    use aegis_proto::v1::{
        Evidence, PushAck, PushTarget, ReviewAck, SegmentChunk, SegmentRequest, Severity,
    };
    use futures_util::Stream;
    use tokio::net::TcpListener;
    use tonic::transport::{Endpoint, Server};
    use tonic::{Request, Response, Status};

    type AlertStream = Pin<Box<dyn Stream<Item = Result<AlertEvent, Status>> + Send + 'static>>;
    type SegmentStream = Pin<Box<dyn Stream<Item = Result<SegmentChunk, Status>> + Send + 'static>>;

    #[derive(Clone, Debug)]
    struct CapturedDecision {
        auth: Option<String>,
        request: ReviewRequest,
    }

    #[derive(Clone, Debug)]
    struct CapturedFilter {
        auth: Option<String>,
        filter: DeviceFilter,
    }

    #[derive(Clone)]
    struct FakeReview {
        events: Arc<Vec<AlertEvent>>,
        decisions: Arc<Mutex<Vec<CapturedDecision>>>,
        filters: Arc<Mutex<Vec<CapturedFilter>>>,
        ack_applied: bool,
    }

    impl FakeReview {
        fn with_events(events: Vec<AlertEvent>) -> Self {
            Self {
                events: Arc::new(events),
                decisions: Arc::new(Mutex::new(Vec::new())),
                filters: Arc::new(Mutex::new(Vec::new())),
                ack_applied: true,
            }
        }

        fn with_unapplied_ack() -> Self {
            Self {
                ack_applied: false,
                ..Self::with_events(Vec::new())
            }
        }
    }

    #[tonic::async_trait]
    impl Review for FakeReview {
        async fn submit_decision(
            &self,
            req: Request<ReviewRequest>,
        ) -> Result<Response<ReviewAck>, Status> {
            let auth = auth_header(&req);
            let request = req.into_inner();
            self.decisions
                .lock()
                .expect("decisions lock")
                .push(CapturedDecision {
                    auth,
                    request: request.clone(),
                });
            Ok(Response::new(ReviewAck {
                alert_id: request.alert_id,
                applied: self.ack_applied,
            }))
        }

        async fn register_push_target(
            &self,
            _req: Request<PushTarget>,
        ) -> Result<Response<PushAck>, Status> {
            Ok(Response::new(PushAck { ok: true }))
        }

        type StreamPendingReviewsStream = AlertStream;

        async fn stream_pending_reviews(
            &self,
            req: Request<DeviceFilter>,
        ) -> Result<Response<Self::StreamPendingReviewsStream>, Status> {
            let auth = auth_header(&req);
            let filter = req.into_inner();
            self.filters
                .lock()
                .expect("filters lock")
                .push(CapturedFilter { auth, filter });
            let events = self.events.as_ref().clone();
            Ok(Response::new(Box::pin(futures_util::stream::iter(
                events.into_iter().map(Ok),
            ))))
        }

        type FetchSegmentStream = SegmentStream;

        async fn fetch_segment(
            &self,
            _req: Request<SegmentRequest>,
        ) -> Result<Response<Self::FetchSegmentStream>, Status> {
            Ok(Response::new(Box::pin(futures_util::stream::iter([Ok(
                SegmentChunk {
                    data: b"fake clip".to_vec(),
                },
            )]))))
        }
    }

    struct TestReviewServer {
        endpoint: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl TestReviewServer {
        async fn spawn(review: FakeReview) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake review server");
            let addr = listener.local_addr().expect("fake review addr");
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let task = tokio::spawn(async move {
                Server::builder()
                    .add_service(ReviewServer::new(review))
                    .serve_with_incoming(incoming)
                    .await
                    .expect("fake review server serves");
            });
            Self {
                endpoint: format!("http://{addr}"),
                task,
            }
        }
    }

    impl Drop for TestReviewServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[test]
    fn server_choice_resolves_regions_and_self_hosted() {
        assert!(resolve_endpoint("").contains("eu-west-2"));
        assert!(resolve_endpoint("cloud").contains("eu-west-2"));
        assert!(resolve_endpoint("unknown").contains("eu-west-2"));
        assert_eq!(resolve_endpoint("us"), "https://us.cloud.phbulwark.app");
        assert_eq!(
            resolve_endpoint("https://family.example.test:8443"),
            "https://family.example.test:8443"
        );

        assert_eq!(
            server_settings_initial_state(""),
            ("uk".to_string(), String::new())
        );
        assert_eq!(
            server_settings_initial_state("https://family.example.test:8443"),
            (
                "selfhosted".to_string(),
                "https://family.example.test:8443".to_string()
            )
        );
    }

    #[test]
    fn server_inventory_merges_builtins_custom_and_legacy_url() {
        let custom = SavedServer::new("self-home", "Home server", "https://home.example.test:8443");
        let rows =
            server_inventory_for_choice("https://legacy.example.test:8443", vec![custom.clone()]);

        assert!(rows.iter().any(|s| s.id == "uk" && s.builtin));
        assert!(rows.iter().any(|s| s.id == "us" && s.builtin));
        assert!(rows.iter().any(|s| s == &custom));
        assert!(rows.iter().any(|s| {
            s.endpoint == "https://legacy.example.test:8443" && s.label == "Self-hosted"
        }));
    }

    #[test]
    fn custom_server_inventory_normalizes_invalid_and_duplicates() {
        let rows = normalize_custom_servers(vec![
            SavedServer::new("self-a", "A", "https://a.example.test:8443"),
            SavedServer::new("self-a", "Duplicate id", "https://b.example.test:8443"),
            SavedServer::new(
                "self-c",
                "Duplicate endpoint",
                "https://a.example.test:8443",
            ),
            SavedServer::new("bad", "Bad", "ftp://bad.example.test"),
            SavedServer::new("", "Empty", "https://empty.example.test"),
        ]);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "self-a");
        assert_eq!(rows[0].label, "A");
        assert!(!rows[0].builtin);
    }

    #[test]
    fn custom_server_choice_resolves_by_id() {
        let server = SavedServer::new("self-home", "Home server", "https://home.example.test:8443");
        let rows = server_inventory_for_choice("", vec![server.clone()]);
        assert_eq!(server_for_choice_from("self-home", &rows), server);
        assert_eq!(
            custom_server_id(" https://home.example.test:8443 "),
            custom_server_id("https://home.example.test:8443")
        );
    }

    #[test]
    fn server_session_keys_are_endpoint_scoped() {
        let london = server_session_key("http://london.example:8443");
        let us = server_session_key("http://us.example:8443");
        let london_again = server_session_key(" http://london.example:8443 ");

        assert_eq!(london, london_again);
        assert_ne!(london, us);
        assert_eq!(london.len(), 16);
        assert!(london.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn pair_expiry_text_is_human_readable() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        assert!(pair_expiry_text(now + 30_000).contains("expires in"));
        assert_eq!(pair_expiry_text(0), "unknown expiry");
    }

    #[test]
    fn offline_seed_is_fake_safe_and_non_actionable() {
        let rows = seed();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|a| !a.actionable));
        assert!(rows.iter().all(|a| a.thumbnail.is_empty()));
        assert!(rows.iter().all(|a| a.segment_uri.is_none()));
        assert!(rows.iter().any(|a| a.id == "a-1001"));
        assert!(rows.iter().any(|a| a.title.contains("Possible grooming")));
    }

    #[test]
    fn fake_alert_mapping_shows_allowed_evidence_but_never_csam() {
        let adult = Alert::from_event(fake_alert(
            "fake-adult",
            "kids-tablet",
            Category::AdultImage,
            tiny_png(),
            "blocked text snippet",
        ));
        assert_eq!(adult.title, "Blocked an adult image");
        assert!(should_show_thumbnail(&adult));
        assert!(should_show_snippet(&adult));

        let csam = Alert::from_event(fake_alert(
            "fake-csam",
            "kids-tablet",
            Category::CsamSuspected,
            tiny_png(),
            "must not render",
        ));
        assert_eq!(csam.title, "Blocked suspected illegal content");
        assert!(!can_show_evidence(csam.category));
        assert!(!should_show_thumbnail(&csam));
        assert!(!should_show_snippet(&csam));
    }

    #[test]
    fn decision_request_and_bearer_metadata_are_stable() {
        let req = review_request_at("alert-1", "device-1", true, 123);
        assert_eq!(req.alert_id, "alert-1");
        assert_eq!(req.device_id, "device-1");
        assert_eq!(req.decision, ReviewDecision::Approve as i32);
        assert_eq!(req.scope, ReviewScope::ThisHost as i32);
        assert_eq!(req.ts, 123);

        let request = request_with_bearer(req, " token-123 ");
        assert_eq!(
            request
                .metadata()
                .get("authorization")
                .expect("authorization metadata")
                .to_str()
                .expect("metadata string"),
            "Bearer token-123"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parent_opens_live_stream_and_maps_fake_alert() {
        let fake = FakeReview::with_events(vec![fake_alert(
            "stream-alert-1",
            "kids-phone",
            Category::Grooming,
            Vec::new(),
            "move this chat elsewhere",
        )]);
        let server = TestReviewServer::spawn(fake.clone()).await;
        wait_for_server(&server.endpoint).await;

        let mut stream = open_pending_review_stream_from(&server.endpoint, "guardian-token")
            .await
            .expect("open fake review stream");
        let event = stream
            .message()
            .await
            .expect("stream message result")
            .expect("one fake alert");
        let alert = Alert::from_event(event);
        assert_eq!(alert.id, "stream-alert-1");
        assert_eq!(alert.device, "kids-phone");
        assert_eq!(alert.title, "Possible grooming detected");
        assert!(should_show_snippet(&alert));

        let filters = fake.filters.lock().expect("filters lock");
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].filter.token, "guardian-token");
        assert!(filters[0].auth.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parent_submit_decision_hits_fake_review_with_bearer_token() {
        let fake = FakeReview::with_events(Vec::new());
        let server = TestReviewServer::spawn(fake.clone()).await;
        wait_for_server(&server.endpoint).await;

        submit_decision_to(
            &server.endpoint,
            "guardian-token",
            "decision-alert-1",
            "kids-device",
            true,
        )
        .await
        .expect("submit fake decision");

        let decisions = fake.decisions.lock().expect("decisions lock");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].auth.as_deref(), Some("Bearer guardian-token"));
        assert_eq!(decisions[0].request.alert_id, "decision-alert-1");
        assert_eq!(decisions[0].request.device_id, "kids-device");
        assert_eq!(
            decisions[0].request.decision,
            ReviewDecision::Approve as i32
        );
        assert!(decisions[0].request.ts > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parent_submit_decision_surfaces_unapplied_ack() {
        let fake = FakeReview::with_unapplied_ack();
        let server = TestReviewServer::spawn(fake).await;
        wait_for_server(&server.endpoint).await;

        let err = submit_decision_to(
            &server.endpoint,
            "guardian-token",
            "decision-alert-2",
            "kids-device",
            false,
        )
        .await
        .expect_err("unapplied ack should surface as an error");
        assert!(err.to_string().contains("did not apply"));
    }

    fn fake_alert(
        alert_id: &str,
        device_id: &str,
        category: Category,
        thumbnail: Vec<u8>,
        snippet: &str,
    ) -> AlertEvent {
        AlertEvent {
            alert_id: alert_id.to_string(),
            kind: if category == Category::Grooming {
                AlertKind::GroomingSuspected
            } else {
                AlertKind::Intervention
            } as i32,
            category: category as i32,
            severity: Severity::High as i32,
            app: "fake-chat".to_string(),
            device_id: device_id.to_string(),
            child_id: "child-1".to_string(),
            ts: 1_700_000_000_000,
            redacted_context: "Fake alert for parent e2e.".to_string(),
            evidence: Some(Evidence {
                sha256: vec![1, 2, 3, 4],
                perceptual_hash: Vec::new(),
                safe_thumbnail: thumbnail,
                text_snippet: snippet.to_string(),
                model_id: "fake-model".to_string(),
                model_version: "0".to_string(),
            }),
            ..Default::default()
        }
    }

    fn tiny_png() -> Vec<u8> {
        vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
    }

    fn auth_header<T>(req: &Request<T>) -> Option<String> {
        req.metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    async fn wait_for_server(endpoint: &str) {
        let ep = Endpoint::from_shared(endpoint.to_string())
            .expect("valid endpoint")
            .connect_timeout(Duration::from_millis(500));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match ep.connect().await {
                Ok(_) => return,
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        panic!("fake review server never came up at {endpoint}: {e}");
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}
