//! Predator Hunters HQ — the guardian console (all-Rust Dioxus UI). "aegis" is
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

use aegis_proto::v1::review_client::ReviewClient;
use aegis_proto::v1::{
    AlertEvent, AlertKind, Category, DeviceFilter, ReviewDecision, ReviewRequest, ReviewScope,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

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

/// Prebuilt proxy binary (preferred). If absent we fall back to `cargo run`.
const PROXY_EXE: &str = r"C:\Users\Jordan\child-safety\target\debug\aegis_proxy.exe";
/// Repo root — cwd for the `cargo run` fallback.
const REPO_ROOT: &str = r"C:\Users\Jordan\child-safety";
/// NSFW model handed to the proxy via `AEGIS_NSFW_MODEL`.
const NSFW_MODEL: &str = r"C:\Users\Jordan\child-safety\models\nsfw.onnx";
/// Cluster endpoint handed to the proxy via `AEGIS_CLUSTER_ENDPOINT`.
const PROXY_CLUSTER_ENDPOINT: &str = "http://127.0.0.1:8443";
/// Prebuilt transparent-VPN binary. VPN mode captures ALL traffic via a TUN and
/// needs Administrator; `aegis_vpn` self-checks elevation and exits immediately
/// if not elevated. Unlike proxy mode it does NOT touch the system proxy.
const VPN_EXE: &str = r"C:\Users\Jordan\child-safety\target\debug\aegis_vpn.exe";

// ---------------------------------------------------------------------------
// Connection layer
// ---------------------------------------------------------------------------

/// Cluster endpoint, from `AEGIS_CLUSTER_ENDPOINT` (default dev gateway).
fn cluster_endpoint() -> String {
    std::env::var("AEGIS_CLUSTER_ENDPOINT").unwrap_or_else(|_| "https://127.0.0.1:8443".to_string())
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
    let mut builder = Endpoint::from_shared(endpoint.clone())?;

    if let Ok(ca_path) = std::env::var("AEGIS_CLUSTER_CA") {
        if !ca_path.is_empty() {
            let ca_pem = std::fs::read(&ca_path)?;
            let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca_pem));
            builder = builder.tls_config(tls)?;
        }
    }

    Ok(builder.connect().await?)
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
            actionable: true,
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
            actionable: true,
            category: Category::Grooming,
            thumbnail: Vec::new(),
            snippet:
                "hey don\u{2019}t tell your mum about this, let\u{2019}s talk on the other app"
                    .into(),
            segment_uri: None,
        },
    ]
}

#[component]
fn App() -> Element {
    // Start with the OFFLINE sample so the console is never blank; the live
    // stream replaces it on first connect.
    let mut alerts = use_signal(seed);
    // Banner shown while we're on sample data (no live cluster connection yet).
    let mut offline = use_signal(|| true);
    // Inline, transient error surfaced by a failed approve/deny RPC.
    let action_error = use_signal(|| Option::<String>::None);

    // Live feed: connect to the family's own cluster over the shared gRPC
    // contract and stream redacted pending reviews into `alerts`. On any failure
    // we keep the seed() sample and leave the offline banner up — never crash.
    //
    // The desktop feature provides a tokio runtime, so tonic async runs here.
    use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
        let channel = match connect_channel().await {
            Ok(ch) => ch,
            Err(_e) => {
                // Stay offline with sample data.
                return;
            }
        };

        let mut client = ReviewClient::new(channel);

        // A guardian session token (from Accounts.Login) scopes the stream to this
        // guardian's children and is REQUIRED by an accounts-wired server. The
        // desktop console has no login UI yet, so we read a pre-obtained token from
        // AEGIS_GUARDIAN_TOKEN; empty = legacy (no-accounts) server. (Login UI TODO.)
        let filter = DeviceFilter {
            device_id: String::new(),
            token: std::env::var("AEGIS_GUARDIAN_TOKEN").unwrap_or_default(),
        };

        let mut stream = match client.stream_pending_reviews(filter).await {
            Ok(resp) => resp.into_inner(),
            Err(_status) => return,
        };

        // First successful item flips us out of OFFLINE mode and clears the
        // sample rows so we only ever show real, redacted alerts.
        let mut went_live = false;

        // A `None`/`Err` (stream ended cleanly or errored) ends the loop; we keep
        // what we already showed and never crash or clear the list.
        while let Ok(Some(event)) = stream.message().await {
            if !went_live {
                went_live = true;
                offline.set(false);
                alerts.write().clear();
            }
            let alert = Alert::from_event(event);
            let mut list = alerts.write();
            // Dedupe by alert_id (idempotency key) across retries.
            if !list.iter().any(|a| a.id == alert.id) {
                list.insert(0, alert);
            }
        }
    });

    rsx! {
        style { {CSS} }
        div { class: "wrap",
            h1 { "Predator Hunters HQ" }
            p { class: "sub",
                "Transparent content-safety: alerts, approve/deny, and an honest coverage view. "
                "No device control, screen capture, or hidden monitoring."
            }

            ProtectionPanel {}

            if offline() {
                div { class: "banner", "Offline — showing sample data. Not connected to your home cluster." }
            }

            if let Some(err) = action_error() {
                div { class: "err", "Couldn't send your decision: {err}" }
            }

            section {
                h2 { "Recent alerts" }
                if alerts.read().is_empty() {
                    p { class: "empty", "All clear — no alerts right now." }
                }
                for a in alerts.read().clone().into_iter() {
                    AlertCard {
                        key: "{a.id}",
                        alert: a.clone(),
                        // Pre-clone (inside a block) the fields the callback needs so
                        // the `move` closure captures THOSE, not `a` — the release
                        // rsx expansion otherwise moves `a` while key/alert still use
                        // it (compiles in debug via hot-reload, fails E0382 in release).
                        on_decide: {
                            let cb_id = a.id.clone();
                            let cb_device = a.device.clone();
                            move |approve: bool| {
                                let id = cb_id.clone();
                                let device = cb_device.clone();
                                let mut alerts = alerts;
                                let mut action_error = action_error;

                                // Optimistically clear the row, then send the real
                                // ReviewRequest (APPROVE/DENY) to the cluster. A
                                // failed RPC restores the row and shows an inline
                                // error — never a panic.
                                let removed: Option<Alert> = {
                                    let mut list = alerts.write();
                                    let idx = list.iter().position(|x| x.id == id);
                                    idx.map(|i| list.remove(i))
                                };
                                action_error.set(None);

                                spawn(async move {
                                    if let Err(e) = submit_decision(&id, &device, approve).await {
                                        // Restore the optimistically-removed row.
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

            section {
                h2 { "Coverage (honest)" }
                CoverageMatrix {}
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
    let mut client = ReviewClient::new(channel);

    let decision = if approve {
        ReviewDecision::Approve
    } else {
        ReviewDecision::Deny
    };

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let req = ReviewRequest {
        alert_id: alert_id.to_string(),
        decision: decision as i32,
        device_id: device_id.to_string(),
        scope: ReviewScope::ThisHost as i32,
        ts,
    };

    // In accounts mode the server requires a guardian session token on the
    // decision RPC (it scopes the approve/deny to the guardian's assigned
    // children). Attach the SAME `AEGIS_GUARDIAN_TOKEN` the alert stream uses, as
    // `authorization: Bearer <token>` metadata. A single-home / no-accounts
    // server ignores it, so an unset token still works there.
    let mut request = tonic::Request::new(req);
    if let Some(token) = std::env::var("AEGIS_GUARDIAN_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
    {
        if let Ok(val) = tonic::metadata::MetadataValue::try_from(format!("Bearer {token}")) {
            request.metadata_mut().insert("authorization", val);
        }
    }

    let ack = client.submit_decision(request).await?.into_inner();
    if !ack.applied {
        anyhow::bail!("the cluster did not apply the decision");
    }
    Ok(())
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
fn spawn_proxy() -> std::io::Result<Child> {
    use std::process::Command;
    if std::path::Path::new(PROXY_EXE).exists() {
        Command::new(PROXY_EXE)
            .env("AEGIS_NSFW_MODEL", NSFW_MODEL)
            .env("AEGIS_CLUSTER_ENDPOINT", PROXY_CLUSTER_ENDPOINT)
            .spawn()
    } else {
        // Dev fallback: build+run from source. cwd = repo root so cargo finds
        // the workspace.
        Command::new("cargo")
            .args([
                "run",
                "-p",
                "aegis-client",
                "--features",
                "onnx",
                "--bin",
                "aegis_proxy",
            ])
            .current_dir(REPO_ROOT)
            .env("AEGIS_NSFW_MODEL", NSFW_MODEL)
            .env("AEGIS_CLUSTER_ENDPOINT", PROXY_CLUSTER_ENDPOINT)
            .spawn()
    }
}

/// Spawn the transparent-VPN binary (`aegis_vpn.exe`). Like [`spawn_proxy`] it
/// passes the model + cluster endpoint, but VPN mode needs Administrator and does
/// NOT touch the system proxy (the TUN captures everything). `aegis_vpn`
/// self-checks elevation and exits immediately if not elevated — the Connect
/// handler detects that fast exit and surfaces a "run as Administrator" hint.
fn spawn_vpn() -> std::io::Result<Child> {
    use std::process::Command;
    if std::path::Path::new(VPN_EXE).exists() {
        Command::new(VPN_EXE)
            .env("AEGIS_NSFW_MODEL", NSFW_MODEL)
            .env("AEGIS_CLUSTER_ENDPOINT", PROXY_CLUSTER_ENDPOINT)
            .spawn()
    } else {
        // Dev fallback: build+run from source (will need an elevated shell).
        Command::new("cargo")
            .args([
                "run",
                "-p",
                "aegis-client",
                "--features",
                "onnx",
                "--bin",
                "aegis_vpn",
            ])
            .current_dir(REPO_ROOT)
            .env("AEGIS_NSFW_MODEL", NSFW_MODEL)
            .env("AEGIS_CLUSTER_ENDPOINT", PROXY_CLUSTER_ENDPOINT)
            .spawn()
    }
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
            Mode::Vpn => "Captures ALL traffic system-wide through a TUN adapter — no proxy settings. Needs PH Bulwark run as Administrator.",
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
                                                "VPN mode needs PH Bulwark run as Administrator. \
                                                 Re-launch as admin, then Connect again."
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
                    span { class: "pg-v mono", "{NSFW_MODEL}" }
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

#[component]
fn AlertCard(alert: Alert, on_decide: EventHandler<bool>) -> Element {
    // THE CSAM EXCEPTION. Suspected CSAM is illegal to view, so this UI shows
    // NEITHER the image NOR the text snippet, regardless of what the event
    // carried. Everything else (intervention blocks, grooming) shows the
    // guardian the real flagged content for an informed decision.
    let is_csam = alert.category == Category::CsamSuspected;

    // Build the inline image data URI only for non-CSAM items that actually
    // carried preview bytes. `image_data_uri` sniffs the format and base64s it.
    let preview_uri: Option<String> = if !is_csam && !alert.thumbnail.is_empty() {
        Some(image_data_uri(&alert.thumbnail))
    } else {
        None
    };

    // The actual flagged text — shown in full to the guardian, except for CSAM.
    let show_snippet = !is_csam && !alert.snippet.is_empty();

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

/// Plays a locally-stored video segment for guardian review. The `blob://<sha>`
/// URI resolves to the per-user segment store on disk (`%LOCALAPPDATA%/Aegis/
/// segments/<sha>.blob`, written by `aegis-video::SegmentStore`). Bytes are read
/// once and shown via a data URI in the desktop webview's `<video>`. The caller
/// only mounts this for NON-CSAM alerts (CSAM is never stored, so the file would
/// not exist anyway — defence in depth).
#[component]
fn SegmentPlayer(uri: String) -> Element {
    let mut data_uri = use_signal(|| Option::<String>::None);
    let mut load_err = use_signal(|| Option::<String>::None);

    use_effect(move || {
        let uri = uri.clone();
        spawn(async move {
            match load_segment_from_disk(&uri) {
                Ok(Some(bytes)) => {
                    // Sniff the container — stored clips may be MP4/fMP4, DASH .m4s,
                    // HLS .ts, or WebM; a hard-coded MP4 MIME breaks playback when
                    // the bytes are something else.
                    let mime = sniff_video_mime(&bytes);
                    data_uri.set(Some(format!("data:{};base64,{}", mime, base64_encode(&bytes))));
                }
                Ok(None) => load_err.set(Some(
                    "not found (expired, purged, or never stored)".to_string(),
                )),
                Err(e) => load_err.set(Some(e)),
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
    body { margin: 0; font-family: system-ui, sans-serif; background: #0f1115; color: #e6e8ee; }
    .wrap { max-width: 760px; margin: 0 auto; padding: 24px; }
    h1 { font-size: 22px; margin: 0 0 4px; }
    .sub { color: #9aa0ad; margin: 0 0 20px; font-size: 13px; }
    h2 { font-size: 15px; margin: 24px 0 10px; color: #c8ccd6; }
    .banner { background: #2a2410; border: 1px solid #4a3f17; color: #e8d9a0; border-radius: 8px; padding: 8px 12px; font-size: 12px; margin-bottom: 14px; }
    .err { background: #3a1c1c; border: 1px solid #5a2a2a; color: #ffd7d7; border-radius: 8px; padding: 8px 12px; font-size: 12px; margin-bottom: 14px; }
    .card { background: #171a21; border: 1px solid #232733; border-radius: 10px; padding: 14px; margin-bottom: 10px; }
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
