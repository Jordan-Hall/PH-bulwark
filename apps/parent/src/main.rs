//! Aegis parent console — all-Rust Dioxus UI.
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
            snippet: "hey don\u{2019}t tell your mum about this, let\u{2019}s talk on the other app".into(),
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

        // Empty device_id == all supervised devices for this guardian.
        let filter = DeviceFilter {
            device_id: String::new(),
        };

        let mut stream = match client.stream_pending_reviews(filter).await {
            Ok(resp) => resp.into_inner(),
            Err(_status) => return,
        };

        // First successful item flips us out of OFFLINE mode and clears the
        // sample rows so we only ever show real, redacted alerts.
        let mut went_live = false;

        loop {
            match stream.message().await {
                Ok(Some(event)) => {
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
                // Stream ended cleanly or errored — stop consuming; keep what we
                // already showed. We do not crash or clear the list.
                Ok(None) | Err(_) => break,
            }
        }
    });

    rsx! {
        style { {CSS} }
        div { class: "wrap",
            h1 { "Aegis — Parent Console" }
            p { class: "sub",
                "Transparent content-safety: alerts, approve/deny, and an honest coverage view. "
                "No device control, screen capture, or hidden monitoring."
            }

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
                        on_decide: move |approve: bool| {
                            let id = a.id.clone();
                            let device = a.device.clone();
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

    let ack = client.submit_decision(req).await?.into_inner();
    if !ack.applied {
        anyhow::bail!("the cluster did not apply the decision");
    }
    Ok(())
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

/// Minimal standard-alphabet base64 encoder (RFC 4648, with `=` padding).
/// Hand-rolled so the console needs no extra dependency for the data URI.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
        ("Web (browsers)", "Filtered", "HTTPS decrypted via the per-install CA"),
        ("Video / live streams", "Filtered", "Buffered, sampled, block/blur/mute"),
        ("WhatsApp / Signal / Messenger (E2E)", "On-device only", "Network can't read; on-device text check"),
        ("iPhone / iPad", "Content filter only", "Apple forbids message/screen access to apps"),
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
"#;
