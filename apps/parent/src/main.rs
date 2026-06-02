//! Aegis parent console — all-Rust Dioxus UI.
//!
//! LEGITIMATE features only: review guardian alerts, **approve / keep-blocked**
//! flagged items, and see the honest coverage matrix. It talks to the home
//! cluster over the SAME gRPC contract the engine serves (`Review` carries the
//! redacted pending-review stream and the approve/deny decision). There is
//! deliberately **no** device-control / screen / location / remote-command
//! surface here — Aegis is a transparent content-safety tool, not a
//! remote-administration console.
//!
//! PRIVACY INVARIANT: this UI NEVER requests or renders raw media. It only ever
//! reads the redacted fields of an `AlertEvent` (kind/category/app/device and
//! the `redacted_context` summary). The safe-thumbnail / hash `Evidence` is not
//! fetched or shown here.
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

/// A guardian-facing alert row (the redacted view; never carries media).
#[derive(Clone, PartialEq)]
struct Alert {
    id: String,
    title: String,
    detail: String,
    device: String,
    when: String,
    /// Whether approve / keep-blocked is offered (intervention & grooming items).
    actionable: bool,
}

impl Alert {
    /// Map a redacted proto [`AlertEvent`] into a UI row. Reads ONLY the safe,
    /// redacted fields — no `Evidence` bytes / thumbnail are touched here.
    fn from_event(ev: AlertEvent) -> Self {
        let kind = ev.kind();
        let category = ev.category();

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
            detail: "On a web page (blurred preview available in-app).".into(),
            device: "Kids tablet".into(),
            when: "2m ago".into(),
            actionable: true,
        },
        Alert {
            id: "a-1002".into(),
            title: "Possible grooming detected".into(),
            detail: "Secrecy + \u{201c}move to another app\u{201d} patterns in a chat.".into(),
            device: "Kids phone".into(),
            when: "18m ago".into(),
            actionable: true,
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
    rsx! {
        div { class: "card",
            div { class: "ttl", "{alert.title}" }
            div { class: "meta", "{alert.device} \u{00b7} {alert.when}" }
            p { class: "detail", "{alert.detail}" }
            if alert.actionable {
                div { class: "row",
                    button { class: "approve", onclick: move |_| on_decide.call(true), "Approve" }
                    button { class: "deny", onclick: move |_| on_decide.call(false), "Keep blocked" }
                }
            }
        }
    }
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
    .row { display: flex; gap: 8px; }
    button { border: 0; border-radius: 8px; padding: 7px 14px; font-size: 13px; cursor: pointer; }
    .approve { background: #2f6f3e; color: #eaffea; }
    .deny { background: #6f2f2f; color: #ffeaea; }
    .empty { color: #8b91a0; }
    table.cov { width: 100%; border-collapse: collapse; font-size: 13px; }
    .cov th, .cov td { text-align: left; padding: 8px; border-bottom: 1px solid #232733; }
    .cov .how { color: #9aa0ad; }
"#;
