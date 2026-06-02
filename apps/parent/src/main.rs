//! Aegis parent console — all-Rust Dioxus UI.
//!
//! LEGITIMATE features only: review guardian alerts, **approve / keep-blocked**
//! flagged items, and see the honest coverage matrix. It talks to the home
//! cluster over the SAME gRPC contract the engine serves (`AlertRelay` for
//! alerts, `Review` for approve/deny). There is deliberately **no** device-
//! control / screen / location / remote-command surface here — Aegis is a
//! transparent content-safety tool, not a remote-administration console.
//!
//! Dioxus `desktop` feature covers Windows + macOS. The same RSX drives the
//! `mobile` (Android/iOS, experimental) and `web` targets, and bumps cleanly to
//! the 0.7/0.8 native Blitz renderer (no webview) when it ships.

use dioxus::prelude::*;

fn main() {
    dioxus::launch(App);
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

/// Seed data stands in until the gRPC client is connected (see INTEGRATION note
/// in `App`). These mirror what `AlertRelay`/`Review` will stream from the cluster.
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
    let mut alerts = use_signal(seed);

    // INTEGRATION: replace `seed()` with a live feed —
    //   let client = aegis_proto::v1::alert_relay_client::AlertRelayClient::connect(endpoint).await?;
    //   ...stream AlertEvents into the signal; approve/deny calls
    //   aegis_proto::v1::review_client::ReviewClient::submit_decision(ReviewRequest{..}).
    // All over mTLS to the family's own cluster.

    rsx! {
        style { {CSS} }
        div { class: "wrap",
            h1 { "Aegis — Parent Console" }
            p { class: "sub",
                "Transparent content-safety: alerts, approve/deny, and an honest coverage view. "
                "No device control, screen capture, or hidden monitoring."
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
                        on_decide: move |_approve: bool| {
                            let id = a.id.clone();
                            // Optimistically clear from the list; the real handler
                            // sends the ReviewRequest to the cluster (APPROVE/DENY).
                            alerts.write().retain(|x| x.id != id);
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
