//! Reusable RSX components: alert cards, the blocked-segment player, the
//! honest coverage matrix, and the per-child VPN control row.

use dioxus::prelude::*;

use bulwark_proto::v1::{Category, Child as ProtoChild, FilteringProfile};

use crate::api::{fetch_segment_remote, get_child_status, set_child_config};
use crate::icons::svg;
use crate::media::{base64_encode, image_data_uri, load_segment_from_disk, sniff_video_mime};
use crate::servers::CHILD_REGIONS;
use crate::state::{should_show_snippet, should_show_thumbnail, Alert};

/// Per-child VPN control row. Local VPN filters on the supervised device;
/// Remote VPN authenticates that device to the selected Bulwark region and
/// moves inspection/inference/enforcement there.
#[component]
pub fn ChildVpnRow(child: ProtoChild) -> Element {
    let child_id = child.child_id.clone();
    let device_id = child.device_id.clone();
    let mut region = use_signal(|| "uk".to_string());
    let mut enabled = use_signal(|| true);
    let mut profile = use_signal(|| FilteringProfile::Preteen as i32);
    let mut filter_location = use_signal(|| 0i32);
    let note = use_signal(|| Option::<String>::None);
    let busy = use_signal(|| false);

    let seed_child_id = child.child_id.clone();
    use_effect(move || {
        let child_id = seed_child_id.clone();
        spawn(async move {
            if let Ok((_, _, _, Some(cfg))) = get_child_status(&child_id).await {
                if CHILD_REGIONS
                    .iter()
                    .any(|(id, _, _)| *id == cfg.server_region.as_str())
                {
                    region.set(cfg.server_region.clone());
                }
                if (1..=3).contains(&cfg.profile) {
                    profile.set(cfg.profile);
                }
                enabled.set(cfg.filtering_enabled);
                filter_location.set(cfg.filter_location);
            }
        });
    });

    rsx! {
        div { class: "vpn-row",
            div { class: "vpn-field",
                span { class: "vpn-label", "Filtering region" }
                div { class: "vpn-seg", role: "group", "aria-label": "Filtering region",
                    for (id, label, _ep) in CHILD_REGIONS.iter().copied() {
                        button {
                            class: if region() == id { "vpn-seg-btn vpn-seg-on" } else { "vpn-seg-btn" },
                            "aria-pressed": region() == id,
                            onclick: move |_| region.set(id.to_string()),
                            "{label}"
                        }
                    }
                }
            }
            div { class: "vpn-field",
                span { class: "vpn-label", "VPN mode" }
                div { class: "vpn-seg", role: "group", "aria-label": "VPN mode",
                    button {
                        class: if filter_location() == 0 { "vpn-seg-btn vpn-seg-on" } else { "vpn-seg-btn" },
                        "aria-pressed": filter_location() == 0,
                        onclick: move |_| filter_location.set(0),
                        "Local VPN"
                    }
                    button {
                        class: if filter_location() == 1 { "vpn-seg-btn vpn-seg-on" } else { "vpn-seg-btn" },
                        "aria-pressed": filter_location() == 1,
                        onclick: move |_| filter_location.set(1),
                        "Remote VPN"
                    }
                }
            }
            if filter_location() == 0 {
                div { class: "vpn-hint",
                    span { dangerous_inner_html: "{svg(\"info\")}" }
                    "Local VPN keeps filtering on the child's device. The device performs inspection and policy enforcement and traffic exits through its normal connection."
                }
            } else {
                div { class: "vpn-hint",
                    span { dangerous_inner_html: "{svg(\"shield-check\")}" }
                    "Remote VPN authenticates this enrolled device to the selected Bulwark region with a short-lived device-bound lease. Traffic is encrypted to that region, filtering runs there, and the public exit IP is the region. If authentication or filtering health fails, the remote tunnel stops instead of silently falling back to an unfiltered path."
                }
            }
            div { class: "vpn-controls",
                label { class: "vpn-field",
                    span { class: "vpn-label", "Strictness" }
                    select {
                        class: "vpn-select",
                        value: "{profile()}",
                        onchange: move |e| {
                            if let Ok(v) = e.value().parse::<i32>() {
                                profile.set(v);
                            }
                        },
                        option { value: "1", "Young child" }
                        option { value: "2", "Preteen" }
                        option { value: "3", "Teen" }
                    }
                }
                button {
                    class: if enabled() { "vpn-toggle vpn-toggle-on" } else { "vpn-toggle vpn-toggle-off" },
                    "aria-pressed": enabled(),
                    onclick: move |_| {
                        let v = !enabled();
                        enabled.set(v);
                    },
                    if enabled() { "Protection on" } else { "Protection off" }
                    span { class: "knob" }
                }
                button {
                    class: "primary vpn-apply",
                    disabled: busy(),
                    onclick: move |_| {
                        let child_id = child_id.clone();
                        let device_id = device_id.clone();
                        let region = region();
                        let endpoint = CHILD_REGIONS
                            .iter()
                            .find(|(id, _, _)| *id == region.as_str())
                            .map(|(_, _, ep)| ep.to_string())
                            .unwrap_or_default();
                        let enabled = enabled();
                        let profile = profile();
                        let filter_location = filter_location();
                        let mut note = note;
                        let mut busy = busy;
                        busy.set(true);
                        note.set(None);
                        spawn(async move {
                            match set_child_config(
                                &child_id,
                                &device_id,
                                &region,
                                &endpoint,
                                enabled,
                                profile,
                                filter_location,
                            ).await {
                                Ok(v) => {
                                    let mode = if filter_location == 1 { "Remote VPN" } else { "Local VPN" };
                                    note.set(Some(format!("Sent {mode} · config v{v} — waiting for the child to confirm…")));
                                    busy.set(false);
                                    let mut confirmed = false;
                                    for _ in 0..36 {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        if let Ok((_, applied, _, _)) = get_child_status(&child_id).await {
                                            if applied >= v {
                                                note.set(Some(format!("{mode} applied on the child's device ✓ v{v}")));
                                                confirmed = true;
                                                break;
                                            }
                                        }
                                    }
                                    if !confirmed {
                                        note.set(Some(format!("v{v} pending — the child's device hasn't confirmed {mode} yet")));
                                    }
                                }
                                Err(e) => {
                                    note.set(Some(format!("Failed: {e}")));
                                    busy.set(false);
                                }
                            }
                        });
                    },
                    if busy() { "Applying…" } else { "Apply settings" }
                }
            }
            if let Some(n) = note() {
                {
                    let applied = n.contains("applied");
                    let failed = n.starts_with("Failed");
                    let cls = if applied { "vpn-note" } else if failed { "vpn-note failed" } else { "vpn-note pending" };
                    let icon = if applied { "check" } else if failed { "alert" } else { "info" };
                    rsx! {
                        div { class: "{cls}", role: "status",
                            span { dangerous_inner_html: "{svg(icon)}" }
                            "{n}"
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn AlertCard(alert: Alert, on_decide: EventHandler<bool>) -> Element {
    let is_csam = alert.category == Category::CsamSuspected;
    let preview_uri: Option<String> = if should_show_thumbnail(&alert) {
        Some(image_data_uri(&alert.thumbnail))
    } else {
        None
    };
    let show_snippet = should_show_snippet(&alert);
    let is_grooming = alert.category == Category::Grooming;
    let (card_cls, eyebrow, ic_cls, ic_name) = if alert.urgent {
        (
            "alert-card alert-sos",
            "URGENT — SOS",
            "alert-ic sos",
            "alert",
        )
    } else if is_csam {
        (
            "alert-card alert-withheld",
            "Blocked — never stored",
            "alert-ic csam",
            "eye-off",
        )
    } else if is_grooming {
        (
            "alert-card alert-serious",
            "Needs your attention",
            "alert-ic warn",
            "alert",
        )
    } else {
        (
            "alert-card alert-handled",
            "Handled for you",
            "alert-ic block",
            "shield-check",
        )
    };

    rsx! {
        div { class: "{card_cls}",
            div { class: "alert-top",
                span { class: "{ic_cls}", dangerous_inner_html: "{svg(ic_name)}" }
                div { class: "alert-head",
                    div { class: "alert-eyebrow", "{eyebrow}" }
                    div { class: "ttl", "{alert.title}" }
                    div { class: "meta", "{alert.device} \u{00b7} {alert.when}" }
                }
            }
            div { class: "alert-body",
                p { class: "detail", "{alert.detail}" }

                if is_csam {
                    div { class: "csam",
                        span { dangerous_inner_html: "{svg(\"eye-off\")}" }
                        "Preview withheld — suspected illegal content is blocked and is never shown or stored."
                    }
                } else {
                    if let Some(seg) = alert.segment_uri.clone() {
                        SegmentPlayer { uri: seg }
                    }
                    if let Some(uri) = preview_uri {
                        div { class: "preview",
                            div { class: "preview-label", "Preview of what was blocked" }
                            img { class: "thumb", src: "{uri}", alt: "Safe preview of the blocked content" }
                        }
                    }
                    if show_snippet {
                        div { class: "snippet",
                            div { class: "snippet-label", "What was blocked" }
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
}

#[component]
pub fn SegmentPlayer(uri: String) -> Element {
    let mut data_uri = use_signal(|| Option::<String>::None);
    let mut load_err = use_signal(|| Option::<String>::None);

    use_effect(move || {
        let uri = uri.clone();
        spawn(async move {
            let bytes = match load_segment_from_disk(&uri) {
                Ok(Some(bytes)) => Some(bytes),
                Ok(None) => match fetch_segment_remote(&uri).await {
                    Ok(bytes) => Some(bytes),
                    Err(error) => {
                        load_err.set(Some(format!("not on disk; cluster fetch failed: {error}")));
                        None
                    }
                },
                Err(error) => {
                    load_err.set(Some(error));
                    None
                }
            };
            if let Some(bytes) = bytes {
                let mime = sniff_video_mime(&bytes);
                data_uri.set(Some(format!("data:{};base64,{}", mime, base64_encode(&bytes))));
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

#[component]
pub fn CoverageMatrix() -> Element {
    let rows = [
        (
            "Web (browsers, desktop)",
            "Filtered via proxy",
            "HTTPS is decrypted with the trusted Bulwark inspection CA while filtering is active",
        ),
        (
            "Android Local VPN",
            "Managed-device coverage",
            "Capture and filtering run locally; full HTTPS inspection requires the Bulwark CA in the managed system trust store",
        ),
        (
            "Android Remote VPN",
            "Authenticated tunnel",
            "Device-bound WireGuard identity + rotating Remote VPN lease; traffic stops if authentication/filter readiness is lost",
        ),
        (
            "Video / live streams",
            "Protected media gate",
            "Buffered and sampled with bounded deadlines; block/blur/mute rather than forwarding unscored media",
        ),
        (
            "WhatsApp / Signal / pinned E2E apps",
            "On-device rendered-content layer",
            "Wire interception cannot decrypt E2E/certificate-pinned payloads; the Android accessibility/OCR layer is the complementary path",
        ),
        (
            "iPhone / iPad",
            "Content filter only",
            "Apple platform restrictions limit cross-app message/screen inspection",
        ),
    ];
    rsx! {
        table { class: "cov",
            thead { tr { th { "App / surface" } th { "Status" } th { "How" } } }
            tbody {
                for (app, status, how) in rows.iter() {
                    {
                        let partial = !status.starts_with("Filtered")
                            && !status.starts_with("Authenticated")
                            && !status.starts_with("Protected");
                        let cls = if partial { "cov-status partial" } else { "cov-status" };
                        rsx! {
                            tr {
                                td { "{app}" }
                                td { span { class: "{cls}", "{status}" } }
                                td { class: "how", "{how}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
