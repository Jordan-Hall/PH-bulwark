//! Reusable RSX components: alert cards, the blocked-segment player, the
//! honest coverage matrix, and the per-child VPN control row.

use dioxus::prelude::*;

use bulwark_proto::v1::{Category, Child as ProtoChild, FilteringProfile};

use crate::api::{fetch_segment_remote, get_child_status, set_child_config};
use crate::media::{base64_encode, image_data_uri, load_segment_from_disk, sniff_video_mime};
use crate::servers::CHILD_REGIONS;
use crate::state::{should_show_snippet, should_show_thumbnail, Alert};

/// Per-child VPN control row: the guardian picks the filtering region/server,
/// toggles filtering on/off, and sets the strictness band — applied to the child
/// device via `ChildControl`. Each control owns its own draft state; "Apply"
/// pushes it and shows the resulting config version (or the error).
#[component]
pub fn ChildVpnRow(child: ProtoChild) -> Element {
    let child_id = child.child_id.clone();
    let device_id = child.device_id.clone();
    let mut region = use_signal(|| "uk".to_string());
    let mut enabled = use_signal(|| true);
    let mut profile = use_signal(|| FilteringProfile::Preteen as i32);
    let mut note = use_signal(|| Option::<String>::None);
    let mut busy = use_signal(|| false);

    rsx! {
        div { class: "vpn-row",
            div { class: "vpn-field",
                span { class: "vpn-label", "Filtering region" }
                div { class: "vpn-seg",
                    for (id, label, _ep) in CHILD_REGIONS.iter().copied() {
                        button {
                            class: if region() == id { "vpn-seg-btn vpn-seg-on" } else { "vpn-seg-btn" },
                            onclick: move |_| region.set(id.to_string()),
                            "{label}"
                        }
                    }
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
                    onclick: move |_| {
                        let v = !enabled();
                        enabled.set(v);
                    },
                    if enabled() { "Filtering on" } else { "Filtering off" }
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
                        let mut note = note;
                        let mut busy = busy;
                        busy.set(true);
                        note.set(None);
                        spawn(async move {
                            match set_child_config(&child_id, &device_id, &region, &endpoint, enabled, profile).await {
                                Ok(v) => {
                                    note.set(Some(format!("Sent · config v{v} — waiting for the child to confirm…")));
                                    busy.set(false);
                                    // The child acks the applied version on its next
                                    // config poll (every 60s while filtering runs, and
                                    // on app foreground) — watch GetChildStatus for up
                                    // to ~3 minutes, then call it pending.
                                    let mut confirmed = false;
                                    for _ in 0..36 {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        if let Ok((_, applied, _)) = get_child_status(&child_id).await {
                                            if applied >= v {
                                                note.set(Some(format!("Applied on the child's device ✓ v{v}")));
                                                confirmed = true;
                                                break;
                                            }
                                        }
                                    }
                                    if !confirmed {
                                        note.set(Some(format!("v{v} pending — the child's device hasn't confirmed yet (offline or app closed)")));
                                    }
                                }
                                Err(e) => {
                                    note.set(Some(format!("Failed: {e}")));
                                    busy.set(false);
                                }
                            }
                        });
                    },
                    if busy() { "Applying..." } else { "Apply VPN settings" }
                }
            }
            if let Some(n) = note() {
                div { class: "vpn-note", "{n}" }
            }
        }
    }
}

#[component]
pub fn AlertCard(alert: Alert, on_decide: EventHandler<bool>) -> Element {
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
/// resolved from the per-user segment store on disk (`%LOCALAPPDATA%/Bulwark/
/// segments/<sha>.blob`, written by `bulwark-video::SegmentStore`) when the parent is
/// co-located with the server; otherwise it falls back to pulling the clip from the
/// cluster over `Review.FetchSegment`. Bytes are shown via a data URI in the desktop
/// webview's `<video>`. The caller only mounts this for NON-CSAM alerts (CSAM is
/// never stored/served, so it would not exist anyway — defence in depth).
#[component]
pub fn SegmentPlayer(uri: String) -> Element {
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

#[component]
pub fn CoverageMatrix() -> Element {
    // HONEST static matrix (audit 2026-06-10): what is filtered TODAY, not the
    // target architecture. Keep in sync with PLAN.md §0a.
    let rows = [
        (
            "Web (browsers, desktop)",
            "Filtered via proxy",
            "Explicit proxy mode: HTTPS decrypted via the per-install CA while the proxy is connected",
        ),
        (
            "Android (transparent VPN)",
            "Being validated",
            "Capture pump implemented; device validation pending; HTTPS coverage limited (Android 7+ ignores user CAs)",
        ),
        (
            "Video / live streams",
            "Filtered via proxy",
            "On the proxy path: buffered, sampled, block/blur/mute",
        ),
        (
            "WhatsApp / Signal / Messenger (E2E / pinned)",
            "Android text check only",
            "Network can't read E2E; on-device text check covers 6 messengers on Android — no OCR agent yet, NOT covered elsewhere",
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
