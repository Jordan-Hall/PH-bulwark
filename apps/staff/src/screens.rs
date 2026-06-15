//! The console screens: Login (password + mandatory TOTP), Fleet health
//! (content-free region gauges), and the tamper-evident Audit log. Every value
//! shown is a count / gauge / id / hash / timestamp — never any child content.

use dioxus::prelude::*;

use bulwark_proto::v1::{Regions, StaffAuditPage};

use crate::router::Route;
use crate::state::{role_label, StaffState};

/// Login gate: email + password + a live 6-digit TOTP code (mandatory 2FA).
#[component]
pub fn Login() -> Element {
    let state = use_context::<StaffState>();
    let nav = use_navigator();

    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut totp = use_signal(String::new);
    let error = use_signal(|| Option::<String>::None);
    let busy = use_signal(|| false);

    // Already signed in (rehydrated token) → straight to the console.
    use_effect(move || {
        if state.logged_in() {
            nav.replace(Route::Fleet {});
        }
    });

    let submit = use_callback(move |_: ()| {
        if busy() {
            return;
        }
        let (e, p, t) = (email(), password(), totp());
        spawn(async move {
            // Signal writes take `&mut self`; rebind the Copy signals as mutable
            // locals inside the future.
            let mut busy = busy;
            let mut error = error;
            let mut state = state;
            busy.set(true);
            error.set(None);
            match crate::api::staff_login(e, p, t).await {
                Ok(session) => {
                    state.sign_in(session);
                    nav.replace(Route::Fleet {});
                }
                Err(err) => error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    });

    rsx! {
        div { class: "card",
            div { class: "brand",
                span { class: "dot" }
                h1 { "PH Staff " span { class: "muted", "Console" } }
            }
            p { class: "sub", "Internal operators console. Staff operate the service, never the families." }

            label { "Work email" }
            input {
                r#type: "email",
                autocomplete: "username",
                value: "{email}",
                oninput: move |e| email.set(e.value()),
            }
            label { "Password" }
            input {
                r#type: "password",
                autocomplete: "current-password",
                value: "{password}",
                oninput: move |e| password.set(e.value()),
            }
            label { "Authenticator code" }
            input {
                r#type: "text",
                inputmode: "numeric",
                placeholder: "6 digits",
                value: "{totp}",
                oninput: move |e| totp.set(e.value()),
                onkeydown: move |e| if e.key() == Key::Enter { submit.call(()) },
            }

            if let Some(err) = error() {
                div { class: "err", "{err}" }
            }

            button {
                class: "btn",
                disabled: busy(),
                onclick: move |_| submit.call(()),
                if busy() { "Signing in…" } else { "Sign in" }
            }
        }
    }
}

/// Fleet & region health — content-free gauges per region.
#[component]
pub fn Fleet() -> Element {
    let state = use_context::<StaffState>();
    let regions = use_resource(move || async move {
        crate::api::list_regions(state.token())
            .await
            .map_err(|e| e.to_string())
    });

    let snap: Option<Result<Regions, String>> = regions.read().as_ref().cloned();

    rsx! {
        div { class: "section-h", h2 { "Fleet & region health" } }
        {match snap {
            None => rsx! { div { class: "loading", "Loading fleet…" } },
            Some(Err(e)) => rsx! { div { class: "err", "Couldn't load fleet: {e}" } },
            Some(Ok(r)) => rsx! {
                if r.regions.is_empty() {
                    div { class: "loading", "No regions reported." }
                }
                div { class: "grid",
                    for region in r.regions.iter() {
                        RegionTile { region: region.clone() }
                    }
                }
            },
        }}
    }
}

#[component]
fn RegionTile(region: bulwark_proto::v1::RegionInfo) -> Element {
    let (status_class, status_dot, status_text) = if !region.probed {
        ("warn", "bg-idle", "Not probed")
    } else if region.healthy {
        ("ok", "bg-ok", "Healthy")
    } else {
        ("bad", "bg-bad", "Degraded")
    };
    rsx! {
        div { class: "tile",
            div { class: "k", "{region.region.to_uppercase()}" }
            div { class: "v {status_class}",
                span { class: "dot-i {status_dot}" }
                "{status_text}"
            }
            div { class: "s mono", "{region.endpoint}" }
            div { class: "s", "Devices enrolled: {region.enrolled_device_count}" }
            div { class: "s", "WireGuard peers: {region.wg_peer_count}" }
            div { class: "s", "Build: {region.deploy_version}" }
            div { class: "s", "TLS expiry (unix ms): {region.tls_cert_expiry_ts}" }
        }
    }
}

/// Tamper-evident staff audit log (ADMIN only on the server).
#[component]
pub fn Audit() -> Element {
    let state = use_context::<StaffState>();
    let page = use_resource(move || async move {
        crate::api::query_audit(state.token(), 0, 100)
            .await
            .map_err(|e| e.to_string())
    });

    let snap: Option<Result<StaffAuditPage, String>> = page.read().as_ref().cloned();

    rsx! {
        div { class: "section-h", h2 { "Staff audit log" } }
        {match snap {
            None => rsx! { div { class: "loading", "Loading audit chain…" } },
            Some(Err(e)) => rsx! { div { class: "err", "Couldn't load audit log: {e}" } },
            Some(Ok(p)) => rsx! {
                div {
                    class: if p.chain_ok { "chain ok" } else { "chain bad" },
                    if p.chain_ok {
                        span { class: "dot-i bg-ok" } "Chain verified intact"
                    } else {
                        span { class: "dot-i bg-bad" } "CHAIN BROKEN — at-rest tampering detected"
                    }
                }
                table {
                    thead {
                        tr {
                            th { "Seq" }
                            th { "Actor" }
                            th { "Role" }
                            th { "Action" }
                            th { "Target" }
                            th { "Hash" }
                        }
                    }
                    tbody {
                        for entry in p.entries.iter() {
                            tr { key: "{entry.seq}",
                                td { class: "mono", "{entry.seq}" }
                                td { "{entry.staff_id}" }
                                td { "{role_label(entry.role)}" }
                                td { "{entry.action}" }
                                td { class: "mono", "{entry.target}" }
                                td { class: "mono", "{short_hash(&entry.entry_hash)}" }
                            }
                        }
                    }
                }
            },
        }}
    }
}

/// First 12 hex chars of a chain hash — enough to eyeball continuity without a wall of hex.
fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
}
