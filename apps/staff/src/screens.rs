//! The console screens: Login (password + mandatory TOTP), Fleet health
//! (content-free region gauges), and the tamper-evident Audit log. Every value
//! shown is a count / gauge / id / hash / timestamp — never any child content.

use dioxus::prelude::*;

use bulwark_proto::v1::{GuardianMeta, Regions, SafetyCaseState, StaffAuditPage};

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

/// Guardian-account support: act on a guardian BY EMAIL only — look up content-free
/// metadata, email a reset code (staff never see it), or clear a login lockout.
#[component]
pub fn Support() -> Element {
    let state = use_context::<StaffState>();
    let mut email = use_signal(String::new);
    let meta = use_signal(|| Option::<Result<GuardianMeta, String>>::None);
    let action = use_signal(|| Option::<String>::None);

    let lookup = use_callback(move |_: ()| {
        let (token, em) = (state.token(), email());
        if em.trim().is_empty() {
            return;
        }
        spawn(async move {
            let mut meta = meta;
            meta.set(Some(
                crate::api::guardian_meta(token, em)
                    .await
                    .map_err(|e| e.to_string()),
            ));
        });
    });
    let send_reset = use_callback(move |_: ()| {
        let (token, em) = (state.token(), email());
        if em.trim().is_empty() {
            return;
        }
        spawn(async move {
            let mut action = action;
            let msg = match crate::api::trigger_reset(token, em).await {
                Ok(ack) => format!(
                    "Reset dispatched (dispatched={}): {}",
                    ack.dispatched, ack.detail
                ),
                Err(e) => format!("Reset failed: {e}"),
            };
            action.set(Some(msg));
        });
    });
    let unlock = use_callback(move |_: ()| {
        let (token, em) = (state.token(), email());
        if em.trim().is_empty() {
            return;
        }
        spawn(async move {
            let mut action = action;
            let msg = match crate::api::unlock_guardian(token, em).await {
                Ok(ack) => format!(
                    "Lockout cleared (account existed={}): {}",
                    ack.existed, ack.detail
                ),
                Err(e) => format!("Unlock failed: {e}"),
            };
            action.set(Some(msg));
        });
    });

    rsx! {
        div { class: "section-h", h2 { "Guardian-account support" } }
        p { class: "muted",
            "Act on a guardian by email. Staff never see passwords, recovery codes, child names, or any alert content — only existence, lockout state, and counts."
        }
        div { class: "tile",
            label { "Guardian email" }
            input {
                r#type: "email",
                value: "{email}",
                oninput: move |e| email.set(e.value()),
            }
            div { style: "display:flex; gap:8px; margin-top:14px; flex-wrap:wrap;",
                button { class: "btn ghost", onclick: move |_| lookup.call(()), "Look up" }
                button { class: "btn ghost", onclick: move |_| send_reset.call(()), "Email reset code" }
                button { class: "btn ghost", onclick: move |_| unlock.call(()), "Clear lockout" }
            }
            if let Some(msg) = action() {
                div { class: "s", style: "margin-top:12px;", "{msg}" }
            }
        }
        {match meta() {
            None => rsx! {},
            Some(Err(e)) => rsx! { div { class: "err", "Lookup failed: {e}" } },
            Some(Ok(m)) if !m.exists => rsx! {
                div { class: "tile",
                    div { class: "k", "Account" }
                    div { class: "v warn", "No account for that email" }
                }
            },
            Some(Ok(m)) => rsx! {
                div { class: "grid",
                    div { class: "tile", div { class: "k", "Account" } div { class: "v ok", "Exists" } }
                    div { class: "tile", div { class: "k", "Lockout" }
                        div { class: if m.locked { "v bad" } else { "v ok" },
                            if m.locked { "Locked" } else { "Clear" }
                        }
                    }
                    div { class: "tile", div { class: "k", "Recovery code" }
                        div { class: "v", if m.has_recovery_code { "Set" } else { "None" } }
                    }
                    div { class: "tile", div { class: "k", "Reset pending" }
                        div { class: "v", if m.reset_pending { "Yes" } else { "No" } }
                    }
                    div { class: "tile", div { class: "k", "Children" } div { class: "v", "{m.child_count}" } }
                    div { class: "tile", div { class: "k", "Devices" } div { class: "v", "{m.device_count}" } }
                }
            },
        }}
    }
}

/// NCMEC safety-report queue — hashes + workflow state ONLY (report-never-store,
/// so there is no media to review). Read-only this increment; the validated
/// state-transition controls land in the next one.
#[component]
pub fn Cases() -> Element {
    let state = use_context::<StaffState>();
    let mut filter = use_signal(|| 0i32); // SafetyCaseState UNSPECIFIED = all
    let cases = use_resource(move || async move {
        crate::api::list_cases(state.token(), filter())
            .await
            .map_err(|e| e.to_string())
    });
    let snap = cases.read().as_ref().cloned();

    rsx! {
        div { class: "section-h",
            h2 { "Safety-report queue (NCMEC)" }
            select {
                onchange: move |e| filter.set(e.value().parse().unwrap_or(0)),
                option { value: "0", "All states" }
                option { value: "1", "Opened" }
                option { value: "2", "Under review" }
                option { value: "3", "Reported (NCMEC)" }
                option { value: "4", "Law enforcement" }
                option { value: "5", "Closed" }
                option { value: "6", "Rejected" }
            }
        }
        p { class: "muted",
            "Hashes + category + region + workflow state only — never media, names, message text, or child/device ids."
        }
        {match snap {
            None => rsx! { div { class: "loading", "Loading cases…" } },
            Some(Err(e)) => rsx! { div { class: "err", "Couldn't load cases: {e}" } },
            Some(Ok(c)) => rsx! {
                if c.cases.is_empty() {
                    div { class: "loading", "No cases for this filter." }
                }
                table {
                    thead {
                        tr {
                            th { "Case" }
                            th { "State" }
                            th { "Region" }
                            th { "sha256" }
                            th { "NCMEC ref" }
                            th { "Opened (unix ms)" }
                        }
                    }
                    tbody {
                        for case in c.cases.iter() {
                            tr { key: "{case.case_id}",
                                td { class: "mono", "{case.case_id}" }
                                td {
                                    {
                                        let (cls, label) = case_state_label(case.state);
                                        rsx! { span { class: "{cls}", "{label}" } }
                                    }
                                }
                                td { "{case.jurisdiction}" }
                                td { class: "mono", "{hex_short(&case.sha256)}" }
                                td { class: "mono", "{case.ncmec_reference}" }
                                td { class: "mono", "{case.opened_ts}" }
                            }
                        }
                    }
                }
            },
        }}
    }
}

/// (css-class, label) for a safety-case workflow state.
fn case_state_label(state: i32) -> (&'static str, &'static str) {
    match SafetyCaseState::try_from(state).unwrap_or(SafetyCaseState::Unspecified) {
        SafetyCaseState::Opened => ("warn", "Opened"),
        SafetyCaseState::UnderReview => ("warn", "Under review"),
        SafetyCaseState::ReportedNcmec => ("ok", "Reported (NCMEC)"),
        SafetyCaseState::LawEnforcement => ("ok", "Law enforcement"),
        SafetyCaseState::Closed => ("muted", "Closed"),
        SafetyCaseState::Rejected => ("muted", "Rejected"),
        SafetyCaseState::Unspecified => ("muted", "—"),
    }
}

/// First 6 bytes of a content hash as hex (12 chars) — enough to correlate a case
/// without rendering a full hash wall. The hash itself carries no content.
fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(6).map(|b| format!("{b:02x}")).collect()
}
