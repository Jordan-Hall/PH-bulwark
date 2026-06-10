//! The console's screens: the six routed tabs (Setup/Alerts/Children/
//! Protection/Server/Coverage — see `crate::router::Route`) plus the
//! protection control panel and server-settings panel they wrap.

use std::cell::RefCell;
use std::process::Child;
use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;

use crate::api::{
    create_guardian_account, create_pair_code_for_child, load_children, login_guardian,
    submit_decision,
};
use crate::components::{AlertCard, ChildVpnRow, CoverageMatrix};
use crate::config::{ffmpeg_display, nsfw_model_display};
use crate::media::{pair_payload, pair_qr_svg};
use crate::process::{
    ca_present, ca_trust_command, disable_system_proxy, enable_system_proxy, kill_proxy,
    proxy_listening, spawn_proxy, spawn_vpn, Mode, ProxyHandle, PROXY_ADDR,
};
use crate::servers::{
    clear_guardian_token, cluster_ca_path_for_endpoint, remove_custom_server, save_guardian_token,
    save_server_choice, saved_choice, saved_token_for_endpoint, selected_server_id,
    server_inventory, upsert_custom_server, DEFAULT_REGION_ID,
};
use crate::state::{
    pair_expiry_text, session_status_text, Alert, AppStatus, Console, PairCodeUi,
};

#[component]
pub fn ProtectionPanel() -> Element {
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
            div { class: "protect-intro",
                h2 { "Protection on this device" }
                p { class: "sub", "Run the on-device filter so flagged content is inspected and kept safe locally. Nothing is recorded or sent anywhere beyond your chosen server." }
            }
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
                                // VPN mode: no system-proxy change. bulwark_vpn exits
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

#[component]
pub fn ServerSettingsPanel(on_saved: EventHandler<()>) -> Element {
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

// ---------------------------------------------------------------------------
// Routed screens (one per console tab — `crate::router::Route`). Bodies are
// the former `match active()` arms, verbatim; only the signal access moved to
// the shared `Console` context so typed form state survives tab switches.
// ---------------------------------------------------------------------------

/// "/" — family setup: guardian sign-in + child pairing (default route).
#[component]
pub fn Setup() -> Element {
    let console = use_context::<Console>();
    let status = console.status;
    let mut create_account = console.create_account;
    let mut email = console.email;
    let mut password = console.password;
    let mut display_name = console.display_name;
    let mut child_name = console.child_name;
    let pair_code = console.pair_code;
    let setup_note = console.setup_note;
    let setup_error = console.setup_error;
    let setup_busy = console.setup_busy;
    rsx! {
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
                        if let Some(qr) = pair_qr_svg(&pair_payload(&pair.code)) {
                            div { class: "pair-qr",
                                div { class: "pair-qr-img", dangerous_inner_html: "{qr}" }
                                div { class: "hint", "Scan this on the child device, or type the code above. Use the same server on both." }
                            }
                        }
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
    }
}

/// "/alerts" — live alert inbox with approve / keep-blocked decisions.
#[component]
pub fn Alerts() -> Element {
    let console = use_context::<Console>();
    let alerts = console.alerts;
    let offline = console.offline;
    let action_error = console.action_error;
    rsx! {
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
    }
}

/// "/children" — roster + per-child filtering controls.
#[component]
pub fn Children() -> Element {
    let console = use_context::<Console>();
    let status = console.status;
    let children = console.children;
    let children_error = console.children_error;
    let children_busy = console.children_busy;
    rsx! {
    section { class: "panel",
        div { class: "panel-head split",
            div {
                h2 { "Children" }
                p { class: "sub", "Children protected by the signed-in guardian on this server. Choose each child's filtering region, strictness, and whether filtering is on." }
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
                ChildVpnRow { child: child.clone() }
            }
        }
    }
    }
}

/// "/protection" — the local protection control panel.
#[component]
pub fn Protection() -> Element {
    rsx! { ProtectionPanel {} }
}

/// "/server" — server/region settings; refreshes the status grid on save.
#[component]
pub fn Server() -> Element {
    let console = use_context::<Console>();
    let mut status = console.status;
    rsx! {
        ServerSettingsPanel {
            on_saved: move |_| status.set(AppStatus::load())
        }
    }
}

/// "/coverage" — the honest enforcement coverage matrix.
#[component]
pub fn Coverage() -> Element {
    rsx! {
        section { class: "panel",
            h2 { "Coverage" }
            CoverageMatrix {}
        }
    }
}
