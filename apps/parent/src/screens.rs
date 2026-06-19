//! The console's screens: the six routed tabs (Setup/Alerts/Children/
//! Protection/Server/Coverage — see `crate::router::Route`) plus the
//! protection control panel and server-settings panel they wrap.

use std::cell::RefCell;
use std::process::Child;
use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;

use crate::api::{
    change_guardian_password, create_guardian_account, create_pair_code_for_child, load_children,
    login_guardian, register_push_target, request_password_reset, reset_password_with_code,
    submit_decision,
};
use crate::brand::logo_data_uri;
use crate::components::{AlertCard, ChildVpnRow, CoverageMatrix};
use crate::config::{ffmpeg_display, nsfw_model_display};
use crate::icons::svg;
use crate::lock::{
    biometric_available, biometric_unlock, clear_pin, set_pin, validate_pin_shape, verify_pin,
    BiometricOutcome, PIN_MAX, PIN_MIN,
};
use crate::media::{pair_qr_svg, setup_payload_v2};
use crate::process::{
    ca_present, ca_trust_command, disable_system_proxy, enable_system_proxy, kill_proxy,
    proxy_listening, spawn_proxy, spawn_vpn, Mode, ProxyHandle, PROXY_ADDR,
};
use crate::provision::{
    build_provisioning_json, provisioning_qr_svg, ProvisioningParams, CHILD_APK_CERT_CHECKSUM,
};
use crate::router::{phase_route, Route};
use crate::servers::{
    clear_push_endpoint, cluster_ca_path_for_endpoint, remove_custom_server, save_guardian_token,
    save_push_endpoint, save_server_choice, saved_choice, saved_push_endpoint,
    saved_token_for_endpoint, selected_server_id, server_inventory, upsert_custom_server,
    DEFAULT_REGION_ID,
};
use crate::state::{pair_expiry_text, segment_code, Alert, AuthState, Console, PairCodeUi};

// ===========================================================================
// GATE SCREENS — reachable BEFORE auth. Welcome → ChooseServer → Auth →
// (SetupLock) → console; plus Splash (the index decider) and Lock (re-open).
// These render inside `GateLayout`'s calm card, NOT the console chrome.
// ===========================================================================

/// "/" — the decider. Reads saved state and `replace()`s to the right place:
/// a locked saved session → Lock; an already-trusted session → console; nothing
/// saved → Welcome. Renders a brief calm splash for the frame before redirect.
#[component]
pub fn Splash() -> Element {
    let nav = use_navigator();
    let auth = use_context::<AuthState>();
    use_effect(move || {
        nav.replace(phase_route(auth.phase()));
    });
    rsx! {
        div { class: "gate-splash",
            img { class: "gate-hero-logo", src: "{logo_data_uri()}", alt: "Bulwark Shield" }
            p { class: "gate-lede", "Getting things ready…" }
        }
    }
}

/// "/welcome" — a short, warm first-run intro: what the Manager does + the
/// privacy stance, then "Get started" → choose a server/region.
#[component]
pub fn Welcome() -> Element {
    let nav = use_navigator();
    rsx! {
        img { class: "gate-hero-logo", src: "{logo_data_uri()}", alt: "Bulwark Shield" }
        h1 { class: "gate-title", "Welcome to your " em { "family's safe space." } }
        p { class: "gate-lede",
            "This is where you look after each child's protection — calmly, and in plain words."
        }
        ul { class: "gate-facts", role: "list",
            li { class: "gate-fact", style: "--i: 0",
                span { class: "gf-ic", dangerous_inner_html: "{svg(\"bell\")}" }
                div {
                    strong { "Review safety alerts" }
                    span { "Calm, redacted summaries of anything that was flagged — you decide what to do." }
                }
            }
            li { class: "gate-fact", style: "--i: 1",
                span { class: "gf-ic", dangerous_inner_html: "{svg(\"child\")}" }
                div {
                    strong { "Manage each child's filtering" }
                    span { "Region, strictness and on/off — per child, applied to their device." }
                }
            }
            li { class: "gate-fact", style: "--i: 2",
                span { class: "gf-ic", dangerous_inner_html: "{svg(\"link\")}" }
                div {
                    strong { "Pair a child's device" }
                    span { "Generate a short code or QR; nothing is installed without you." }
                }
            }
        }
        div { class: "gate-privacy",
            span { class: "gp-ic", dangerous_inner_html: "{svg(\"eye-off\")}" }
            span { "No screen capture, no location, no hidden monitoring. This is care, not surveillance — and you stay in control." }
        }
        button {
            class: "gate-primary",
            "aria-label": "Get started",
            onclick: move |_| { nav.push(Route::ChooseServer {}); },
            "Get started"
        }
        button {
            class: "gate-ghost",
            onclick: move |_| { nav.push(Route::Auth {}); },
            "I already have an account"
        }
    }
}

/// "/choose-server" — pick the region (UK · US · Self-hosted) BEFORE auth, since
/// the session and CA are per-server. Saves the choice, then continues to Auth.
#[component]
pub fn ChooseServer() -> Element {
    let nav = use_navigator();
    let mut auth = use_context::<AuthState>();
    let saved = saved_choice();
    let mut inventory = use_signal(server_inventory);
    let mut selected = use_signal(|| selected_server_id(&saved));
    let mut self_label = use_signal(String::new);
    let mut self_url = use_signal(String::new);
    let mut show_self = use_signal(|| false);
    let mut note = use_signal(|| Option::<String>::None);
    let rows = inventory.read().clone();

    rsx! {
        h2 { class: "gate-title", "Choose your region" }
        p { class: "gate-lede",
            "Your family's data stays within the server you pick. You can change this later in Settings."
        }
        div { class: "region-list",
            for (i, server) in rows.into_iter().enumerate() {
                {
                    let flag = if server.builtin { svg("globe") } else { svg("home") };
                    rsx! {
                        button {
                            key: "{server.id}",
                            class: if selected() == server.id { "region-row region-on" } else { "region-row" },
                            style: "--i: {i}",
                            onclick: {
                                let id = server.id.clone();
                                move |_| selected.set(id.clone())
                            },
                            span { class: "region-flag", dangerous_inner_html: "{flag}" }
                            span { class: "region-body",
                                span { class: "region-name", "{server.label}" }
                                span { class: "region-meta mono", "{server.endpoint}" }
                            }
                            if selected() == server.id {
                                span { class: "region-check", dangerous_inner_html: "{svg(\"check\")}" }
                            }
                        }
                    }
                }
            }
            button {
                class: if show_self() { "region-row region-self region-on" } else { "region-row region-self" },
                style: "--i: 9",
                onclick: move |_| show_self.set(!show_self()),
                span { class: "region-flag", dangerous_inner_html: "{svg(\"home\")}" }
                span { class: "region-body",
                    span { class: "region-name", "Self-hosted server" }
                    span { class: "region-meta", "Run your own backend on a home or private server." }
                }
                if show_self() {
                    span { class: "region-check", dangerous_inner_html: "{svg(\"check\")}" }
                }
            }
        }

        if show_self() {
            div { class: "gate-field",
                label { "Name" }
                input {
                    r#type: "text",
                    placeholder: "Home server",
                    value: "{self_label}",
                    oninput: move |e| self_label.set(e.value()),
                }
            }
            div { class: "gate-field",
                label { "Endpoint" }
                input {
                    r#type: "text",
                    placeholder: "https://your-server:8443",
                    value: "{self_url}",
                    oninput: move |e| self_url.set(e.value()),
                }
            }
        }

        if let Some(n) = note() {
            div { class: "gate-error",
                span { dangerous_inner_html: "{svg(\"alert\")}" }
                "{n}"
            }
        }

        button {
            class: "gate-primary",
            onclick: move |_| {
                // Self-hosted path: add + activate, then continue.
                if show_self() {
                    match upsert_custom_server(&self_label(), &self_url()) {
                        Ok(server) => {
                            if let Err(e) = save_server_choice(&server.id) {
                                note.set(Some(format!("Couldn't make it active: {e}")));
                                return;
                            }
                            inventory.set(server_inventory());
                        }
                        Err(e) => { note.set(Some(e.to_string())); return; }
                    }
                } else if let Err(e) = save_server_choice(&selected()) {
                    note.set(Some(format!("Couldn't save: {e}")));
                    return;
                }
                auth.refresh();
                nav.push(Route::Auth {});
            },
            "Continue"
        }
        button {
            class: "gate-ghost",
            onclick: move |_| { nav.go_back(); },
            "Back"
        }
    }
}

/// "/auth" — sign in or create a guardian account on the selected server. Inline
/// validation; on "email already registered" we switch to Sign-in (no silent
/// login); a successful sign-in offers (skippably) to set a quick-unlock PIN.
#[component]
pub fn Auth() -> Element {
    let nav = use_navigator();
    let auth = use_context::<AuthState>();
    let console = use_context::<Console>();
    let status = auth.status;
    let mut create_account = console.create_account;
    let mut email = console.email;
    let mut password = console.password;
    let mut display_name = console.display_name;
    let setup_error = console.setup_error;
    let setup_busy = console.setup_busy;
    let mut info = use_signal(|| Option::<String>::None);
    // After a successful CREATE, the one-time recovery code to show + have the
    // guardian save before continuing (their self-service reset secret).
    let mut recovery = use_signal(|| Option::<String>::None);

    // Live inline validation (does not block typing; gates the submit button).
    let email_val = email();
    let pw_val = password();
    let email_ok = email_looks_valid(&email_val);
    let pw_len = pw_val.chars().count();
    let pw_ok = pw_len >= 8;
    let creating = create_account();
    let can_submit =
        !email_val.trim().is_empty() && email_ok && !pw_val.is_empty() && (!creating || pw_ok);

    // The submit action, lifted to a closure so both the button and the
    // keyboard "Enter" on the password field can fire it. Behaviour is identical
    // to the previous inline onclick — same create/login flow and routing.
    let submit = move |_: ()| {
        if setup_busy() || !can_submit {
            return;
        }
        let email_value = email().trim().to_string();
        let password_value = password();
        let display_value = display_name().trim().to_string();
        let should_create = create_account();
        let mut setup_busy = setup_busy;
        let mut setup_error = setup_error;
        let mut create_account = create_account;
        let mut info = info;
        let mut auth = auth;
        let nav = nav;
        setup_busy.set(true);
        setup_error.set(None);
        info.set(None);
        spawn(async move {
            // CREATE path: if the server says the account already exists
            // (created == false), DON'T silently log in — tell the guardian
            // and switch to Sign-in so they enter their existing password.
            if should_create {
                match create_guardian_account(&email_value, &password_value, &display_value).await {
                    Ok(ack) if !ack.created => {
                        create_account.set(false);
                        info.set(Some(
                            "This email already has an account — sign in instead.".to_string(),
                        ));
                        setup_busy.set(false);
                        return;
                    }
                    Ok(ack) => {
                        // Account created. Show the one-time recovery code and
                        // STOP — don't auto-continue until the guardian has saved
                        // it (it's their only self-service password reset). The
                        // "I've saved it" button switches to Sign-in + submits.
                        if !ack.recovery_code.is_empty() {
                            recovery.set(Some(ack.recovery_code));
                            setup_busy.set(false);
                            return;
                        }
                    }
                    Err(e) => {
                        setup_error.set(Some(e.to_string()));
                        setup_busy.set(false);
                        return;
                    }
                }
            }
            // LOGIN path (also the second half of a successful create).
            match login_guardian(&email_value, &password_value).await {
                Ok(session) => {
                    if let Err(e) = save_guardian_token(&session.token) {
                        setup_error.set(Some(format!(
                            "Signed in, but couldn't save the session: {e}"
                        )));
                        setup_busy.set(false);
                        return;
                    }
                    let mut unlocked = auth.unlocked;
                    unlocked.set(true);
                    auth.refresh();
                    setup_busy.set(false);
                    // NOTE: no auto-registration of a saved push endpoint on
                    // login. Remote push delivery is gated OFF until per-guardian
                    // scoped fan-out ships (issue #140) — until then enrolling an
                    // endpoint would put this device in the server's GLOBAL fan-out
                    // (every registered endpoint receives every family's alert), a
                    // cross-tenant leak. The endpoint is saved on-device only and
                    // activates automatically once #140 lands.
                    // Offer (skippably) a quick-unlock PIN. If one already
                    // exists, skip straight to the console.
                    if crate::lock::pin_is_set() {
                        nav.replace(Route::Alerts {});
                    } else {
                        nav.replace(Route::SetupLock {});
                    }
                }
                Err(e) => {
                    setup_error.set(Some(e.to_string()));
                    setup_busy.set(false);
                }
            }
        });
    };

    // One-time recovery-code panel takes over the screen after a successful
    // create, until the guardian confirms they've saved it.
    if let Some(code) = recovery() {
        return rsx! {
            div { class: "gate-hero", dangerous_inner_html: "{svg(\"key\")}" }
            h2 { class: "gate-title", "Save your recovery code" }
            p { class: "gate-lede",
                "This is the ONLY way to reset your password yourself if you forget it. "
                "Write it down or store it in a password manager — we can't show it again."
            }
            div { class: "recovery-code", role: "text", "aria-label": "Recovery code",
                "{code}"
            }
            button {
                class: "gate-ghost copy-btn",
                onclick: {
                    let code = code.clone();
                    move |_| { let _ = crate::media::copy_to_clipboard(&code); }
                },
                span { dangerous_inner_html: "{svg(\"copy\")}" }
                "Copy code"
            }
            div { class: "gate-privacy",
                span { class: "gp-ic", dangerous_inner_html: "{svg(\"info\")}" }
                span { "Keep it private. Anyone with this code and your email can reset your password." }
            }
            button {
                class: "gate-primary",
                onclick: move |_| {
                    recovery.set(None);
                    create_account.set(false);
                    submit(());
                },
                "I've saved it — continue"
            }
        };
    }

    rsx! {
        img { class: "gate-hero-logo", src: "{logo_data_uri()}", alt: "Bulwark Shield" }
        h2 { class: "gate-title", if creating { "Create your account" } else { "Welcome back" } }
        p { class: "gate-lede", "for {status().server_label}" }

        div { class: "gate-seg",
            button {
                class: if creating { "gate-seg-btn gate-seg-on" } else { "gate-seg-btn" },
                onclick: move |_| { create_account.set(true); info.set(None); },
                "Create account"
            }
            button {
                class: if !creating { "gate-seg-btn gate-seg-on" } else { "gate-seg-btn" },
                onclick: move |_| { create_account.set(false); info.set(None); },
                "Sign in"
            }
        }

        if let Some(msg) = info() {
            div { class: "gate-info",
                span { dangerous_inner_html: "{svg(\"info\")}" }
                "{msg}"
            }
        }

        div { class: "gate-field",
            label { r#for: "auth-email", "Email" }
            input {
                id: "auth-email",
                r#type: "email",
                autofocus: true,
                placeholder: "guardian@example.com",
                value: "{email}",
                oninput: move |e| email.set(e.value()),
                onkeydown: move |e| { if e.key() == Key::Enter { submit(()); } },
            }
            if !email_val.trim().is_empty() && !email_ok {
                span { class: "gate-hint-bad", "Enter a valid email address." }
            }
        }

        if creating {
            div { class: "gate-field",
                label { r#for: "auth-name", "Display name" }
                input {
                    id: "auth-name",
                    r#type: "text",
                    placeholder: "Guardian",
                    value: "{display_name}",
                    oninput: move |e| display_name.set(e.value()),
                    onkeydown: move |e| { if e.key() == Key::Enter { submit(()); } },
                }
            }
        }

        div { class: "gate-field",
            label { r#for: "auth-pw", "Password" }
            input {
                id: "auth-pw",
                r#type: "password",
                placeholder: if creating { "At least 8 characters" } else { "Your password" },
                value: "{password}",
                oninput: move |e| password.set(e.value()),
                onkeydown: move |e| { if e.key() == Key::Enter { submit(()); } },
            }
            if creating && !pw_val.is_empty() {
                PasswordStrength { len: pw_len }
            }
        }

        button {
            class: "gate-primary",
            disabled: setup_busy() || !can_submit,
            onclick: move |_| submit(()),
            if setup_busy() {
                "Working…"
            } else if creating {
                "Create account"
            } else {
                "Sign in"
            }
        }

        if let Some(err) = setup_error() {
            div { class: "gate-error",
                span { dangerous_inner_html: "{svg(\"alert\")}" }
                "{err}"
            }
        }

        if !creating {
            button {
                class: "gate-link",
                onclick: move |_| { nav.push(Route::ForgotPassword {}); },
                "Forgot your password?"
            }
        }

        button {
            class: "gate-ghost",
            onclick: move |_| { nav.push(Route::ChooseServer {}); },
            "Change region ({status().server_label})"
        }
    }
}

/// "/forgot-password" — self-service reset with the one-time recovery code (no
/// operator/email needed). On success the server rotates the code, so we show the
/// FRESH one to save, then send the guardian back to Sign-in.
#[component]
pub fn ForgotPassword() -> Element {
    let nav = use_navigator();
    let auth = use_context::<AuthState>();
    let status = auth.status;
    let mut email = use_signal(String::new);
    let mut code = use_signal(String::new);
    let mut new_pw = use_signal(String::new);
    let busy = use_signal(|| false);
    let error = use_signal(|| Option::<String>::None);
    // The fresh recovery code returned after a successful reset (save this one).
    let new_code = use_signal(|| Option::<String>::None);
    // Generic confirmation after requesting an emailed code (anti-enumeration:
    // the same message whether or not the email has an account).
    let emailed = use_signal(|| Option::<String>::None);
    let emailing = use_signal(|| false);

    let email_v = email();
    let pw_len = new_pw().chars().count();
    let can_submit = !email_v.trim().is_empty()
        && email_looks_valid(&email_v)
        && !code().trim().is_empty()
        && pw_len >= 8;
    let can_email = !email_v.trim().is_empty() && email_looks_valid(&email_v);

    // "Email me a code": ask the server to send a short-lived reset code to the
    // account address. Always shows the same generic confirmation.
    let request_email = move |_: ()| {
        if emailing() || !can_email {
            return;
        }
        let email_value = email().trim().to_string();
        let mut emailing = emailing;
        let mut emailed = emailed;
        let mut error = error;
        emailing.set(true);
        error.set(None);
        spawn(async move {
            match request_password_reset(&email_value).await {
                Ok(ack) => {
                    emailed.set(Some(if ack.detail.is_empty() {
                        "If that email has an account, a reset code is on its way. Enter it below."
                            .to_string()
                    } else {
                        ack.detail
                    }));
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            emailing.set(false);
        });
    };

    let submit = move |_: ()| {
        if busy() || !can_submit {
            return;
        }
        let email_value = email().trim().to_string();
        let code_value = code();
        let pw_value = new_pw();
        let mut busy = busy;
        let mut error = error;
        let mut new_code = new_code;
        busy.set(true);
        error.set(None);
        spawn(async move {
            match reset_password_with_code(&email_value, &code_value, &pw_value).await {
                Ok(ack) if ack.ok => {
                    new_code.set(Some(ack.new_recovery_code));
                    busy.set(false);
                }
                Ok(ack) => {
                    error.set(Some(if ack.detail.is_empty() {
                        "That email and recovery code didn't match.".to_string()
                    } else {
                        ack.detail
                    }));
                    busy.set(false);
                }
                Err(e) => {
                    error.set(Some(e.to_string()));
                    busy.set(false);
                }
            }
        });
    };

    // Success view: show the rotated recovery code to save, then back to Sign-in.
    if let Some(fresh) = new_code() {
        return rsx! {
            div { class: "gate-hero", dangerous_inner_html: "{svg(\"check\")}" }
            h2 { class: "gate-title", "Password reset" }
            p { class: "gate-lede",
                "Your password is updated and you're signed out everywhere. "
                "Here is your NEW recovery code — the old one no longer works."
            }
            div { class: "recovery-code", role: "text", "aria-label": "New recovery code", "{fresh}" }
            button {
                class: "gate-ghost copy-btn",
                onclick: {
                    let fresh = fresh.clone();
                    move |_| { let _ = crate::media::copy_to_clipboard(&fresh); }
                },
                span { dangerous_inner_html: "{svg(\"copy\")}" }
                "Copy code"
            }
            button {
                class: "gate-primary",
                onclick: move |_| { nav.replace(Route::Auth {}); },
                "Back to sign in"
            }
        };
    }

    rsx! {
        div { class: "gate-hero", dangerous_inner_html: "{svg(\"key\")}" }
        h2 { class: "gate-title", "Reset your password" }
        p { class: "gate-lede",
            "Use the recovery code you saved when you created your account on {status().server_label} — "
            "or have a code emailed to you."
        }

        div { class: "gate-field",
            label { r#for: "fp-email", "Email" }
            input {
                id: "fp-email",
                r#type: "email",
                autofocus: true,
                placeholder: "guardian@example.com",
                value: "{email}",
                oninput: move |e| email.set(e.value()),
            }
        }

        button {
            class: "gate-ghost",
            disabled: emailing() || !can_email,
            onclick: move |_| request_email(()),
            span { class: "gg-ic", dangerous_inner_html: "{svg(\"mail\")}" }
            if emailing() { "Sending…" } else { "Email me a code instead" }
        }
        if let Some(msg) = emailed() {
            div { class: "gate-info",
                span { dangerous_inner_html: "{svg(\"info\")}" }
                "{msg}"
            }
        }

        div { class: "gate-field",
            label { r#for: "fp-code", "Recovery or emailed code" }
            input {
                id: "fp-code",
                r#type: "text",
                class: "mono",
                placeholder: "XXXXX-XXXXX-XXXXX-XXXXX",
                value: "{code}",
                oninput: move |e| code.set(e.value()),
            }
        }
        div { class: "gate-field",
            label { r#for: "fp-pw", "New password" }
            input {
                id: "fp-pw",
                r#type: "password",
                placeholder: "At least 8 characters",
                value: "{new_pw}",
                oninput: move |e| new_pw.set(e.value()),
                onkeydown: move |e| { if e.key() == Key::Enter { submit(()); } },
            }
            if !new_pw().is_empty() {
                PasswordStrength { len: pw_len }
            }
        }

        button {
            class: "gate-primary",
            disabled: busy() || !can_submit,
            onclick: move |_| submit(()),
            if busy() { "Resetting…" } else { "Reset password" }
        }

        if let Some(err) = error() {
            div { class: "gate-error",
                span { dangerous_inner_html: "{svg(\"alert\")}" }
                "{err}"
            }
        }

        button {
            class: "gate-ghost",
            onclick: move |_| { nav.push(Route::Auth {}); },
            "Back to sign in"
        }
    }
}

/// Inline password-strength hint (length-based, calm — not a scary meter).
#[component]
fn PasswordStrength(len: usize) -> Element {
    let (cls, label) = if len >= 12 {
        ("ps-strong", "Strong")
    } else if len >= 8 {
        ("ps-ok", "Good")
    } else {
        ("ps-weak", "Too short — use at least 8")
    };
    rsx! {
        div { class: "pw-strength",
            div { class: "pw-bar",
                div { class: "pw-fill {cls}", style: "width: {strength_pct(len)}%" }
            }
            span { class: "pw-label {cls}", "{label}" }
        }
    }
}

fn strength_pct(len: usize) -> u32 {
    ((len.min(12) as f32 / 12.0) * 100.0).round() as u32
}

/// Cheap, honest email shape check (one `@`, a dot in the domain). Not RFC-perfect
/// — just enough to catch obvious typos before a round-trip.
fn email_looks_valid(email: &str) -> bool {
    let e = email.trim();
    let mut parts = e.splitn(2, '@');
    let (local, domain) = match (parts.next(), parts.next()) {
        (Some(l), Some(d)) => (l, d),
        _ => return false,
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains(' ')
}

/// "/setup-lock" — offered right after a successful sign-in: set a 4–6 digit
/// quick-unlock PIN (+ enable biometric where available). Fully skippable.
#[component]
pub fn SetupLock() -> Element {
    let nav = use_navigator();
    let mut pin = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut err = use_signal(|| Option::<String>::None);

    let pin_val = pin();
    let confirm_val = confirm();
    let shape_ok = validate_pin_shape(&pin_val).is_ok();
    let matches = !confirm_val.is_empty() && pin_val == confirm_val;
    let can_save = shape_ok && matches;

    rsx! {
        div { class: "gate-hero locked", role: "img", "aria-label": "Lock",
            dangerous_inner_html: "{svg(\"lock\")}"
        }
        h2 { class: "gate-title", "Stay signed in" }
        p { class: "gate-lede",
            "Set a quick-unlock PIN so you can re-open the Manager without typing your password each time. Your session stays on this device."
        }

        if biometric_available() {
            div { class: "gate-privacy",
                span { class: "gp-ic", dangerous_inner_html: "{svg(\"fingerprint\")}" }
                span { "Biometric unlock is available on this device — you'll be able to unlock with it, with the PIN as a backup." }
            }
        }

        div { class: "gate-field",
            label { "Create a PIN ({PIN_MIN}–{PIN_MAX} digits)" }
            input {
                r#type: "password",
                inputmode: "numeric",
                placeholder: "••••",
                maxlength: "{PIN_MAX}",
                value: "{pin}",
                oninput: move |e| {
                    let v: String = e.value().chars().filter(|c| c.is_ascii_digit()).take(PIN_MAX).collect();
                    pin.set(v);
                },
            }
        }
        div { class: "gate-field",
            label { "Confirm PIN" }
            input {
                r#type: "password",
                inputmode: "numeric",
                placeholder: "••••",
                maxlength: "{PIN_MAX}",
                value: "{confirm}",
                oninput: move |e| {
                    let v: String = e.value().chars().filter(|c| c.is_ascii_digit()).take(PIN_MAX).collect();
                    confirm.set(v);
                },
            }
            if !confirm_val.is_empty() && !matches {
                span { class: "gate-hint-bad", "PINs don't match yet." }
            }
        }

        if let Some(e) = err() {
            div { class: "gate-error",
                span { dangerous_inner_html: "{svg(\"alert\")}" }
                "{e}"
            }
        }

        button {
            class: "gate-primary",
            disabled: !can_save,
            onclick: move |_| {
                match set_pin(&pin()) {
                    Ok(()) => { nav.replace(Route::Alerts {}); }
                    Err(e) => err.set(Some(e)),
                }
            },
            "Set PIN and continue"
        }
        button {
            class: "gate-ghost",
            onclick: move |_| { nav.replace(Route::Alerts {}); },
            "Skip for now"
        }
        p { class: "gate-fine",
            "Skipping is fine — you'll stay signed in on this device, and you can set a PIN anytime in Settings."
        }
    }
}

/// "/lock" — shown on re-open when a saved session AND a PIN exist. Unlock via
/// biometric (preferred affordance, when wired) or the PIN. Always offers the PIN.
#[component]
pub fn Lock() -> Element {
    let nav = use_navigator();
    let mut auth = use_context::<AuthState>();
    let status = auth.status;
    let mut pin = use_signal(String::new);
    let mut err = use_signal(|| Option::<String>::None);
    let tries = use_signal(|| 0u32);

    let unlock = move |entered: String| {
        let auth = auth;
        let mut err = err;
        let mut tries = tries;
        let mut pin = pin;
        if verify_pin(&entered) {
            let mut unlocked = auth.unlocked;
            unlocked.set(true);
            nav.replace(Route::Alerts {});
        } else {
            tries.set(tries() + 1);
            pin.set(String::new());
            err.set(Some("That PIN didn't match. Try again.".to_string()));
        }
    };

    rsx! {
        div { class: "gate-hero locked", role: "img", "aria-label": "Locked",
            dangerous_inner_html: "{svg(\"lock\")}"
        }
        h2 { class: "gate-title", "Welcome back" }
        p { class: "gate-lede", "Unlock the Manager for {status().server_label}." }

        if biometric_available() {
            button {
                class: "gate-primary",
                onclick: move |_| {
                    match biometric_unlock() {
                        BiometricOutcome::Verified => {
                            let mut unlocked = auth.unlocked;
                            unlocked.set(true);
                            nav.replace(Route::Alerts {});
                        }
                        // Declined/Unavailable → stay on the PIN (the real path).
                        _ => err.set(Some("Biometric unavailable — enter your PIN.".to_string())),
                    }
                },
                "Unlock with biometrics"
            }
            div { class: "gate-or", span { "or enter your PIN" } }
        }

        div { class: "gate-field",
            label { r#for: "lock-pin", "PIN" }
            input {
                id: "lock-pin",
                r#type: "password",
                inputmode: "numeric",
                autofocus: true,
                placeholder: "••••",
                maxlength: "{PIN_MAX}",
                value: "{pin}",
                oninput: move |e| {
                    let v: String = e.value().chars().filter(|c| c.is_ascii_digit()).take(PIN_MAX).collect();
                    pin.set(v);
                },
                onkeydown: move |e| {
                    if e.key() == Key::Enter {
                        unlock(pin());
                    }
                },
            }
        }

        if let Some(e) = err() {
            div { class: "gate-error",
                span { dangerous_inner_html: "{svg(\"alert\")}" }
                "{e}"
            }
        }
        if tries() >= 3 {
            div { class: "gate-info",
                span { dangerous_inner_html: "{svg(\"info\")}" }
                "Forgot your PIN? Sign out and sign back in with your email and password."
            }
        }

        button {
            class: "gate-primary",
            disabled: pin().chars().count() < PIN_MIN,
            onclick: move |_| { unlock(pin()); },
            "Unlock"
        }
        button {
            class: "gate-ghost danger-link",
            onclick: move |_| {
                // Full sign-out: drop the session + PIN, return to Welcome.
                let _ = crate::servers::clear_guardian_token();
                let _ = clear_pin();
                let mut unlocked = auth.unlocked;
                unlocked.set(false);
                auth.refresh();
                nav.replace(Route::Welcome {});
            },
            "Sign out instead"
        }
    }
}

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
                div { class: "protect-state-wrap",
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
                div { class: "err",
                    span { dangerous_inner_html: "{svg(\"alert\")}" }
                    "{err}"
                }
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
        section { class: "panel",
            div { class: "panel-head",
                h2 { "Region & server" }
                p { class: "sub",
                    "Choose the one server your family's data routes through. Each region keeps its own saved sign-in — switching is safe and reversible."
                }
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
                class: "primary",
                onclick: move |_| {
                    let choice = selected();
                    match save_server_choice(&choice) {
                        Ok(()) => {
                            on_saved.call(());
                            note.set(Some("Saved — this region now has its own guardian session.".to_string()));
                        }
                        Err(e) => note.set(Some(format!("Couldn't save: {e}"))),
                    }
                },
                "Save region"
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

/// Remote-notification settings — the guardian registers a self-hosted
/// **UnifiedPush** endpoint (FOSS; no Google/Apple) so safety alerts can reach
/// THIS device when they're away from the child's device. The redacted alert is
/// HTTP-POSTed by the server to the endpoint URL; no alert content is sent at
/// registration time, and registration is AUTHENTICATED with the guardian's
/// session token. On Android the endpoint URL is acquired natively from the
/// device's UnifiedPush distributor (the bundled `PushService` writes it to the
/// app files dir and this field auto-fills on mount); on desktop, paste your
/// distributor's topic URL by hand (e.g. an `ntfy` topic). See
/// docs/design/parent-notifications.md.
#[component]
pub fn NotificationsPanel() -> Element {
    let mut endpoint = use_signal(saved_push_endpoint);
    let busy = use_signal(|| false);
    let mut note = use_signal(|| Option::<String>::None);
    let mut error = use_signal(|| Option::<String>::None);
    let mut registered = use_signal(|| !saved_push_endpoint().is_empty());

    let save_and_register = move |_: ()| {
        if busy() {
            return;
        }
        let value = endpoint().trim().to_string();
        let mut busy = busy;
        let mut note = note;
        let mut error = error;
        let mut registered = registered;
        busy.set(true);
        note.set(None);
        error.set(None);
        spawn(async move {
            // Persist FIRST so a later sign-in re-registers it automatically,
            // then register with the current server (carries the guardian token).
            if let Err(e) = save_push_endpoint(&value) {
                error.set(Some(format!("Couldn't save the endpoint: {e}")));
                busy.set(false);
                return;
            }
            match register_push_target(&value).await {
                Ok(()) => {
                    registered.set(true);
                    note.set(Some(
                        "Saved on this device. Remote delivery to the Manager switches on \
                         automatically once per-guardian alert routing ships — until then your \
                         endpoint stays on this device only."
                            .to_string(),
                    ));
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    rsx! {
        section { class: "panel",
            div { class: "panel-head",
                h2 { "Notifications" }
                p { class: "sub",
                    "Get safety alerts on this device through a self-hosted, open-source push service (UnifiedPush) — no Google or Apple services involved. Only redacted, content-free alerts are ever sent."
                }
            }

            div { class: "box",
                h3 { "Self-hosted push endpoint" }
                p { class: "sub",
                    "Paste the endpoint URL from your UnifiedPush distributor (for example an "
                    span { class: "mono", "ntfy" }
                    " topic URL like "
                    span { class: "mono", "https://ntfy.sh/your-topic" }
                    "). On Android this fills in automatically from your installed UnifiedPush distributor; on desktop, paste it here."
                }
                label { class: "field",
                    span { "Endpoint URL" }
                    input {
                        r#type: "url",
                        placeholder: "https://ntfy.sh/your-topic",
                        value: "{endpoint}",
                        oninput: move |e| endpoint.set(e.value()),
                    }
                }
                div { class: "row",
                    button {
                        class: "primary",
                        disabled: busy() || endpoint().trim().is_empty(),
                        onclick: move |_| save_and_register(()),
                        if busy() { "Saving…" } else { "Save endpoint" }
                    }
                    if registered() {
                        button {
                            class: "ghost danger-link",
                            disabled: busy(),
                            onclick: move |_| {
                                let _ = clear_push_endpoint();
                                endpoint.set(String::new());
                                registered.set(false);
                                note.set(Some("Removed the saved endpoint on this device. Existing server registrations expire on their own.".to_string()));
                                error.set(None);
                            },
                            "Forget endpoint"
                        }
                    }
                }

                div { class: "hint",
                    "Registration is signed in with your guardian account — the server only accepts an endpoint from an authenticated guardian, and rejects anything that isn't a public https URL."
                }

                if let Some(n) = note() {
                    div { class: "seg-note", "{n}" }
                }
                if let Some(e) = error() {
                    div { class: "err",
                        span { dangerous_inner_html: "{svg(\"alert\")}" }
                        "Couldn't register notifications: {e}"
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Routed screens (one per console tab — `crate::router::Route`). Bodies are
// the former `match active()` arms, verbatim; only the signal access moved to
// the shared `Console` context so typed form state survives tab switches.
// ---------------------------------------------------------------------------

/// The "add a child + pairing code" panel. POST-AUTH only (mounted inside the
/// `Children` console screen) — guardian sign-in now lives on the gate's `Auth`
/// screen, so this is purely the pairing step.
#[component]
pub fn AddChildPanel() -> Element {
    let console = use_context::<Console>();
    let mut child_name = console.child_name;
    let pair_code = console.pair_code;
    let setup_note = console.setup_note;
    let setup_error = console.setup_error;
    let setup_busy = console.setup_busy;
    rsx! {
        div { class: "box add-child",
            h3 { "Pair a new device" }
            p { class: "sub", "Give the child a name and generate a setup code to scan, paste, or type on their device. Nothing is installed without you." }
            label { class: "field",
                span { "Child's name" }
                input {
                    r#type: "text",
                    placeholder: "e.g. Maya",
                    value: "{child_name}",
                    oninput: move |e| child_name.set(e.value()),
                }
            }
            button {
                class: "primary",
                disabled: setup_busy() || child_name().trim().is_empty(),
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
                                setup_note.set(Some("Setup code ready — scan or paste it on the child's device.".to_string()));
                                pair_code.set(Some(pair));
                            }
                            Err(e) => setup_error.set(Some(e.to_string())),
                        }
                        setup_busy.set(false);
                    });
                },
                if setup_busy() { "Working…" } else { "Generate setup code" }
            }
            if let Some(pair) = pair_code() {
                SetupCodePanel { pair: pair.clone() }
            }
            if let Some(note) = setup_note() {
                div { class: "ok-note",
                    span { dangerous_inner_html: "{svg(\"check\")}" }
                    "{note}"
                }
            }
            if let Some(err) = setup_error() {
                div { class: "err",
                    span { dangerous_inner_html: "{svg(\"alert\")}" }
                    "{err}"
                }
            }
        }
    }
}

/// The "Setup code" panel shown once a pair code is minted: the short code big
/// and segmented (the type-it-by-hand fallback), a QR of the full v2 setup
/// payload (the child app scans it via "Scan the setup QR"; copy/paste is the
/// fallback), and a one-tap copy of the same JSON for the child app's paste
/// field. The payload bundles the server address, this one-time code + expiry,
/// the child's name, and — when the active server has a pinned CA — that
/// public certificate, so the child device can make its first secure call. If
/// the payload can't be built, the short code alone still pairs — never blocked.
#[component]
fn SetupCodePanel(pair: PairCodeUi) -> Element {
    let mut copied = use_signal(|| false);
    // Built fresh each render (a small file read), so the pinned-CA state for
    // the active server is always current.
    let payload = setup_payload_v2(&pair.child_name, &pair.code, pair.expires_ts, true);
    // QR of the full payload; if a large pinned CA makes it too dense to encode,
    // fall back to a QR without the CA (scanning still fills server + code —
    // the copy button below always carries the complete payload).
    let (qr, qr_is_complete) = match payload.as_deref().and_then(pair_qr_svg) {
        Some(full) => (Some(full), true),
        None => (
            setup_payload_v2(&pair.child_name, &pair.code, pair.expires_ts, false)
                .as_deref()
                .and_then(pair_qr_svg),
            false,
        ),
    };
    rsx! {
        div { class: "pair-code",
            div { class: "preview-label", "Setup code for {pair.child_name}" }
            div { class: "code-seg", role: "text", "aria-label": "Pairing code {pair.code}",
                for (i, group) in segment_code(&pair.code).into_iter().enumerate() {
                    span { key: "{i}", "{group}" }
                }
            }
            div { class: "meta", "{pair_expiry_text(pair.expires_ts)}" }
            if let Some(qr) = qr {
                div { class: "pair-qr",
                    div {
                        class: "pair-qr-img setup-qr-img",
                        role: "img",
                        "aria-label": "Pairing QR code for {pair.child_name}",
                        dangerous_inner_html: "{qr}",
                    }
                    div { class: "hint",
                        if qr_is_complete {
                            "On your child's phone, tap \u{201c}Scan the setup QR\u{201d} in PH Bulwark and point it here — or use \u{201c}Copy setup code\u{201d} and paste it. It carries the server address and this one-time pairing code."
                        } else {
                            "This server's pinned certificate doesn't fit in a QR — use \u{201c}Copy setup code\u{201d} and paste it into PH Bulwark on your child's phone instead."
                        }
                    }
                }
            }
            if let Some(full) = payload {
                div { class: "setup-row",
                    button {
                        class: "ghost copy-btn",
                        "aria-label": "Copy setup code",
                        onclick: move |_| {
                            let _ = crate::media::copy_to_clipboard(&full);
                            copied.set(true);
                            spawn(async move {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                copied.set(false);
                            });
                        },
                        span { dangerous_inner_html: "{svg(\"copy\")}" }
                        if copied() { "Copied" } else { "Copy setup code" }
                    }
                }
            } else {
                div { class: "hint",
                    "Type the code into PH Bulwark on your child's phone, choosing the same region."
                }
            }
        }
    }
}

/// "Provision a dedicated device" panel — generates the Android **Device-Owner**
/// enrollment QR for a freshly factory-reset phone you're dedicating to a child.
/// Scanning it from the Android Setup Wizard ("tap the welcome screen 6 times")
/// installs PH Bulwark as the device owner and auto-links it to the chosen child,
/// so protection is on from first boot and the child cannot remove it. The child
/// id + family id come from the roster above; Wi-Fi is optional (a wiped device
/// needs a network to download the app before any account exists).
#[component]
fn ProvisionDevicePanel() -> Element {
    let mut child_id = use_signal(String::new);
    let mut family_id = use_signal(String::new);
    let mut wifi_ssid = use_signal(String::new);
    let mut wifi_pw = use_signal(String::new);
    let mut json = use_signal(|| Option::<String>::None);
    // The QR only installs if the operator has filled the signed-APK URL + the
    // signing-certificate checksum in provision.rs — warn until they have.
    let not_ready = CHILD_APK_CERT_CHECKSUM.starts_with("TODO");
    rsx! {
        div { class: "box add-child",
            h3 { "Provision a dedicated device" }
            p { class: "sub",
                "For a NEW or wiped phone you\u{2019}re dedicating to a child: generate a setup QR, factory-reset that device, then on its first welcome screen tap the screen 6 times and scan this. PH Bulwark installs as the managed device-owner \u{2014} protection on from first boot, and the child can\u{2019}t remove it. Never do this on a phone holding data you need."
            }
            if not_ready {
                div { class: "err",
                    span { dangerous_inner_html: "{svg(\"alert\")}" }
                    "Not ready to ship: set the signed APK URL + signing-certificate checksum in provision.rs first \u{2014} the QR won\u{2019}t install the app without them."
                }
            }
            label { class: "field",
                span { "Child id (from the roster above)" }
                input { r#type: "text", placeholder: "child_\u{2026}", value: "{child_id}", oninput: move |e| child_id.set(e.value()) }
            }
            label { class: "field",
                span { "Family id" }
                input { r#type: "text", placeholder: "family_\u{2026}", value: "{family_id}", oninput: move |e| family_id.set(e.value()) }
            }
            label { class: "field",
                span { "Wi\u{2011}Fi network (optional \u{2014} a wiped device needs internet)" }
                input { r#type: "text", placeholder: "SSID", value: "{wifi_ssid}", oninput: move |e| wifi_ssid.set(e.value()) }
            }
            label { class: "field",
                span { "Wi\u{2011}Fi password (optional)" }
                input { r#type: "password", value: "{wifi_pw}", oninput: move |e| wifi_pw.set(e.value()) }
            }
            button {
                class: "primary",
                disabled: not_ready
                    || child_id().trim().is_empty()
                    || family_id().trim().is_empty(),
                onclick: move |_| {
                    let cid = child_id();
                    let fid = family_id();
                    let ssid = wifi_ssid();
                    let pw = wifi_pw();
                    let ssid_t = ssid.trim();
                    let params = ProvisioningParams {
                        child_id: cid.trim(),
                        family_id: fid.trim(),
                        cluster_endpoint_override: "",
                        wifi_ssid: if ssid_t.is_empty() { None } else { Some(ssid_t) },
                        wifi_password: if pw.is_empty() { None } else { Some(pw.as_str()) },
                        apk_url: "",
                        cert_checksum: "",
                    };
                    json.set(build_provisioning_json(&params));
                },
                "Generate provisioning QR"
            }
            if let Some(j) = json() {
                ProvisioningQrPanel { json: j }
            }
        }
    }
}

/// The provisioning QR + copy fallback, shown once a payload is built.
#[component]
fn ProvisioningQrPanel(json: String) -> Element {
    let mut copied = use_signal(|| false);
    let qr = provisioning_qr_svg(&json);
    rsx! {
        div { class: "pair-code",
            div { class: "preview-label", "Scan on the wiped device\u{2019}s welcome screen" }
            if let Some(qr) = qr {
                div { class: "pair-qr",
                    div {
                        class: "pair-qr-img setup-qr-img",
                        role: "img",
                        "aria-label": "Device provisioning QR code",
                        dangerous_inner_html: "{qr}",
                    }
                    div { class: "hint",
                        "Factory-reset the dedicated device, then on its very first welcome screen tap the screen 6 times and scan this. It downloads PH Bulwark and sets it as the managed device-owner, linked to this child."
                    }
                }
            } else {
                div { class: "err",
                    span { dangerous_inner_html: "{svg(\"alert\")}" }
                    "This provisioning payload is too large to encode as a QR \u{2014} use \u{201c}Copy provisioning JSON\u{201d} instead."
                }
            }
            div { class: "setup-row",
                button {
                    class: "ghost copy-btn",
                    "aria-label": "Copy provisioning JSON",
                    onclick: move |_| {
                        let _ = crate::media::copy_to_clipboard(&json);
                        copied.set(true);
                        spawn(async move {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            copied.set(false);
                        });
                    },
                    span { dangerous_inner_html: "{svg(\"copy\")}" }
                    if copied() { "Copied" } else { "Copy provisioning JSON" }
                }
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
            h2 { "Safety alerts" }
            p { class: "sub",
                if offline() { "Reconnecting — live alerts will resume automatically." } else { "Calm, redacted summaries of anything flagged on the devices in your care. Review and decide what to do." }
            }
        }
        if alerts.read().is_empty() {
            div { class: "empty-state",
                div { class: "empty-ic", dangerous_inner_html: "{svg(\"leaf\")}" }
                p { class: "empty", "All clear — nothing needs you right now." }
                p { class: "empty-sub", "When something is flagged on a child's device, a calm summary appears here for you to review." }
            }
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

/// "/children" — roster + per-child filtering controls + add-a-child pairing.
#[component]
pub fn Children() -> Element {
    let console = use_context::<Console>();
    let children = console.children;
    let children_error = console.children_error;
    let children_busy = console.children_busy;

    // One roster-load path, shared by the mount auto-load and the manual
    // "Refresh roster" button so the two can't drift. The synchronous body
    // reads NO signal it also writes — the in-flight guard and every `set`
    // live inside the spawned task. That keeps the `use_effect` below from
    // subscribing to `children_busy` (which it flips), which would otherwise
    // re-trigger the effect each time the load finishes and loop the RPC.
    // Same shape as `ChildVpnRow`'s seed effect.
    let load_roster = move || {
        let mut children = children;
        let mut children_busy = children_busy;
        let mut children_error = children_error;
        spawn(async move {
            if children_busy() {
                return;
            }
            children_busy.set(true);
            children_error.set(None);
            match load_children().await {
                Ok(rows) => children.set(rows),
                Err(e) => children_error.set(Some(e.to_string())),
            }
            children_busy.set(false);
        });
    };

    // Auto-load the roster once when the tab mounts, so a guardian opening
    // Children sees their paired devices without a manual refresh (mirrors the
    // alert stream auto-connecting and ChildVpnRow auto-seeding its draft).
    use_effect(load_roster);

    rsx! {
    section { class: "panel",
        div { class: "panel-head split",
            div {
                h2 { "Your children" }
                p { class: "sub", "Everyone protected by your account on this region. Set each child's filtering region, strictness, and whether protection is on — changes are sent straight to their device." }
            }
            button {
                class: "ghost",
                disabled: children_busy(),
                onclick: move |_| load_roster(),
                if children_busy() { "Refreshing…" } else { "Refresh roster" }
            }
        }
        if let Some(err) = children_error() {
            div { class: "err",
                span { dangerous_inner_html: "{svg(\"alert\")}" }
                "{err}"
            }
        }
        if children.read().is_empty() && !children_busy() {
            div { class: "empty-state",
                div { class: "empty-ic", dangerous_inner_html: "{svg(\"child\")}" }
                p { class: "empty", "No children here yet." }
                p { class: "empty-sub", "Pair your first device below — it takes about a minute. Already paired one? Try \u{201c}Refresh roster\u{201d} above." }
            }
        }
        for child in children.read().clone().into_iter() {
            div { class: "child-card", key: "{child.child_id}",
                div { class: "child-hero",
                    div { class: "child-avatar", "{name_initial(&child.child_name)}" }
                    div { class: "child-id",
                        div { class: "child-name", "{child.child_name}" }
                        div { class: "child-device mono", "device {child.device_id}" }
                        span { class: "child-care",
                            span { dangerous_inner_html: "{svg(\"shield-check\")}" }
                            "In your care"
                        }
                    }
                    div { class: "child-guardians",
                        strong { "{child.guardian_account_ids.len()}" }
                        if child.guardian_account_ids.len() == 1 { "guardian" } else { "guardians" }
                    }
                }
                ChildVpnRow { child: child.clone() }
            }
        }

        AddChildPanel {}

        ProvisionDevicePanel {}
    }
    }
}

/// First letter of a child's display name for the avatar tile (uppercased).
/// Falls back to a bullet for an empty name so the tile never renders blank.
fn name_initial(name: &str) -> String {
    name.trim()
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "\u{2022}".to_string())
}

/// "/protection" — the local protection control panel.
#[component]
pub fn Protection() -> Element {
    rsx! { ProtectionPanel {} }
}

/// "/server" — server/region settings; refreshes the gate's status snapshot on
/// save (switching servers can change whether a session exists, so the guard
/// re-evaluates reachability on the next render).
#[component]
pub fn Server() -> Element {
    let mut auth = use_context::<AuthState>();
    rsx! {
        ServerSettingsPanel {
            on_saved: move |_| auth.refresh()
        }
        NotificationsPanel {}
    }
}

/// "/coverage" — the honest enforcement coverage matrix.
#[component]
pub fn Coverage() -> Element {
    rsx! {
        section { class: "panel",
            div { class: "panel-head",
                h2 { "What's covered" }
                p { class: "sub", "An honest, current view of what filtering reaches on each device and surface — not the future roadmap. We'd rather be clear about the gaps." }
            }
            CoverageMatrix {}
        }
    }
}

/// "/console/change-password" — the signed-in guardian changes their password
/// (proves the old one). Server invalidates the account's OTHER sessions on
/// success; this one stays live.
#[component]
pub fn ChangePassword() -> Element {
    let nav = use_navigator();
    let mut old_pw = use_signal(String::new);
    let mut new_pw = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let busy = use_signal(|| false);
    let error = use_signal(|| Option::<String>::None);
    let done = use_signal(|| false);

    let new_len = new_pw().chars().count();
    let matches = !confirm().is_empty() && new_pw() == confirm();
    let can_submit = !old_pw().is_empty() && new_len >= 8 && matches;

    let submit = move |_: ()| {
        if busy() || !can_submit {
            return;
        }
        let old_value = old_pw();
        let new_value = new_pw();
        let mut busy = busy;
        let mut error = error;
        let mut done = done;
        busy.set(true);
        error.set(None);
        spawn(async move {
            match change_guardian_password(&old_value, &new_value).await {
                Ok(_) => {
                    done.set(true);
                    busy.set(false);
                }
                Err(e) => {
                    error.set(Some(e.to_string()));
                    busy.set(false);
                }
            }
        });
    };

    rsx! {
        section { class: "panel panel-narrow",
            div { class: "panel-head",
                h2 { "Change your password" }
                p { class: "sub", "Choose a new password for your guardian account. For your safety, this signs out your other devices." }
            }

            if done() {
                div { class: "ok-banner",
                    span { dangerous_inner_html: "{svg(\"check\")}" }
                    "Password changed. Your other devices have been signed out."
                }
                button {
                    class: "primary",
                    onclick: move |_| { nav.replace(Route::Alerts {}); },
                    "Back to alerts"
                }
            } else {
                div { class: "field",
                    label { r#for: "cp-old", "Current password" }
                    input {
                        id: "cp-old",
                        r#type: "password",
                        autofocus: true,
                        value: "{old_pw}",
                        oninput: move |e| old_pw.set(e.value()),
                    }
                }
                div { class: "field",
                    label { r#for: "cp-new", "New password" }
                    input {
                        id: "cp-new",
                        r#type: "password",
                        placeholder: "At least 8 characters",
                        value: "{new_pw}",
                        oninput: move |e| new_pw.set(e.value()),
                    }
                    if !new_pw().is_empty() {
                        PasswordStrength { len: new_len }
                    }
                }
                div { class: "field",
                    label { r#for: "cp-confirm", "Confirm new password" }
                    input {
                        id: "cp-confirm",
                        r#type: "password",
                        value: "{confirm}",
                        oninput: move |e| confirm.set(e.value()),
                        onkeydown: move |e| { if e.key() == Key::Enter { submit(()); } },
                    }
                    if !confirm().is_empty() && !matches {
                        span { class: "gate-hint-bad", "Passwords don't match." }
                    }
                }

                if let Some(err) = error() {
                    div { class: "gate-error",
                        span { dangerous_inner_html: "{svg(\"alert\")}" }
                        "{err}"
                    }
                }

                div { class: "row",
                    button {
                        class: "primary",
                        disabled: busy() || !can_submit,
                        onclick: move |_| submit(()),
                        if busy() { "Saving…" } else { "Change password" }
                    }
                    button {
                        class: "ghost",
                        onclick: move |_| { nav.go_back(); },
                        "Cancel"
                    }
                }
            }
        }
    }
}
