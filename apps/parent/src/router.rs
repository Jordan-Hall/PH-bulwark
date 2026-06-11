//! `dioxus-router` wiring for the console, now AUTH-GATED.
//!
//! Nothing in the console (alerts/children/protection/server/coverage) is
//! reachable until a guardian session exists for the selected server AND the app
//! lock has been cleared. The route set has two layers:
//!
//! * **Gate screens** — `Splash` (decides where to send the guardian), `Welcome`,
//!   `ChooseServer`, `Auth` (sign-in / create), `SetupLock`, `Lock`. These render
//!   with their OWN calm chrome (no console topbar/tabs) under `GateLayout`.
//! * **Console screens** — the original six tabs, wrapped by `ConsoleLayout`,
//!   which is itself a GUARD: if the console isn't reachable it renders nothing
//!   and `replace()`s back to `Splash`. So even a hand-typed `/alerts` URL can't
//!   show data before auth.
//!
//! The guard pattern (this router alpha has no built-in `onEnter`): a guarded
//! layout reads `AuthState`, and when the gate isn't satisfied it schedules a
//! `navigator().replace(Splash)` in `use_effect` and renders an empty node that
//! same frame — no flash of protected content.

use std::time::Duration;

use dioxus::prelude::*;

use crate::api::open_pending_review_stream;
use crate::brand::logo_data_uri;
use crate::icons::svg;
use crate::screens::{
    Alerts, Auth, ChangePassword, Children, ChooseServer, Coverage, ForgotPassword, Lock,
    Protection, Server, SetupLock, Splash, Welcome,
};
use crate::state::{session_status_text, Alert, AuthPhase, AuthState, Console};
use crate::theme::CSS;

/// Two layout groups: the calm GATE flow and the guarded CONSOLE.
#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    // --- Gate flow (no console chrome) ---
    #[layout(GateLayout)]
    /// Index: decides Lock / console / welcome from saved state and redirects.
    #[route("/")]
    Splash {},
    #[route("/welcome")]
    Welcome {},
    #[route("/choose-server")]
    ChooseServer {},
    #[route("/auth")]
    Auth {},
    #[route("/forgot-password")]
    ForgotPassword {},
    #[route("/setup-lock")]
    SetupLock {},
    #[route("/lock")]
    Lock {},
    #[end_layout]
    // --- Console (guarded by ConsoleLayout) ---
    #[layout(ConsoleLayout)]
    #[route("/console/alerts")]
    Alerts {},
    #[route("/console/children")]
    Children {},
    #[route("/console/protection")]
    Protection {},
    #[route("/console/server")]
    Server {},
    #[route("/console/coverage")]
    Coverage {},
    #[route("/console/change-password")]
    ChangePassword {},
}

/// Tab styling for the console nav.
fn tab_class(current: &Route, target: &Route) -> &'static str {
    if current == target {
        "nav-btn nav-on"
    } else {
        "nav-btn"
    }
}

/// Root: provide the shared console + auth state, start the review-stream
/// coroutine (a no-op data-wise until a session exists), then mount the router.
#[component]
pub fn App() -> Element {
    let console = use_context_provider(Console::new);
    let _auth = use_context_provider(AuthState::new);
    let mut alerts = console.alerts;
    let mut offline = console.offline;

    use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
        loop {
            // No saved session → nothing to stream; idle until one appears. (No
            // demo seeding — the gate keeps the console unreachable until auth.)
            if crate::servers::guardian_token().is_empty() {
                offline.set(false);
                if !alerts.read().is_empty() {
                    alerts.write().clear();
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            let mut stream = match open_pending_review_stream().await {
                Ok(stream) => stream,
                Err(_e) => {
                    offline.set(true);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            offline.set(false);
            alerts.write().clear();

            while let Ok(Some(event)) = stream.message().await {
                let alert = Alert::from_event(event);
                let mut list = alerts.write();
                if !list.iter().any(|a| a.id == alert.id) {
                    list.insert(0, alert);
                }
            }

            offline.set(true);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    rsx! { Router::<Route> {} }
}

/// Calm chrome for the GATE flow: the brand wordmark + a centered card stage.
/// Distinct from the console chrome — pre-auth there is no topbar/status/tabs.
#[component]
fn GateLayout() -> Element {
    rsx! {
        style { {CSS} }
        div { class: "gate-stage",
            div { class: "gate-aurora" }
            div { class: "gate-brand",
                img {
                    class: "brand-logo-chip",
                    src: "{logo_data_uri()}",
                    alt: "Bulwark Shield",
                }
                span { class: "gate-wordmark", "Manager" }
            }
            div { class: "gate-card",
                Outlet::<Route> {}
            }
            p { class: "gate-foot",
                "A calm, transparent way to help keep your child safer online. No screen capture, no location, no hidden monitoring."
            }
        }
    }
}

/// Persistent console chrome — AND the auth guard for every console screen.
/// If the console isn't reachable (no session, or locked), it renders nothing and
/// redirects to `Splash`, so no gated data ever paints.
#[component]
fn ConsoleLayout() -> Element {
    // All hooks run UNCONDITIONALLY (rules of hooks) — we branch on the result,
    // never on whether a hook is called.
    let nav = use_navigator();
    let auth = use_context::<AuthState>();
    let route = use_route::<Route>();
    let console = use_context::<Console>();

    let reachable = auth.console_reachable();

    // GUARD: the effect re-checks reachability each render and redirects when the
    // console is no longer reachable (no session / locked / "Lock now").
    use_effect(move || {
        if !auth.console_reachable() {
            nav.replace(Route::Splash {});
        }
    });

    // Render an empty calm frame this paint if not reachable — no gated content.
    if !reachable {
        return rsx! {
            style { {CSS} }
            div { class: "gate-stage" }
        };
    }

    let alerts = console.alerts;
    let offline = console.offline;
    let action_error = console.action_error;
    let status = auth.status;
    rsx! {
        style { {CSS} }
        div { class: "app",
            header { class: "topbar",
                div { class: "topbar-brand",
                    img {
                        class: "brand-logo-chip",
                        src: "{logo_data_uri()}",
                        alt: "Bulwark Shield",
                    }
                    div {
                        h1 {
                            "PH Bulwark "
                            span { class: "accent", "Manager" }
                        }
                        p { class: "sub",
                            "Calm, transparent content-safety for the devices in your care. No device control, screen capture, or hidden monitoring."
                        }
                    }
                }
                div { class: "topbar-actions",
                    ChangePwButton {}
                    LockNowButton {}
                    SignOutButton {}
                }
            }

            div { class: "status-grid",
                div { class: "status-tile",
                    span { class: "status-k", "Region" }
                    span { class: "status-v", "{status().server_label}" }
                    span { class: "status-sub mono", "{status().endpoint}" }
                }
                div { class: "status-tile",
                    span { class: "status-k", "Guardian" }
                    span {
                        class: if status().logged_in { "status-v ok" } else { "status-v warn" },
                        span {
                            class: if status().logged_in { "status-dot live" } else { "status-dot idle" },
                        }
                        "{session_status_text(&status())}"
                    }
                    span { class: "status-sub mono", "session {status().session_key}" }
                }
                div { class: "status-tile",
                    span { class: "status-k", "Alerts" }
                    span { class: "status-v", "{alerts.read().len()}" }
                    span { class: "status-sub",
                        if offline() { "Reconnecting…" } else { "Live — updating in real time" }
                    }
                }
            }

            nav { class: "tabs", "aria-label": "Console sections",
                Link { class: tab_class(&route, &Route::Alerts {}), to: Route::Alerts {},
                    span { class: "nav-ic", dangerous_inner_html: "{svg(\"bell\")}" }
                    "Alerts"
                }
                Link { class: tab_class(&route, &Route::Children {}), to: Route::Children {},
                    span { class: "nav-ic", dangerous_inner_html: "{svg(\"child\")}" }
                    "Children"
                }
                Link { class: tab_class(&route, &Route::Protection {}), to: Route::Protection {},
                    span { class: "nav-ic", dangerous_inner_html: "{svg(\"shield\")}" }
                    "Protection"
                }
                Link { class: tab_class(&route, &Route::Server {}), to: Route::Server {},
                    span { class: "nav-ic", dangerous_inner_html: "{svg(\"server\")}" }
                    "Region"
                }
                Link { class: tab_class(&route, &Route::Coverage {}), to: Route::Coverage {},
                    span { class: "nav-ic", dangerous_inner_html: "{svg(\"grid\")}" }
                    "Coverage"
                }
            }

            if offline() {
                div { class: "banner",
                    span { class: "banner-ic", dangerous_inner_html: "{svg(\"info\")}" }
                    "Reconnecting to your server — alerts will resume automatically."
                }
            }

            if let Some(err) = action_error() {
                div { class: "err",
                    span { dangerous_inner_html: "{svg(\"alert\")}" }
                    "Couldn't send your decision: {err}"
                }
            }

            Outlet::<Route> {}
        }
    }
}

/// "Change password": jump to the in-console change-password screen.
#[component]
fn ChangePwButton() -> Element {
    let nav = use_navigator();
    rsx! {
        button {
            class: "ghost",
            onclick: move |_| { nav.push(Route::ChangePassword {}); },
            span { class: "btn-ic", dangerous_inner_html: "{svg(\"key\")}" }
            "Password"
        }
    }
}

/// "Lock now": flip `unlocked` off (re-locks this app run) and go to the Lock
/// screen. Only meaningful when a PIN is set; otherwise it falls back to Splash.
#[component]
fn LockNowButton() -> Element {
    let nav = use_navigator();
    let auth = use_context::<AuthState>();
    rsx! {
        button {
            class: "ghost",
            onclick: move |_| {
                let mut unlocked = auth.unlocked;
                unlocked.set(false);
                if crate::lock::pin_is_set() {
                    nav.replace(Route::Lock {});
                } else {
                    nav.replace(Route::Splash {});
                }
            },
            span { class: "btn-ic", dangerous_inner_html: "{svg(\"lock\")}" }
            "Lock now"
        }
    }
}

/// "Sign out": clear the per-server session token, re-lock, and return to the
/// gate. (Leaves the PIN record alone — signing back in re-uses the same PIN.)
#[component]
fn SignOutButton() -> Element {
    let nav = use_navigator();
    let mut auth = use_context::<AuthState>();
    rsx! {
        button {
            class: "ghost danger-link",
            onclick: move |_| {
                let _ = crate::servers::clear_guardian_token();
                let mut unlocked = auth.unlocked;
                unlocked.set(false);
                auth.refresh();
                nav.replace(Route::Splash {});
            },
            span { class: "btn-ic", dangerous_inner_html: "{svg(\"lock-open\")}" }
            "Sign out"
        }
    }
}

/// Resolve the gate phase to its destination route (used by `Splash`).
pub fn phase_route(phase: AuthPhase) -> Route {
    match phase {
        AuthPhase::Locked => Route::Lock {},
        AuthPhase::Authed => Route::Alerts {},
        AuthPhase::NeedsSignIn => Route::Welcome {},
    }
}
