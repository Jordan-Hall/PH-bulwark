//! `dioxus-router` wiring for the console: the typed `Route` enum + the
//! persistent `ConsoleLayout` (topbar + status grid + tab Links) wrapping every
//! screen's `Outlet`. Each route maps to a component of the same name in
//! `crate::screens`.

use std::time::Duration;

use dioxus::prelude::*;

use crate::api::open_pending_review_stream;
use crate::screens::{Alerts, Children, Coverage, Protection, Server, Setup};
use crate::state::{seed, session_status_text, Alert, AppStatus, Console};
use crate::theme::CSS;

/// One route per console tab, all nested under the shared `ConsoleLayout`.
#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    #[layout(ConsoleLayout)]
    #[route("/")]
    Setup {},
    #[route("/alerts")]
    Alerts {},
    #[route("/children")]
    Children {},
    #[route("/protection")]
    Protection {},
    #[route("/server")]
    Server {},
    #[route("/coverage")]
    Coverage {},
}

/// Tab styling: the router replaces the old `ActiveView` + `nav_class` pair.
fn tab_class(current: &Route, target: &Route) -> &'static str {
    if current == target {
        "nav-btn nav-on"
    } else {
        "nav-btn"
    }
}

/// Root: provide the shared console state, start the review-stream coroutine,
/// then mount the router. (No `use_route` here — we are outside the Router.)
#[component]
pub fn App() -> Element {
    let console = use_context_provider(Console::new);
    let mut alerts = console.alerts;
    let mut offline = console.offline;

    use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
        loop {
            let mut stream = match open_pending_review_stream().await {
                Ok(stream) => stream,
                Err(_e) => {
                    offline.set(true);
                    if alerts.read().is_empty() {
                        alerts.set(seed());
                    }
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

/// Persistent chrome (style + topbar + status grid + tab Links + banners)
/// wrapping every routed screen.
#[component]
fn ConsoleLayout() -> Element {
    let route = use_route::<Route>();
    let console = use_context::<Console>();
    let alerts = console.alerts;
    let offline = console.offline;
    let action_error = console.action_error;
    let mut status = console.status;
    rsx! {
        style { {CSS} }
        div { class: "app",
            header { class: "topbar",
                div {
                    h1 { "PH Bulwark Manager" }
                    p { class: "sub",
                        "Transparent content-safety for managed child devices. No device control, screen capture, or hidden monitoring."
                    }
                }
                button {
                    class: "ghost",
                    onclick: move |_| status.set(AppStatus::load()),
                    "Refresh"
                }
            }

            div { class: "status-grid",
                div { class: "status-tile",
                    span { class: "status-k", "Server" }
                    span { class: "status-v", "{status().server_label}" }
                    span { class: "status-sub mono", "{status().endpoint}" }
                }
                div { class: "status-tile",
                    span { class: "status-k", "Guardian" }
                    span {
                        class: if status().logged_in { "status-v ok" } else { "status-v warn" },
                        "{session_status_text(&status())}"
                    }
                    span { class: "status-sub mono", "session {status().session_key}" }
                }
                div { class: "status-tile",
                    span { class: "status-k", "Alerts" }
                    span { class: "status-v", "{alerts.read().len()}" }
                    span { class: "status-sub",
                        if offline() { "Demo/disconnected" } else { "Live stream" }
                    }
                }
            }

            nav { class: "tabs",
                Link { class: tab_class(&route, &Route::Setup {}), to: Route::Setup {}, "Setup" }
                Link { class: tab_class(&route, &Route::Alerts {}), to: Route::Alerts {}, "Alerts" }
                Link { class: tab_class(&route, &Route::Children {}), to: Route::Children {}, "Children" }
                Link { class: tab_class(&route, &Route::Protection {}), to: Route::Protection {}, "Protection" }
                Link { class: tab_class(&route, &Route::Server {}), to: Route::Server {}, "Server" }
                Link { class: tab_class(&route, &Route::Coverage {}), to: Route::Coverage {}, "Coverage" }
            }

            if offline() {
                div { class: "banner", "Demo mode — sample alerts are shown until a live guardian session connects." }
            }

            if let Some(err) = action_error() {
                div { class: "err", "Couldn't send your decision: {err}" }
            }

            Outlet::<Route> {}
        }
    }
}
