//! Router: a LOGIN gate (index) and a guarded CONSOLE (fleet health + audit).
//! The console layout is itself the auth guard — with no staff session it renders
//! nothing and redirects to the login screen, so no staff surface paints
//! pre-auth (mirrors the Manager's gate pattern).

use dioxus::prelude::*;

use crate::screens::{Audit, Cases, Fleet, Login, Support};
use crate::state::{role_label, StaffState};
use crate::theme::CSS;

#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    #[layout(GateLayout)]
    #[route("/")]
    Login {},
    #[end_layout]
    #[layout(ConsoleLayout)]
    #[route("/console/fleet")]
    Fleet {},
    #[route("/console/support")]
    Support {},
    #[route("/console/cases")]
    Cases {},
    #[route("/console/audit")]
    Audit {},
}

#[component]
pub fn App() -> Element {
    use_context_provider(StaffState::new);
    rsx! {
        Router::<Route> {}
    }
}

/// Calm chrome for the login gate.
#[component]
fn GateLayout() -> Element {
    rsx! {
        style { {CSS} }
        div { class: "staff",
            div { class: "gate",
                Outlet::<Route> {}
            }
        }
    }
}

fn tab_class(current: &Route, target: &Route) -> &'static str {
    if current == target {
        "tab on"
    } else {
        "tab"
    }
}

/// Persistent console chrome + the auth guard. No session → render nothing and
/// redirect to the login gate.
#[component]
fn ConsoleLayout() -> Element {
    let nav = use_navigator();
    let state = use_context::<StaffState>();
    let route = use_route::<Route>();

    let logged_in = state.logged_in();
    use_effect(move || {
        if !state.logged_in() {
            nav.replace(Route::Login {});
        }
    });
    if !logged_in {
        return rsx! {
            style { {CSS} }
            div { class: "staff" }
        };
    }

    let role = state
        .session
        .read()
        .as_ref()
        .map(|s| s.role)
        .unwrap_or_default();

    rsx! {
        style { {CSS} }
        div { class: "staff",
            div { class: "app",
                header { class: "topbar",
                    div { class: "brand",
                        span { class: "dot" }
                        h1 { "PH Staff " span { class: "muted", "Console" } }
                    }
                    div { class: "who",
                        span { class: "pill", "Role: {role_label(role)}" }
                        SignOutButton {}
                    }
                }
                nav { class: "tabs", "aria-label": "Sections",
                    Link { class: tab_class(&route, &Route::Fleet {}), to: Route::Fleet {}, "Fleet health" }
                    Link { class: tab_class(&route, &Route::Support {}), to: Route::Support {}, "Guardian support" }
                    Link { class: tab_class(&route, &Route::Cases {}), to: Route::Cases {}, "Safety queue" }
                    Link { class: tab_class(&route, &Route::Audit {}), to: Route::Audit {}, "Audit log" }
                }
                Outlet::<Route> {}
            }
        }
    }
}

#[component]
fn SignOutButton() -> Element {
    let nav = use_navigator();
    let mut state = use_context::<StaffState>();
    rsx! {
        button {
            class: "btn ghost",
            onclick: move |_| {
                state.sign_out();
                nav.replace(Route::Login {});
            },
            "Sign out"
        }
    }
}
