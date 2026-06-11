//! `dioxus-router` wiring: the journey's typed `Route` enum + the persistent
//! `JourneyLayout` (brand + progress shield + card) that wraps every step's
//! `Outlet`. Each route maps to a component of the same name in `crate::screens`.

use dioxus::prelude::*;

use crate::screens::{Done, How, Pair, Permissions, Welcome};
use crate::state::Setup;
use crate::theme::CSS;

/// One route per onboarding step, all nested under the shared `JourneyLayout`.
#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    #[layout(JourneyLayout)]
    #[route("/")]
    Welcome {},
    #[route("/how")]
    How {},
    #[route("/permissions")]
    Permissions {},
    #[route("/pair")]
    Pair {},
    #[route("/done")]
    Done {},
}

const TOTAL: usize = 5;

/// Map the active route to its (index, label) for the progress shield.
fn route_progress(route: &Route) -> (usize, &'static str) {
    match route {
        Route::Welcome {} => (0, "Welcome"),
        Route::How {} => (1, "How it works"),
        Route::Permissions {} => (2, "Permissions"),
        Route::Pair {} => (3, "Connect"),
        Route::Done {} => (4, "Protected"),
    }
}

/// Root: provide the shared onboarding state, then mount the router.
#[component]
pub fn App() -> Element {
    use_context_provider(Setup::new);
    rsx! { Router::<Route> {} }
}

/// Persistent chrome (brand + progress shield + card) wrapping every step.
#[component]
fn JourneyLayout() -> Element {
    let route = use_route::<Route>();
    let (idx, label) = route_progress(&route);
    let fill = (idx as f32 / (TOTAL - 1) as f32 * 100.0).round();
    rsx! {
        style { {CSS} }
        div { class: "stage",
            div { class: "aurora" }
            div { class: "brand", "PH Bulwark " span { class: "brand-accent", "Shield" } }
            div { class: "progress",
                div { class: "shield",
                    div { class: "shield-fill", style: "height: {fill}%" }
                    span { class: "shield-glyph", "🛡" }
                }
                div { class: "progress-text",
                    span { class: "step-no", "Step {idx + 1} of {TOTAL}" }
                    span { class: "step-label", "{label}" }
                }
            }
            div { key: "{idx}", class: "card",
                Outlet::<Route> {}
            }
        }
    }
}
