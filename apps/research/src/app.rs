//! Router wiring + the persistent shell (theme root, atmosphere layers, nav,
//! footer). Dioxus 0.8 `dioxus-router`: a `Routable` enum, one `#[layout(Shell)]`
//! painting the chrome around every `Outlet`.

use dioxus::prelude::*;

use crate::assets::ph_logo_data_uri;
use crate::components::{ClosingCta, SiteFooter};
use crate::icons::svg;
use crate::pages::{About, Approach, Contact, Home, Research};
use crate::theme::STYLE;

/// Colour scheme. Provided as a `Signal<Theme>` context by `App`, toggled from
/// the nav, read back into the `data-theme` attribute on the theme root — which
/// is what every light/dark CSS variable keys off.
#[derive(Clone, Copy, PartialEq)]
pub enum Theme {
    Dark,
    Light,
}

#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    #[layout(Shell)]
    #[route("/")]
    Home {},
    #[route("/research")]
    Research {},
    #[route("/approach")]
    Approach {},
    #[route("/about")]
    About {},
    #[route("/contact")]
    Contact {},
}

/// Root: inject the one stylesheet, provide the theme, paint the themed stage,
/// mount the router.
#[component]
pub fn App() -> Element {
    let theme = use_context_provider(|| Signal::new(Theme::Dark));
    let mode = if theme() == Theme::Light { "light" } else { "dark" };
    rsx! {
        style { {STYLE} }
        div { class: "theme-root", "data-theme": "{mode}",
            div { class: "stage-bg" }
            div { class: "stage-grid" }
            div { class: "stage-grain" }
            Router::<Route> {}
        }
    }
}

/// Persistent chrome: sticky nav, the routed `Outlet`, a shared closing CTA,
/// and the footer.
#[component]
fn Shell() -> Element {
    rsx! {
        NavBar {}
        main { Outlet::<Route> {} }
        ClosingCta {}
        SiteFooter {}
    }
}

fn nav_class(current: &Route, target: &Route) -> &'static str {
    if current == target {
        "nav-link on"
    } else {
        "nav-link"
    }
}

#[component]
fn NavBar() -> Element {
    let route = use_route::<Route>();
    let mut theme = use_context::<Signal<Theme>>();
    let toggle_icon = if theme() == Theme::Light { "moon" } else { "sun" };
    rsx! {
        nav { class: "nav",
            div { class: "nav-inner",
                Link { class: "brand", to: Route::Home {},
                    img { class: "brand-logo", src: "{ph_logo_data_uri()}", alt: "Predator Hunters" }
                    span { class: "brand-tag", "Research" }
                }
                div { class: "nav-links",
                    Link { class: nav_class(&route, &Route::Research {}), to: Route::Research {}, "Research" }
                    Link { class: nav_class(&route, &Route::Approach {}), to: Route::Approach {}, "Approach" }
                    Link { class: nav_class(&route, &Route::About {}), to: Route::About {}, "About" }
                    Link { class: nav_class(&route, &Route::Contact {}), to: Route::Contact {}, "Contact" }
                }
                div { class: "nav-right",
                    button {
                        class: "theme-toggle",
                        "aria-label": "Switch between light and dark theme",
                        onclick: move |_| {
                            let next = if theme() == Theme::Light { Theme::Dark } else { Theme::Light };
                            theme.set(next);
                        },
                        span { dangerous_inner_html: svg(toggle_icon) }
                    }
                    Link { class: "btn btn-primary btn-sm nav-cta", to: Route::Contact {},
                        "Work with us"
                        span { dangerous_inner_html: svg("arrow-right") }
                    }
                    Link { class: "btn btn-ghost btn-sm nav-burger", to: Route::Contact {},
                        span { dangerous_inner_html: svg("arrow-right") }
                    }
                }
            }
        }
    }
}
