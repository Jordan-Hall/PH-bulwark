//! Router wiring + the persistent shell (theme root, atmosphere layers, nav,
//! footer). Dioxus 0.8 `dioxus-router`: a `Routable` enum, one `#[layout(Shell)]`
//! painting the chrome around every `Outlet`.

use dioxus::prelude::*;

use crate::assets::{FAVICON, PH_LOGO};
use crate::components::{ClosingCta, SiteFooter};
use crate::icons::svg;
use crate::pages::{About, Approach, Contact, Home, NotFound, Privacy, Research, Systems};

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
    #[route("/systems")]
    Systems {},
    #[route("/approach")]
    Approach {},
    #[route("/about")]
    About {},
    #[route("/contact")]
    Contact {},
    #[route("/privacy")]
    Privacy {},
    #[route("/:..segments")]
    NotFound { segments: Vec<String> },
}

/// SSG hook: `dx build --ssg` POSTs to `/api/static_routes` and pre-renders each
/// path it returns. We hand back every non-dynamic route from the `Routable`
/// enum (the catch-all `NotFound` is dynamic and is skipped automatically), so
/// crawlers / link bots / no-JS clients get fully-rendered HTML.
#[server(endpoint = "static_routes")]
async fn static_routes() -> Result<Vec<String>, ServerFnError> {
    Ok(Route::static_routes().iter().map(ToString::to_string).collect())
}

/// Root: inject the one stylesheet, provide the theme, paint the themed stage,
/// mount the router.
#[component]
pub fn App() -> Element {
    let theme = use_context_provider(|| Signal::new(Theme::Dark));
    let mode = if theme() == Theme::Light { "light" } else { "dark" };
    rsx! {
        dioxus::document::Link { rel: "icon", href: FAVICON }
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
    let mut menu = use_signal(|| false);
    let toggle_icon = if theme() == Theme::Light { "moon" } else { "sun" };
    let burger_icon = if menu() { "close" } else { "menu" };
    rsx! {
        nav { class: "nav",
            div { class: "nav-inner",
                Link { class: "brand", to: Route::Home {}, onclick: move |_| menu.set(false),
                    img { class: "brand-logo", src: PH_LOGO, alt: "Predator Hunters" }
                    span { class: "brand-tag", "Research" }
                }
                div { class: "nav-links",
                    Link { class: nav_class(&route, &Route::Research {}), to: Route::Research {}, "Research" }
                    Link { class: nav_class(&route, &Route::Systems {}), to: Route::Systems {}, "Systems" }
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
                    button {
                        class: "theme-toggle nav-burger",
                        "aria-label": "Open menu",
                        "aria-expanded": "{menu()}",
                        onclick: move |_| { let v = menu(); menu.set(!v); },
                        span { dangerous_inner_html: svg(burger_icon) }
                    }
                }
            }
            if menu() {
                div { class: "nav-menu",
                    Link { class: nav_class(&route, &Route::Research {}), to: Route::Research {}, onclick: move |_| menu.set(false), "Research" }
                    Link { class: nav_class(&route, &Route::Systems {}), to: Route::Systems {}, onclick: move |_| menu.set(false), "Systems" }
                    Link { class: nav_class(&route, &Route::Approach {}), to: Route::Approach {}, onclick: move |_| menu.set(false), "Approach" }
                    Link { class: nav_class(&route, &Route::About {}), to: Route::About {}, onclick: move |_| menu.set(false), "About" }
                    Link { class: nav_class(&route, &Route::Contact {}), to: Route::Contact {}, onclick: move |_| menu.set(false), "Contact" }
                    Link { class: "btn btn-primary nav-menu-cta", to: Route::Contact {}, onclick: move |_| menu.set(false),
                        "Work with us"
                        span { dangerous_inner_html: svg("arrow-right") }
                    }
                }
            }
        }
    }
}
