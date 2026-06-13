//! Catch-all 404 page, so an old or mistyped URL lands somewhere calm with a
//! way back, instead of a blank screen.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

#[component]
pub fn NotFound(segments: Vec<String>) -> Element {
    let _ = segments;
    rsx! {
        crate::components::Seo {
            title: "Not found | Predator Hunters Research",
            description: "That page is not here. Head back to Predator Hunters Research.",
            path: "/404",
            image: "/og/home.png",
        }
        dioxus::document::Meta { name: "robots", content: "noindex, follow" }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "404" }
                h1 { class: "rise d2",
                    "That page "
                    span { class: "grad-text", "isn't here." }
                }
                p { class: "lede rise d3",
                    "The link is probably old or mistyped. Nothing's broken, the page just doesn't exist. If a link on our own site sent you here, tell us and we'll fix it."
                }
                div { class: "hero-actions rise d4", style: "margin-top:30px;",
                    Link { class: "btn btn-primary", to: Route::Home {},
                        "Back to the start"
                        span { dangerous_inner_html: svg("arrow-right") }
                    }
                    Link { class: "btn btn-ghost", to: Route::Research {},
                        span { class: "ic", dangerous_inner_html: svg("layers") }
                        "See the research"
                    }
                    a { class: "btn btn-ghost", href: "mailto:research@predatorhunters.co.uk?subject=Broken%20link",
                        span { class: "ic", dangerous_inner_html: svg("mail") }
                        "Report a broken link"
                    }
                }
            }
        }
    }
}
