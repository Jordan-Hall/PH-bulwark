//! Shared chrome rendered on every route: the closing call-to-action and the
//! footer. Both are framing-disciplined (independent research + journalism;
//! convictions / public-record only; nothing stored).

use dioxus::prelude::*;

use crate::app::Route;
use crate::assets::ph_logo_data_uri;
use crate::icons::svg;

/// The shared closing CTA — investment / collaboration attraction, kept honest.
/// Suppressed on the Contact route, where it would only repeat that page.
#[component]
pub fn ClosingCta() -> Element {
    let route = use_route::<Route>();
    if route == (Route::Contact {}) {
        return rsx! {};
    }
    rsx! {
        section { class: "section",
            div { class: "wrap",
                div { class: "cta reveal",
                    div { class: "cta-inner",
                        p { class: "eyebrow", style: "margin-bottom:18px;", "Backers · partners · researchers" }
                        h2 {
                            "Help us build the AI that keeps "
                            span { class: "grad-text", "children safer." }
                        }
                        p { class: "lede",
                            "We are a small, self-funded team four years into the work. If you fund frontier safety research, build alongside us, or want to put these models to work protecting children, we want to talk."
                        }
                        div { class: "cta-actions",
                            Link { class: "btn btn-primary", to: Route::Contact {},
                                "Start a conversation"
                                span { dangerous_inner_html: svg("arrow-right") }
                            }
                            Link { class: "btn btn-ghost", to: Route::Research {},
                                span { class: "ic", dangerous_inner_html: svg("layers") }
                                "See the research"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Site footer.
#[component]
pub fn SiteFooter() -> Element {
    rsx! {
        footer { class: "footer",
            div { class: "wrap",
                div { class: "footer-top",
                    div {
                        Link { class: "brand", to: Route::Home {},
                            img { class: "brand-logo", src: "{ph_logo_data_uri()}", alt: "Predator Hunters" }
                            span { class: "brand-tag", "Research" }
                        }
                        p { class: "footer-blurb",
                            "An independent child-safety AI lab. We build privacy-preserving models that run on a child's own device — detecting unsafe content and predatory conversation patterns, storing nothing."
                        }
                    }
                    div {
                        h4 { "Research" }
                        ul {
                            li { Link { to: Route::Research {}, "The models" } }
                            li { Link { to: Route::Approach {}, "Our approach" } }
                            li { Link { to: Route::Approach {}, "Principles" } }
                        }
                    }
                    div {
                        h4 { "Organisation" }
                        ul {
                            li { Link { to: Route::About {}, "About the lab" } }
                            li { Link { to: Route::About {}, "Team" } }
                            li { Link { to: Route::Contact {}, "Contact" } }
                            li { a { href: "https://predatorhunters.co.uk", "Main site ↗" } }
                        }
                    }
                    div {
                        h4 { "Connect" }
                        ul {
                            li { a { href: "mailto:research@predatorhunters.co.uk", "research@predatorhunters.co.uk" } }
                            li { a { href: "https://predatorhunters.co.uk", "Press & journalism ↗" } }
                        }
                        div { style: "margin-top:18px;",
                            img { class: "brand-logo", src: "{ph_logo_data_uri()}", alt: "Predator Hunters", style: "height:46px;" }
                        }
                    }
                }
                div { class: "footer-bottom",
                    p { "© 2026 Predator Hunters Research. All rights reserved." }
                    p { class: "legal",
                        "Independent research & journalism. We report only on matters concluded in court and on the public record — never pre-trial — and operate independently of any law-enforcement agency. Models run on-device; no raw messages or media are stored."
                    }
                }
            }
        }
    }
}
