//! PH Bulwark — the per-product page (ships next). The device-wide shield that
//! filters unsafe content in place and alerts a guardian. Plain copy.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

/// (icon, title, body)
const POINTS: [(&str, &str, &str); 3] = [
    (
        "shield-check",
        "Block in place, not the whole site",
        "When unsafe content appears, the shield removes only that part and leaves the rest of the page working, so a child keeps the search, social and learning sites they actually need. Only when something is serious is it blocked outright.",
    ),
    (
        "eye-off",
        "A short, redacted alert",
        "When something needs a guardian, they get a short alert with no message contents in it. The shield never keeps the raw content behind it, only a redacted record of the alert, in an encrypted, tamper-evident log that deletes itself on a clock.",
    ),
    (
        "scale",
        "Illegal material: blocked and reported",
        "Child-abuse material is blocked on sight and reported to the proper authority as the law requires. It is never stored, served, or generated.",
    ),
];

#[component]
pub fn PhBulwark() -> Element {
    rsx! {
        crate::components::Seo {
            title: "PH Bulwark: a shield for the whole device | Predator Hunters",
            description: "PH Bulwark filters unsafe content in place across apps and the web, blocks illegal material, and sends a guardian a short redacted alert. Models run on the child's own device; no raw content is kept.",
            path: "/systems/ph-bulwark",
            image: "/og/systems.png",
        }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "PH Bulwark · ships next" }
                h1 { class: "rise d2",
                    "A shield for the "
                    span { class: "grad-text", "whole device." }
                }
                p { class: "lede rise d3",
                    "PH Bulwark sits across every app and the open web. It filters unsafe content in place, warns a guardian when something is wrong, and keeps the rest of the page working."
                }
                div { class: "hero-actions rise d4", style: "margin-top:30px;",
                    Link { class: "btn btn-primary", to: Route::Waitlist {},
                        "Join the alpha"
                        span { dangerous_inner_html: svg("arrow-right") }
                    }
                    Link { class: "btn btn-ghost", to: Route::Systems {},
                        span { class: "ic", dangerous_inner_html: svg("layers") }
                        "Both systems"
                    }
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "hero-grid",
                    div { class: "reveal",
                        div { class: "phone",
                            div { class: "phone-screen",
                                div { class: "phone-notch" }
                                span { class: "phone-shield", dangerous_inner_html: svg("shield") }
                                div { class: "phone-title", "Blocked by PH Bulwark" }
                                div { class: "phone-sub", "This content was flagged as unsafe." }
                            }
                        }
                    }
                    div {
                        for (icon , title , body) in POINTS {
                            div { key: "{title}", class: "card reveal", style: "margin-bottom:14px;",
                                div { class: "card-ic", dangerous_inner_html: svg(icon) }
                                h3 { "{title}" }
                                p { "{body}" }
                            }
                        }
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Honest status" }
                    h2 { "Where it actually is." }
                    p { class: "lede", "We will be straight about it. The core filtering works today. The wider network coverage and some of the on-device models are still being tested, and we will keep saying so here until they are finished. Android comes first, with Windows, iOS, iPad and Mac on the roadmap." }
                }
            }
        }
    }
}
