//! Contact — the "work with us" page. Investment / collaboration attraction,
//! kept honest: real email lanes, no fake form, the journalism on the main site.

use dioxus::prelude::*;

use crate::icons::svg;

/// (icon, title, description, link-label, href)
const LANES: [(&str, &str, &str, &str, &str); 4] = [
    (
        "spark",
        "Backers & funders",
        "We are self-funded and looking for people who back safety research. Help us put protective models on more children’s phones.",
        "research@predatorhunters.co.uk",
        "mailto:research@predatorhunters.co.uk?subject=Funding%20Predator%20Hunters%20Research",
    ),
    (
        "cpu",
        "Researchers & engineers",
        "On-device machine learning, Rust systems, testing against the way predators really behave. If that is your craft and this is your cause, get in touch.",
        "research@predatorhunters.co.uk",
        "mailto:research@predatorhunters.co.uk?subject=Joining%20the%20lab",
    ),
    (
        "shield-check",
        "Safeguarding partners",
        "Schools, charities and platforms that want real protection for children, without turning to surveillance to get it.",
        "research@predatorhunters.co.uk",
        "mailto:research@predatorhunters.co.uk?subject=Partnership",
    ),
    (
        "doc",
        "Press & journalism",
        "For court reporting, investigations and downloads, head to the main Predator Hunters site. That is where the journalism lives.",
        "predatorhunters.co.uk",
        "https://predatorhunters.co.uk",
    ),
];

#[component]
pub fn Contact() -> Element {
    rsx! {
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Contact" }
                h1 { class: "rise d2",
                    "Work "
                    span { class: "grad-text", "with us." }
                }
                p { class: "lede rise d3",
                    "We are a small team with a big job, and we move faster with the right people beside us. Whatever you bring, money, code, or care, start here."
                }
                div { class: "hero-actions rise d4", style: "margin-top:30px;",
                    a { class: "btn btn-primary", href: "mailto:research@predatorhunters.co.uk",
                        span { dangerous_inner_html: svg("mail") }
                        "research@predatorhunters.co.uk"
                    }
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "grid-2",
                    for (icon , title , desc , label , href) in LANES {
                        div { key: "{title}", class: "card reveal",
                            div { class: "card-ic", dangerous_inner_html: svg(icon) }
                            h3 { "{title}" }
                            p { "{desc}" }
                            a { class: "btn btn-ghost btn-sm", style: "margin-top:18px;", href: "{href}",
                                span { class: "ic", dangerous_inner_html: svg("arrow-up-right") }
                                "{label}"
                            }
                        }
                    }
                }
            }
        }
    }
}
