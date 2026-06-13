//! Contact — the "work with us" page. Investment / collaboration attraction,
//! kept honest: real email lanes, no fake form, the journalism on the main site.

use dioxus::prelude::*;

use crate::icons::svg;

/// (icon, title, description, link-label, href)
const LANES: [(&str, &str, &str, &str, &str); 4] = [
    (
        "spark",
        "Backers & funders",
        "We are self-funded and looking for partners who fund frontier safety research. Help us put more protective models on more children’s devices.",
        "research@predatorhunters.co.uk",
        "mailto:research@predatorhunters.co.uk?subject=Funding%20%E2%80%94%20Predator%20Hunters%20Research",
    ),
    (
        "cpu",
        "Researchers & engineers",
        "On-device machine learning, Rust systems, evaluation against real-world evasion. If that is your craft and this is your cause, we want to hear from you.",
        "research@predatorhunters.co.uk",
        "mailto:research@predatorhunters.co.uk?subject=Joining%20the%20lab",
    ),
    (
        "shield-check",
        "Safeguarding partners",
        "Schools, charities and platforms that want to put privacy-preserving protection to work — without adopting surveillance to do it.",
        "research@predatorhunters.co.uk",
        "mailto:research@predatorhunters.co.uk?subject=Partnership",
    ),
    (
        "doc",
        "Press & journalism",
        "For court reporting, investigations and downloads, head to the main Predator Hunters site — that is where the journalism lives.",
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
                    "We are a small team with a large mission, and we move faster with the right people beside us. Whatever you bring — capital, code, or care — start here."
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
