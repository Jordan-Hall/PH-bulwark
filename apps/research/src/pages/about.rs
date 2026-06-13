//! About — who we are, where we came from, and the line between what we are
//! and what we are not.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

/// (year, event)
const TIMELINE: [(&str, &str); 4] = [
    ("2017", "Predator Hunters begins — an independent organisation protecting children online and training the parents who keep them safe."),
    ("2022", "The research lab opens. Privacy-first prototyping of on-device safety models begins in earnest."),
    ("2025", "The first models reach real devices inside the product — recognising grooming patterns and filtering unsafe content, on-device."),
    ("Today", "A family of six models in development and in production. A small team, the same mission."),
];

#[component]
pub fn About() -> Element {
    rsx! {
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "About" }
                h1 { class: "rise d2",
                    "An independent lab inside a movement that started in "
                    span { class: "grad-text", "2017." }
                }
                p { class: "lede rise d3",
                    "Predator Hunters Research is the AI arm of an independent child-protection and journalism organisation. We are small, self-funded, and four years deep in the work of building safety technology that earns a family’s trust."
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "prose reveal",
                    p {
                        "For most of a decade, Predator Hunters has worked on the front line of child protection — investigating, reporting from court, and teaching parents how to keep their children safe online. Along the way one thing became obvious: the danger had moved faster than the tools families had to meet it."
                    }
                    p {
                        "So we started building. The research lab exists to put modern machine learning to work on that problem — "
                        strong { "without" }
                        " adopting the surveillance playbook that so much ‘safety’ software relies on. Everything we ship has to protect a child and respect them at the same time."
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Timeline" }
                    h2 { "How we got here." }
                }
                dl { class: "deflist reveal",
                    for (year , event) in TIMELINE {
                        div { key: "{year}", class: "def",
                            dt { "{year}" }
                            dd { "{event}" }
                        }
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Team" }
                    h2 { "Built by a small team." }
                    p { class: "lede", "Deliberately lean, deeply committed, and honest about what that means: we build carefully and say no often." }
                }
                div { class: "team-grid",
                    div { class: "member reveal",
                        div { class: "member-photo", "JU" }
                        b { "Jordan Upton" }
                        div { class: "role", "Founder · Lead developer" }
                        p { "Designs and builds the models and the systems that run them — and holds the line on what the lab will never build." }
                    }
                    div { class: "member reveal",
                        div { class: "member-photo", style: "background:var(--card-bg);color:var(--green-2);border:1px solid var(--hair-strong);", dangerous_inner_html: svg("scale") }
                        b { "Safeguarding advisors" }
                        div { class: "role", "Guidance" }
                        p { "Practitioners who keep the work grounded in real child-protection practice and the law." }
                    }
                    div { class: "member reveal",
                        div { class: "member-photo", style: "background:var(--card-bg);color:var(--orange);border:1px solid var(--hair-strong);", dangerous_inner_html: svg("github") }
                        b { "Open-source contributors" }
                        div { class: "role", "Engineering" }
                        p { "The wider community that helps build and harden the tooling around the models." }
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "grid-2",
                    div { class: "card reveal",
                        div { class: "card-ic", dangerous_inner_html: svg("check") }
                        h3 { "What we are" }
                        p { "Independent researchers and journalists building privacy-preserving AI to protect children, and reporting — from the public court record — on those who harm them." }
                    }
                    div { class: "card reveal",
                        div { class: "card-ic", style: "color:var(--orange);background:rgba(245,130,32,.10);border-color:rgba(245,130,32,.22);", dangerous_inner_html: svg("eye-off") }
                        h3 { "What we are not" }
                        p { "Not a surveillance company, not a law-enforcement agency, and not a public-accusation platform. We never name anyone pre-trial and never collect a child’s private life." }
                    }
                }
                div { style: "margin-top:28px;",
                    Link { class: "btn btn-ghost", to: Route::Approach {},
                        "Read our principles"
                        span { class: "ic", dangerous_inner_html: svg("arrow-right") }
                    }
                }
            }
        }
    }
}
