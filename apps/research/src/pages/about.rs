//! About — who we are, where we came from, and the line between what we are and
//! what we are not. Plain copy.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

/// (year, event)
const TIMELINE: [(&str, &str); 4] = [
    ("2017", "Predator Hunters begins. An independent group protecting children online and training the parents who keep them safe."),
    ("2022", "The research lab opens, and serious work on privacy-first, on-device models begins."),
    ("2025", "The first prototype lands the hardest job of all. It detects unsafe video and rewrites it in place, blurring or muting only the bad moments while the rest plays on."),
    ("Today", "In final development of our first alpha, heading into staged testing. From here, more and more goes into the models."),
];

#[component]
pub fn About() -> Element {
    rsx! {
        dioxus::document::Title { "About · Predator Hunters Research" }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "About" }
                h1 { class: "rise d2",
                    "An independent lab inside a movement that started in "
                    span { class: "grad-text", "2017." }
                }
                p { class: "lede rise d3",
                    "Predator Hunters Research is the AI arm of an independent child-protection and journalism group. We are small, self-funded, and four years into building safety tech a family can actually trust."
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "prose reveal",
                    p {
                        "For most of a decade, Predator Hunters has worked on the front line of child protection. Investigating, reporting from court, teaching parents how to keep their children safe online. One thing kept getting clearer. The danger was moving faster than the tools families had to meet it."
                    }
                    p {
                        "So we started building. The lab puts modern machine learning to work on that problem, without the surveillance that so much "
                        strong { "safety" }
                        " software leans on. Anything we ship has to protect a child and respect them at the same time."
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
                    p { class: "lede", "Lean on purpose, and honest about what that means. We build carefully and we say no a lot." }
                }
                div { class: "team-grid",
                    div { class: "member reveal",
                        div { class: "member-photo", "JU" }
                        b { "Jordan Upton" }
                        div { class: "role", "Founder · Lead developer" }
                        p { "Designs and builds the models and the systems that run them, and holds the line on what the lab will never build." }
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
                        p { "Independent researchers and journalists. We build privacy-first AI to protect children, and we report on the people who harm them, from the public court record." }
                    }
                    div { class: "card reveal",
                        div { class: "card-ic", style: "color:var(--orange);background:rgba(245,130,32,.10);border-color:rgba(245,130,32,.22);", dangerous_inner_html: svg("eye-off") }
                        h3 { "What we are not" }
                        p { "Not a surveillance company, not a police force, and not a place for public accusations. We never name anyone before a trial, and we never collect a child's private life." }
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
