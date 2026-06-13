//! Approach — the principles that constrain the work. This is the page that
//! draws the line between child-protection and surveillance.

use dioxus::prelude::*;

use crate::icons::svg;

/// (icon, title, description) — the things we never touch.
const NEVER: [(&str, &str, &str); 4] = [
    ("eye-off", "The screen", "We never record or stream what a child sees or types. Screen-reading happens on-device, in the moment, for one purpose — and is gone."),
    ("globe", "Their location", "No GPS, no movement history, no who-they’re-with. None of it is collected."),
    ("waveform", "Raw content", "No message, image or video is stored or sent. Only a redacted, content-free signal that something needs a guardian."),
    ("lock", "Anyone else", "The tools run on one consenting child’s own device — never on bystanders, never on adults, never covertly."),
];

/// (term, definition) — the principles.
const PRINCIPLES: [(&str, &str); 6] = [
    ("On-device by default", "Models run on the child’s own phone. Leaving the device is the rare exception, not the rule — and never carries raw content."),
    ("We remember nothing", "The system is built so there is nothing to leak. No raw messages or media are ever stored; alerts are redacted and content-free."),
    ("A human always decides", "Models surface concern; people act on it. Guardians decide for their child; our editors decide what we report. No automated accusation, ever."),
    ("Detect, block, report — never store", "Illegal child-abuse material is blocked on sight and reported to the proper authority as the law requires. It is never stored, served, or generated."),
    ("Independent, post-conviction", "Our journalism reports only on matters concluded in court and on the public record. Never pre-trial naming; independent of any law-enforcement agency."),
    ("Open methods, closed data", "We are transparent about how the models work and never publish what could harm a child — their data, a grooming corpus, or live weights."),
];

#[component]
pub fn Approach() -> Element {
    rsx! {
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Approach" }
                h1 { class: "rise d2",
                    "Protection "
                    span { class: "grad-text", "without surveillance." }
                }
                p { class: "lede rise d3",
                    "It would be easier to build child-safety AI by watching everything. We don’t, because a tool that sees everything is a tool that can be turned against the child it claims to protect. Every choice below follows from that."
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "prose reveal",
                    p {
                        "Predator Hunters has protected children and trained parents since "
                        strong { "2017" }
                        ". The research lab is the newest part of that work — and it inherits the same non-negotiables. We treat a child’s privacy as part of their safety, not a trade against it."
                    }
                    p {
                        "So our models are small enough to run on the device, the system is designed to "
                        strong { "store nothing" }
                        ", and a person is always the one who acts. These are constraints, and we keep them even when they make the engineering harder."
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "The line we hold" }
                    h2 { "What our research will never touch." }
                }
                div { class: "grid-4",
                    for (icon , title , desc) in NEVER {
                        div { key: "{title}", class: "card reveal",
                            div { class: "card-ic", dangerous_inner_html: svg(icon) }
                            h3 { "{title}" }
                            p { "{desc}" }
                        }
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Principles" }
                    h2 { "Six commitments, in plain words." }
                }
                dl { class: "deflist reveal",
                    for (term , def) in PRINCIPLES {
                        div { key: "{term}", class: "def",
                            dt { "{term}" }
                            dd { "{def}" }
                        }
                    }
                }
            }
        }
    }
}
