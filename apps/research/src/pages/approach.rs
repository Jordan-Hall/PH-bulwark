//! Approach — the principles that constrain the work. Plain copy.

use dioxus::prelude::*;

use crate::icons::svg;

/// (icon, title, description) — the things we never touch.
const NEVER: [(&str, &str, &str); 4] = [
    ("eye-off", "The screen", "We never record or stream what a child sees or types. The screen is read on the phone, in the moment, for one job, and then it is gone."),
    ("globe", "Their location", "No GPS, no movement history, no record of who they are with. None of it is collected."),
    ("waveform", "Raw content", "No message, image or video is stored or sent. A parent gets a short, redacted signal that something needs them, nothing more."),
    ("lock", "Anyone else", "The tools run on one child's own phone, with consent. Never on the people around them, never on adults, and never in secret."),
];

/// (term, definition) — the principles.
const PRINCIPLES: [(&str, &str); 6] = [
    ("On device by default", "The models run on the child's own phone. Leaving it is the rare exception, and even then it never carries raw content."),
    ("We remember nothing", "The system is built so there is nothing to leak. No raw messages or images are ever kept, and alerts carry no content."),
    ("A person always decides", "The models raise a concern and a person acts on it. A parent decides for their child, and our editors decide what we report. Nothing is ever an automated accusation."),
    ("Block and report, never store", "Illegal child-abuse material is blocked on sight and reported to the right authority, as the law requires. It is never stored, served, or made."),
    ("Independent and post-conviction", "Our journalism reports only on cases that have been to court and are on the public record. We never name anyone before a trial, and we are independent of any police force."),
    ("Open methods, closed data", "We explain how the models work. We never publish anything that could harm a child, like their data, a grooming dataset, or live weights."),
];

#[component]
pub fn Approach() -> Element {
    rsx! {
        dioxus::document::Title { "Approach · Predator Hunters Research" }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Approach" }
                h1 { class: "rise d2",
                    "Protection "
                    span { class: "grad-text", "without surveillance." }
                }
                p { class: "lede rise d3",
                    "It would be easier to build this by watching everything a child does. We don't. A tool that sees everything can be turned against the child it is meant to protect, and every choice below follows from that."
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "prose reveal",
                    p {
                        "Predator Hunters has protected children and trained parents since "
                        strong { "2017" }
                        ". The lab is the newest part of that work, and it keeps the same hard rules. We treat a child's privacy as part of their safety, not something to trade away for it."
                    }
                    p {
                        "So the models are small enough to run on the phone, the system is built to "
                        strong { "keep nothing" }
                        ", and a person is always the one who acts. These are real constraints, and we hold them even when they make the work harder."
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
