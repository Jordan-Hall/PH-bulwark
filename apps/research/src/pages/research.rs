//! Research — the models and the methodology. This is the site's centre of
//! gravity (the journalism + downloads live on the main site).

use dioxus::prelude::*;

use crate::icons::svg;

/// (index, title, icon, description, status-class, status-label)
const MODELS: [(&str, &str, &str, &str, &str, &str); 6] = [
    (
        "01",
        "Grooming-pattern recognition",
        "scan",
        "A compact language model that recognises the shape of predatory conversation — secrecy pressure, “let’s move to another app”, gift offers, age and personal-information probing — and raises a content-free flag for a guardian. Tuned so that secrecy and isolation outrank simple age questions.",
        "live",
        "In alpha",
    ),
    (
        "02",
        "On-device content filtering",
        "shield-check",
        "Real-time classification of unsafe imagery and text as it loads, on the device itself. Illegal child-abuse material is detected, blocked instantly, and reported as the law requires — never stored, never shown, never generated.",
        "live",
        "In alpha",
    ),
    (
        "03",
        "Screen-reading for encrypted apps",
        "cpu",
        "Conventional, on-device OCR that catches grooming inside end-to-end-encrypted chats by reading only the text already drawn on screen. Never keystrokes, never passwords; raw text never leaves the device.",
        "live",
        "In alpha",
    ),
    (
        "04",
        "Video detection & in-place rewriting",
        "layers",
        "Our flagship alpha capability: detecting unsafe video as it plays and rewriting it on the fly — blurring or muting only the offending moments and re-packaging the same stream, so the rest plays uninterrupted. On-device, nothing stored.",
        "live",
        "In alpha",
    ),
    (
        "05",
        "Offender-record matching",
        "network",
        "Research into linking convictions already on the public court record to support our journalism and community protection. Post-conviction only, human-reviewed, and built with data-protection law in mind — never pre-trial, never an automated accusation.",
        "research",
        "Research",
    ),
    (
        "06",
        "Edge distillation",
        "waveform",
        "The enabling work: distilling and quantising every model small enough to run offline on a mid-range phone, because protection that needs the cloud is protection that can be switched off.",
        "research",
        "Research",
    ),
];

/// (icon, title, description)
const METHOD: [(&str, &str, &str); 3] = [
    (
        "layers",
        "Rules first, AI second",
        "A deterministic rules engine handles the clear-cut cases; models are the minimal layer on top. No large language model sits in any real-time path — it is faster, cheaper, auditable, and private.",
    ),
    (
        "cpu",
        "Edge-sized, offline",
        "Every shipped model is distilled and quantised to run on the device with no network round-trip. Protection that depends on a server is protection an adult can quietly remove.",
    ),
    (
        "fingerprint",
        "Tested against real evasion",
        "We evaluate the way predators actually behave — pressure to move apps, to keep secrets, to isolate — and tune for the harm we must never miss, not for a leaderboard.",
    ),
];

#[component]
pub fn Research() -> Element {
    rsx! {
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Research" }
                h1 { class: "rise d2",
                    "Catch the danger. "
                    span { class: "grad-text", "Keep none of the child." }
                }
                p { class: "lede rise d3",
                    "A small family of focused models, each doing one safety job well. Most already run in our alpha build; the rest are in the lab. All of them run on-device and store nothing."
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "research-list",
                    for (num , title , icon , desc , tagcls , tagtxt) in MODELS {
                        div { key: "{num}", class: "r-row reveal",
                            span { class: "r-num", "{num}" }
                            div { class: "r-title",
                                span { class: "r-ic", dangerous_inner_html: svg(icon) }
                                h3 { "{title}" }
                            }
                            p { class: "r-desc", "{desc}" }
                            div { style: "display:flex;align-items:center;justify-content:flex-end;",
                                span { class: "tag {tagcls}", "{tagtxt}" }
                            }
                        }
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Methodology" }
                    h2 { "Small, deterministic, and private by construction." }
                    p { class: "lede", "Our constraints are deliberate. They make the models cheaper to run, easier to audit, and impossible to quietly turn into surveillance." }
                }
                div { class: "grid-3",
                    for (icon , title , desc) in METHOD {
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
                    span { class: "sec-index", "Disclosure" }
                    h2 { "What we publish — and what we never will." }
                }
                dl { class: "deflist reveal",
                    div { class: "def",
                        dt { "We publish" }
                        dd { "How the models work — architectures, evaluation methods, safety findings — and the open-source tooling around them." }
                    }
                    div { class: "def",
                        dt { "We never publish" }
                        dd { "A child’s data, a raw grooming corpus, or live model weights — nor anything that would help an adult evade protection. Those stay closed, permanently." }
                    }
                }
            }
        }
    }
}
