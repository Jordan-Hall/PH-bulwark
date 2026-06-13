//! Research — the models, how we train them, and what we are aiming for. This
//! is the lab's centre of gravity and doubles as the white paper. Plain copy.

use dioxus::prelude::*;

use crate::icons::svg;

/// (index, title, icon, description, status-class, status-label)
const MODELS: [(&str, &str, &str, &str, &str, &str); 6] = [
    (
        "01",
        "Grooming-pattern recognition",
        "scan",
        "A small language model that learns the shape of predatory talk. Secrecy pressure, pushing a child to move to another app, gifts, fishing for their age or address. It raises a flag a parent can act on, with no message contents attached, and it is tuned so that secrecy and isolation count for more than a simple age question.",
        "live",
        "In alpha",
    ),
    (
        "02",
        "On-device content filtering",
        "shield-check",
        "It checks images and text as a page loads and blocks the unsafe ones in place. Only the harmful part is removed, so the rest of an ordinary page keeps working and there are no blunt whole-site bans. Illegal child-abuse material is blocked on sight and reported as the law requires. It is never stored, shown, or generated.",
        "live",
        "In alpha",
    ),
    (
        "03",
        "Reading the screen in encrypted apps",
        "cpu",
        "Plain OCR, running on the phone, reads the text already drawn on screen. That lets it catch grooming even inside end-to-end-encrypted chats. It never logs keystrokes or passwords, and the text never leaves the device.",
        "live",
        "In alpha",
    ),
    (
        "04",
        "Video detection and in-place rewriting",
        "layers",
        "Our flagship alpha. It spots unsafe video as it plays and rewrites it on the fly, blurring or muting only the moments that are a problem and re-packaging the same stream so the rest plays without a break. It runs on the phone and keeps nothing.",
        "live",
        "In alpha",
    ),
    (
        "05",
        "Offender-record matching",
        "network",
        "Early research into linking convictions that are already on the public court record, to support our journalism and help protect communities. A person reviews every match, it happens only after a case has been to court, and it is built around data-protection law. Never before a trial, never an automated accusation.",
        "research",
        "Research",
    ),
    (
        "06",
        "Edge distillation",
        "bolt",
        "The work underneath all of it. We shrink every model so it runs offline on a mid-range phone, because protection that needs the cloud is protection an adult can switch off.",
        "research",
        "Research",
    ),
];

/// (term, definition) — what we are aiming for.
const AIMS: [(&str, &str); 4] = [
    ("A phone a parent can trust", "One a parent can hand a child knowing the worst is caught, without anyone watching over the child's shoulder."),
    ("Cover the whole phone", "Text, images, video and audio, across apps and the web, all judged on the device."),
    ("Small enough for any phone", "Models light and fast enough to run on a cheap handset, and given away where giving them away protects more children."),
    ("A standard others can use", "We publish how the work is done and open the tooling, so good protection does not stay locked inside one company."),
];

#[component]
pub fn Research() -> Element {
    rsx! {
        dioxus::document::Title { "Research · Predator Hunters Research" }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Research" }
                h1 { class: "rise d2",
                    "Catch the danger. "
                    span { class: "grad-text", "Keep none of the child." }
                }
                p { class: "lede rise d3",
                    "A small family of focused models, each doing one safety job well. Most already run in our alpha. The rest are still in the lab. All of them run on the phone and store nothing."
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

        // ---------- HOW WE TRAIN ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "White paper · How we train" }
                    h2 { "We train for the harm we cannot miss." }
                }
                div { class: "prose reveal",
                    p {
                        "We do not scrape children's data. The models learn from lawful public datasets, from examples of grooming that safeguarding practitioners label with us, from synthetic conversations, and from plenty of ordinary chat so the model does not cry wolf at every clumsy message."
                    }
                    p {
                        "Rules come first and the model comes second. A plain set of rules handles the obvious cases. The model is the thin layer on top for the rest. No large language model sits in the live path, which keeps the work fast, cheap to run, and easy to check."
                    }
                    p {
                        "We tune for recall on real danger rather than for a leaderboard, and we test against the way predators actually behave: keeping secrets, moving a child to another app, cutting them off from the people around them. Then we distill everything down small enough to run offline on a mid-range phone."
                    }
                    p {
                        strong { "Nothing a child sends is ever used to train, and no raw content is kept." }
                        " That is a hard rule, not a setting."
                    }
                }
            }
        }

        // ---------- WHAT WE'RE AIMING FOR ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "White paper · What we're aiming for" }
                    h2 { "Where this is going." }
                }
                dl { class: "deflist reveal",
                    for (term , def) in AIMS {
                        div { key: "{term}", class: "def",
                            dt { "{term}" }
                            dd { "{def}" }
                        }
                    }
                }
            }
        }

        // ---------- BENCHMARK ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Benchmark" }
                    h2 { "We measured the frontier. Most of it looked away." }
                    p { class: "lede", "We built a benchmark of 36 real child-safety tasks across five areas, then ran six frontier models through it. Only xAI's Grok took the work on. That gap is a big part of why we build our own." }
                }
                dl { class: "deflist reveal",
                    div { class: "def", dt { "Grok-4.1 · xAI" } dd { "79.9% average. 100% on real grooming cases, 95.2% on stranger-meeting scenarios." } }
                    div { class: "def", dt { "Grok-3 · xAI" } dd { "59.5% average." } }
                    div { class: "def", dt { "Claude-Opus-4.6 · Anthropic" } dd { "42.2% average. Declined the real-grooming and health-risk tasks." } }
                    div { class: "def", dt { "Gemini-3-Pro / 2.5-Pro · Google" } dd { "Declined most tasks. 0.0%." } }
                    div { class: "def", dt { "GPT-5 · OpenAI" } dd { "Declined all five categories. 0.0%." } }
                }
                div { style: "margin-top:26px;",
                    a { class: "btn btn-primary", href: "https://benchmark.predatorhunters.co.uk",
                        "See the full benchmark"
                        span { dangerous_inner_html: svg("arrow-up-right") }
                    }
                }
            }
        }

        // ---------- DISCLOSURE ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Disclosure" }
                    h2 { "What we publish, and what we never will." }
                }
                dl { class: "deflist reveal",
                    div { class: "def",
                        dt { "We publish" }
                        dd { "How the models work, how we test them, what we find, and the open-source tooling around them." }
                    }
                    div { class: "def",
                        dt { "We never publish" }
                        dd { "A child's data, a raw grooming dataset, or live model weights, and nothing that would help an adult get around the protection. That stays closed for good." }
                    }
                }
            }
        }
    }
}
