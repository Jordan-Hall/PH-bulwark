//! Home — the lab's front door. Hero (with a live "protective telemetry"
//! readout), mission statement, research highlights, principles, the numbers,
//! and a founder note. Framing-disciplined: protective, privacy-first, nothing
//! stored, independent.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

/// (index, title, icon, description, status-class, status-label)
const HIGHLIGHTS: [(&str, &str, &str, &str, &str, &str); 4] = [
    (
        "01",
        "Grooming-pattern recognition",
        "scan",
        "A small language model that recognises predatory conversation patterns — secrecy pressure, “let’s move to another app”, age and personal-info probing — and warns a guardian. Content-free alerts only.",
        "live",
        "In alpha",
    ),
    (
        "02",
        "On-device content filtering",
        "shield-check",
        "Real-time classification of unsafe imagery and text, running entirely on the child’s own device. Illegal material is detected, blocked and reported — never stored.",
        "live",
        "In alpha",
    ),
    (
        "03",
        "Reading the screen in encrypted apps",
        "cpu",
        "Conventional on-device OCR that catches grooming inside end-to-end-encrypted chats by reading only what is already on screen — never keystrokes, never passwords, never sent off-device.",
        "live",
        "In alpha",
    ),
    (
        "04",
        "Offender-record matching",
        "network",
        "Early research into linking convictions already on the public court record, to help our journalism protect communities — human-reviewed, post-conviction only.",
        "research",
        "Research",
    ),
];

/// (icon, title, description)
const PRINCIPLES: [(&str, &str, &str); 4] = [
    (
        "cpu",
        "On-device by default",
        "Inference runs on the child’s own phone. The default is that nothing leaves it.",
    ),
    (
        "eye-off",
        "We remember nothing",
        "No raw messages or media are stored — ever. Only redacted, content-free safety signals.",
    ),
    (
        "scale",
        "A human always decides",
        "Models surface concerns. People — guardians, our editors — make the call. No automated accusations.",
    ),
    (
        "doc",
        "Open methods, closed data",
        "We publish how the models work. We never publish a child’s data, a grooming corpus, or live weights.",
    ),
];

#[component]
pub fn Home() -> Element {
    rsx! {
        // ---------- HERO ----------
        header { class: "hero",
            div { class: "wrap",
                div { class: "hero-grid",
                    div {
                        div { class: "hero-eyebrow rise d1",
                            span { class: "dot" }
                            span { "Predator Hunters · AI research lab" }
                        }
                        h1 { class: "rise d2",
                            "The AI that protects children — "
                            span { class: "grad-text", "and remembers nothing." }
                        }
                        p { class: "hero-lede rise d3",
                            "We build privacy-preserving models that run on a child’s own device — recognising unsafe content and predatory conversation patterns, warning a guardian, and storing nothing at all."
                        }
                        div { class: "hero-actions rise d4",
                            Link { class: "btn btn-primary", to: Route::Research {},
                                "Explore the research"
                                span { dangerous_inner_html: svg("arrow-right") }
                            }
                            Link { class: "btn btn-ghost", to: Route::Approach {},
                                span { class: "ic", dangerous_inner_html: svg("shield") }
                                "Our principles"
                            }
                        }
                        dl { class: "hero-meta rise d5",
                            div { dt { "Front line since" } dd { "2017" } }
                            div { dt { "Inference" } dd { "On-device" } }
                            div { dt { "Raw content stored" } dd { "0 bytes" } }
                            div { dt { "Methods" } dd { "Open" } }
                        }
                    }
                    div { class: "rise d4",
                        Readout {}
                    }
                }
            }
        }

        // ---------- MISSION ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "statement-grid",
                    h2 { class: "statement reveal",
                        "Children deserve protection that "
                        span { class: "grad-text", "does not surveil them." }
                        " We prove it can be done."
                    }
                    div { class: "statement-aside reveal",
                        p {
                            "Most “online safety” technology watches everything a child does and ships it to a server. We reject that model. Our research question is narrower and harder: can a model catch real danger while seeing as little as possible — and keeping none of it?"
                        }
                        p {
                            "Four years of prototyping say yes. The result runs on the device, raises a redacted flag a guardian can act on, and forgets the rest."
                        }
                    }
                }
            }
        }

        // ---------- RESEARCH HIGHLIGHTS ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "01 — The work" }
                    h2 { "Models that catch danger, not childhoods." }
                    p { class: "lede", "A handful of focused models, each doing one safety job well — most already running in our alpha build." }
                }
                div { class: "research-list",
                    for (num , title , icon , desc , tagcls , tagtxt) in HIGHLIGHTS {
                        Link { key: "{num}", class: "r-row reveal", to: Route::Research {},
                            span { class: "r-num", "{num}" }
                            div { class: "r-title",
                                span { class: "r-ic", dangerous_inner_html: svg(icon) }
                                h3 { "{title}" }
                            }
                            p { class: "r-desc", "{desc}" }
                            div { style: "display:flex;align-items:center;gap:14px;justify-content:flex-end;",
                                span { class: "tag {tagcls}", "{tagtxt}" }
                                span { class: "r-arrow", dangerous_inner_html: svg("arrow-up-right") }
                            }
                        }
                    }
                }
                div { style: "margin-top:28px;",
                    Link { class: "btn btn-ghost", to: Route::Research {},
                        "See all research"
                        span { class: "ic", dangerous_inner_html: svg("arrow-right") }
                    }
                }
            }
        }

        // ---------- BLOCK IN PLACE (the differentiator) ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "hero-grid",
                    div {
                        span { class: "sec-index", "The difference" }
                        h2 { style: "margin-top:14px;",
                            "Block in place — "
                            span { class: "grad-text", "not the whole web." }
                        }
                        p { class: "lede", style: "margin-top:18px;",
                            "Most filters ban an entire site the instant it might show something unsafe — so a child loses legitimate search, social and learning sites by association, and families give up on the filter altogether. We don’t. Our models remove or replace only the unsafe content, in place, and leave the rest of the page working."
                        }
                    }
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
                }
            }
        }

        // ---------- PRINCIPLES ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "02 — How we work" }
                    h2 { "Four lines we will not cross." }
                }
                div { class: "grid-4",
                    for (icon , title , desc) in PRINCIPLES {
                        div { key: "{title}", class: "card reveal",
                            div { class: "card-ic", dangerous_inner_html: svg(icon) }
                            h3 { "{title}" }
                            p { "{desc}" }
                        }
                    }
                }
            }
        }

        // ---------- NUMBERS ----------
        section { class: "section",
            div { class: "wrap",
                dl { class: "stats reveal",
                    div { class: "stat", dt { "2017" } dd { "On the front line since" } }
                    div { class: "stat", dt { "76K" } dd { "People in our community" } }
                    div { class: "stat", dt { span { class: "grad-text", "0" } } dd { "Raw messages or media stored" } }
                    div { class: "stat", dt { "100%" } dd { "On-device inference" } }
                }
            }
        }

        // ---------- FOUNDER NOTE ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "statement-grid",
                    div {
                        span { class: "sec-index", style: "margin-bottom:18px;", "03 — Who builds it" }
                        h2 { class: "reveal", "A small team, four years deep." }
                        p { class: "lede reveal", style: "margin-top:18px;",
                            "Predator Hunters Research is the AI arm of an independent child-protection organisation that has been on the front line since 2017. We are small, self-funded, and obsessive about getting the safety — and the privacy — right."
                        }
                        div { style: "margin-top:26px;",
                            Link { class: "btn btn-ghost", to: Route::About {},
                                "Meet the team"
                                span { class: "ic", dangerous_inner_html: svg("arrow-right") }
                            }
                        }
                    }
                    div { class: "team-grid reveal",
                        div { class: "member",
                            div { class: "member-photo", "JU" }
                            b { "Jordan Upton" }
                            div { class: "role", "Founder · Lead developer" }
                            p { "Builds the models and the systems they run on — and decides what we will never build." }
                        }
                    }
                }
            }
        }
    }
}

/// The hero "protective telemetry" panel — a calm, technical readout that says,
/// at a glance, what the lab's work does and does not do.
#[component]
fn Readout() -> Element {
    rsx! {
        div { class: "readout",
            div { class: "ro-scan" }
            div { class: "readout-bar",
                span { class: "tl", i {} i {} i {} }
                b { "on-device · research build" }
            }
            div { class: "readout-body",
                div { class: "ro-row",
                    span { class: "ro-k", "grooming-pattern model" }
                    span { class: "ro-v good", span { class: "live" } "active" }
                }
                div { class: "ro-row",
                    span { class: "ro-k", "content classifier" }
                    span { class: "ro-v good", span { class: "live" } "active" }
                }
                div { class: "ro-row",
                    span { class: "ro-k", "raw messages stored" }
                    span { class: "ro-v", "0 bytes" }
                }
                div { class: "ro-row",
                    span { class: "ro-k", "guardian alert" }
                    span { class: "ro-v", "redacted" }
                }
                div { class: "ro-row",
                    span { class: "ro-k", "sent to the cloud" }
                    span { class: "ro-v", "never" }
                }
            }
        }
    }
}
