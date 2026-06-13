//! Home — the lab's front door. Plain, human copy (no em-dashes / AI cadence).

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

/// (index, title, icon, description, status-class, status-label)
const HIGHLIGHTS: [(&str, &str, &str, &str, &str, &str); 4] = [
    (
        "01",
        "Grooming-pattern recognition",
        "scan",
        "A small language model that learns how predators talk. Secrecy pressure, pushing a child onto another app, fishing for their age or address. When it sees the pattern it tells a parent, with none of the message contents attached.",
        "live",
        "In alpha",
    ),
    (
        "02",
        "On-device content filtering",
        "shield-check",
        "It checks images and text as a page loads and blocks the unsafe ones in place. Only the harmful part is removed, so the rest of the page still works. Illegal child-abuse material is blocked on sight and reported as the law requires, and it is never stored or shown.",
        "live",
        "In alpha",
    ),
    (
        "03",
        "Reading the screen in encrypted apps",
        "cpu",
        "Plain OCR, running on the phone, reads the text already on screen. That lets it catch grooming even inside end-to-end-encrypted chats. It never logs keystrokes or passwords, and nothing it reads leaves the device.",
        "live",
        "In alpha",
    ),
    (
        "04",
        "Offender-record matching",
        "network",
        "Early research into linking convictions that are already on the public court record, to support our journalism. A person reviews every match, and only after a case has been to court.",
        "research",
        "Research",
    ),
];

/// (icon, title, description) — the four lines we hold.
const PRINCIPLES: [(&str, &str, &str); 4] = [
    (
        "cpu",
        "On device by default",
        "The models run on the child's own phone. Nothing leaves it unless there is a real reason for it to.",
    ),
    (
        "eye-off",
        "We remember nothing",
        "No raw messages or images are ever kept. A parent gets a short, redacted alert and nothing more.",
    ),
    (
        "scale",
        "A person always decides",
        "The models raise a concern. A person decides what happens next, whether that is a parent or one of our editors. Nothing is ever an automated accusation.",
    ),
    (
        "doc",
        "Open methods, closed data",
        "We are happy to explain how the models work. We will never hand over a child's data, a grooming dataset, or live model weights.",
    ),
];

/// (icon, name, tagline, description, status)
const SYSTEMS: [(&str, &str, &str, &str, &str); 2] = [
    (
        "camera",
        "PH Camera",
        "Ships first",
        "A camera that will not take or keep an unsafe photo. Every frame is checked on the phone and thrown away. The app has no internet permission, so nothing it sees can leave the device.",
        "Alpha",
    ),
    (
        "shield",
        "PH Bulwark",
        "Ships next",
        "The shield for the whole device. It filters unsafe content in place across apps and the web, warns a parent when something is wrong, and keeps the rest of the page working.",
        "In build",
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
                            span { "Predator Hunters · AI research" }
                        }
                        h1 { class: "rise d2",
                            "AI that protects children "
                            span { class: "grad-text", "without watching them." }
                        }
                        p { class: "hero-lede rise d3",
                            "Our models run on a child's own phone. They catch unsafe content and the way predators talk, flag it to a parent, and keep nothing."
                        }
                        div { class: "hero-actions rise d4",
                            Link { class: "btn btn-primary", to: Route::Research {},
                                "See the research"
                                span { dangerous_inner_html: svg("arrow-right") }
                            }
                            Link { class: "btn btn-ghost", to: Route::Approach {},
                                span { class: "ic", dangerous_inner_html: svg("shield") }
                                "How we work"
                            }
                        }
                        dl { class: "hero-meta rise d5",
                            div { dt { "On the front line since" } dd { "2017" } }
                            div { dt { "Where it runs" } dd { "On the phone" } }
                            div { dt { "Raw content kept" } dd { "0 bytes" } }
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
                        span { class: "grad-text", "does not spy on them." }
                        " We think that is possible, and we are building it."
                    }
                    div { class: "statement-aside reveal",
                        p {
                            "Most online-safety tools watch everything a child does and send it off to a server. We don't want to build that. Our question is harder. Can a model catch real danger while seeing as little as possible, and keeping none of it?"
                        }
                        p {
                            "Four years of work say yes. What we have runs on the phone, raises a short flag a parent can act on, and forgets the rest."
                        }
                    }
                }
            }
        }

        // ---------- SYSTEMS PREVIEW ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "01 — What we ship" }
                    h2 { "Two systems, one job." }
                    p { class: "lede", "The research turns into apps families can actually install. The camera comes first, the full shield follows." }
                }
                div { class: "grid-2",
                    for (icon , name , tag , desc , status) in SYSTEMS {
                        Link { key: "{name}", class: "card reveal", to: Route::Systems {},
                            div { style: "display:flex;align-items:center;justify-content:space-between;",
                                div { class: "card-ic", dangerous_inner_html: svg(icon) }
                                span { class: "tag live", "{status}" }
                            }
                            h3 { style: "margin-top:18px;", "{name}" }
                            div { class: "role", style: "font-family:var(--mono);font-size:.7rem;letter-spacing:.14em;text-transform:uppercase;color:var(--orange);margin:6px 0 10px;", "{tag}" }
                            p { "{desc}" }
                        }
                    }
                }
            }
        }

        // ---------- BLOCK IN PLACE ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "The difference" }
                    h2 {
                        "Block in place, "
                        span { class: "grad-text", "not the whole web." }
                    }
                    p { class: "lede",
                        "Most filters ban a whole site the moment it might show something unsafe, so a child loses the search, social and learning sites they actually need. We do two things instead. When we can, we pull out only the unsafe parts and leave the page working. When the content is serious, we block it outright."
                    }
                }
                div { class: "mock-pair reveal",
                    div {
                        div { class: "browser",
                            div { class: "browser-bar",
                                span { class: "dots", i {} i {} i {} }
                                span { class: "browser-url", "search results · images" }
                            }
                            div { class: "tile-grid",
                                div { class: "tile" }
                                div { class: "tile blocked", dangerous_inner_html: svg("shield") }
                                div { class: "tile" }
                                div { class: "tile" }
                                div { class: "tile" }
                                div { class: "tile blocked", dangerous_inner_html: svg("shield") }
                            }
                        }
                        p { class: "mock-cap", "Filtered in place. The page keeps working." }
                    }
                    div {
                        div { class: "phone",
                            div { class: "phone-screen",
                                div { class: "phone-notch" }
                                span { class: "phone-shield", dangerous_inner_html: svg("shield") }
                                div { class: "phone-title", "Blocked by PH Bulwark" }
                                div { class: "phone-sub", "This content was flagged as unsafe." }
                            }
                        }
                        p { class: "mock-cap", "Blocked outright when it must be." }
                    }
                }
            }
        }

        // ---------- RESEARCH HIGHLIGHTS ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "02 — The models" }
                    h2 { "Small models, each with one safety job." }
                    p { class: "lede", "Most of these already run in our alpha. None of them need the cloud." }
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
            }
        }

        // ---------- BENCHMARK ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "cta reveal",
                    div { class: "cta-inner",
                        p { class: "eyebrow", style: "margin-bottom:18px;", "Our child-safety benchmark" }
                        h2 {
                            "We asked the big AI models to help protect children. "
                            span { class: "grad-text", "Most said no." }
                        }
                        p { class: "lede",
                            "We built a benchmark of 36 real child-safety tasks and ran six frontier models through it. GPT-5 refused all five categories. Gemini refused most. Only xAI's Grok took the work on, and Grok-4.1 scored 79.9% on average and 100% on real grooming cases. That gap is a big part of why we build our own models."
                        }
                        div { class: "cta-actions",
                            a { class: "btn btn-primary", href: "https://benchmark.predatorhunters.co.uk",
                                "See the benchmark"
                                span { dangerous_inner_html: svg("arrow-up-right") }
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
                    span { class: "sec-index", "03 — How we work" }
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
                    div { class: "stat", dt { span { class: "grad-text", "0" } } dd { "Raw messages or images kept" } }
                    div { class: "stat", dt { "100%" } dd { "Runs on the phone" } }
                }
            }
        }

        // ---------- FOUNDER ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "statement-grid",
                    div {
                        span { class: "sec-index", style: "margin-bottom:18px;", "04 — Who builds it" }
                        h2 { class: "reveal", "A small team, four years in." }
                        p { class: "lede reveal", style: "margin-top:18px;",
                            "Predator Hunters Research is the AI side of a child-protection group that has run since 2017. We are small and self-funded, and we care as much about a child's privacy as we do about their safety."
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
                            p { "Builds the models and the systems they run on, and decides what we won't build." }
                        }
                    }
                }
            }
        }
    }
}

/// The hero "protective telemetry" panel. A calm, technical readout of what the
/// work does and does not do.
#[component]
fn Readout() -> Element {
    rsx! {
        div { class: "readout",
            div { class: "ro-scan" }
            div { class: "readout-bar",
                span { class: "tl", i {} i {} i {} }
                b { "on device · research build" }
            }
            div { class: "readout-body",
                div { class: "ro-row",
                    span { class: "ro-k", "grooming model" }
                    span { class: "ro-v good", span { class: "live" } "active" }
                }
                div { class: "ro-row",
                    span { class: "ro-k", "content filter" }
                    span { class: "ro-v good", span { class: "live" } "active" }
                }
                div { class: "ro-row",
                    span { class: "ro-k", "raw messages kept" }
                    span { class: "ro-v", "0 bytes" }
                }
                div { class: "ro-row",
                    span { class: "ro-k", "parent alert" }
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
