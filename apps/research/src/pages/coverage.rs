//! Coverage — an honest matrix of what the tools catch today, what is alert-only,
//! and what is not technically possible (e.g. inspecting end-to-end-encrypted
//! traffic on the wire). Owning the limits in writing builds more trust than any
//! feature claim. Grounded in docs/research/platform-feasibility.md.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

/// (surface, how it is handled, where it stands, status-class)
/// status-class: "ok" = working, "part" = partial/alert-only, "no" = not yet / not possible.
const ROWS: [(&str, &str, &str, &str); 8] = [
    (
        "Photos the child takes",
        "PH Camera checks every frame on the device before it can be saved.",
        "Working in alpha",
        "ok",
    ),
    (
        "Images on the open web",
        "Filtered in place on the device, so the page keeps working.",
        "Working in alpha",
        "ok",
    ),
    (
        "Grooming in chat text",
        "An on-device model reads the text already drawn on screen and flags the pattern.",
        "Working in alpha",
        "ok",
    ),
    (
        "Unsafe video",
        "Detected as it plays and rewritten in place on the device, blurring or muting only the bad moments.",
        "Alpha, our flagship",
        "ok",
    ),
    (
        "Encrypted (end-to-end) apps",
        "We never touch the wire. We read what is already on screen, on the device, after the app has decrypted it.",
        "On-screen only",
        "part",
    ),
    (
        "Apps that pin their certificates",
        "The optional network filter cannot inspect these. We fall back to the on-device screen read, which is lossier.",
        "Partial, by design",
        "part",
    ),
    (
        "The optional network filter",
        "Routes non-pinned traffic through our server or one you host. It helps with some apps, not all.",
        "Partial",
        "part",
    ),
    (
        "Audio (calls, voice notes)",
        "Not yet. It is on the research bench, not in a shipping build.",
        "Research",
        "no",
    ),
];

#[component]
pub fn Coverage() -> Element {
    rsx! {
        crate::components::Seo {
            title: "Coverage: what we catch, and what we can't | Predator Hunters",
            description: "An honest matrix of what Predator Hunters tools catch on the device today, what is on-screen-only, and what is not possible over the network, like inspecting end-to-end-encrypted traffic on the wire.",
            path: "/coverage",
            image: "/og/research.png",
        }
        style { dangerous_inner_html: COVERAGE_CSS }

        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Coverage" }
                h1 { class: "rise d2",
                    "What we catch, and "
                    span { class: "grad-text", "what we can't." }
                }
                p { class: "lede rise d3",
                    "No tool sees everything, and a child-safety tool that pretends otherwise is its own kind of harm. Here is what works on the device today, what is on-screen only, and what is not technically possible. We would rather you trust this page than a feature list."
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "cov-wrap reveal",
                    table { class: "cov-table",
                        thead {
                            tr {
                                th { "Surface" }
                                th { "How we handle it" }
                                th { "Where it stands" }
                            }
                        }
                        tbody {
                            for (surface , how , stands , cls) in ROWS {
                                tr { key: "{surface}",
                                    td { b { "{surface}" } }
                                    td { "{how}" }
                                    td { span { class: "cov-tag {cls}", "{stands}" } }
                                }
                            }
                        }
                    }
                }

                div { class: "prose reveal", style: "margin-top:32px;",
                    h3 { style: "margin-bottom:10px;", "The one line we will not cross" }
                    p {
                        "We do not break encryption, and we never will. When a chat is end-to-end encrypted, the only honest way to help is to read what is already on the child's own screen, on their own device, after the app itself has shown it. That is a deliberate limit, not a gap we are hiding."
                    }
                }

                div { style: "margin-top:26px; display:flex; gap:12px; flex-wrap:wrap;",
                    Link { class: "btn btn-ghost", to: Route::Approach {},
                        span { class: "ic", dangerous_inner_html: svg("shield") }
                        "How we work"
                    }
                    Link { class: "btn btn-ghost", to: Route::Research {},
                        span { class: "ic", dangerous_inner_html: svg("layers") }
                        "The models"
                    }
                }
            }
        }
    }
}

const COVERAGE_CSS: &str = r#"
.cov-wrap { overflow-x: auto; border: 1px solid var(--hair-strong); border-radius: var(--r-lg); background: var(--card-bg); }
.cov-table { width: 100%; border-collapse: collapse; min-width: 640px; }
.cov-table th, .cov-table td { text-align: left; padding: 16px 18px; border-bottom: 1px solid var(--hair); vertical-align: top; }
.cov-table thead th { font-family: var(--mono); font-size: .68rem; letter-spacing: .16em; text-transform: uppercase; color: var(--ink-2); background: var(--bg-2); }
.cov-table tbody tr:last-child td { border-bottom: none; }
.cov-table td { font-size: .94rem; color: var(--ink-2); line-height: 1.55; }
.cov-table td b { color: var(--head); }
.cov-tag { display: inline-block; white-space: nowrap; font-family: var(--mono); font-size: .64rem; letter-spacing: .1em; text-transform: uppercase; padding: 5px 10px; border-radius: 999px; border: 1px solid var(--hair-strong); }
.cov-tag.ok { color: var(--green-2); border-color: rgba(143,210,74,.4); background: rgba(143,210,74,.08); }
.cov-tag.part { color: var(--orange); border-color: rgba(245,130,32,.4); background: rgba(245,130,32,.08); }
.cov-tag.no { color: var(--muted); }
"#;
