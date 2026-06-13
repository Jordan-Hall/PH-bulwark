//! Security — responsible-disclosure policy + safe-harbour. A trust signal for
//! the exact audience that checks: safeguarding partners and security
//! researchers. Plain, human copy; reuses the shared page styles.

use dioxus::prelude::*;

use crate::icons::svg;

/// (term, definition) — the disclosure policy.
const POLICY: [(&str, &str); 5] = [
    (
        "How to report",
        "Email research@predatorhunters.co.uk with what you found and how to reproduce it. We read every report. If it is sensitive, say so in the first line and we will reply with a way to share details safely.",
    ),
    (
        "Safe harbour",
        "If you act in good faith, stay within this page, and give us a fair chance to fix things before going public, we will not pursue or support legal action against you. Tell us who to credit and we will, once a fix is out.",
    ),
    (
        "In scope",
        "research.predatorhunters.co.uk and the open-source engine. Things we care about most: anything that could expose a child's data, weaken the on-device boundary, or get around a filter.",
    ),
    (
        "Out of scope, and a hard line",
        "Never test against a real child, a real device in use by a child, or anyone who has not consented. Do not run denial-of-service, send spam, or use social engineering against our team. Use your own test accounts and devices.",
    ),
    (
        "What to expect",
        "We aim to acknowledge a report within a few days. We will tell you honestly whether it is something we can fix, when, and we will keep you in the loop. We are a small team, so please be patient with timing, not with severity.",
    ),
];

#[component]
pub fn Security() -> Element {
    rsx! {
        crate::components::Seo {
            title: "Security & responsible disclosure | Predator Hunters Research",
            description: "How to report a security issue to Predator Hunters Research. Good-faith safe harbour, scope, and one hard line: never test against a real child or a child's device.",
            path: "/security",
            image: "/og/home.png",
        }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Security" }
                h1 { class: "rise d2",
                    "Found a problem? "
                    span { class: "grad-text", "Tell us." }
                }
                p { class: "lede rise d3",
                    "We build software that protects children, so we take a security report as seriously as anything we do. If you have found a weakness, here is how to reach us and what we promise in return."
                }
                div { class: "hero-actions rise d4", style: "margin-top:30px;",
                    a { class: "btn btn-primary", href: "mailto:research@predatorhunters.co.uk?subject=Security%20report",
                        span { dangerous_inner_html: svg("mail") }
                        "Report a security issue"
                    }
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                dl { class: "deflist reveal",
                    for (term , def) in POLICY {
                        div { key: "{term}", class: "def",
                            dt { "{term}" }
                            dd { "{def}" }
                        }
                    }
                }
                p { class: "prose", style: "margin-top:28px;",
                    "There is a machine-readable version of this at "
                    a { href: "/.well-known/security.txt", style: "color:var(--green-2); text-decoration:underline; text-underline-offset:3px;", "/.well-known/security.txt" }
                    "."
                }
            }
        }
    }
}
