//! Privacy policy. Plain language. Makes the key nuance explicit: the AI runs
//! on-device by default, and the OPTIONAL network filter routes through our own
//! servers or a self-hosted instance the guardian controls, never a third party.

use dioxus::prelude::*;

use crate::icons::svg;

/// (term, definition)
const POLICY: [(&str, &str); 8] = [
    (
        "On the device by default",
        "The models run on the child's own phone. Deciding whether something is unsafe happens there, not on someone else's server.",
    ),
    (
        "We keep no raw content",
        "No raw message, image or video is ever stored by us. When something needs a guardian, what we keep is a short, redacted record: the verdict, a stripped-back text snippet or a blurred thumbnail, held in an encrypted log that deletes itself on a clock. The raw thing is never written down in the first place.",
    ),
    (
        "If you turn on the network filter",
        "You can route the device's traffic through a filtering VPN. When you do, that traffic goes to our own servers, or to an instance you host yourself, and never to a third party. Even then no raw content is kept, and the filter is always on, so a child is never quietly left on an unfiltered connection.",
    ),
    (
        "What we never touch",
        "No screen recordings, no keystrokes, no passwords, no location tracking, and no browsing profile built about anyone.",
    ),
    (
        "Illegal material",
        "Child-abuse material is detected, blocked on sight, and reported to the proper authority as the law requires. It is never stored, shown, or generated.",
    ),
    (
        "Our journalism",
        "Our reporting uses only what is already on the public court record, after a case has concluded. We never publish a child's data, and we never name anyone before they are charged.",
    ),
    (
        "This website",
        "This site keeps one thing in your browser: whether you chose light or dark mode. There are no tracking cookies, no advertising, and no analytics that identify you.",
    ),
    (
        "Your data and your rights",
        "Because we hold almost nothing, there is very little to ask us for. We follow UK GDPR and the ICO's Children's Code, and we treat anything to do with a child as the most sensitive data there is. If you have a question about data, or you are a guardian who wants to understand exactly what the product does, email us and a person will answer.",
    ),
];

#[component]
pub fn Privacy() -> Element {
    rsx! {
        crate::components::Seo {
            title: "Privacy | Predator Hunters Research",
            description: "On-device by default; the optional filtering VPN routes to our own or a self-hosted server, never a third party; no raw messages or media are stored.",
            path: "/privacy",
            image: "/og/privacy.png",
        }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Privacy" }
                h1 { class: "rise d2",
                    "Privacy is "
                    span { class: "grad-text", "the whole point." }
                }
                p { class: "lede rise d3",
                    "We build child-safety tools that try to see as little as possible, and keep no more than a guardian needs to act on. Here is exactly what that means, in plain words."
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
                    "Questions about any of this go to "
                    a { href: "mailto:research@predatorhunters.co.uk", style: "color:var(--green-2); text-decoration:underline; text-underline-offset:3px;", "research@predatorhunters.co.uk" }
                    ". Last updated June 2026."
                }
                div { style: "margin-top:24px;",
                    a { class: "btn btn-ghost", href: "mailto:research@predatorhunters.co.uk",
                        span { class: "ic", dangerous_inner_html: svg("mail") }
                        "Ask us anything"
                    }
                }
            }
        }
    }
}
