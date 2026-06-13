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
    ("On device by default", "The models run on the child's own phone. You can route traffic through a filtering VPN, but only to our servers or an instance you host yourself, never a third party, and it never carries raw content."),
    ("No raw content, ever", "No raw message, image or video is ever stored. What we keep is a short, redacted record for the guardian, the verdict and a stripped-back snippet or a blurred thumbnail, held in an encrypted, tamper-evident log that deletes itself on a clock. There is nothing raw sitting on a server to leak, because we never put it there."),
    ("A person always decides", "The models raise a concern and a person acts on it. A parent decides for their child, and our editors decide what we report. Nothing is ever an automated accusation."),
    ("Block and report, never store", "Illegal child-abuse material is blocked on sight and reported to the right authority, as the law requires. It is never stored, served, or made."),
    ("Stings, then the courts", "Our frontline team runs decoy operations and, when it is safe, confronts the person and holds them for the police with everything we have gathered. We never name anyone before they are charged. Footage is held back until there is a conviction, censored where it is needed, and published only when it genuinely helps people protect children. We work with the police, not in their place."),
    ("Open methods, closed data", "We explain how the models work. We never publish anything that could harm a child, like their data, a grooming dataset, or live weights."),
];

/// (question, answer) — the trust questions people ask first.
const FAQ: [(&str, &str); 5] = [
    ("Is this spyware?", "No. It is openly installed, visible on the device, and can be switched off. It only ever runs on a child's own phone, with consent, and never on adults or anyone who has not agreed to it."),
    ("What data leaves the phone?", "By default, none of the content. The models judge things on the device. When something needs a parent they get a short, redacted alert with no message contents in it. If you turn on the network filter, traffic goes to our servers or one you host yourself, never a third party, and still nothing raw is kept."),
    ("Can it read my child's private messages?", "It reads what is already on the screen, on the device, so it can catch grooming inside encrypted apps. It never logs keystrokes or passwords, and that text never leaves the phone or gets stored."),
    ("Do you keep or sell any of it?", "We don't sell anything, and we never store raw messages, images or video. What we keep is a short, redacted record for the guardian, the verdict and a stripped-back snippet or a blurred thumbnail, in an encrypted log that deletes itself on a clock. Illegal material is blocked and reported as the law requires, never kept."),
    ("Who is it meant for?", "A guardian setting it up on a device they own, for a child in their care. It is not a tool for monitoring adults or anyone who has not consented."),
];

#[component]
pub fn Approach() -> Element {
    rsx! {
        crate::components::Seo {
            title: "Approach: protection without surveillance | Predator Hunters",
            description: "How we work and the lines we will not cross: on-device by default, no raw content kept, a person always decides, and protection without surveillance.",
            path: "/approach",
            image: "/og/approach.png",
        }
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
                        "Predator Hunters has worked on the front line since "
                        strong { "2017" }
                        ", running online decoy operations, reporting from court, and training parents. The lab is the newest part of that work, and it keeps the same hard rules. We treat a child's privacy as part of their safety, not something to trade away for it."
                    }
                    p {
                        "So the models are small enough to run on the phone, the system keeps "
                        strong { "no raw content" }
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

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Questions" }
                    h2 { "The questions people ask first." }
                }
                dl { class: "deflist reveal",
                    for (q , a) in FAQ {
                        div { key: "{q}", class: "def",
                            dt { "{q}" }
                            dd { "{a}" }
                        }
                    }
                }
            }
        }
    }
}
