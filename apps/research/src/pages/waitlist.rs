//! Waitlist — families asking to join the alpha. We need just enough to plan
//! the rollout: a contact email, which device it is for, and the rough age of
//! the guardian and the child. Plain, human copy.
//!
//! v10a ships the FORM on the current static deploy: submitting builds a
//! pre-filled `mailto:` so a request lands in our inbox with no backend. v10b
//! wires a `#[server]` endpoint + storage once the site runs the fullstack
//! server as its origin. The retention line is honest about what we keep.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

/// Byte-correct percent-encoding for the mailto query (RFC 3986 unreserved set
/// kept literal, everything else `%XX`). Our content is ASCII, but encoding by
/// byte keeps it correct regardless.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

const DEVICES: [&str; 5] = ["Windows", "macOS", "iPad", "Android", "iPhone (iOS)"];
const PARENT_AGES: [&str; 5] = ["18 to 24", "25 to 34", "35 to 44", "45 to 54", "55 or older"];
const CHILD_AGES: [&str; 5] = ["Under 5", "5 to 9", "10 to 12", "13 to 15", "16 to 17"];

#[component]
pub fn Waitlist() -> Element {
    let mut email = use_signal(String::new);
    let mut device = use_signal(String::new);
    let mut parent_age = use_signal(String::new);
    let mut child_age = use_signal(String::new);

    let ready = !email().trim().is_empty();
    let body = format!(
        "I would like to join the Predator Hunters alpha.\n\nEmail: {}\nDevice: {}\nMy age group: {}\nMy child's age group: {}\n",
        email(),
        if device().is_empty() { "(not given)".into() } else { device() },
        if parent_age().is_empty() { "(not given)".into() } else { parent_age() },
        if child_age().is_empty() { "(not given)".into() } else { child_age() },
    );
    let mailto = format!(
        "mailto:research@predatorhunters.co.uk?subject={}&body={}",
        enc("Join the Predator Hunters alpha"),
        enc(&body)
    );

    rsx! {
        crate::components::Seo {
            title: "Join the alpha | Predator Hunters Research",
            description: "Ask to join the Predator Hunters alpha. Tell us the device and the rough age of the guardian and child. We store your email only to contact you about the alpha.",
            path: "/waitlist",
            image: "/og/home.png",
        }
        style { dangerous_inner_html: WAITLIST_CSS }

        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Early access" }
                h1 { class: "rise d2",
                    "Join the "
                    span { class: "grad-text", "alpha." }
                }
                p { class: "lede rise d3",
                    "We are starting staged testing with a small group of families. Tell us where it would run and roughly how old everyone is, and we will be in touch as places open up."
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "wl-grid",
                    // ---- the form ----
                    div { class: "wl-form reveal",
                        label { class: "wl-field",
                            span { class: "wl-label", "Your email" }
                            input {
                                r#type: "email",
                                class: "wl-input",
                                placeholder: "you@example.com",
                                autocomplete: "email",
                                value: "{email}",
                                oninput: move |e| email.set(e.value()),
                            }
                        }

                        label { class: "wl-field",
                            span { class: "wl-label", "Which device is it for?" }
                            select {
                                class: "wl-input",
                                value: "{device}",
                                oninput: move |e| device.set(e.value()),
                                option { value: "", "Choose a device" }
                                for d in DEVICES {
                                    option { value: "{d}", "{d}" }
                                }
                            }
                        }

                        div { class: "wl-row",
                            label { class: "wl-field",
                                span { class: "wl-label", "Your age group" }
                                select {
                                    class: "wl-input",
                                    value: "{parent_age}",
                                    oninput: move |e| parent_age.set(e.value()),
                                    option { value: "", "Choose" }
                                    for a in PARENT_AGES {
                                        option { value: "{a}", "{a}" }
                                    }
                                }
                            }
                            label { class: "wl-field",
                                span { class: "wl-label", "Your child's age group" }
                                select {
                                    class: "wl-input",
                                    value: "{child_age}",
                                    oninput: move |e| child_age.set(e.value()),
                                    option { value: "", "Choose" }
                                    for a in CHILD_AGES {
                                        option { value: "{a}", "{a}" }
                                    }
                                }
                            }
                        }

                        if ready {
                            a { class: "btn btn-primary wl-submit", href: "{mailto}",
                                "Join the waitlist"
                                span { dangerous_inner_html: svg("arrow-right") }
                            }
                        } else {
                            span { class: "btn btn-primary wl-submit wl-disabled", "aria-disabled": "true",
                                "Add your email to continue"
                            }
                        }

                        p { class: "wl-note",
                            "This opens your email app with the details filled in, so nothing is sent until you press send. Prefer to write it yourself? "
                            a { href: "mailto:research@predatorhunters.co.uk?subject=Join%20the%20Predator%20Hunters%20alpha", "research@predatorhunters.co.uk" }
                            "."
                        }
                    }

                    // ---- what we do with it ----
                    aside { class: "wl-aside reveal",
                        div { class: "wl-card",
                            div { class: "card-ic", dangerous_inner_html: svg("eye-off") }
                            h3 { "What we keep" }
                            p { "We store your email only to contact you about the alpha. The device and age groups help us plan which builds to send first. We do not sell any of it, we will not add you to a newsletter, and you can ask us to delete it at any time." }
                        }
                        div { class: "wl-card",
                            div { class: "card-ic", dangerous_inner_html: svg("shield-check") }
                            h3 { "Who it is for" }
                            p { "A guardian setting things up for a child in their care, on a device they own. The age groups are rough bands on purpose. We do not need a name, a date of birth, or anything that identifies your child." }
                        }
                        div { style: "margin-top:4px;",
                            Link { class: "btn btn-ghost btn-sm", to: Route::Privacy {},
                                span { class: "ic", dangerous_inner_html: svg("doc") }
                                "Read the privacy policy"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Scoped form styling. Kept in the page (not index.html) so it never collides
/// with the global stylesheet, and built from the same design tokens.
const WAITLIST_CSS: &str = r#"
.wl-grid { display: grid; grid-template-columns: 1.1fr .9fr; gap: clamp(24px, 4vw, 48px); align-items: start; }
.wl-form { display: flex; flex-direction: column; gap: 18px; padding: clamp(20px, 3vw, 32px);
  border: 1px solid var(--hair-strong); border-radius: var(--r-lg); background: var(--card-bg); }
.wl-field { display: flex; flex-direction: column; gap: 8px; }
.wl-label { font-family: var(--mono); font-size: .7rem; letter-spacing: .14em; text-transform: uppercase; color: var(--ink-2); }
.wl-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.wl-input { width: 100%; box-sizing: border-box; min-height: 48px; padding: 12px 14px; font: inherit; font-size: 1rem;
  color: var(--head); background: var(--bg); border: 1px solid var(--hair-strong); border-radius: var(--r-sm);
  transition: border-color .18s, box-shadow .18s; appearance: none; -webkit-appearance: none; }
.wl-input:focus { outline: none; border-color: rgba(245,130,32,.6); box-shadow: 0 0 0 3px rgba(245,130,32,.18); }
select.wl-input { cursor: pointer; background-image: linear-gradient(45deg, transparent 50%, var(--ink-2) 50%), linear-gradient(135deg, var(--ink-2) 50%, transparent 50%);
  background-position: calc(100% - 20px) calc(1.35em), calc(100% - 15px) calc(1.35em); background-size: 5px 5px, 5px 5px; background-repeat: no-repeat; padding-right: 38px; }
.wl-submit { justify-content: center; margin-top: 6px; min-height: 48px; }
.wl-disabled { opacity: .5; cursor: not-allowed; }
.wl-note { font-size: .86rem; color: var(--muted); line-height: 1.6; margin: 2px 0 0; }
.wl-note a { color: var(--green-2); text-decoration: underline; text-underline-offset: 3px; }
.wl-aside { display: flex; flex-direction: column; gap: 16px; }
.wl-card { padding: 20px; border: 1px solid var(--hair); border-radius: var(--r-md); background: var(--card-bg); }
.wl-card h3 { margin: 12px 0 6px; }
.wl-card p { color: var(--ink-2); font-size: .95rem; line-height: 1.65; }
@media (max-width: 860px) { .wl-grid { grid-template-columns: 1fr; } }
@media (max-width: 460px) { .wl-row { grid-template-columns: 1fr; } }
"#;
