//! Waitlist — families asking to join the alpha. We need just enough to plan
//! the rollout: a contact email, which device it is for, and the rough age of
//! the guardian and the child. Plain, human copy.
//!
//! Submission posts to the `join_waitlist` server function, which validates,
//! rate-limits, and appends one redacted line to an append-only file on a
//! persisted volume. If the server is unreachable (e.g. the static-only
//! fallback deploy, or the server process is down), the form degrades to a
//! pre-filled `mailto:` so a request still lands in our inbox. We store the
//! email only to contact a guardian about the alpha; no name or DOB is asked.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

const DEVICES: [&str; 5] = ["Windows", "macOS", "iPad", "Android", "iPhone (iOS)"];
const PARENT_AGES: [&str; 5] = ["18 to 24", "25 to 34", "35 to 44", "45 to 54", "55 or older"];
const CHILD_AGES: [&str; 5] = ["Under 5", "5 to 9", "10 to 12", "13 to 15", "16 to 17"];

/// Loose email sanity check (no regex dependency). Good enough to catch typos;
/// the real gate is that a person reads the inbox.
fn looks_like_email(s: &str) -> bool {
    let s = s.trim();
    match s.find('@') {
        Some(i) if i > 0 && i + 1 < s.len() => {
            let domain = &s[i + 1..];
            domain.contains('.') && !domain.ends_with('.') && !s.contains(' ') && s.len() <= 254
        }
        _ => false,
    }
}

/// Byte-correct percent-encoding for the mailto fallback query.
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

/// Append one redacted waitlist line. Server-only: file IO + a crude global
/// rate limit (per-IP is intentionally skipped to avoid coupling to the proxy
/// header setup; the honeypot + validation + this cap are enough for an alpha).
#[cfg(feature = "server")]
mod store {
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    const WINDOW_SECS: u64 = 60;
    const MAX_PER_WINDOW: usize = 30;
    static HITS: OnceLock<Mutex<Vec<u64>>> = OnceLock::new();

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn json_str(s: &str) -> String {
        let mut o = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                '\n' => o.push_str("\\n"),
                '\r' => o.push_str("\\r"),
                '\t' => o.push_str("\\t"),
                c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
                c => o.push(c),
            }
        }
        o.push('"');
        o
    }

    /// Returns Err with a human message on rate-limit or storage failure.
    pub fn record(
        email: &str,
        device: &str,
        parent_age: &str,
        child_age: &str,
    ) -> Result<(), String> {
        let lock = HITS.get_or_init(|| Mutex::new(Vec::new()));
        {
            let mut hits = lock.lock().unwrap_or_else(|e| e.into_inner());
            let t = now();
            hits.retain(|&h| t.saturating_sub(h) < WINDOW_SECS);
            if hits.len() >= MAX_PER_WINDOW {
                return Err("We are getting a lot of sign-ups right now. Please try again in a minute.".into());
            }
            hits.push(t);
        }

        let path =
            std::env::var("WAITLIST_DATA").unwrap_or_else(|_| "/data/waitlist.jsonl".to_string());
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let line = format!(
            "{{\"ts\":{},\"email\":{},\"device\":{},\"parent_age\":{},\"child_age\":{}}}\n",
            now(),
            json_str(email),
            json_str(device),
            json_str(parent_age),
            json_str(child_age),
        );
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("Could not save your sign-up ({e}). Please email us instead."))?;
        f.write_all(line.as_bytes())
            .map_err(|e| format!("Could not save your sign-up ({e}). Please email us instead."))?;
        Ok(())
    }
}

/// Join the alpha. `company` is a honeypot: real users never see or fill it, so
/// a non-empty value is treated as a bot and silently dropped.
#[server(endpoint = "join_waitlist")]
async fn join_waitlist(
    email: String,
    device: String,
    parent_age: String,
    child_age: String,
    company: String,
) -> Result<(), ServerFnError> {
    if !company.trim().is_empty() {
        return Ok(());
    }
    let email = email.trim();
    if !looks_like_email(email) {
        return Err(ServerFnError::new("Please enter a valid email address."));
    }
    if !device.is_empty() && !DEVICES.contains(&device.as_str()) {
        return Err(ServerFnError::new("Please choose a device from the list."));
    }
    if !parent_age.is_empty() && !PARENT_AGES.contains(&parent_age.as_str()) {
        return Err(ServerFnError::new("Please choose an age group from the list."));
    }
    if !child_age.is_empty() && !CHILD_AGES.contains(&child_age.as_str()) {
        return Err(ServerFnError::new("Please choose an age group from the list."));
    }
    #[cfg(feature = "server")]
    store::record(email, &device, &parent_age, &child_age).map_err(ServerFnError::new)?;
    Ok(())
}

#[derive(Clone, PartialEq)]
enum Status {
    Idle,
    Sending,
    Done,
    Error(String),
}

#[component]
pub fn Waitlist() -> Element {
    let mut email = use_signal(String::new);
    let mut device = use_signal(String::new);
    let mut parent_age = use_signal(String::new);
    let mut child_age = use_signal(String::new);
    let mut company = use_signal(String::new); // honeypot
    let mut status = use_signal(|| Status::Idle);

    // mailto fallback, used if the server is unreachable.
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

    let submit = move |_| {
        if email().trim().is_empty() {
            return;
        }
        status.set(Status::Sending);
        let (e, d, p, c, hp) = (email(), device(), parent_age(), child_age(), company());
        spawn(async move {
            match join_waitlist(e, d, p, c, hp).await {
                Ok(()) => status.set(Status::Done),
                Err(err) => status.set(Status::Error(err.to_string())),
            }
        });
    };

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
                    div { class: "wl-form reveal",
                        if status() == Status::Done {
                            div { class: "wl-done",
                                div { class: "card-ic", dangerous_inner_html: svg("shield-check") }
                                h3 { "You are on the list." }
                                p { "Thanks. We will email you as alpha places open up. Nothing else, and you can ask us to remove you any time." }
                            }
                        } else {
                            // honeypot — hidden from real users, catches bots
                            input {
                                r#type: "text",
                                name: "company",
                                class: "wl-hp",
                                tabindex: "-1",
                                autocomplete: "off",
                                "aria-hidden": "true",
                                value: "{company}",
                                oninput: move |e| company.set(e.value()),
                            }

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

                            if email().trim().is_empty() {
                                span { class: "btn btn-primary wl-submit wl-disabled", "aria-disabled": "true",
                                    "Add your email to continue"
                                }
                            } else if status() == Status::Sending {
                                span { class: "btn btn-primary wl-submit wl-disabled", "aria-disabled": "true",
                                    "Sending..."
                                }
                            } else {
                                button { class: "btn btn-primary wl-submit", onclick: submit,
                                    "Join the waitlist"
                                    span { dangerous_inner_html: svg("arrow-right") }
                                }
                            }

                            if let Status::Error(msg) = status() {
                                p { class: "wl-error",
                                    "{msg} "
                                    a { href: "{mailto}", "Email us instead" }
                                    "."
                                }
                            }

                            p { class: "wl-note",
                                "We store your email only to contact you about the alpha. Prefer to write it yourself? "
                                a { href: "{mailto}", "research@predatorhunters.co.uk" }
                                "."
                            }
                        }
                    }

                    aside { class: "wl-aside reveal",
                        div { class: "wl-card",
                            div { class: "card-ic", dangerous_inner_html: svg("eye-off") }
                            h3 { "What we keep" }
                            p { "We store your email so we can contact you about the alpha, plus the device and age bands to plan which builds to send first. We do not sell any of it, we will not add you to a newsletter, and you can ask us to delete it at any time." }
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
.wl-hp { position: absolute; left: -9999px; width: 1px; height: 1px; opacity: 0; pointer-events: none; }
.wl-note { font-size: .86rem; color: var(--muted); line-height: 1.6; margin: 2px 0 0; }
.wl-note a, .wl-error a { color: var(--green-2); text-decoration: underline; text-underline-offset: 3px; }
.wl-error { font-size: .9rem; color: var(--orange); line-height: 1.6; margin: 2px 0 0; }
.wl-done { text-align: center; padding: 16px 8px; }
.wl-done h3 { margin: 12px 0 6px; }
.wl-done p { color: var(--ink-2); }
.wl-aside { display: flex; flex-direction: column; gap: 16px; }
.wl-card { padding: 20px; border: 1px solid var(--hair); border-radius: var(--r-md); background: var(--card-bg); }
.wl-card h3 { margin: 12px 0 6px; }
.wl-card p { color: var(--ink-2); font-size: .95rem; line-height: 1.65; }
@media (max-width: 860px) { .wl-grid { grid-template-columns: 1fr; } }
@media (max-width: 460px) { .wl-row { grid-template-columns: 1fr; } }
"#;
