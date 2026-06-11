//! The onboarding steps — one routed component per `crate::router::Route`
//! variant. Navigation is `dioxus-router` (`use_navigator().push(..)`); shared
//! grant/code state comes from the `Setup` context.

use dioxus::prelude::*;

use crate::components::PermissionRow;
use crate::router::Route;
use crate::state::Setup;

#[component]
pub fn Welcome() -> Element {
    let nav = use_navigator();
    rsx! {
        div { class: "hero", role: "img", "aria-label": "Sunrise", "🌅" }
        h1 { "Let's set up protection," br {} em { "together." } }
        p { class: "lede",
            "A calm, open way to help keep your child a little safer online. "
            "It takes about three minutes, and we'll explain every step in plain words."
        }
        button {
            class: "primary",
            "aria-label": "Begin setup",
            onclick: move |_| { nav.push(Route::How {}); },
            "Begin"
        }
        p { class: "fine", "Nothing here is hidden. You'll see exactly what this app does — and what it never does — next." }
    }
}

#[component]
pub fn How() -> Element {
    let nav = use_navigator();
    rsx! {
        h2 { "What PH Bulwark does" }
        p { class: "lede", "And, just as importantly, what it never does." }
        ul { class: "facts", role: "list",
            li { class: "fact do stagger", style: "--i: 0",
                span { class: "tick", "aria-hidden": "true", "✓" }
                div {
                    strong { "Spots grooming & unsafe content" }
                    span { "Checks chats, pages and images right here on the device — never on a server." }
                }
            }
            li { class: "fact do stagger", style: "--i: 1",
                span { class: "tick", "aria-hidden": "true", "✓" }
                div {
                    strong { "Sends you a gentle, redacted alert" }
                    span { "You get a calm, plain summary — never the raw messages themselves." }
                }
            }
            li { class: "fact dont stagger", style: "--i: 2",
                span { class: "cross", "aria-hidden": "true", "✕" }
                div {
                    strong { "Never spies" }
                    span { "No live screen, no location tracking, no reading everything. This is care, not surveillance." }
                }
            }
        }
        div { class: "row",
            button {
                class: "ghost",
                "aria-label": "Go back to welcome",
                onclick: move |_| { nav.push(Route::Welcome {}); },
                "Back"
            }
            button {
                class: "primary",
                "aria-label": "I understand, continue to permissions",
                onclick: move |_| { nav.push(Route::Permissions {}); },
                "I understand"
            }
        }
    }
}

#[component]
pub fn Permissions() -> Element {
    let nav = use_navigator();
    let setup = use_context::<Setup>();
    let mut accessibility = setup.accessibility;
    let mut network = setup.network;
    let mut device_admin = setup.device_admin;
    let all = setup.all_granted();
    rsx! {
        h2 { "Three permissions, plainly" }
        p { class: "lede", "Tap to allow each one. Here's exactly why it's needed — and what it can't see." }
        div { class: "perms", role: "list",
            PermissionRow {
                icon: "💬", name: "Accessibility",
                reason: "Reads text already on screen in chats to spot grooming. It never sees your typing or passwords.",
                granted: accessibility(),
                ongrant: move |_| accessibility.set(true),
            }
            PermissionRow {
                icon: "🌐", name: "Safe browsing (VPN)",
                reason: "Checks web pages for unsafe images and content as they load on this device. Nothing leaves the phone.",
                granted: network(),
                ongrant: move |_| network.set(true),
            }
            PermissionRow {
                icon: "🔒", name: "Stay-on protection",
                reason: "Keeps the app from being quietly removed, so protection can't be switched off without you knowing.",
                granted: device_admin(),
                ongrant: move |_| device_admin.set(true),
            }
        }
        div { class: "row",
            button {
                class: "ghost",
                "aria-label": "Go back to how it works",
                onclick: move |_| { nav.push(Route::How {}); },
                "Back"
            }
            button {
                class: "primary",
                disabled: !all,
                "aria-label": if all { "Continue to connect" } else { "Allow all three permissions to continue" },
                onclick: move |_| { nav.push(Route::Pair {}); },
                if all { "Continue" } else { "Allow all three to continue" }
            }
        }
    }
}

#[component]
pub fn Pair() -> Element {
    let nav = use_navigator();
    let setup = use_context::<Setup>();
    let mut code = setup.code;
    let ok = setup.code_ok();
    let entered: String = code().chars().filter(|c| c.is_alphanumeric()).collect();
    rsx! {
        div { class: "hero", role: "img", "aria-label": "Link", "🔗" }
        h2 { "Connect to your console" }
        p { class: "lede",
            "Open PH Bulwark Manager on your own phone. It'll show a short "
            em { "pairing code" } " — type it in below."
        }
        div { class: "code-field",
            // Friendly segmented affordance: six soft slots that "fill" as you type,
            // sitting behind one accessible text input that owns the real value.
            div { class: "code-slots", "aria-hidden": "true",
                for i in 0..6_usize {
                    span {
                        class: if entered.chars().nth(i).is_some() { "slot filled" } else { "slot" },
                        {entered.chars().nth(i).map(String::from).unwrap_or_default()}
                    }
                }
            }
            if entered.is_empty() {
                span { class: "code-ghost", "aria-hidden": "true", "Enter code" }
            }
            input {
                class: "code-input",
                r#type: "text",
                inputmode: "latin",
                autocomplete: "off",
                autocapitalize: "characters",
                spellcheck: "false",
                maxlength: "8",
                "aria-label": "Pairing code from PH Bulwark Manager",
                placeholder: "Enter code",
                value: "{code}",
                oninput: move |e| code.set(e.value().to_uppercase()),
            }
        }
        p { class: "hint",
            span { class: "hint-icon", "aria-hidden": "true", "📷" }
            "The Manager app can also show a QR to scan. Scanning is coming soon — for now, just type the code."
        }
        div { class: "row",
            button {
                class: "ghost",
                "aria-label": "Go back to permissions",
                onclick: move |_| { nav.push(Route::Permissions {}); },
                "Back"
            }
            button {
                class: "primary",
                disabled: !ok,
                "aria-label": if ok { "Connect to console" } else { "Enter the pairing code to connect" },
                onclick: move |_| { nav.push(Route::Done {}); },
                "Connect"
            }
        }
        p { class: "fine", "The code expires after a few minutes — if it won't take, generate a fresh one in the Manager." }
    }
}

#[component]
pub fn Done() -> Element {
    let nav = use_navigator();
    let mut setup = use_context::<Setup>();
    rsx! {
        div { class: "seal", role: "img", "aria-label": "Protection active",
            div { class: "seal-ring" }
            div { class: "seal-ring two" }
            div { class: "seal-core", span { class: "seal-check", "✓" } }
        }
        h1 { "Protection is active." }
        p { class: "lede",
            "You're all set. This device is now watched calmly for grooming and unsafe "
            "content — and you'll get a gentle alert if anything ever needs you. "
            "You can turn it off any time from the Manager."
        }
        div { class: "done-pills", role: "list",
            span { class: "pill stagger", style: "--i: 0", role: "listitem", "✓ On-device" }
            span { class: "pill stagger", style: "--i: 1", role: "listitem", "✓ Private" }
            span { class: "pill stagger", style: "--i: 2", role: "listitem", "✓ Connected" }
        }
        button {
            class: "primary",
            "aria-label": "Finish setup",
            onclick: move |_| { setup.reset(); nav.push(Route::Welcome {}); },
            "Done"
        }
    }
}
