//! Reusable RSX shared across the journey's steps.

use dioxus::prelude::*;

/// One permission row in the Permissions step: icon + plain-language reason, and
/// either a "Grant" button or a granted check.
#[component]
pub fn PermissionRow(
    icon: String,
    name: String,
    reason: String,
    granted: bool,
    ongrant: EventHandler<()>,
) -> Element {
    rsx! {
        div { class: if granted { "perm granted" } else { "perm" },
            div { class: "perm-icon", "{icon}" }
            div { class: "perm-body",
                strong { "{name}" }
                span { "{reason}" }
            }
            if granted {
                span { class: "perm-done", "✓" }
            } else {
                button { class: "grant", onclick: move |_| ongrant.call(()), "Grant" }
            }
        }
    }
}
