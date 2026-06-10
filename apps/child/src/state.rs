//! Shared onboarding state, provided once at the app root (`router::App`) and
//! read by each routed step via `use_context::<Setup>()`.

use dioxus::prelude::*;

/// Permission grants + the pair code, shared across the routed steps.
///
/// On mobile the grant flags are flipped by the native bridge (`java_plugin!`);
/// on desktop/web the buttons flip them locally so the journey previews
/// end-to-end. `Signal` is `Copy`, so `Setup` is `Copy` and cheap to pass around.
#[derive(Clone, Copy)]
pub struct Setup {
    pub accessibility: Signal<bool>,
    pub network: Signal<bool>,
    pub device_admin: Signal<bool>,
    pub code: Signal<String>,
}

impl Setup {
    /// Build the initial (all-ungranted) state. Called inside
    /// `use_context_provider` at the app root, so the signals live for the whole
    /// app.
    pub fn new() -> Self {
        Self {
            accessibility: Signal::new(false),
            network: Signal::new(false),
            device_admin: Signal::new(false),
            code: Signal::new(String::new()),
        }
    }

    /// All three OS permissions granted → the Permissions step can continue.
    pub fn all_granted(&self) -> bool {
        (self.accessibility)() && (self.network)() && (self.device_admin)()
    }

    /// The pair code has enough alphanumerics to attempt a connection.
    pub fn code_ok(&self) -> bool {
        (self.code)()
            .trim()
            .chars()
            .filter(|c| c.is_alphanumeric())
            .count()
            >= 6
    }

    /// Reset for a fresh run (the Done step's "Done" button).
    pub fn reset(&mut self) {
        self.accessibility.set(false);
        self.network.set(false);
        self.device_admin.set(false);
        self.code.set(String::new());
    }
}
