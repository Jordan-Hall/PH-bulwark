//! PH Bulwark — child onboarding **DESIGN PREVIEW** (Dioxus 0.8), NOT the shipped
//! child app. The shipped child app is **native** (`platform/android`: VpnService /
//! AccessibilityService / DeviceAdminReceiver + the Rust core over JNI) — a webview
//! cannot be those OS services. This crate exists to iterate the journey's design on
//! desktop/web (and drive the `tools/ui-tests` web journey); its grant buttons just
//! flip shared signal state, they do not touch real OS services.
//!
//! Code-split into modules, driven by `dioxus-router` (each step a route under a
//! shared `JourneyLayout`). See docs/design/dioxus-app-architecture.md.

mod components;
mod router;
mod screens;
mod state;
mod theme;

fn main() {
    dioxus::launch(router::App);
}
