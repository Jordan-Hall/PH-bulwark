//! PH Bulwark — child app (Dioxus 0.8). The onboarding "setup journey", now
//! code-split into modules and driven by `dioxus-router`: each step is a route
//! under a shared `JourneyLayout`. See docs/design/dioxus-app-architecture.md.
//!
//! UI only. The real OS services live native in `platform/android` (VpnService /
//! AccessibilityService / DeviceAdminReceiver); on the mobile target the grant
//! buttons bridge to them via `java_plugin!`. Here they flip shared signal state
//! so the journey is fully previewable on desktop/web.

mod components;
mod router;
mod screens;
mod state;
mod theme;

fn main() {
    dioxus::launch(router::App);
}
