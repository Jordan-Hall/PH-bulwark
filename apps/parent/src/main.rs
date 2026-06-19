//! PH Bulwark Manager — the guardian console (all-Rust Dioxus UI). "bulwark" is
//! the internal engineering codename; the product is Predator Hunters Bulwark.
//!
//! LEGITIMATE features only: review guardian alerts, **approve / keep-blocked**
//! flagged items, and see the honest coverage matrix. It talks to the home
//! cluster over the SAME gRPC contract the engine serves (`Review` carries the
//! pending-review stream and the approve/deny decision). There is deliberately
//! **no** device-control / screen / location / remote-command surface here —
//! Bulwark is a transparent content-safety tool, not a remote-administration
//! console.
//!
//! GUARDIAN-TRANSPARENCY MODEL: the console now shows guardians the FULL flagged
//! content for review — the actual blocked text snippet (`Evidence.text_snippet`)
//! and an inline preview of the blocked media (`Evidence.safe_thumbnail`,
//! rendered as a base64 data URI) — alongside the app/device/time context. The
//! parent sees what was blocked so they can make an informed approve/deny call.
//!
//! THE ONE EXCEPTION — suspected CSAM is NEVER previewed: when
//! `category == Category::CsamSuspected` the console renders no image and no
//! snippet, even if evidence bytes/text are present. Instead it shows a notice
//! that the content is withheld and never shown or stored. Previewing
//! suspected CSAM would be illegal, so it is the single thing this UI never
//! displays; the server also refuses to approve it.
//!
//! Dioxus `desktop` feature covers Windows + macOS. The same RSX drives the
//! `mobile` (Android/iOS, experimental) and `web` targets, and bumps cleanly to
//! the 0.7/0.8 native Blitz renderer (no webview) when it ships.

mod api;
mod brand;
mod components;
mod config;
mod icons;
mod lock;
mod media;
mod process;
mod provision;
mod router;
mod screens;
mod servers;
mod state;
mod theme;

#[cfg(test)]
mod tests;

fn main() {
    dioxus::launch(router::App);
}
