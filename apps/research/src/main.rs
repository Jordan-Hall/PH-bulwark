//! Predator Hunters Research — the public site for an independent child-safety
//! AI lab. All-Rust Dioxus 0.8 web app with fullstack SSG: every static route is
//! pre-rendered to real HTML at build time (`dx build --platform web --ssg`),
//! then the wasm hydrates on the client. Crawlers, link-preview bots, no-JS
//! clients and assistive tech get the full body; users still get the SPA.
//!
//! EDITORIAL VOICE (load-bearing — see docs/FRAMING.md): independent research +
//! journalism. We report only on matters concluded in court (convictions /
//! public record), never pre-trial, and claim no law-enforcement partnership.
//! The models run on-device; an optional filtering VPN routes through our own or
//! a self-hosted server, never a third party; nothing raw is stored.

mod app;
mod assets;
mod components;
mod icons;
mod pages;

fn main() {
    let builder = dioxus::LaunchBuilder::new();
    // SERVER build only: enable incremental static generation so the `--ssg`
    // pre-render writes the finished HTML to disk (the client/web build has no
    // `ServeConfig`). Default static dir is `./static`.
    #[cfg(feature = "server")]
    let builder = builder.with_cfg(
        dioxus::server::ServeConfig::new()
            .incremental(dioxus::server::IncrementalRendererConfig::new()),
    );
    builder.launch(app::App);
}
