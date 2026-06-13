//! Predator Hunters Research — the public site for an independent child-safety
//! AI lab. All-Rust Dioxus 0.8 web app (ships as wasm to
//! research.predatorhunters.co.uk via `dx build --platform web`).
//!
//! EDITORIAL VOICE (load-bearing — see docs/FRAMING.md): this lab is presented
//! as **independent research and journalism**. We report only on matters that
//! have concluded in court (convictions / public court records) — **never
//! pre-trial naming** — and we **do not** claim any law-enforcement
//! partnership. The journalism, downloads, and case archive live on the
//! separate MAIN site; THIS site is the research/AI lab: our mission, our
//! models, our principles, and the team.
//!
//! PRIVACY POSTURE mirrors the product: the AI runs on-device, no raw messages
//! or media are stored, and illegal imagery is detect → block → report (never
//! stored). Nothing here is offensive-security, surveillance, or "stalkerware".

mod app;
mod assets;
mod components;
mod icons;
mod pages;
mod theme;

fn main() {
    dioxus::launch(app::App);
}
