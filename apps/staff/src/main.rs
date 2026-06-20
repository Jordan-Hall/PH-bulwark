//! PH Staff operators console — the INTERNAL console for Predator Hunters staff
//! (fleet/region health, guardian-account support, the NCMEC safety-report
//! workflow, and the tamper-evident staff audit log). "bulwark" is the internal
//! engineering codename.
//!
//! NOT guardian-facing and NOT child-facing — a completely separate account
//! system, token namespace, and gRPC surface (`StaffAdmin`) from PH Bulwark /
//! PH Bulwark Manager. Design: docs/design/staff-management-system.md.
//!
//! GUARDIAN PRIVACY FROM STAFF IS A PRODUCT FEATURE: every staff surface is
//! content-free by message shape. This UI renders ONLY counts, gauges, ids,
//! hashes, timestamps, and workflow state — never child content, alert payloads,
//! names, locations, or media (there is none to show; CSAM is report-never-store).

mod api;
mod config;
mod router;
mod screens;
mod session;
mod state;
mod theme;

fn main() {
    dioxus::launch(router::App);
}
