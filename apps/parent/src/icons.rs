//! A small, cohesive inline-SVG icon set (no icon-font dependency). Each helper
//! returns self-contained SVG markup dropped into the RSX via `dangerous_inner_html`
//! on a wrapping element. All icons share one line language: 1.6px round strokes,
//! `currentColor`, 24x24 viewBox — so colour is controlled by the parent's CSS.

//! Screens drop these into the RSX via `dangerous_inner_html: "{svg(\"name\")}"`
//! on a wrapping element (which carries the layout class), so one helper serves
//! every icon slot regardless of size/colour.

/// Raw SVG body for `name`. Unknown names fall back to a neutral dot so a typo can
/// never blow up the render. Strokes use `currentColor` and round caps/joins, so
/// the parent element's CSS `color` drives the icon colour. Each arm is a complete,
/// self-contained `<svg>…</svg>` literal (24x24 viewBox).
pub fn svg(name: &'static str) -> &'static str {
    match name {
        // Shield — the brand mark / protection.
        "shield" => SHIELD,
        "shield-check" => SHIELD_CHECK,
        "bell" => BELL,
        "mail" => MAIL,
        "child" => CHILD,
        "link" => LINK,
        "lock" => LOCK,
        "lock-open" => LOCK_OPEN,
        "fingerprint" => FINGERPRINT,
        "check" => CHECK,
        "globe" => GLOBE,
        "home" => HOME,
        "leaf" => LEAF,
        "shield-off" => SHIELD_OFF,
        "server" => SERVER,
        "grid" => GRID,
        "eye-off" => EYE_OFF,
        "info" => INFO,
        "alert" => ALERT,
        "key" => KEY,
        "copy" => COPY,
        // Fallback: a simple ring — a typo can never blow up the render.
        _ => DOT,
    }
}

const KEY: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><circle cx="8" cy="8" r="4"/><path d="M11 11l8 8M16 16l2-2M19 19l2-2"/></svg>"#;
const COPY: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>"#;

const SHIELD: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z"/></svg>"#;
const SHIELD_CHECK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>"#;
const SHIELD_OFF: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z"/><path d="M9 12h6"/></svg>"#;
const BELL: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M6 9a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6z"/><path d="M10 19a2 2 0 0 0 4 0"/></svg>"#;
const MAIL: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="3" y="5" width="18" height="14" rx="2.2"/><path d="M3.5 7.5l8.5 6 8.5-6"/></svg>"#;
const CHILD: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="7" r="3.2"/><path d="M5.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/></svg>"#;
const LINK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M9 13a4 4 0 0 0 5.7.3l2.7-2.7a4 4 0 0 0-5.6-5.7l-1.5 1.5"/><path d="M15 11a4 4 0 0 0-5.7-.3L6.6 13.4a4 4 0 0 0 5.6 5.7l1.5-1.5"/></svg>"#;
const LOCK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="5" y="11" width="14" height="9" rx="2.2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>"#;
const LOCK_OPEN: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="5" y="11" width="14" height="9" rx="2.2"/><path d="M8 11V8a4 4 0 0 1 7.7-1.5"/></svg>"#;
const FINGERPRINT: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 11a2.5 2.5 0 0 1 2.5 2.5v1a6 6 0 0 0 .5 2.4"/><path d="M7.5 16.5A6 6 0 0 1 7 14v-1a5 5 0 0 1 8.6-3.5"/><path d="M4.8 11.5A8 8 0 0 1 19 9.3"/><path d="M9.5 19.2A8 8 0 0 1 9 14"/></svg>"#;
const CHECK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M5 12.5l4 4 10-10"/></svg>"#;
const GLOBE: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.5 2.3 2.5 14.7 0 17"/><path d="M12 3.5c-2.5 2.3-2.5 14.7 0 17"/></svg>"#;
const HOME: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M4 11l8-6 8 6"/><path d="M6 10v9h12v-9"/><path d="M10 19v-5h4v5"/></svg>"#;
const LEAF: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M5 19c0-8 5-13 14-13 0 9-5 14-13 14"/><path d="M5 19c2.5-4 5.5-6.5 9.5-8.5"/></svg>"#;
const SERVER: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="4" y="4" width="16" height="7" rx="2"/><rect x="4" y="13" width="16" height="7" rx="2"/><path d="M8 7.5h.01M8 16.5h.01"/></svg>"#;
const GRID: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="4" y="4" width="7" height="7" rx="1.6"/><rect x="13" y="4" width="7" height="7" rx="1.6"/><rect x="4" y="13" width="7" height="7" rx="1.6"/><rect x="13" y="13" width="7" height="7" rx="1.6"/></svg>"#;
const EYE_OFF: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M4 4l16 16"/><path d="M9.9 5.2A9.3 9.3 0 0 1 12 5c5 0 8.5 4.5 9.5 7-.4 1-1.3 2.4-2.6 3.6"/><path d="M6.2 7.8C4.4 9.1 3.3 10.9 2.5 12c1 2.5 4.5 7 9.5 7 1.3 0 2.5-.3 3.5-.7"/><path d="M9.8 9.9a3 3 0 0 0 4.2 4.3"/></svg>"#;
const INFO: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="8.5"/><path d="M12 11v5"/><path d="M12 7.8h.01"/></svg>"#;
const ALERT: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 4l8.5 15h-17L12 4z"/><path d="M12 10v4"/><path d="M12 17h.01"/></svg>"#;
const DOT: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="6"/></svg>"#;
