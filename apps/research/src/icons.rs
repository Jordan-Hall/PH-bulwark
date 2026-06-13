//! A small, cohesive inline-SVG icon set (no icon-font dependency). Each helper
//! returns self-contained `<svg>` markup dropped into the RSX via
//! `dangerous_inner_html` on a wrapping element. One line language: 1.5px round
//! strokes, `currentColor`, 24×24 viewBox — so the parent's CSS `color` drives
//! the icon. Unknown names fall back to a neutral ring, so a typo can never
//! blow up the render.

pub fn svg(name: &str) -> &'static str {
    match name {
        "shield" => SHIELD,
        "shield-check" => SHIELD_CHECK,
        "eye-off" => EYE_OFF,
        "lock" => LOCK,
        "cpu" => CPU,
        "layers" => LAYERS,
        "scan" => SCAN,
        "waveform" => WAVEFORM,
        "network" => NETWORK,
        "fingerprint" => FINGERPRINT,
        "leaf" => LEAF,
        "globe" => GLOBE,
        "arrow-right" => ARROW_RIGHT,
        "arrow-up-right" => ARROW_UP_RIGHT,
        "check" => CHECK,
        "plus" => PLUS,
        "minus" => MINUS,
        "mail" => MAIL,
        "github" => GITHUB,
        "doc" => DOC,
        "spark" => SPARK,
        "device" => DEVICE,
        "scale" => SCALE,
        "sun" => SUN,
        "moon" => MOON,
        "camera" => CAMERA,
        "bolt" => BOLT,
        "menu" => MENU,
        "close" => CLOSE,
        "facebook" => FACEBOOK,
        "x" => XTWITTER,
        "share" => SHARE,
        _ => DOT,
    }
}

const SHIELD: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 2.6l7.5 3.2v5.1c0 4.8-3.2 8.1-7.5 9.5-4.3-1.4-7.5-4.7-7.5-9.5V5.8L12 2.6z"/></svg>"#;
const SHIELD_CHECK: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 2.6l7.5 3.2v5.1c0 4.8-3.2 8.1-7.5 9.5-4.3-1.4-7.5-4.7-7.5-9.5V5.8L12 2.6z"/><path d="M8.8 12l2.2 2.2 4.2-4.4"/></svg>"#;
const EYE_OFF: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M3.5 3.5l17 17"/><path d="M10 5.2A9 9 0 0 1 12 5c5 0 8.5 4.5 9.5 7-.4 1-1.2 2.3-2.4 3.5"/><path d="M6.4 7.6C4.6 8.9 3.4 10.7 2.5 12c1 2.5 4.5 7 9.5 7 1.2 0 2.4-.3 3.4-.7"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.3"/></svg>"#;
const LOCK: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="5" y="11" width="14" height="9" rx="2.2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>"#;
const CPU: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 2.5v3M14 2.5v3M10 18.5v3M14 18.5v3M2.5 10h3M2.5 14h3M18.5 10h3M18.5 14h3"/></svg>"#;
const LAYERS: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/></svg>"#;
const SCAN: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2"/><path d="M4 12h16"/></svg>"#;
const WAVEFORM: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M3 12h2.5M19 12h2"/><path d="M7.5 8v8M11 4.5v15M14.5 7v10"/></svg>"#;
const NETWORK: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="5" r="2.4"/><circle cx="5" cy="18" r="2.4"/><circle cx="19" cy="18" r="2.4"/><path d="M10.4 6.9L6.4 15.7M13.6 6.9l4 8.8M7.4 18h9.2"/></svg>"#;
const FINGERPRINT: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 11a2.5 2.5 0 0 1 2.5 2.5v1a6 6 0 0 0 .5 2.4"/><path d="M7.5 16.5A6 6 0 0 1 7 14v-1a5 5 0 0 1 8.6-3.5"/><path d="M4.8 11.5A8 8 0 0 1 19 9.3"/><path d="M9.5 19.2A8 8 0 0 1 9 14"/></svg>"#;
const LEAF: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M5 19c0-8 5-13 14-13 0 9-5 14-13 14"/><path d="M5 19c2.5-4 5.5-6.5 9.5-8.5"/></svg>"#;
const GLOBE: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.5 2.3 2.5 14.7 0 17M12 3.5c-2.5 2.3-2.5 14.7 0 17"/></svg>"#;
const ARROW_RIGHT: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M4 12h15.5"/><path d="M13.5 6l6 6-6 6"/></svg>"#;
const ARROW_UP_RIGHT: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M7 17L17 7"/><path d="M8 7h9v9"/></svg>"#;
const CHECK: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M5 12.5l4 4 10-10"/></svg>"#;
const PLUS: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 5v14M5 12h14"/></svg>"#;
const MINUS: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M5 12h14"/></svg>"#;
const MAIL: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="3" y="5" width="18" height="14" rx="2.2"/><path d="M3.5 7.5l8.5 6 8.5-6"/></svg>"#;
const GITHUB: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M9 19c-4 1.3-4-2-5.5-2.5M15 21v-3.2c0-.9.2-1.5-.4-2 2.6-.3 5.3-1.3 5.3-5.8 0-1.3-.5-2.4-1.2-3.2.1-.3.5-1.5-.1-3 0 0-1-.3-3.3 1.2a11 11 0 0 0-6 0C6.9 1.5 5.9 1.8 5.9 1.8c-.6 1.6-.2 2.8-.1 3-.8.8-1.2 1.9-1.2 3.2 0 4.5 2.7 5.5 5.3 5.8-.3.3-.6.8-.5 1.6V21"/></svg>"#;
const DOC: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M7 3h7l4 4v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M13 3v5h5M9 13h6M9 16.5h6"/></svg>"#;
const SPARK: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 3c.6 4.3 1.7 5.4 6 6-4.3.6-5.4 1.7-6 6-.6-4.3-1.7-5.4-6-6 4.3-.6 5.4-1.7 6-6z"/></svg>"#;
const DEVICE: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="7" y="2.5" width="10" height="19" rx="2.4"/><path d="M10.5 18.5h3"/></svg>"#;
const SCALE: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M12 3v18M7 21h10"/><path d="M5 7l-2.5 6a2.8 2.8 0 0 0 5 0L5 7zM19 7l-2.5 6a2.8 2.8 0 0 0 5 0L19 7zM5 7h14"/></svg>"#;
const SUN: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2.5M12 19v2.5M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M2.5 12h2.5M19 12h2.5M4.6 19.4l1.8-1.8M17.6 6.4l1.8-1.8"/></svg>"#;
const MOON: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M20 14.5A8 8 0 0 1 9.5 4 7 7 0 1 0 20 14.5z"/></svg>"#;
const CAMERA: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M4 8.5a2 2 0 0 1 2-2h1.6l1-1.6h4.8l1 1.6H18a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/><circle cx="12" cy="12.5" r="3.2"/></svg>"#;
const BOLT: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M13 2L5 13h6l-1 9 8-11h-6l1-9z"/></svg>"#;
const FACEBOOK: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path d="M22 12a10 10 0 1 0-11.56 9.88v-6.99H7.9V12h2.54V9.8c0-2.5 1.49-3.89 3.77-3.89 1.09 0 2.24.2 2.24.2v2.46H15.2c-1.24 0-1.63.77-1.63 1.56V12h2.78l-.44 2.89h-2.34v6.99A10 10 0 0 0 22 12z"/></svg>"#;
const XTWITTER: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path d="M17.53 3h3.02l-6.6 7.54L21.75 21h-6.09l-4.77-6.23L5.43 21H2.4l7.06-8.07L2.25 3h6.24l4.31 5.7L17.53 3zm-1.06 16.2h1.67L7.6 4.7H5.8l10.67 14.5z"/></svg>"#;
const SHARE: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.2 10.9l7.6-3.8M8.2 13.1l7.6 3.8"/></svg>"#;
const MENU: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M4 7h16M4 12h16M4 17h16"/></svg>"#;
const CLOSE: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><path d="M6 6l12 12M18 6L6 18"/></svg>"#;
const DOT: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="6"/></svg>"#;
