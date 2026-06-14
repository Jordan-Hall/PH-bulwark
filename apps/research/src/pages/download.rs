//! Download — how to install the alpha apps (Android today). Three FOSS routes:
//! Obtainium (auto-update from GitHub Releases), our self-hosted F-Droid repo,
//! and a direct APK download with published SHA-256 checksums. A QR opens the
//! releases on a phone. Plain copy; URLs come from docs/distribution.md.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

const RELEASES_URL: &str = "https://github.com/Jordan-Hall/PH-bulwark/releases";
const FDROID_REPO: &str = "https://dist.predatorhunters.co.uk/fdroid/repo";

/// (app, package id, apk asset)
const APPS: [(&str, &str, &str); 3] = [
    ("PH Camera", "co.predatorhunters.bulwark.camera", "camera-release.apk"),
    ("PH Bulwark", "co.predatorhunters.bulwark", "app-release.apk"),
    ("PH Bulwark Manager", "co.predatorhunters.bulwark.manager", "manager-release.apk"),
];

/// Render a QR code to inline SVG (no network, no third party). Empty on error.
fn qr_svg(data: &str) -> String {
    use qrcode::render::svg;
    use qrcode::QrCode;
    match QrCode::new(data.as_bytes()) {
        Ok(code) => code
            .render::<svg::Color>()
            .min_dimensions(180, 180)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

#[component]
pub fn Download() -> Element {
    rsx! {
        crate::components::Seo {
            title: "Download the alpha (FOSS) | Predator Hunters Research",
            description: "Install PH Camera and PH Bulwark on Android via Obtainium, our self-hosted F-Droid repo, or a direct APK with published SHA-256 checksums. Fully open, no app-store account needed.",
            path: "/download",
            image: "/og/systems.png",
        }
        style { dangerous_inner_html: DOWNLOAD_CSS }

        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Download · alpha" }
                h1 { class: "rise d2",
                    "Install the "
                    span { class: "grad-text", "alpha." }
                }
                p { class: "lede rise d3",
                    "The apps are free and fully open source. They run on Android today, with the other platforms on the way. Pick whichever install route you trust most. We would rather you verify the download than take our word for it."
                }
            }
        }

        // ---------- THE APPS ----------
        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "The apps" }
                    h2 { "Three apps, one signing key." }
                }
                div { class: "grid-3",
                    for (app , pkg , apk) in APPS {
                        div { key: "{app}", class: "card reveal",
                            h3 { "{app}" }
                            div { class: "dl-mono", "{pkg}" }
                            div { class: "dl-mono", style: "color:var(--green-2);", "{apk}" }
                        }
                    }
                }
            }
        }

        // ---------- INSTALL ROUTES ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "How to install" }
                    h2 { "Three open routes." }
                }
                div { class: "grid-2",
                    div { class: "card reveal",
                        div { class: "card-ic", dangerous_inner_html: svg("bolt") }
                        h3 { "Obtainium (auto-updates)" }
                        p { "Obtainium installs and updates the apps straight from our GitHub Releases. Add a source pointing at the releases repo, once per app, with the APK filter for that app." }
                        div { class: "dl-mono", style: "margin-top:10px;", "{RELEASES_URL}" }
                        p { style: "margin-top:10px; font-size:.86rem; color:var(--muted);", "Filters: camera-release.apk, app-release.apk, manager-release.apk." }
                    }
                    div { class: "card reveal",
                        div { class: "card-ic", dangerous_inner_html: svg("shield-check") }
                        h3 { "Our F-Droid repo" }
                        p { "Add our self-hosted F-Droid repository and both apps appear in the F-Droid client, updating from the mirror. When you add it, F-Droid shows the repo fingerprint to confirm before anything installs." }
                        div { class: "dl-mono", style: "margin-top:10px;", "{FDROID_REPO}" }
                    }
                }
                div { class: "grid-2", style: "margin-top:18px;",
                    div { class: "card reveal",
                        div { class: "card-ic", dangerous_inner_html: svg("doc") }
                        h3 { "Direct APK" }
                        p { "Prefer to do it by hand? Download the APK for each app from the GitHub Releases page and install it, then verify the checksum below." }
                        a { class: "btn btn-primary btn-sm", style: "margin-top:12px;", href: "{RELEASES_URL}", target: "_blank", rel: "noopener",
                            "Open GitHub Releases"
                            span { dangerous_inner_html: svg("arrow-up-right") }
                        }
                    }
                    div { class: "card reveal", style: "display:flex; flex-direction:column; align-items:center; text-align:center;",
                        h3 { style: "align-self:flex-start;", "Scan to your phone" }
                        div { class: "dl-qr", dangerous_inner_html: qr_svg(RELEASES_URL) }
                        p { style: "font-size:.82rem; color:var(--muted);", "Opens the releases on your phone." }
                    }
                }
            }
        }

        // ---------- VERIFY ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Verify what you install" }
                    h2 { "Trust, but check." }
                }
                div { class: "prose reveal",
                    p {
                        "Every release ships a checksum file next to the APKs: "
                        span { class: "dl-inline", "SHA256SUMS-android-foss" }
                        " for the camera and shield, and "
                        span { class: "dl-inline", "SHA256SUMS-manager-foss" }
                        " for the manager. Download the file alongside the APKs and check them in one line."
                    }
                    pre { class: "dl-pre", "sha256sum -c SHA256SUMS-android-foss" }
                    p {
                        "Obtainium and F-Droid verify the app's signature for you automatically, so the apps only ever update to a build signed with the same key. Direct downloads are worth checking by hand with the command above."
                    }
                }
                div { style: "margin-top:24px; display:flex; gap:12px; flex-wrap:wrap;",
                    Link { class: "btn btn-ghost", to: Route::Systems {},
                        span { class: "ic", dangerous_inner_html: svg("layers") }
                        "What the apps do"
                    }
                    Link { class: "btn btn-ghost", to: Route::Security {},
                        span { class: "ic", dangerous_inner_html: svg("shield") }
                        "Report a security issue"
                    }
                }
            }
        }
    }
}

const DOWNLOAD_CSS: &str = r#"
.dl-mono { font-family: var(--mono); font-size: .78rem; word-break: break-all; color: var(--ink-2); margin-top: 8px; }
.dl-inline { font-family: var(--mono); font-size: .82rem; color: var(--green-2); }
.dl-pre { font-family: var(--mono); font-size: .82rem; background: var(--bg-2); border: 1px solid var(--hair-strong); border-radius: var(--r-sm); padding: 12px 14px; overflow-x: auto; color: var(--ink); margin: 14px 0; }
.dl-qr { background: #fff; padding: 12px; border-radius: var(--r-sm); width: 180px; height: 180px; margin: 12px 0; }
.dl-qr svg { width: 100%; height: 100%; display: block; }
"#;
