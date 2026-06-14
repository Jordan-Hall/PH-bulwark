//! PH Camera — the per-product page (ships first). A camera that checks every
//! frame on the device and will not take or keep an unsafe photo. Plain copy.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

/// (icon, title, body)
const POINTS: [(&str, &str, &str); 3] = [
    (
        "scan",
        "Checked before it is saved",
        "Every frame is judged on the device, in the moment, before it can become a file. If a shot is unsafe it simply never gets written. There is no gallery entry to find, delete, or recover.",
    ),
    (
        "eye-off",
        "No internet, by design",
        "The app asks for no internet permission at all. The operating system itself then guarantees that nothing the camera sees can leave the device, because there is no way out. Nothing is stored, logged, or sent.",
    ),
    (
        "shield-check",
        "Safe is the only default",
        "If the safety check cannot run for any reason, the camera does not save the shot. It fails closed, never open, so a gap in the check is never a gap in protection.",
    ),
];

#[component]
pub fn PhCamera() -> Element {
    rsx! {
        crate::components::Seo {
            title: "PH Camera: a camera that won't take an unsafe photo | Predator Hunters",
            description: "PH Camera checks every frame on the device before anything is saved, and asks for no internet permission, so an unsafe photo never becomes a file and nothing it sees can leave the device.",
            path: "/systems/ph-camera",
            image: "/og/systems.png",
        }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "PH Camera · ships first" }
                h1 { class: "rise d2",
                    "A camera that won't take an "
                    span { class: "grad-text", "unsafe photo." }
                }
                p { class: "lede rise d3",
                    "Children get pushed into taking photos they should never take. PH Camera checks every frame on the device before anything is saved, so an unsafe shot never becomes a file in the first place."
                }
                div { class: "hero-actions rise d4", style: "margin-top:30px;",
                    Link { class: "btn btn-primary", to: Route::Waitlist {},
                        "Join the alpha"
                        span { dangerous_inner_html: svg("arrow-right") }
                    }
                    Link { class: "btn btn-ghost", to: Route::Systems {},
                        span { class: "ic", dangerous_inner_html: svg("layers") }
                        "Both systems"
                    }
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "hero-grid",
                    div {
                        for (icon , title , body) in POINTS {
                            div { key: "{title}", class: "card reveal", style: "margin-bottom:14px;",
                                div { class: "card-ic", dangerous_inner_html: svg(icon) }
                                h3 { "{title}" }
                                p { "{body}" }
                            }
                        }
                    }
                    div { class: "reveal",
                        div { class: "phone",
                            div { class: "phone-screen",
                                div { class: "phone-notch" }
                                span { class: "phone-shield", style: "color:#bfe6c4;", dangerous_inner_html: svg("camera") }
                                div { class: "phone-title", "PH Camera" }
                                div { class: "phone-sub", "Unsafe photos never get taken or saved." }
                            }
                        }
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Where it runs" }
                    h2 { "Android first, every device next." }
                    p { class: "lede", "The camera ships on Android first. The same on-device check is built to follow onto Windows, iOS, iPad and Mac, so the protection is not tied to one phone. Illegal child-abuse material is always blocked and reported as the law requires, and is never stored or shown." }
                }
            }
        }
    }
}
