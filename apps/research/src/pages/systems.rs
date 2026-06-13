//! Systems (the lab's applied work) — the two apps that put the models on a
//! real phone: PH Camera (ships first) and PH Bulwark, the shield (ships next).
//! Plain, human copy.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

#[component]
pub fn Systems() -> Element {
    rsx! {
        dioxus::document::Title { "Systems · Predator Hunters Research" }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Systems" }
                h1 { class: "rise d2",
                    "Research you can "
                    span { class: "grad-text", "install." }
                }
                p { class: "lede rise d3",
                    "The models only matter once they reach a real device. These are the two apps that carry them. The camera comes first, the full shield comes next."
                }
            }
        }

        // ---------- PH CAMERA ----------
        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "hero-grid",
                    div {
                        span { class: "sec-index", "PH Camera · ships first" }
                        h2 { style: "margin-top:14px;", "A camera that won't take an unsafe photo." }
                        p { class: "lede", style: "margin-top:18px;",
                            "Children get pushed into taking photos they should never take. PH Camera checks every frame on the phone before anything is saved. If a shot is unsafe it never becomes a file."
                        }
                        p { class: "prose", style: "margin-top:14px;",
                            "The app asks for no internet permission at all, so the phone itself guarantees that nothing it sees can leave it. Nothing is stored, nothing is logged, nothing is sent. If the safety check cannot run, the camera will not save the shot. Safe is the only default."
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

        // ---------- PH BULWARK (THE SHIELD) ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "hero-grid",
                    div { class: "reveal",
                        div { class: "phone",
                            div { class: "phone-screen",
                                div { class: "phone-notch" }
                                span { class: "phone-shield", dangerous_inner_html: svg("shield") }
                                div { class: "phone-title", "Blocked by PH Bulwark" }
                                div { class: "phone-sub", "This content was flagged as unsafe." }
                            }
                        }
                    }
                    div {
                        span { class: "sec-index", "PH Bulwark · ships next" }
                        h2 { style: "margin-top:14px;", "A shield for the whole device." }
                        p { class: "lede", style: "margin-top:18px;",
                            "PH Bulwark sits across every app and the open web. When unsafe content shows up it takes out only that part and leaves the rest of the page working, so a child keeps the sites they actually need."
                        }
                        p { class: "prose", style: "margin-top:14px;",
                            "When something serious appears it sends a parent a short, redacted alert with no message contents in it. Illegal material is blocked and reported as the law requires. The shield never keeps the content behind it."
                        }
                    }
                }
            }
        }

        // ---------- HOW THEY FIT ----------
        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "The roadmap" }
                    h2 { "One device, covered end to end." }
                    p { class: "lede", "The camera guards what a child creates. The shield guards what reaches them. Together they cover the whole phone, and both run the same models the research builds." }
                }
                div { style: "margin-top:8px;",
                    Link { class: "btn btn-ghost", to: Route::Research {},
                        "See the models behind them"
                        span { class: "ic", dangerous_inner_html: svg("arrow-right") }
                    }
                }
            }
        }
    }
}
