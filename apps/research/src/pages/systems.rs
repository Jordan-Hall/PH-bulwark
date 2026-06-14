//! Systems — the overview of the lab's applied work: two apps that put the
//! models on a real device. Each links to its own product page. Plain copy.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

#[component]
pub fn Systems() -> Element {
    rsx! {
        crate::components::Seo {
            title: "Systems: PH Camera and PH Bulwark | Predator Hunters",
            description: "The apps that carry the models. PH Camera won't take an unsafe photo; PH Bulwark filters unsafe content in place across the whole device. Android first, every platform next.",
            path: "/systems",
            image: "/og/systems.png",
        }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "Systems" }
                h1 { class: "rise d2",
                    "Research you can "
                    span { class: "grad-text", "install." }
                }
                p { class: "lede rise d3",
                    "The models only matter once they reach a real device. These are the two apps that carry them. The camera comes first, the full shield comes next, and both are built to run across every device a family uses."
                }
            }
        }

        // ---------- THE TWO PRODUCTS ----------
        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "grid-2",
                    Link { class: "card reveal", to: Route::PhCamera {},
                        div { style: "display:flex;align-items:center;justify-content:space-between;",
                            div { class: "card-ic", style: "color:#bfe6c4;", dangerous_inner_html: svg("camera") }
                            span { class: "tag live", "Alpha" }
                        }
                        h3 { style: "margin-top:18px;", "PH Camera" }
                        div { class: "role", style: "font-family:var(--mono);font-size:.7rem;letter-spacing:.14em;text-transform:uppercase;color:var(--orange);margin:6px 0 10px;", "Ships first" }
                        p { "A camera that checks every frame on the device and will not take or keep an unsafe photo. No internet permission, so nothing it sees can leave the device." }
                        span { class: "btn btn-ghost btn-sm", style: "margin-top:16px;",
                            "About PH Camera"
                            span { class: "ic", dangerous_inner_html: svg("arrow-right") }
                        }
                    }
                    Link { class: "card reveal", to: Route::PhBulwark {},
                        div { style: "display:flex;align-items:center;justify-content:space-between;",
                            div { class: "card-ic", dangerous_inner_html: svg("shield") }
                            span { class: "tag live", "In build" }
                        }
                        h3 { style: "margin-top:18px;", "PH Bulwark" }
                        div { class: "role", style: "font-family:var(--mono);font-size:.7rem;letter-spacing:.14em;text-transform:uppercase;color:var(--orange);margin:6px 0 10px;", "Ships next" }
                        p { "A shield for the whole device. It filters unsafe content in place across apps and the web, warns a guardian when something is wrong, and keeps the rest of the page working." }
                        span { class: "btn btn-ghost btn-sm", style: "margin-top:16px;",
                            "About PH Bulwark"
                            span { class: "ic", dangerous_inner_html: svg("arrow-right") }
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
                    h2 { "Every device, covered end to end." }
                    p { class: "lede", "The camera guards what a child creates. The shield guards what reaches them. Together they cover the whole device, and both run the same models the research builds. Android comes first, with Windows, iOS, iPad and Mac on the roadmap, because protection should follow a child across everything they use, not stop at one phone." }
                }
                div { style: "margin-top:8px; display:flex; gap:12px; flex-wrap:wrap;",
                    Link { class: "btn btn-primary", to: Route::Waitlist {},
                        "Join the alpha"
                        span { dangerous_inner_html: svg("arrow-right") }
                    }
                    Link { class: "btn btn-ghost", to: Route::Research {},
                        "See the models behind them"
                        span { class: "ic", dangerous_inner_html: svg("arrow-right") }
                    }
                }
                p { class: "prose", style: "margin-top:28px; padding-top:18px; border-top:1px solid var(--hair); font-size:.86rem; color:var(--muted); max-width:60ch;",
                    "Intended use. These tools are for a guardian protecting their own minor child, on a device they own and control. They are not for monitoring adults, partners, or anyone else, and not for covert surveillance. We build to UK GDPR and the ICO's Children's Code, and monitoring law varies by country, so please check what applies where you are."
                }
            }
        }
    }
}
