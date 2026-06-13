//! Shared chrome rendered on every route: the closing call-to-action and the
//! footer. Both are framing-disciplined (independent research + journalism;
//! convictions / public-record only; no raw content kept).

use dioxus::prelude::*;

use crate::app::Route;
use crate::assets::PH_LOGO;
use crate::icons::svg;

/// Per-page SEO head: title, description, canonical, and Open Graph / Twitter
/// tags, all route-specific. Rendered at the top of each page so the SSG
/// pre-render bakes them into THAT route's static head — real per-page SEO and
/// per-page social cards, not one global set.
#[component]
pub fn Seo(title: String, description: String, path: String, image: String) -> Element {
    let url = format!("https://research.predatorhunters.co.uk{path}");
    let img = format!("https://research.predatorhunters.co.uk{image}");
    rsx! {
        dioxus::document::Title { "{title}" }
        dioxus::document::Meta { name: "description", content: "{description}" }
        dioxus::document::Link { rel: "canonical", href: "{url}" }
        dioxus::document::Meta { property: "og:title", content: "{title}" }
        dioxus::document::Meta { property: "og:description", content: "{description}" }
        dioxus::document::Meta { property: "og:url", content: "{url}" }
        dioxus::document::Meta { property: "og:image", content: "{img}" }
        dioxus::document::Meta { name: "twitter:title", content: "{title}" }
        dioxus::document::Meta { name: "twitter:description", content: "{description}" }
        dioxus::document::Meta { name: "twitter:image", content: "{img}" }
    }
}

/// The shared closing CTA — investment / collaboration attraction, kept honest.
/// Suppressed on the Contact route, where it would only repeat that page.
#[component]
pub fn ClosingCta() -> Element {
    let route = use_route::<Route>();
    if route == (Route::Contact {}) {
        return rsx! {};
    }
    rsx! {
        section { class: "section",
            div { class: "wrap",
                div { class: "cta reveal",
                    div { class: "cta-inner",
                        p { class: "eyebrow", style: "margin-bottom:18px;", "Backers · partners · researchers" }
                        h2 {
                            "Help us build the AI that keeps "
                            span { class: "grad-text", "children safer." }
                        }
                        p { class: "lede",
                            "We are a small, self-funded team, four years into this. If you fund safety research, want to build with us, or want to put these models to work protecting children, get in touch."
                        }
                        div { class: "cta-actions",
                            Link { class: "btn btn-primary", to: Route::Contact {},
                                "Start a conversation"
                                span { dangerous_inner_html: svg("arrow-right") }
                            }
                            Link { class: "btn btn-ghost", to: Route::Research {},
                                span { class: "ic", dangerous_inner_html: svg("layers") }
                                "See the research"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Site footer.
#[component]
pub fn SiteFooter() -> Element {
    rsx! {
        footer { class: "footer",
            div { class: "wrap",
                div { class: "footer-top",
                    div {
                        Link { class: "brand", to: Route::Home {},
                            img { class: "brand-logo", src: PH_LOGO, alt: "Predator Hunters" }
                            span { class: "brand-tag", "Research" }
                        }
                        p { class: "footer-blurb",
                            "An independent child-safety AI lab. We build small models that run on a child's own devices, across Windows, Mac, Android, iOS and iPad, catch unsafe content and the way predators talk, and keep no raw messages or images."
                        }
                    }
                    div {
                        h4 { "Research" }
                        ul {
                            li { Link { to: Route::Research {}, "The models" } }
                            li { Link { to: Route::Approach {}, "Our approach" } }
                            li { Link { to: Route::Approach {}, "Principles" } }
                        }
                    }
                    div {
                        h4 { "Organisation" }
                        ul {
                            li { Link { to: Route::About {}, "About the lab" } }
                            li { Link { to: Route::Contact {}, "Contact" } }
                            li { Link { to: Route::Privacy {}, "Privacy" } }
                            li { Link { to: Route::Security {}, "Security" } }
                            li { a { href: "https://github.com/Jordan-Hall/PH-bulwark", target: "_blank", rel: "noopener", "Source on GitHub ↗" } }
                            li { a { href: "https://predatorhunters.co.uk", target: "_blank", rel: "noopener", "Main site ↗" } }
                        }
                    }
                    div {
                        h4 { "Connect" }
                        ul {
                            li { a { href: "mailto:research@predatorhunters.co.uk", "research@predatorhunters.co.uk" } }
                            li { a { href: "https://www.facebook.com/Online.Stings", target: "_blank", rel: "noopener", "Facebook ↗" } }
                            li { a { href: "https://x.com/PredHunTers", target: "_blank", rel: "noopener", "X · @PredHunTers ↗" } }
                            li { a { href: "https://predatorhunters.co.uk", target: "_blank", rel: "noopener", "Press & journalism ↗" } }
                        }
                        div { style: "margin-top:18px;",
                            img { class: "brand-logo", src: PH_LOGO, alt: "Predator Hunters", style: "height:46px;" }
                        }
                    }
                }
                div { style: "display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-top:44px; padding-top:24px; border-top:1px solid var(--hair);",
                    span { style: "font-family:var(--mono); font-size:.68rem; letter-spacing:.2em; text-transform:uppercase; color:var(--muted); margin-right:4px;", "Share" }
                    a {
                        class: "btn btn-ghost btn-sm",
                        href: "https://twitter.com/intent/tweet?text=Predator%20Hunters%20Research%20%E2%80%94%20child-safety%20AI&url=https%3A%2F%2Fresearch.predatorhunters.co.uk",
                        target: "_blank", rel: "noopener",
                        span { dangerous_inner_html: svg("x") }
                        "Post on X"
                    }
                    a {
                        class: "btn btn-ghost btn-sm",
                        href: "https://www.facebook.com/sharer/sharer.php?u=https%3A%2F%2Fresearch.predatorhunters.co.uk",
                        target: "_blank", rel: "noopener",
                        span { dangerous_inner_html: svg("facebook") }
                        "Share on Facebook"
                    }
                    button {
                        class: "btn btn-ghost btn-sm",
                        onclick: move |_| {
                            let _ = dioxus::document::eval("const u=location.href,t=document.title;if(navigator.share){navigator.share({title:t,url:u}).catch(function(){});}else if(navigator.clipboard){navigator.clipboard.writeText(u);}");
                        },
                        span { dangerous_inner_html: svg("share") }
                        "Share this page"
                    }
                }
                div { class: "footer-bottom",
                    p { "© 2026 Predator Hunters Research. All rights reserved." }
                    p { class: "legal",
                        "Independent research and journalism. Our frontline team runs stings and hands evidence to the police; we never name anyone before they are charged, and we hold footage back until there is a conviction. The models run on the device, and no raw messages or images are kept."
                    }
                }
            }
        }
    }
}
