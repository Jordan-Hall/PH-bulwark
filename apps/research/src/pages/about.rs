//! About — who we are, where we came from, and the line between what we are and
//! what we are not. Plain copy.

use dioxus::prelude::*;

use crate::app::Route;
use crate::icons::svg;

/// (year, event)
const TIMELINE: [(&str, &str); 4] = [
    ("2017", "Predator Hunters begins as an online decoy operation. We find the adults who go looking for children, hand the evidence to the police, and teach parents what to watch for."),
    ("2022", "The research lab opens. We start turning years of frontline experience into privacy-first models that run on the child's own devices."),
    ("2025", "The hardest prototype lands. It catches unsafe video and rewrites it in place, blurring or muting only the bad moments while the rest plays on."),
    ("Today", "A smaller frontline team still runs the decoy work, and it still teaches us how offenders really behave. Most of our effort now goes into the lab, heading into staged testing of the first alpha."),
];

#[component]
pub fn About() -> Element {
    rsx! {
        crate::components::Seo {
            title: "About: independent child-safety AI lab | Predator Hunters",
            description: "Predator Hunters Research is the AI arm of an independent child-protection group on the front line since 2017. A small, self-funded team.",
            path: "/about",
            image: "/og/about.png",
        }
        header { class: "page-head",
            div { class: "wrap",
                p { class: "eyebrow rise d1", "About" }
                h1 { class: "rise d2",
                    "An independent lab inside a movement that started in "
                    span { class: "grad-text", "2017." }
                }
                p { class: "lede rise d3",
                    "Predator Hunters Research is the AI arm of an independent child-protection and journalism group. We are small, self-funded, and four years into building safety tech a family can actually trust."
                }
            }
        }

        section { class: "section", style: "padding-top:clamp(20px,4vh,48px);",
            div { class: "wrap",
                div { class: "prose reveal",
                    p {
                        "We have been at this for nearly ten years. It started on the front line, with decoy operations. Posing as children online to find the adults who go looking for them, gathering the evidence, confronting them when it is safe to do so, and holding them for the police. A smaller team still does that work today. It is careful, draining work, and it taught us something no dataset ever could. We watched, first-hand, how grooming begins, how it escalates, and how an offender will move a child from one app to the next to avoid being caught."
                    }
                    p {
                        "That is the ground the lab is built on. We took what we had learned and started building software, so the same patterns could be caught early, on a child's own devices, without the surveillance so much "
                        strong { "safety" }
                        " software leans on. Two lines have never moved. We never name anyone before they are charged, and we hold any footage back until there is a conviction, censored where it is needed and shown only when it genuinely helps people keep children safe."
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Timeline" }
                    h2 { "How we got here." }
                }
                dl { class: "deflist reveal",
                    for (year , event) in TIMELINE {
                        div { key: "{year}", class: "def",
                            dt { "{year}" }
                            dd { "{event}" }
                        }
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "sec-head",
                    span { class: "sec-index", "Team" }
                    h2 { "Built by a small team." }
                    p { class: "lede", "Lean on purpose, and honest about what that means. We build carefully and we say no a lot." }
                }
                div { class: "team-grid",
                    div { class: "member reveal",
                        div { class: "member-photo", "JU" }
                        b { "Jordan Upton" }
                        div { class: "role", "Founder · Lead developer" }
                        p { "Designs and builds the models and the systems that run them, and holds the line on what the lab will never build." }
                    }
                    div { class: "member reveal",
                        div { class: "member-photo", style: "background:var(--card-bg);color:var(--green-2);border:1px solid var(--hair-strong);", dangerous_inner_html: svg("scale") }
                        b { "Safeguarding advisors" }
                        div { class: "role", "Guidance" }
                        p { "Practitioners who keep the work grounded in real child-protection practice and the law." }
                    }
                    div { class: "member reveal",
                        div { class: "member-photo", style: "background:var(--card-bg);color:var(--orange);border:1px solid var(--hair-strong);", dangerous_inner_html: svg("github") }
                        b { "Open-source contributors" }
                        div { class: "role", "Engineering" }
                        p { "The wider community that helps build and harden the tooling around the models." }
                    }
                }
            }
        }

        section { class: "section",
            div { class: "wrap",
                div { class: "grid-2",
                    div { class: "card reveal",
                        div { class: "card-ic", dangerous_inner_html: svg("check") }
                        h3 { "What we are" }
                        p { "A frontline child-protection team with years of real experience. We run online decoy operations to find adults who go looking for children, and when it is safe to, we confront them and hold them for the police with everything we have gathered. We report on cases once they have been to court, and we build privacy-first AI to protect children. The lab is the newest part of that work. The frontline team, smaller now, still runs." }
                    }
                    div { class: "card reveal",
                        div { class: "card-ic", style: "color:var(--orange);background:rgba(245,130,32,.10);border-color:rgba(245,130,32,.22);", dangerous_inner_html: svg("eye-off") }
                        h3 { "What we are not" }
                        p { "We are not the police, not a surveillance company, and not in it for a show. We never name anyone before they are charged. We hold footage back until there is a conviction, censor it where it is needed, and only run it when it genuinely teaches people how to keep children safe. We work with the police, not in their place, and we never go digging into a child's private life." }
                    }
                }
                div { style: "margin-top:28px;",
                    Link { class: "btn btn-ghost", to: Route::Approach {},
                        "Read our principles"
                        span { class: "ic", dangerous_inner_html: svg("arrow-right") }
                    }
                }
            }
        }
    }
}
