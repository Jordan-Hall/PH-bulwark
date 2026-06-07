//! PH Bulwark — child app onboarding "setup journey" (Dioxus 0.8 UI).
//!
//! A calm, transparent walkthrough a guardian completes on the child's device:
//! welcome → what it does (and doesn't) → grant the three OS permissions, plainly
//! explained → enter the pairing code from the console → protection active.
//!
//! This is the UI only. The real OS services live native in `platform/android`
//! (VpnService / AccessibilityService / DeviceAdminReceiver); on the mobile target
//! the grant buttons bridge to them via `java_plugin!`. Here they flip local state
//! so the journey is fully previewable on desktop.

use dioxus::prelude::*;

fn main() {
    dioxus::launch(App);
}

#[derive(Clone, Copy, PartialEq)]
enum Step {
    Welcome,
    How,
    Permissions,
    Pair,
    Done,
}

impl Step {
    fn idx(self) -> usize {
        match self {
            Step::Welcome => 0,
            Step::How => 1,
            Step::Permissions => 2,
            Step::Pair => 3,
            Step::Done => 4,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Step::Welcome => "Welcome",
            Step::How => "How it works",
            Step::Permissions => "Permissions",
            Step::Pair => "Connect",
            Step::Done => "Protected",
        }
    }
}

const TOTAL: usize = 5;

#[component]
fn App() -> Element {
    let mut step = use_signal(|| Step::Welcome);
    // Permission grants (flipped by the native bridge on mobile; local here).
    let mut accessibility = use_signal(|| false);
    let mut network = use_signal(|| false);
    let mut device_admin = use_signal(|| false);
    let mut code = use_signal(String::new);

    let s = step();
    let fill = (s.idx() as f32 / (TOTAL - 1) as f32 * 100.0).round();
    let all_granted = accessibility() && network() && device_admin();
    let code_ok = code().trim().chars().filter(|c| c.is_alphanumeric()).count() >= 6;

    rsx! {
        style { {CSS} }
        div { class: "stage",
            div { class: "aurora" }

            div { class: "brand", "PH Bulwark " span { class: "brand-accent", "Shield" } }

            // ---- progress: a shield that fills as the journey completes ----
            div { class: "progress",
                div { class: "shield",
                    div { class: "shield-fill", style: "height: {fill}%" }
                    span { class: "shield-glyph", "🛡" }
                }
                div { class: "progress-text",
                    span { class: "step-no", "Step {s.idx() + 1} of {TOTAL}" }
                    span { class: "step-label", "{s.label()}" }
                }
            }

            // ---- the active step (keyed so each gets a fresh fade-in) ----
            div { key: "{s.idx()}", class: "card",
                match s {
                    Step::Welcome => rsx! {
                        div { class: "hero", "🌅" }
                        h1 { "Let's set up protection," br {} em { "together." } }
                        p { class: "lede",
                            "A calm, transparent way to help keep your child safer online. "
                            "It takes about three minutes — we'll explain every step."
                        }
                        button { class: "primary", onclick: move |_| step.set(Step::How), "Begin" }
                        p { class: "fine", "Nothing is hidden. You'll see exactly what this app does next." }
                    },

                    Step::How => rsx! {
                        h2 { "What PH Bulwark does" }
                        p { class: "lede", "And, just as importantly, what it never does." }
                        div { class: "facts",
                            div { class: "fact do",
                                span { class: "tick", "✓" }
                                div {
                                    strong { "Spots grooming & unsafe content" }
                                    span { "Checks chats, pages and images right on this device." }
                                }
                            }
                            div { class: "fact do",
                                span { class: "tick", "✓" }
                                div {
                                    strong { "Sends you a gentle, redacted alert" }
                                    span { "You get a plain summary — never the raw messages." }
                                }
                            }
                            div { class: "fact dont",
                                span { class: "cross", "✕" }
                                div {
                                    strong { "No spying" }
                                    span { "No live screen, no location, no reading everything. Not surveillance." }
                                }
                            }
                        }
                        div { class: "row",
                            button { class: "ghost", onclick: move |_| step.set(Step::Welcome), "Back" }
                            button { class: "primary", onclick: move |_| step.set(Step::Permissions), "I understand" }
                        }
                    },

                    Step::Permissions => rsx! {
                        h2 { "Three permissions, plainly" }
                        p { class: "lede", "Tap to grant each one. Here's exactly why it's needed." }
                        div { class: "perms",
                            PermissionRow {
                                icon: "💬", name: "Accessibility",
                                reason: "Reads text already on screen in chats to spot grooming. It never sees your typing or passwords.",
                                granted: accessibility(),
                                ongrant: move |_| accessibility.set(true),
                            }
                            PermissionRow {
                                icon: "🌐", name: "Safe browsing (VPN)",
                                reason: "Checks web pages for unsafe images and content as they load on this device.",
                                granted: network(),
                                ongrant: move |_| network.set(true),
                            }
                            PermissionRow {
                                icon: "🔒", name: "Stay-on protection",
                                reason: "Stops the app being quietly removed, so protection can't be switched off without you knowing.",
                                granted: device_admin(),
                                ongrant: move |_| device_admin.set(true),
                            }
                        }
                        div { class: "row",
                            button { class: "ghost", onclick: move |_| step.set(Step::How), "Back" }
                            button {
                                class: "primary",
                                disabled: !all_granted,
                                onclick: move |_| step.set(Step::Pair),
                                if all_granted { "Continue" } else { "Grant all three to continue" }
                            }
                        }
                    },

                    Step::Pair => rsx! {
                        div { class: "hero", "🔗" }
                        h2 { "Connect to your console" }
                        p { class: "lede",
                            "Open PH Bulwark Manager on your own phone and enter the "
                            em { "pairing code" } " it shows you."
                        }
                        input {
                            class: "code-input",
                            r#type: "text",
                            maxlength: "8",
                            placeholder: "● ● ● ● ● ●",
                            value: "{code}",
                            oninput: move |e| code.set(e.value().to_uppercase()),
                        }
                        div { class: "row",
                            button { class: "ghost", onclick: move |_| step.set(Step::Permissions), "Back" }
                            button {
                                class: "primary",
                                disabled: !code_ok,
                                onclick: move |_| step.set(Step::Done),
                                "Connect"
                            }
                        }
                        p { class: "fine", "The code expires after a few minutes — generate a fresh one if needed." }
                    },

                    Step::Done => rsx! {
                        div { class: "hero glow", "🛡" }
                        h1 { "Protection is active." }
                        p { class: "lede",
                            "You're all set. This device is now watched calmly for grooming and unsafe "
                            "content — and you'll get a gentle alert if anything ever needs you."
                        }
                        div { class: "done-pills",
                            span { class: "pill", "✓ On-device" }
                            span { class: "pill", "✓ Private" }
                            span { class: "pill", "✓ Connected" }
                        }
                        button { class: "primary",
                            onclick: move |_| {
                                step.set(Step::Welcome);
                                accessibility.set(false);
                                network.set(false);
                                device_admin.set(false);
                                code.set(String::new());
                            },
                            "Done"
                        }
                    },
                }
            }
        }
    }
}

#[component]
fn PermissionRow(icon: String, name: String, reason: String, granted: bool, ongrant: EventHandler<()>) -> Element {
    rsx! {
        div { class: if granted { "perm granted" } else { "perm" },
            div { class: "perm-icon", "{icon}" }
            div { class: "perm-body",
                strong { "{name}" }
                span { "{reason}" }
            }
            if granted {
                span { class: "perm-done", "✓" }
            } else {
                button { class: "grant", onclick: move |_| ongrant.call(()), "Grant" }
            }
        }
    }
}

const CSS: &str = r#"
@import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,600&family=Hanken+Grotesk:wght@400;500;600;700&display=swap');

:root {
  --cream: #FBF6EE;
  --card: #FFFDF9;
  --teal: #114B4A;
  --teal-2: #0C3837;
  --amber: #E8915B;
  --peach: #F4C89B;
  --sage: #8CB7A6;
  --ink: #2A2420;
  --muted: #756A60;
  --line: #ECE2D4;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body { background: var(--cream); }

.stage {
  position: relative;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-start;
  gap: 24px;
  padding: 40px 22px 56px;
  font-family: 'Hanken Grotesk', sans-serif;
  color: var(--ink);
  overflow: hidden;
}

/* warm dawn glow — atmosphere, not a flat fill */
.aurora {
  position: fixed; inset: -30% -10% auto -10%; height: 70vh; z-index: 0;
  background:
    radial-gradient(40% 50% at 25% 20%, rgba(244,200,155,.55), transparent 70%),
    radial-gradient(45% 55% at 85% 10%, rgba(140,183,166,.45), transparent 70%),
    radial-gradient(35% 45% at 60% 35%, rgba(232,145,91,.30), transparent 70%);
  filter: blur(8px);
  pointer-events: none;
}

/* ---- brand wordmark ---- */
.brand { position: relative; z-index: 1; font-family: 'Fraunces', serif; font-weight: 600; font-size: 18px; letter-spacing: .02em; color: var(--teal-2); }
.brand-accent { color: var(--amber); font-style: italic; }

/* ---- progress shield ---- */
.progress { position: relative; z-index: 1; display: flex; flex-direction: column; align-items: center; gap: 10px; }
.shield {
  position: relative; width: 58px; height: 66px;
  clip-path: polygon(50% 0, 100% 16%, 100% 56%, 50% 100%, 0 56%, 0 16%);
  background: rgba(17,75,74,.10);
  border: 0;
}
.shield-fill {
  position: absolute; left: 0; bottom: 0; width: 100%;
  background: linear-gradient(180deg, var(--sage), var(--teal));
  transition: height .7s cubic-bezier(.2,.8,.2,1);
}
.shield-glyph {
  position: absolute; inset: 0; display: grid; place-items: center;
  font-size: 26px; filter: grayscale(.2);
}
.progress-text { display: flex; flex-direction: column; align-items: center; gap: 1px; }
.step-no { font-size: 11px; letter-spacing: .14em; text-transform: uppercase; color: var(--amber); font-weight: 700; }
.step-label { font-family: 'Fraunces', serif; font-size: 16px; color: var(--teal); font-weight: 500; }

/* ---- card ---- */
.card {
  position: relative; z-index: 1;
  width: 100%; max-width: 440px;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 26px;
  padding: 34px 28px 30px;
  box-shadow: 0 24px 60px -28px rgba(17,75,74,.35), 0 2px 0 rgba(255,255,255,.7) inset;
  animation: rise .6s cubic-bezier(.2,.8,.2,1) both;
}
@keyframes rise { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }

.hero { font-size: 52px; line-height: 1; margin-bottom: 14px; }
.hero.glow { filter: drop-shadow(0 8px 22px rgba(140,183,166,.7)); animation: pulse 2.6s ease-in-out infinite; }
@keyframes pulse { 0%,100% { transform: scale(1); } 50% { transform: scale(1.06); } }

h1 { font-family: 'Fraunces', serif; font-weight: 500; font-size: 30px; line-height: 1.12; letter-spacing: -.01em; color: var(--teal-2); margin-bottom: 12px; }
h1 em, h1 br + em { font-style: italic; color: var(--amber); }
h2 { font-family: 'Fraunces', serif; font-weight: 500; font-size: 25px; color: var(--teal-2); margin-bottom: 8px; letter-spacing: -.01em; }
.lede { font-size: 15.5px; line-height: 1.55; color: var(--muted); margin-bottom: 22px; }
em { font-style: italic; }

/* ---- facts (how it works) ---- */
.facts { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; }
.fact { display: flex; gap: 13px; align-items: flex-start; padding: 14px 15px; border-radius: 16px; background: #FAF4EA; border: 1px solid var(--line); }
.fact.dont { background: #FBEEE6; border-color: #F3DEC9; }
.fact strong { display: block; font-size: 15px; color: var(--ink); margin-bottom: 2px; }
.fact span { display: block; font-size: 13.5px; color: var(--muted); line-height: 1.45; }
.tick, .cross { flex: none; width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; font-size: 14px; font-weight: 700; }
.tick { background: var(--sage); color: #fff; }
.cross { background: var(--amber); color: #fff; }

/* ---- permissions ---- */
.perms { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; }
.perm { display: flex; gap: 13px; align-items: center; padding: 14px; border-radius: 16px; border: 1px solid var(--line); background: #FAF4EA; transition: all .35s ease; }
.perm.granted { background: #EEF5F0; border-color: var(--sage); }
.perm-icon { flex: none; width: 42px; height: 42px; border-radius: 13px; background: #fff; display: grid; place-items: center; font-size: 21px; box-shadow: 0 4px 12px -6px rgba(17,75,74,.4); }
.perm-body { flex: 1; }
.perm-body strong { display: block; font-size: 14.5px; }
.perm-body span { display: block; font-size: 12.5px; color: var(--muted); line-height: 1.4; margin-top: 2px; }
.grant { flex: none; border: 0; background: var(--teal); color: var(--cream); font-family: inherit; font-weight: 600; font-size: 13px; padding: 9px 16px; border-radius: 999px; cursor: pointer; transition: transform .1s ease, background .2s; }
.grant:hover { background: var(--teal-2); }
.grant:active { transform: scale(.95); }
.perm-done { flex: none; width: 32px; height: 32px; border-radius: 50%; background: var(--sage); color: #fff; display: grid; place-items: center; font-weight: 700; }

/* ---- pairing code ---- */
.code-input {
  width: 100%; text-align: center; font-family: 'Fraunces', serif; font-size: 30px;
  letter-spacing: .35em; padding: 18px 12px; margin: 6px 0 22px;
  border: 2px dashed var(--peach); border-radius: 18px; background: #FFFBF4; color: var(--teal-2);
  text-transform: uppercase; outline: none; transition: border-color .2s;
}
.code-input:focus { border-color: var(--amber); border-style: solid; }
.code-input::placeholder { letter-spacing: .2em; color: #D9C7AE; }

/* ---- buttons / rows ---- */
.row { display: flex; gap: 10px; }
.row .primary { flex: 1; }
button { font-family: 'Hanken Grotesk', sans-serif; }
.primary {
  width: 100%; border: 0; background: var(--teal); color: var(--cream);
  font-weight: 600; font-size: 16px; padding: 15px 18px; border-radius: 16px; cursor: pointer;
  box-shadow: 0 14px 26px -14px rgba(17,75,74,.8); transition: transform .12s ease, background .2s, box-shadow .2s;
}
.primary:hover { background: var(--teal-2); }
.primary:active { transform: translateY(1px) scale(.99); }
.primary:disabled { background: #CDBFAE; color: #F3ECE0; box-shadow: none; cursor: not-allowed; }
.ghost { border: 0; background: transparent; color: var(--muted); font-weight: 600; font-size: 15px; padding: 15px 18px; border-radius: 16px; cursor: pointer; }
.ghost:hover { color: var(--teal); }

.fine { font-size: 12.5px; color: #9A8E80; margin-top: 16px; text-align: center; line-height: 1.5; }

/* ---- done ---- */
.done-pills { display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; margin: 8px 0 26px; }
.pill { font-size: 12.5px; font-weight: 600; color: var(--teal); background: #EEF5F0; border: 1px solid var(--sage); padding: 7px 13px; border-radius: 999px; }
"#;
