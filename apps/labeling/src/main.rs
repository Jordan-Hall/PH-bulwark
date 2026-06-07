//! PH Bulwark labeling app — Dioxus 0.8 client for trusted volunteers.
//!
//! Fetches the next (most-uncertain) window from `aegis-labeling-server`, shows
//! the conversation, lets the volunteer mark it grooming/safe + pick stages, and
//! submits the label. The server records it as `corrections.jsonl`, which the rom
//! retrain loop (`pipeline/retrain.py`) consumes.
//!
//! One codebase, many targets:
//!   dx serve                       # desktop, for dev/preview
//!   dx build --platform android    # the volunteer app (native, "native first")
//!   dx build --platform web        # zero-install fallback
//!
//! Config (consts below for the scaffold — wire to settings/env before shipping):
//! API base, bearer token, and this volunteer's id.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

// Configurable at BUILD time so the volunteer (mobile/web) build targets the real
// labeling server — `127.0.0.1` is the device itself, unreachable on a phone. Set
// LABELING_API / LABELING_TOKEN / LABELING_LABELER; the values below are dev defaults.
const API: &str = match option_env!("LABELING_API") {
    Some(u) => u,
    None => "http://127.0.0.1:7878",
};
const TOKEN: &str = match option_env!("LABELING_TOKEN") {
    Some(t) => t,
    None => "dev-token",
};
const LABELER: &str = match option_env!("LABELING_LABELER") {
    Some(l) => l,
    None => "volunteer-1",
};
const STAGES: &[&str] = &[
    "age_probing",
    "trust_building",
    "isolation",
    "location_probing",
    "contact_escalation",
    "explicit_solicitation",
    "meeting_requests",
    "coercion_threats",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct Message {
    role: String,
    text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct Task {
    id: String,
    messages: Vec<Message>,
    #[serde(default)]
    model_score: Option<f32>,
    #[serde(default)]
    label: Option<u8>,
}

#[derive(Serialize)]
struct Submission {
    task_id: String,
    labeler: String,
    label: u8,
    stages: Vec<String>,
}

fn main() {
    dioxus::launch(App);
}

async fn fetch_next() -> Option<Task> {
    let resp = reqwest::Client::new()
        .get(format!("{API}/tasks/next?labeler={LABELER}"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .ok()?;
    if resp.status().as_u16() == 204 {
        return None;
    }
    resp.json::<Task>().await.ok()
}

async fn submit(task_id: String, label: u8, stages: Vec<String>) -> bool {
    reqwest::Client::new()
        .post(format!("{API}/labels"))
        .bearer_auth(TOKEN)
        .json(&Submission {
            task_id,
            labeler: LABELER.to_string(),
            label,
            stages,
        })
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

#[component]
fn App() -> Element {
    let mut task = use_signal(|| None::<Task>);
    let mut selected = use_signal(Vec::<String>::new);
    let mut status = use_signal(|| "Loading…".to_string());
    let mut done = use_signal(|| 0u32);

    // Load the first task on mount.
    use_effect(move || {
        spawn(async move {
            match fetch_next().await {
                Some(t) => {
                    task.set(Some(t));
                    status.set(String::new());
                }
                None => status.set("All caught up — no tasks left 🎉".into()),
            }
        });
    });

    // Submit the current task with `label`, then advance to the next.
    let submit_label = move |label: u8| {
        let Some(t) = task() else { return };
        let stages = selected();
        spawn(async move {
            if submit(t.id.clone(), label, stages).await {
                done += 1;
                selected.set(Vec::new());
                status.set("Loading…".into());
                match fetch_next().await {
                    Some(nt) => {
                        task.set(Some(nt));
                        status.set(String::new());
                    }
                    None => {
                        task.set(None);
                        status.set("All caught up — no tasks left 🎉".into());
                    }
                }
            } else {
                status.set("Submit failed — check the server / token.".into());
            }
        });
    };

    rsx! {
        div { style: "max-width:640px;margin:0 auto;padding:16px;font-family:system-ui,sans-serif;",
            h2 { "🛡️ PH Bulwark — Labeling" }
            p { style: "color:#b00;font-size:13px;",
                "Content warning: these are real grooming transcripts. You consented to review them; stop any time."
            }
            p { style: "color:#555;", "Labeled this session: {done}" }

            if let Some(t) = task() {
                if let Some(s) = t.model_score {
                    p { style: "color:#777;font-size:12px;",
                        "model score: {s:.3} (closer to 0.5 = the model is unsure → your call matters most)"
                    }
                }
                div { style: "border:1px solid #ddd;border-radius:8px;padding:12px;margin:8px 0;",
                    for (i, m) in t.messages.iter().enumerate() {
                        div {
                            key: "{i}",
                            style: if m.role == "self" {
                                "text-align:right;margin:4px 0;"
                            } else {
                                "text-align:left;margin:4px 0;"
                            },
                            span {
                                style: if m.role == "self" {
                                    "display:inline-block;background:#dcf8c6;border-radius:10px;padding:6px 10px;"
                                } else {
                                    "display:inline-block;background:#eee;border-radius:10px;padding:6px 10px;"
                                },
                                "{m.text}"
                            }
                        }
                    }
                }

                p { style: "font-weight:600;margin-top:12px;", "Grooming stages present:" }
                div { style: "display:flex;flex-wrap:wrap;gap:8px;",
                    for stage in STAGES.iter() {
                        label { key: "{stage}", style: "font-size:13px;",
                            input {
                                r#type: "checkbox",
                                checked: selected().iter().any(|x| x == stage),
                                onchange: move |_| {
                                    let s = stage.to_string();
                                    let mut v = selected();
                                    if let Some(idx) = v.iter().position(|x| x == &s) {
                                        v.remove(idx);
                                    } else {
                                        v.push(s);
                                    }
                                    selected.set(v);
                                }
                            }
                            " {stage}"
                        }
                    }
                }

                div { style: "display:flex;gap:12px;margin-top:16px;",
                    button {
                        style: "flex:1;padding:14px;font-size:16px;background:#c0392b;color:#fff;border:none;border-radius:8px;",
                        onclick: move |_| submit_label(1),
                        "🚩 Grooming"
                    }
                    button {
                        style: "flex:1;padding:14px;font-size:16px;background:#27ae60;color:#fff;border:none;border-radius:8px;",
                        onclick: move |_| submit_label(0),
                        "✓ Safe"
                    }
                }
            } else {
                p { "{status}" }
            }
        }
    }
}
