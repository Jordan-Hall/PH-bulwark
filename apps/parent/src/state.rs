//! Domain model + shared UI state for the console: app status, the shared
//! `Console` context, the guardian-facing Alert shape, and the
//! evidence-display policy helpers.

use dioxus::prelude::*;

use bulwark_proto::v1::{AlertEvent, AlertKind, Category, Child as ProtoChild};

use crate::servers::{active_server_label, cluster_endpoint, guardian_token, server_session_key};

#[derive(Clone, PartialEq)]
pub struct AppStatus {
    pub server_label: String,
    pub endpoint: String,
    pub session_key: String,
    pub logged_in: bool,
}

impl AppStatus {
    pub fn load() -> Self {
        let endpoint = cluster_endpoint();
        Self {
            server_label: active_server_label(),
            session_key: server_session_key(&endpoint),
            logged_in: !guardian_token().is_empty(),
            endpoint,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct PairCodeUi {
    pub child_name: String,
    pub code: String,
    pub expires_ts: i64,
}

/// Console-wide UI state — all 16 root signals from the old `app::App` —
/// provided once at the app root (`router::App`) and read by the layout +
/// each routed screen via `use_context::<Console>()`. `Signal` is `Copy`,
/// so `Console` is `Copy` and cheap to hand around (mirrors the child
/// app's `Setup` struct).
#[derive(Clone, Copy)]
pub struct Console {
    /// Live inbox, newest first (seeded with demo rows while offline).
    pub alerts: Signal<Vec<Alert>>,
    /// True until the review stream connects (drives the demo banner).
    pub offline: Signal<bool>,
    /// Last approve/keep-blocked submit failure, shown in the chrome.
    pub action_error: Signal<Option<String>>,
    /// Server/session snapshot for the status grid + logged_in gating.
    pub status: Signal<AppStatus>,
    // Family-setup form (Setup screen).
    pub setup_note: Signal<Option<String>>,
    pub setup_error: Signal<Option<String>>,
    pub setup_busy: Signal<bool>,
    pub create_account: Signal<bool>,
    pub email: Signal<String>,
    pub password: Signal<String>,
    pub display_name: Signal<String>,
    pub child_name: Signal<String>,
    pub pair_code: Signal<Option<PairCodeUi>>,
    // Children roster (Children screen).
    pub children: Signal<Vec<ProtoChild>>,
    pub children_error: Signal<Option<String>>,
    pub children_busy: Signal<bool>,
}

impl Console {
    /// Build the initial state. Called inside `use_context_provider` at the
    /// app root, so the signals live for the whole app — typed form fields and
    /// the pair code survive tab switches exactly as they did under the old
    /// single-component `match active()`.
    pub fn new() -> Self {
        Self {
            alerts: Signal::new(seed()),
            offline: Signal::new(true),
            action_error: Signal::new(None),
            status: Signal::new(AppStatus::load()),
            setup_note: Signal::new(None),
            setup_error: Signal::new(None),
            setup_busy: Signal::new(false),
            create_account: Signal::new(true),
            email: Signal::new(String::new()),
            password: Signal::new(String::new()),
            display_name: Signal::new(String::new()),
            child_name: Signal::new(String::new()),
            pair_code: Signal::new(None),
            children: Signal::new(Vec::new()),
            children_error: Signal::new(None),
            children_busy: Signal::new(false),
        }
    }
}

/// A guardian-facing alert row.
///
/// Carries the full review payload: the context summary plus, for non-CSAM
/// items, the actual flagged text snippet and a safe inline media preview so the
/// guardian sees exactly what was blocked. CSAM-suspected items deliberately
/// carry no preview surfaced to the UI (see [`AlertCard`]).
#[derive(Clone, PartialEq)]
pub struct Alert {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub device: String,
    pub when: String,
    /// Whether approve / keep-blocked is offered (intervention & grooming items).
    pub actionable: bool,
    /// The classifier category; gates the CSAM "never preview" exception.
    pub category: Category,
    /// Safe (blurred/cropped) preview bytes from `Evidence.safe_thumbnail`.
    /// Empty when none was provided. Never rendered for CsamSuspected.
    pub thumbnail: Vec<u8>,
    /// The actual flagged text from `Evidence.text_snippet` (full, not redacted
    /// to the guardian). Empty when none. Never rendered for CsamSuspected.
    pub snippet: String,
    /// Local `blob://<sha256>` reference to a blocked/borderline VIDEO segment
    /// retained on this node for review (`AlertEvent.local_segment_uri`). `None`
    /// when no clip. Never set/played for CsamSuspected.
    pub segment_uri: Option<String>,
}

impl Alert {
    /// Map a proto [`AlertEvent`] into a UI row.
    ///
    /// Carries through the `Evidence` preview fields (`safe_thumbnail`,
    /// `text_snippet`) and the `category` so the card can show the guardian the
    /// real flagged content — except for CSAM, which [`AlertCard`] never renders.
    pub fn from_event(ev: AlertEvent) -> Self {
        let kind = ev.kind();
        let category = ev.category();

        // Pull the preview/evidence the cluster attached, if any. These are the
        // SAFE thumbnail and the flagged text excerpt; the CSAM exception is
        // enforced at render time in AlertCard, not here, so the row always
        // honestly reflects what the event carried.
        let (thumbnail, snippet) = match ev.evidence {
            Some(ref e) => (e.safe_thumbnail.clone(), e.text_snippet.clone()),
            None => (Vec::new(), String::new()),
        };

        // Title is a plain-language summary derived from kind + category — never
        // from any raw content.
        let title = match kind {
            AlertKind::GroomingSuspected => "Possible grooming detected".to_string(),
            AlertKind::Intervention => match category {
                Category::AdultImage => "Blocked an adult image".to_string(),
                Category::AdultAudio => "Muted adult audio".to_string(),
                Category::AdultText => "Blocked adult text".to_string(),
                Category::Violence => "Blocked violent content".to_string(),
                Category::SelfHarm => "Blocked self-harm content".to_string(),
                Category::Hate => "Blocked hateful content".to_string(),
                Category::CsamSuspected => "Blocked suspected illegal content".to_string(),
                _ => "Blocked flagged content".to_string(),
            },
            AlertKind::ProtectionDisabled => "Protection changed on the device".to_string(),
            AlertKind::Unspecified => "Safety alert".to_string(),
        };

        // The redacted, safe summary the cluster prepared. If empty, fall back to
        // the app/site name only.
        let detail = if !ev.redacted_context.is_empty() {
            ev.redacted_context.clone()
        } else if !ev.app.is_empty() {
            format!("In {}.", ev.app)
        } else {
            "A flagged item (redacted summary unavailable).".to_string()
        };

        let device = if ev.device_id.is_empty() {
            "Supervised device".to_string()
        } else {
            ev.device_id.clone()
        };

        // A locally-stored video segment to review, if the cluster attached one.
        // (The store never persists CSAM, so this is always empty for CSAM; the
        // card also gates playback on category as defence in depth.)
        let segment_uri = Some(ev.local_segment_uri).filter(|s| !s.is_empty());

        Self {
            id: ev.alert_id,
            title,
            detail,
            device,
            when: format_when(ev.ts),
            // Both product triggers are actionable (guardian can approve/deny).
            actionable: true,
            category,
            thumbnail,
            snippet,
            segment_uri,
        }
    }
}

/// Render a unix-epoch-millis timestamp as a short relative string. Falls back
/// gracefully for clock skew / unset timestamps.
pub fn format_when(ts_millis: i64) -> String {
    if ts_millis <= 0 {
        return "just now".to_string();
    }
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(ts_millis);
    let delta_secs = (now_millis - ts_millis).max(0) / 1000;
    if delta_secs < 60 {
        "just now".to_string()
    } else if delta_secs < 3600 {
        format!("{}m ago", delta_secs / 60)
    } else if delta_secs < 86_400 {
        format!("{}h ago", delta_secs / 3600)
    } else {
        format!("{}d ago", delta_secs / 86_400)
    }
}

/// Seed data stands in as an OFFLINE fallback while the gRPC client is not
/// connected. These mirror what `Review.StreamPendingReviews` streams from the
/// cluster — all redacted, never media.
pub fn seed() -> Vec<Alert> {
    vec![
        Alert {
            id: "a-1001".into(),
            title: "Blocked an adult image".into(),
            detail: "On a web page.".into(),
            device: "Kids tablet".into(),
            when: "2m ago".into(),
            actionable: false,
            category: Category::AdultImage,
            // Offline sample: no real bytes to preview.
            thumbnail: Vec::new(),
            snippet: String::new(),
            segment_uri: None,
        },
        Alert {
            id: "a-1002".into(),
            title: "Possible grooming detected".into(),
            detail: "Secrecy + \u{201c}move to another app\u{201d} patterns in a chat.".into(),
            device: "Kids phone".into(),
            when: "18m ago".into(),
            actionable: false,
            category: Category::Grooming,
            thumbnail: Vec::new(),
            snippet:
                "hey don\u{2019}t tell your mum about this, let\u{2019}s talk on the other app"
                    .into(),
            segment_uri: None,
        },
    ]
}

pub fn session_status_text(status: &AppStatus) -> &'static str {
    if status.logged_in {
        "Logged in"
    } else {
        "Login needed"
    }
}

pub fn pair_expiry_text(ts_millis: i64) -> String {
    if ts_millis <= 0 {
        return "unknown expiry".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(ts_millis);
    let secs = (ts_millis - now).max(0) / 1000;
    if secs < 60 {
        format!("expires in {}s", secs.max(1))
    } else {
        format!("expires in {}m", secs / 60)
    }
}

pub fn can_show_evidence(category: Category) -> bool {
    category != Category::CsamSuspected
}

pub fn should_show_thumbnail(alert: &Alert) -> bool {
    can_show_evidence(alert.category) && !alert.thumbnail.is_empty()
}

pub fn should_show_snippet(alert: &Alert) -> bool {
    can_show_evidence(alert.category) && !alert.snippet.is_empty()
}
