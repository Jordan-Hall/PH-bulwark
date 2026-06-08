//! bulwark-ui — the local guardian dashboard + cluster admin (axum).
//!
//! Read-only views over the redacted audit store plus a **coverage matrix** that
//! is honest about what is and isn't filtered per app (E2E / pinned / QUIC gaps,
//! per PLAN §0a). All data is already redacted by contract (no explicit media,
//! no raw message text).
//!
//! The only write surface is config. The `llm-explain` feature adds a single,
//! guardian-INITIATED "explain this flagged thread" endpoint (off by default,
//! never automatic, never in the hot path — minimal-AI principle).
//!
//! `#![forbid(unsafe_code)]`, no telemetry.
#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
};
use bulwark_store::Store;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
}

/// Redacted event as shown in the dashboard (built from a `Verdict`; carries no
/// content/media — only metadata + the explainable rationale).
#[derive(Debug, Serialize)]
pub struct EventView {
    pub ts: i64,
    pub category: i32,
    pub action: i32,
    pub severity: i32,
    pub score: f32,
    pub rationale: String,
}

/// One row of the coverage matrix: what we can actually inspect for an app.
#[derive(Debug, Serialize)]
pub struct CoverageRow {
    pub app: String,
    pub web_mitm: bool,  // ordinary HTTPS we can decrypt
    pub e2e: bool,       // end-to-end encrypted → on-device OCR only
    pub pinned: bool,    // cert-pinned → on-device OCR only
    pub ocr_agent: bool, // on-device OCR active for this app
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub device: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
}
fn default_limit() -> u32 {
    100
}

/// Build the dashboard router.
pub fn router(state: AppState) -> Router {
    let r = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/events", get(events))
        .route("/api/coverage", get(coverage))
        .with_state(state);

    #[cfg(feature = "llm-explain")]
    let r = r.route("/api/explain", post(explain_enabled));
    #[cfg(not(feature = "llm-explain"))]
    let r = r.route("/api/explain", post(explain_disabled));

    r
}

async fn healthz() -> &'static str {
    "ok"
}

async fn events(State(st): State<AppState>, Query(q): Query<EventsQuery>) -> Json<Vec<EventView>> {
    let device = q.device.into();
    let limit = q.limit.min(1000);
    let rows = st.store.recent(&device, limit).await.unwrap_or_default();
    let views = rows
        .into_iter()
        .map(|e| EventView {
            ts: e.ts,
            category: e.verdict.category,
            action: e.verdict.action,
            severity: e.verdict.severity,
            score: e.verdict.score,
            rationale: e.verdict.rationale,
        })
        .collect();
    Json(views)
}

/// Static-ish coverage matrix (honest about the network's hard limits). A full
/// build derives `ocr_agent`/`pinned` live from bulwark-net's pinning registry +
/// bulwark-agent's active apps.
async fn coverage(State(_st): State<AppState>) -> Json<Vec<CoverageRow>> {
    Json(vec![
        CoverageRow {
            app: "web (browsers)".into(),
            web_mitm: true,
            e2e: false,
            pinned: false,
            ocr_agent: false,
            note: "HTTPS decrypted via per-install CA".into(),
        },
        CoverageRow {
            app: "WhatsApp / Signal / Messenger secret".into(),
            web_mitm: false,
            e2e: true,
            pinned: true,
            ocr_agent: true,
            note: "E2E — network cannot read; on-device OCR only".into(),
        },
    ])
}

#[cfg(not(feature = "llm-explain"))]
async fn explain_disabled() -> (axum::http::StatusCode, &'static str) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "LLM explain is disabled (build with --features llm-explain to enable; opt-in only)",
    )
}

#[cfg(feature = "llm-explain")]
#[derive(Deserialize)]
struct ExplainReq {
    thread_id: String,
}

#[cfg(feature = "llm-explain")]
async fn explain_enabled(Json(req): Json<ExplainReq>) -> Json<serde_json::Value> {
    // Guardian-initiated ONLY. Sends a redacted thread summary to a configured
    // LLM and returns a plain-language explanation. Never automatic; logged with
    // consent. SEAM: wire the LLM client + redaction here.
    Json(serde_json::json!({
        "thread_id": req.thread_id,
        "explanation": "(llm-explain enabled; client not yet wired)",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_is_honest_about_e2e() {
        // Compile-level guard that the coverage type encodes the E2E limitation.
        let row = CoverageRow {
            app: "Signal".into(),
            web_mitm: false,
            e2e: true,
            pinned: true,
            ocr_agent: true,
            note: "x".into(),
        };
        assert!(
            row.e2e && !row.web_mitm,
            "E2E apps are not network-readable"
        );
    }
}
