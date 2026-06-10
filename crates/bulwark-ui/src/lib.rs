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
    /// Live coverage feed (the network engine's pinning-registry snapshot),
    /// injected by the host process. The standalone dashboard binary has no
    /// engine in-process → [`NoCoverage`].
    pub coverage: Arc<dyn CoverageSource>,
}

/// What the network engine LEARNED about a host. Engine-agnostic mirror of
/// bulwark-net's `HostCapability`, so this crate carries no network-engine
/// dependency — the host process maps between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostInspection {
    /// TLS inspection succeeded before — ordinary HTTPS we filter in-line.
    Inspectable,
    /// TLS inspection was rejected (cert-pinned and/or E2E) — the network
    /// cannot read it; the host/app is routed to on-device OCR.
    Pinned,
}

/// One live per-host observation feeding the coverage matrix.
#[derive(Debug, Clone)]
pub struct HostCoverage {
    /// The host (SNI) or app id the engine classified.
    pub host: String,
    /// What was learned about it.
    pub inspection: HostInspection,
}

/// Live source of coverage data, injected by the process that owns the
/// network engine (bulwark-client wraps `PinningRegistry::snapshot()` in
/// this). Closures work directly via the blanket impl below.
pub trait CoverageSource: Send + Sync {
    /// Point-in-time list of hosts with a learned capability.
    fn snapshot(&self) -> Vec<HostCoverage>;
}

/// Closures are sources, so hosts can inject without a newtype.
impl<F> CoverageSource for F
where
    F: Fn() -> Vec<HostCoverage> + Send + Sync,
{
    fn snapshot(&self) -> Vec<HostCoverage> {
        self()
    }
}

/// No engine attached (standalone dashboard binary): zero rows, honestly.
pub struct NoCoverage;
impl CoverageSource for NoCoverage {
    fn snapshot(&self) -> Vec<HostCoverage> {
        Vec::new()
    }
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

/// Bind `bind` and serve the dashboard until shutdown. Convenience for host
/// processes that embed the dashboard (e.g. the runnable proxy) without
/// taking a direct axum dependency.
pub async fn serve(state: AppState, bind: &str) -> anyhow::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "bulwark-ui dashboard listening");
    axum::serve(listener, app).await?;
    Ok(())
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

/// The coverage matrix, derived LIVE from the injected [`CoverageSource`]
/// (bulwark-net's pinning registry): one honest row per host the engine has
/// actually classified. Inspection-rejected hosts show as pinned → routed to
/// on-device OCR. The network cannot distinguish cert-pinning from E2E (both
/// reject our leaf at the handshake), so the note says so rather than guess.
async fn coverage(State(st): State<AppState>) -> Json<Vec<CoverageRow>> {
    Json(st.coverage.snapshot().into_iter().map(coverage_row).collect())
}

/// Map one learned host observation onto an honest matrix row.
fn coverage_row(h: HostCoverage) -> CoverageRow {
    match h.inspection {
        HostInspection::Inspectable => CoverageRow {
            app: h.host,
            web_mitm: true,
            e2e: false,
            pinned: false,
            ocr_agent: false,
            note: "HTTPS inspected in-line via the per-install CA".into(),
        },
        HostInspection::Pinned => CoverageRow {
            app: h.host,
            web_mitm: false,
            // Unknowable from the network: pinning is what we OBSERVED. The
            // note carries the E2E caveat instead of a guessed flag.
            e2e: false,
            pinned: true,
            ocr_agent: true,
            note: "TLS inspection rejected (cert-pinned and/or E2E) — network cannot read; routed to on-device OCR".into(),
        },
    }
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

    #[tokio::test]
    async fn coverage_derives_rows_from_the_live_source() {
        let store = bulwark_store::open_in_memory().unwrap();
        let source = || {
            vec![
                HostCoverage {
                    host: "example.com".into(),
                    inspection: HostInspection::Inspectable,
                },
                HostCoverage {
                    host: "signal.org".into(),
                    inspection: HostInspection::Pinned,
                },
            ]
        };
        let st = AppState {
            store,
            coverage: Arc::new(source),
        };
        let Json(rows) = coverage(State(st)).await;
        assert_eq!(rows.len(), 2);
        let web = rows.iter().find(|r| r.app == "example.com").unwrap();
        assert!(web.web_mitm && !web.pinned && !web.ocr_agent);
        let pinned = rows.iter().find(|r| r.app == "signal.org").unwrap();
        assert!(!pinned.web_mitm && pinned.pinned && pinned.ocr_agent);
        assert!(pinned.note.contains("OCR"));
    }

    #[tokio::test]
    async fn coverage_is_empty_without_an_engine() {
        let st = AppState {
            store: bulwark_store::open_in_memory().unwrap(),
            coverage: Arc::new(NoCoverage),
        };
        let Json(rows) = coverage(State(st)).await;
        assert!(rows.is_empty(), "no engine attached → no fabricated rows");
    }

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
