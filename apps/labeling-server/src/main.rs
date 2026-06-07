//! HTTP/JSON transport for the labeling service (the `server` feature).
//!
//! Trusted-volunteer auth (Phase 1): a single shared bearer token in the
//! `LABELING_TOKEN` env var. Endpoints:
//!   GET  /healthz
//!   GET  /tasks/next?labeler=<id>   -> 200 Task | 204 (all done)
//!   POST /labels  {task_id,labeler,label,stages} -> 200 | 404 (unknown task)
//!   GET  /stats   -> {labeled,total}
//!
//! Config via env: LABELING_TASKS, LABELING_CORRECTIONS, LABELING_TOKEN,
//! LABELING_ADDR. The corrections file it writes feeds rom `pipeline/retrain.py`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

use aegis_labeling_server::store::{LabelStore, Submission};

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<LabelStore>>,
    token: Arc<String>,
}

#[derive(Deserialize)]
struct NextQuery {
    #[allow(dead_code)]
    labeler: Option<String>,
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.strip_prefix("Bearer ").unwrap_or(h) == token)
        .unwrap_or(false)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn next_task(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<NextQuery>,
) -> impl IntoResponse {
    if !authorized(&headers, &st.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let store = st.store.lock().await;
    match store.next_task() {
        Some(t) => Json(t.clone()).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn post_label(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(sub): Json<Submission>,
) -> impl IntoResponse {
    if !authorized(&headers, &st.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut store = st.store.lock().await;
    match store.record(&sub) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn stats(State(st): State<AppState>) -> impl IntoResponse {
    let (labeled, total) = st.store.lock().await.stats();
    Json(serde_json::json!({ "labeled": labeled, "total": total }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tasks = PathBuf::from(std::env::var("LABELING_TASKS").unwrap_or_else(|_| "tasks.jsonl".into()));
    let corrections =
        PathBuf::from(std::env::var("LABELING_CORRECTIONS").unwrap_or_else(|_| "corrections.jsonl".into()));
    let token = std::env::var("LABELING_TOKEN").unwrap_or_else(|_| "dev-token".into());

    let store = LabelStore::load(&tasks, &corrections)?;
    let (labeled, total) = store.stats();
    println!("labeling-server: {total} tasks ({labeled} already labeled) from {}", tasks.display());

    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        token: Arc::new(token),
    };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/tasks/next", get(next_task))
        .route("/labels", post(post_label))
        .route("/stats", get(stats))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    let addr: SocketAddr = std::env::var("LABELING_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7878".into())
        .parse()?;
    println!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
