//! `bulwark-ui` binary — serves the local guardian dashboard.
//! `BULWARK_UI_BIND` sets the listen address (default 127.0.0.1:8080).
#![forbid(unsafe_code)]

use std::sync::Arc;

use bulwark_ui::{serve, AppState, NoCoverage};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = bulwark_core::init_tracing_default();

    // SEAM (integration): open the encrypted client store with a key from the OS
    // keystore. bulwark-store finalizes the exact constructor; this is the one
    // wiring point the dashboard binary needs.
    let store: Arc<dyn bulwark_store::Store> = bulwark_store::open_in_memory()?;

    let bind = std::env::var("BULWARK_UI_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    // Standalone dashboard: no network engine in this process → empty coverage
    // source. The embedded host (bulwark_proxy) injects the live pinning
    // snapshot instead.
    serve(
        AppState {
            store,
            coverage: Arc::new(NoCoverage),
        },
        &bind,
    )
    .await
}
