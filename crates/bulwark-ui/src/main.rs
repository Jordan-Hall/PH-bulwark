//! `bulwark-ui` binary — serves the local guardian dashboard.
//! `BULWARK_UI_BIND` sets the listen address (default 127.0.0.1:8080).
#![forbid(unsafe_code)]

use std::sync::Arc;

use bulwark_ui::{router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = bulwark_core::init_tracing_default();

    // SEAM (integration): open the encrypted client store with a key from the OS
    // keystore. bulwark-store finalizes the exact constructor; this is the one
    // wiring point the dashboard binary needs.
    let store: Arc<dyn bulwark_store::Store> = bulwark_store::open_in_memory()?;

    let bind = std::env::var("BULWARK_UI_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let app = router(AppState { store });
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "bulwark-ui dashboard listening");
    axum::serve(listener, app).await?;
    Ok(())
}
