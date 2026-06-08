//! `bulwark-client` binary — brings up interception and runs the filtering loop.
//! Single-node usage pairs this with `bulwark-server --role all-in-one`.
#![forbid(unsafe_code)]

use std::sync::Arc;

use bulwark_client::{ClientConfig, Pipeline};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = bulwark_core::init_tracing_default();
    let cfg = ClientConfig::default();

    // SEAM: construct the platform interceptor (Windows Wintun + MITM + per-install CA).
    // Exact constructor confirmed at integration; bulwark-net exposes NetInterceptor + NetConfig.
    // NetInterceptor::new returns Result (fail-closed if the keystore can't
    // provide a CA key) — propagate it.
    let net = bulwark_net::NetInterceptor::new(bulwark_net::NetConfig::default())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let interceptor: Arc<dyn bulwark_net::Interceptor> = Arc::new(net);
    interceptor
        .start()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Retain blocked/borderline NON-CSAM video clips locally so the guardian app
    // can replay them (video analysis runs on-device; CSAM is never stored).
    let pipeline = Pipeline::new(cfg).with_default_segment_store();
    tracing::info!("bulwark-client running — intercept → classify → grooming/policy → block/alert");

    let result = pipeline.run(interceptor.clone()).await;
    let _ = interceptor.shutdown().await;
    result.map_err(|e| anyhow::anyhow!(e.to_string()))
}
