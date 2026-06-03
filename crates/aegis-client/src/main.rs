//! `aegis-client` binary — brings up interception and runs the filtering loop.
//! Single-node usage pairs this with `aegis-server --role all-in-one`.
#![forbid(unsafe_code)]

use std::sync::Arc;

use aegis_client::{ClientConfig, Pipeline};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = aegis_core::init_tracing_default();
    let cfg = ClientConfig::default();

    // SEAM: construct the platform interceptor (Windows Wintun + MITM + per-install CA).
    // Exact constructor confirmed at integration; aegis-net exposes NetInterceptor + NetConfig.
    // NetInterceptor::new returns Result (fail-closed if the keystore can't
    // provide a CA key) — propagate it.
    let net = aegis_net::NetInterceptor::new(aegis_net::NetConfig::default())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let interceptor: Arc<dyn aegis_net::Interceptor> = Arc::new(net);
    interceptor
        .start()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let pipeline = Pipeline::new(cfg);
    tracing::info!("aegis-client running — intercept → classify → grooming/policy → block/alert");

    let result = pipeline.run(interceptor.clone()).await;
    let _ = interceptor.shutdown().await;
    result.map_err(|e| anyhow::anyhow!(e.to_string()))
}
