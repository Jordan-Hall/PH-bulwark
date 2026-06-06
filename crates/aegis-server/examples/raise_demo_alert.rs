//! DEV-ONLY: raise one synthetic guardian alert against a running cluster.
//!
//! Usage:
//!   AEGIS_CLUSTER_ENDPOINT=http://127.0.0.1:8443 cargo run -p aegis-server --example raise_demo_alert

use aegis_proto::v1::alert_relay_client::AlertRelayClient;
use aegis_proto::v1::{AlertEvent, AlertKind, Category, Evidence, Severity};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::var("AEGIS_CLUSTER_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8443".to_string());
    let device_id = std::env::var("AEGIS_DEMO_DEVICE_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "aegis-proxy-local".to_string());
    let n = now_ms();

    let event = AlertEvent {
        alert_id: format!("demo-{n}"),
        kind: AlertKind::Intervention as i32,
        category: Category::AdultText as i32,
        severity: Severity::High as i32,
        app: "demo.local".to_string(),
        device_id,
        ts: n,
        redacted_context: "Synthetic e2e alert raised through AlertRelay.".to_string(),
        evidence: Some(Evidence {
            sha256: vec![0xde, 0xad, 0xbe, 0xef],
            perceptual_hash: Vec::new(),
            safe_thumbnail: Vec::new(),
            text_snippet: "demo blocked text snippet".to_string(),
            model_id: "dev-demo".to_string(),
            model_version: "0".to_string(),
        }),
        ..Default::default()
    };

    let alert_id = event.alert_id.clone();
    let mut client = AlertRelayClient::connect(endpoint).await?;
    let ack = client.raise_alert(event).await?.into_inner();
    println!(
        "raised {alert_id}: delivered={} deduped={} detail={}",
        ack.delivered, ack.deduped, ack.detail
    );
    Ok(())
}
