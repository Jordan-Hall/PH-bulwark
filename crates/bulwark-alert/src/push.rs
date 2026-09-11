//! Self-hosted UnifiedPush alert delivery with connection-time SSRF protection.
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bulwark_proto::v1::{
    AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AlertKind, Category, Severity,
};

use crate::error::{AlertError, Result};
use crate::render::assert_no_media;
use crate::AlertSink;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[async_trait]
pub trait PushTransport: Send + Sync {
    async fn send(&self, endpoint: &str, data: &serde_json::Value) -> Result<()>;
}

/// The production transport intentionally does not hold a reusable resolver-backed
/// reqwest client: every delivery re-resolves the endpoint, validates every answer,
/// then builds a client whose DNS entry is pinned to one validated address. This
/// closes registration-time DNS rebinding and validation/connect TOCTOU windows.
pub struct UnifiedPushTransport;

impl UnifiedPushTransport {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    async fn pinned_client(endpoint: &str) -> Result<(reqwest::Client, reqwest::Url)> {
        let url = reqwest::Url::parse(endpoint)
            .map_err(|e| AlertError::Push(format!("invalid UnifiedPush URL: {e}")))?;
        if !matches!(url.scheme(), "https" | "http") {
            return Err(AlertError::Push(
                "UnifiedPush endpoint must use http or https".into(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(AlertError::Push(
                "UnifiedPush endpoint must not contain URL userinfo".into(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| AlertError::Push("UnifiedPush endpoint has no host".into()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| AlertError::Push("UnifiedPush endpoint has no usable port".into()))?;

        let mut resolved = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| AlertError::Push(format!("UnifiedPush DNS lookup failed: {e}")))?
            .collect::<Vec<_>>();
        resolved.sort_unstable();
        resolved.dedup();
        if resolved.is_empty() {
            return Err(AlertError::Push(
                "UnifiedPush endpoint resolved to no addresses".into(),
            ));
        }
        if let Some(addr) = resolved.iter().find(|addr| !is_public_destination(addr.ip())) {
            return Err(AlertError::Push(format!(
                "UnifiedPush endpoint resolves to a blocked internal/non-routable address: {}",
                addr.ip()
            )));
        }

        // Pin the exact validated address. TLS still uses the original hostname/SNI.
        let selected: SocketAddr = resolved[0];
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .resolve(host, selected)
            .build()
            .map_err(|e| AlertError::Push(format!("building pinned HTTP client: {e}")))?;
        Ok((client, url))
    }
}

impl Default for UnifiedPushTransport {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl PushTransport for UnifiedPushTransport {
    async fn send(&self, endpoint: &str, data: &serde_json::Value) -> Result<()> {
        let (http, url) = Self::pinned_client(endpoint).await?;
        let response = http
            .post(url)
            .json(data)
            .send()
            .await
            .map_err(|e| AlertError::Push(format!("UnifiedPush POST failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(AlertError::Push(format!(
                "UnifiedPush endpoint returned {status}: {}",
                truncate(&body, 256)
            )));
        }
        Ok(())
    }
}

fn is_public_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
        }
    }
}

pub struct UnifiedPushSink {
    endpoint: String,
    transport: Arc<dyn PushTransport>,
}

impl UnifiedPushSink {
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        let endpoint = endpoint.into();
        if endpoint.trim().is_empty() {
            return Err(AlertError::Config(
                "UnifiedPush endpoint URL is empty".into(),
            ));
        }
        let transport = Arc::new(UnifiedPushTransport::new()?);
        Ok(Self {
            endpoint,
            transport,
        })
    }

    pub fn with_transport(endpoint: impl Into<String>, transport: Arc<dyn PushTransport>) -> Self {
        Self {
            endpoint: endpoint.into(),
            transport,
        }
    }

    fn ack(alert_id: &str, delivered: bool, detail: &str) -> AlertAck {
        AlertAck {
            alert_id: alert_id.to_string(),
            delivered,
            deduped: false,
            detail: detail.to_string(),
        }
    }

    fn redacted_data(event: &AlertEvent) -> serde_json::Value {
        let kind = AlertKind::try_from(event.kind).unwrap_or(AlertKind::Unspecified);
        let category = Category::try_from(event.category).unwrap_or(Category::Unspecified);
        let severity = Severity::try_from(event.severity).unwrap_or(Severity::Unspecified);
        serde_json::json!({
            "alert_id": event.alert_id,
            "kind": (kind as i32).to_string(),
            "category": (category as i32).to_string(),
            "severity": (severity as i32).to_string(),
            "device_id": event.device_id,
            "ts": event.ts.to_string(),
            "redacted_context": clamp_context(&event.redacted_context),
        })
    }

    async fn deliver_one(&self, event: &AlertEvent) -> Result<()> {
        assert_no_media(event)?;
        let data = Self::redacted_data(event);
        self.transport.send(&self.endpoint, &data).await?;
        tracing::info!(
            alert_id = %event.alert_id,
            device_id = %event.device_id,
            "guardian alert pushed via UnifiedPush (redacted)"
        );
        Ok(())
    }
}

pub trait TokenRegistry: Send + Sync {
    fn endpoints_for(&self, event: &AlertEvent) -> Vec<String>;
}

pub struct UnifiedPushFanoutSink {
    transport: Arc<dyn PushTransport>,
    registry: Arc<dyn TokenRegistry>,
}

impl UnifiedPushFanoutSink {
    pub fn new(registry: Arc<dyn TokenRegistry>) -> Result<Self> {
        Ok(Self {
            transport: Arc::new(UnifiedPushTransport::new()?),
            registry,
        })
    }

    pub fn with_transport(
        transport: Arc<dyn PushTransport>,
        registry: Arc<dyn TokenRegistry>,
    ) -> Self {
        Self {
            transport,
            registry,
        }
    }

    async fn fan_one(&self, event: &AlertEvent) -> Result<(usize, usize)> {
        assert_no_media(event)?;
        let endpoints = self.registry.endpoints_for(event);
        let attempted = endpoints.len();
        if attempted == 0 {
            return Ok((0, 0));
        }
        let data = UnifiedPushSink::redacted_data(event);
        let mut delivered = 0usize;
        // Endpoint lists are normally tiny. Sequential sends deliberately bound
        // fanout pressure; a slow endpoint has a hard request timeout above.
        for endpoint in &endpoints {
            match self.transport.send(endpoint, &data).await {
                Ok(()) => delivered += 1,
                Err(error) => tracing::warn!(
                    alert_id = %event.alert_id,
                    %error,
                    "UnifiedPush fan-out failed for one guardian endpoint"
                ),
            }
        }
        Ok((delivered, attempted))
    }
}

#[async_trait]
impl AlertSink for UnifiedPushFanoutSink {
    async fn raise(&self, event: AlertEvent) -> Result<AlertAck> {
        let (delivered, attempted) = self.fan_one(&event).await?;
        Ok(UnifiedPushSink::ack(
            &event.alert_id,
            delivered > 0,
            &format!("pushed to {delivered}/{attempted} guardian device(s)"),
        ))
    }

    async fn raise_batch(&self, batch: AlertBatch) -> Result<AlertAckBatch> {
        let mut acks = Vec::with_capacity(batch.events.len());
        for event in &batch.events {
            match self.fan_one(event).await {
                Ok((delivered, attempted)) => acks.push(UnifiedPushSink::ack(
                    &event.alert_id,
                    delivered > 0,
                    &format!("pushed to {delivered}/{attempted} guardian device(s)"),
                )),
                Err(error) => acks.push(UnifiedPushSink::ack(
                    &event.alert_id,
                    false,
                    &format!("push failed: {error}"),
                )),
            }
        }
        Ok(AlertAckBatch { acks })
    }
}

#[async_trait]
impl AlertSink for UnifiedPushSink {
    async fn raise(&self, event: AlertEvent) -> Result<AlertAck> {
        self.deliver_one(&event).await?;
        Ok(Self::ack(&event.alert_id, true, "pushed via UnifiedPush"))
    }

    async fn raise_batch(&self, batch: AlertBatch) -> Result<AlertAckBatch> {
        let mut acks = Vec::with_capacity(batch.events.len());
        for event in &batch.events {
            match self.deliver_one(event).await {
                Ok(()) => acks.push(Self::ack(&event.alert_id, true, "pushed via UnifiedPush")),
                Err(error) => {
                    tracing::warn!(
                        alert_id = %event.alert_id,
                        %error,
                        "UnifiedPush failed for one event in batch"
                    );
                    acks.push(Self::ack(
                        &event.alert_id,
                        false,
                        &format!("push failed: {error}"),
                    ));
                }
            }
        }
        Ok(AlertAckBatch { acks })
    }
}

fn clamp_context(value: &str) -> String {
    const MAX: usize = 1_000;
    if value.chars().count() <= MAX {
        return value.to_string();
    }
    let truncated: String = value.chars().take(MAX).collect();
    format!("{truncated}… (truncated)")
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        value.chars().take(max).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::{Evidence, Severity};

    fn event_with_secret_thumb() -> AlertEvent {
        AlertEvent {
            alert_id: "push-1".to_string(),
            kind: AlertKind::Intervention as i32,
            category: Category::CsamSuspected as i32,
            severity: Severity::Critical as i32,
            app: "messenger".to_string(),
            device_id: "kids-phone".to_string(),
            ts: 1_717_200_000_000,
            redacted_context: "Flagged content was blocked.".to_string(),
            evidence: Some(Evidence {
                sha256: vec![0xde, 0xad, 0xbe, 0xef],
                perceptual_hash: vec![0x01, 0x02],
                safe_thumbnail: vec![0xFF, 0xD8, 0xFF, 0xE0, 0x13, 0x37],
                text_snippet: "redacted".to_string(),
                model_id: "rules".to_string(),
                model_version: "1.0".to_string(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn private_network_destinations_are_blocked() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(!is_public_destination(ip.parse().unwrap()), "{ip}");
        }
        assert!(is_public_destination("8.8.8.8".parse().unwrap()));
        assert!(is_public_destination("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn redacted_data_carries_only_safe_scalars_and_no_evidence() {
        let event = event_with_secret_thumb();
        let data = UnifiedPushSink::redacted_data(&event);
        let object = data.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(|key| key.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "alert_id",
                "category",
                "device_id",
                "kind",
                "redacted_context",
                "severity",
                "ts",
            ]
        );
        assert!(object.get("evidence").is_none());
        assert!(object.get("safe_thumbnail").is_none());
        assert!(object.get("sha256").is_none());
        assert!(object.get("text_snippet").is_none());
    }

    #[test]
    fn sink_rejects_empty_endpoint() {
        assert!(matches!(
            UnifiedPushSink::new("   "),
            Err(AlertError::Config(_))
        ));
    }

    #[derive(Clone, Default)]
    struct CapturingPush {
        sent: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
        fail: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    }

    #[async_trait]
    impl PushTransport for CapturingPush {
        async fn send(&self, endpoint: &str, data: &serde_json::Value) -> Result<()> {
            if self.fail.lock().unwrap().contains(endpoint) {
                return Err(AlertError::Push(format!("forced fail for {endpoint}")));
            }
            self.sent
                .lock()
                .unwrap()
                .push((endpoint.to_string(), data.clone()));
            Ok(())
        }
    }

    struct StaticRegistry(Vec<String>);
    impl TokenRegistry for StaticRegistry {
        fn endpoints_for(&self, _event: &AlertEvent) -> Vec<String> {
            self.0.clone()
        }
    }

    const EP1: &str = "https://ntfy.example/upX1";
    const EP2: &str = "https://ntfy.example/upX2";
    const EP3: &str = "https://ntfy.example/upX3";

    fn safe_event(id: &str) -> AlertEvent {
        AlertEvent {
            alert_id: id.into(),
            kind: AlertKind::Intervention as i32,
            category: Category::AdultImage as i32,
            severity: Severity::High as i32,
            device_id: "kids-phone".into(),
            redacted_context: "blocked".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn fanout_is_best_effort() {
        let capture = CapturingPush::default();
        capture.fail.lock().unwrap().insert(EP2.into());
        let registry = Arc::new(StaticRegistry(vec![EP1.into(), EP2.into(), EP3.into()]));
        let sink = UnifiedPushFanoutSink::with_transport(Arc::new(capture.clone()), registry);
        let ack = sink.raise(safe_event("a2")).await.unwrap();
        assert!(ack.delivered);
        assert_eq!(capture.sent.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn fanout_rejects_media_before_send() {
        let capture = CapturingPush::default();
        let registry = Arc::new(StaticRegistry(vec![EP1.into()]));
        let sink = UnifiedPushFanoutSink::with_transport(Arc::new(capture.clone()), registry);
        let mut bad = safe_event("bad");
        bad.evidence = Some(Evidence {
            sha256: vec![0u8; 200],
            ..Default::default()
        });
        assert!(sink.raise(bad).await.is_err());
        assert!(capture.sent.lock().unwrap().is_empty());
    }
}
