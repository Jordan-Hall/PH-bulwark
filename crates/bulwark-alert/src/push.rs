//! Self-hosted UnifiedPush alert sink (FOSS, no Google/Apple).
//!
//! This module is compiled **only** with the non-default `push` cargo feature.
//! It adds a second [`AlertSink`](crate::AlertSink) backend,
//! [`UnifiedPushSink`], so the guardian phone app receives a real-time push *in
//! addition to* the existing email path — without changing the default
//! (email-only) build.
//!
//! ## UnifiedPush model (no service account, no project id, no OAuth)
//!
//! [UnifiedPush](https://unifiedpush.org) decouples the app from any single
//! proprietary push provider. The guardian's device runs a *distributor*
//! (e.g. ntfy, NextPush) which hands the app a plain **endpoint URL**. To
//! deliver a notification the server simply HTTP-POSTs the payload to that URL —
//! there is no token exchange, no signing key, no Google/Apple dependency. The
//! endpoint may be a self-hosted ntfy-compatible server on a private network, so
//! the transport does NOT force `https_only`; the URL's own scheme governs
//! (we still default to https in any config). A non-2xx response is an
//! [`AlertError::Push`].
//!
//! ## Hard privacy invariant (data-handling.md §1–2, class C0)
//!
//! Exactly like the email renderer, this sink NEVER transmits raw media,
//! thumbnails, or message bodies. It POSTs a JSON **data** body carrying ONLY
//! redacted scalar fields:
//!
//! - `alert_id`, `kind`, `category`, `severity`, `device_id`, `ts`,
//!   and `redacted_context`.
//!
//! Evidence (`safe_thumbnail`, `sha256`, `text_snippet`, …) is deliberately
//! *not* forwarded over push — not even hashes. A CSAM-suspected alert is
//! treated identically: the phone gets a notification that something was
//! flagged, never the content itself. [`assert_no_media`](crate::render::assert_no_media)
//! runs first as a belt-and-braces guard and hard-fails on anything that smells
//! like raw bytes, so it is structurally impossible to push a media blob.
//!
//! The payload is POSTed as the raw JSON request body — we deliberately do NOT
//! set any ntfy `Title`/`Message`/`Tags` headers, which would render visible
//! text in a system banner. The app parses the body and builds its own UI from
//! the redacted fields.
//!
//! ## Best-effort delivery
//!
//! Every failure path returns an [`AlertError`] (it never panics). Whether a
//! caller treats a push failure as fatal or log-and-continue is the caller's
//! choice; the email path remains the system of record.

use std::sync::Arc;

use async_trait::async_trait;

use bulwark_proto::v1::{
    AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AlertKind, Category, Severity,
};

use crate::error::{AlertError, Result};
use crate::render::assert_no_media;
use crate::AlertSink;

/// Transport seam: POST ONE redacted data payload to ONE UnifiedPush endpoint.
/// Mirrors the email path's `MailTransport` — the HTTP concern lives behind this
/// trait so the sinks can be unit-tested with a capturing mock (no network, no
/// credentials of any kind).
#[async_trait]
pub trait PushTransport: Send + Sync {
    /// POST the already-redacted `data` map to `endpoint` (a UnifiedPush
    /// endpoint URL). The `data` is the output of the no-media redactor — the
    /// transport MUST NOT add media.
    async fn send(&self, endpoint: &str, data: &serde_json::Value) -> Result<()>;
}

/// Production [`PushTransport`]: POSTs a redacted JSON body to a self-hosted
/// UnifiedPush endpoint URL over a rustls `reqwest` client.
///
/// No project id, service account, OAuth token, or any Google/Apple dependency
/// is involved — the endpoint URL is everything we need.
pub struct UnifiedPushTransport {
    http: reqwest::Client,
}

impl UnifiedPushTransport {
    /// Build the transport. The rustls `reqwest` client is *not* `https_only`:
    /// a self-hosted ntfy-compatible distributor may live behind plain http on a
    /// private network, and the endpoint URL's own scheme decides the wire.
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| AlertError::Push(format!("building HTTP client: {e}")))?;
        Ok(Self { http })
    }
}

impl Default for UnifiedPushTransport {
    fn default() -> Self {
        // A builder with no special options cannot realistically fail; fall back
        // to the default client so `Default` stays infallible.
        Self {
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl PushTransport for UnifiedPushTransport {
    async fn send(&self, endpoint: &str, data: &serde_json::Value) -> Result<()> {
        // POST the redacted data as the raw JSON body. No ntfy Title/Message/Tags
        // headers — those would render visible text in a system banner; the app
        // parses this body and builds its own UI from the redacted fields.
        let resp = self
            .http
            .post(endpoint)
            .json(data)
            .send()
            .await
            .map_err(|e| AlertError::Push(format!("UnifiedPush POST failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AlertError::Push(format!(
                "UnifiedPush endpoint returned {status}: {}",
                truncate(&body, 256)
            )));
        }
        Ok(())
    }
}

/// UnifiedPush [`AlertSink`] for a SINGLE guardian endpoint URL.
///
/// Construct with [`UnifiedPushSink::new`]. Delegates the network concern to a
/// [`PushTransport`]; [`UnifiedPushSink::with_transport`] injects a mock in
/// tests.
pub struct UnifiedPushSink {
    /// Where to send the redacted notification — the guardian device's
    /// UnifiedPush endpoint URL (proto `PushTarget.push_endpoint`), supplied at
    /// construction so this crate stays free of any device registry.
    endpoint: String,
    transport: Arc<dyn PushTransport>,
}

impl UnifiedPushSink {
    /// Build a sink delivering to the guardian `endpoint` URL over the real
    /// UnifiedPush transport.
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

    /// Test/seam constructor over any [`PushTransport`] (no network).
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

    /// Build the **data** payload — redacted scalar fields ONLY. No media,
    /// no thumbnails, no message bodies, no evidence (not even hashes).
    fn redacted_data(event: &AlertEvent) -> serde_json::Value {
        let kind = AlertKind::try_from(event.kind).unwrap_or(AlertKind::Unspecified);
        let category = Category::try_from(event.category).unwrap_or(Category::Unspecified);
        let severity = Severity::try_from(event.severity).unwrap_or(Severity::Unspecified);

        // Values are stringified scalars so the app parses a uniform shape.
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

    /// Deliver one event as a redacted data message. Runs the no-media guard
    /// first; on any failure returns an [`AlertError`] (never panics).
    async fn deliver_one(&self, event: &AlertEvent) -> Result<()> {
        // Belt-and-braces: the same hard invariant the email path enforces.
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

/// Source of the guardian UnifiedPush endpoint URLs to fan an alert out to, read
/// AT RAISE TIME (so an endpoint registered after the sink was built still gets
/// alerts). The relay's `AlertHub` implements this over its in-memory
/// `push_targets`.
pub trait TokenRegistry: Send + Sync {
    /// A snapshot of every registered guardian endpoint URL right now (may be
    /// empty).
    fn tokens(&self) -> Vec<String>;
}

/// An [`AlertSink`] that pushes the redacted event to EVERY currently-registered
/// guardian endpoint URL (read from a [`TokenRegistry`] at raise time) — unlike
/// [`UnifiedPushSink`], which binds one endpoint at construction. Best-effort:
/// one endpoint's failure never aborts the others; an empty registry is a
/// successful no-op acked `delivered = false`.
pub struct UnifiedPushFanoutSink {
    transport: Arc<dyn PushTransport>,
    registry: Arc<dyn TokenRegistry>,
}

impl UnifiedPushFanoutSink {
    /// Build over the real UnifiedPush transport, reading endpoints from
    /// `registry`. No server-side config (no project/service account) is needed.
    pub fn new(registry: Arc<dyn TokenRegistry>) -> Result<Self> {
        let transport = Arc::new(UnifiedPushTransport::new()?);
        Ok(Self {
            transport,
            registry,
        })
    }

    /// Test/seam constructor over any transport + registry (no network).
    pub fn with_transport(
        transport: Arc<dyn PushTransport>,
        registry: Arc<dyn TokenRegistry>,
    ) -> Self {
        Self {
            transport,
            registry,
        }
    }

    /// Fan one event out to every current endpoint. Returns (delivered, attempted).
    async fn fan_one(&self, event: &AlertEvent) -> Result<(usize, usize)> {
        assert_no_media(event)?; // hard privacy invariant, before any send
        let endpoints = self.registry.tokens();
        let attempted = endpoints.len();
        if attempted == 0 {
            return Ok((0, 0));
        }
        let data = UnifiedPushSink::redacted_data(event);
        let mut delivered = 0usize;
        for endpoint in &endpoints {
            match self.transport.send(endpoint, &data).await {
                Ok(()) => delivered += 1,
                Err(e) => tracing::warn!(alert_id = %event.alert_id, error = %e,
                    "UnifiedPush fan-out failed for one guardian endpoint"),
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
                Err(e) => acks.push(UnifiedPushSink::ack(
                    &event.alert_id,
                    false,
                    &format!("push failed: {e}"),
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
        // Push has no email-style digest; each event is a separate notification.
        // Best-effort: one event's failure must not abort the rest, so we record
        // a per-event ack rather than bailing on the first error.
        let mut acks = Vec::with_capacity(batch.events.len());
        for event in &batch.events {
            match self.deliver_one(event).await {
                Ok(()) => acks.push(Self::ack(&event.alert_id, true, "pushed via UnifiedPush")),
                Err(e) => {
                    tracing::warn!(
                        alert_id = %event.alert_id,
                        error = %e,
                        "UnifiedPush failed for one event in batch"
                    );
                    acks.push(Self::ack(
                        &event.alert_id,
                        false,
                        &format!("push failed: {e}"),
                    ));
                }
            }
        }
        Ok(AlertAckBatch { acks })
    }
}

/// Bound the redacted context we push so a notification can't carry an oversized
/// blob. Mirrors the renderer's clamp intent (summaries, not transcripts).
fn clamp_context(s: &str) -> String {
    const MAX: usize = 1_000;
    if s.chars().count() <= MAX {
        return s.to_string();
    }
    let truncated: String = s.chars().take(MAX).collect();
    format!("{truncated}… (truncated)")
}

/// Truncate an error/response body before logging or surfacing it.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::{Category, Evidence, Severity};

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
    fn redacted_data_carries_only_safe_scalars_and_no_evidence() {
        let event = event_with_secret_thumb();
        let data = UnifiedPushSink::redacted_data(&event);
        let obj = data.as_object().unwrap();

        // Exactly the allowed redacted fields, nothing else.
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
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

        // No evidence / media / thumbnail / hash fields leak in.
        assert!(obj.get("evidence").is_none());
        assert!(obj.get("safe_thumbnail").is_none());
        assert!(obj.get("sha256").is_none());
        assert!(obj.get("text_snippet").is_none());

        // The serialized JSON must not contain the thumbnail bytes in any form.
        let json = serde_json::to_string(&data).unwrap();
        assert!(!json.to_lowercase().contains("ffd8ffe0"));
        assert!(!json.contains("deadbeef"));
    }

    #[test]
    fn csam_alert_is_pushed_as_a_redacted_notification_only() {
        // A CSAM-suspected event must still produce only the redacted scalar
        // payload — never the content, never the (illegal) thumbnail bytes.
        let event = event_with_secret_thumb();
        assert_eq!(event.category, Category::CsamSuspected as i32);
        let data = UnifiedPushSink::redacted_data(&event);
        assert_eq!(
            data["category"],
            (Category::CsamSuspected as i32).to_string()
        );
        assert_eq!(data["redacted_context"], "Flagged content was blocked.");
        // And the no-media guard accepts this redacted event.
        assert_no_media(&event).unwrap();
    }

    #[test]
    fn sink_rejects_empty_endpoint() {
        // An empty endpoint URL is a config error, caught at construction.
        assert!(matches!(
            UnifiedPushSink::new("   "),
            Err(AlertError::Config(_))
        ));
    }

    // --- Fan-out: mock transport + registry (no network) ----------------------

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
        fn tokens(&self) -> Vec<String> {
            self.0.clone()
        }
    }

    // URL-shaped endpoints, the way a UnifiedPush distributor hands them out.
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
    async fn fanout_sends_to_every_registered_endpoint() {
        let cap = CapturingPush::default();
        let reg = Arc::new(StaticRegistry(vec![EP1.into(), EP2.into(), EP3.into()]));
        let sink = UnifiedPushFanoutSink::with_transport(Arc::new(cap.clone()), reg);
        let ack = sink.raise(safe_event("a1")).await.unwrap();
        assert!(ack.delivered);

        // Every send hit the registered endpoint URL (and nothing else).
        let sent = cap.sent.lock().unwrap();
        let endpoints: Vec<&str> = sent.iter().map(|(e, _)| e.as_str()).collect();
        assert_eq!(endpoints, [EP1, EP2, EP3]);
        // Payload is content-free: only the safe redacted scalars, never evidence.
        for (_, data) in sent.iter() {
            let obj = data.as_object().unwrap();
            assert!(obj.get("safe_thumbnail").is_none());
            assert!(obj.get("sha256").is_none());
            assert!(obj.get("text_snippet").is_none());
            assert_eq!(obj["alert_id"], "a1");
        }
    }

    #[tokio::test]
    async fn fanout_is_best_effort_one_failure_doesnt_abort() {
        let cap = CapturingPush::default();
        cap.fail.lock().unwrap().insert(EP2.into());
        let reg = Arc::new(StaticRegistry(vec![EP1.into(), EP2.into(), EP3.into()]));
        let sink = UnifiedPushFanoutSink::with_transport(Arc::new(cap.clone()), reg);
        let ack = sink.raise(safe_event("a2")).await.unwrap();
        assert!(ack.delivered, "2/3 still delivered");
        assert_eq!(cap.sent.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn fanout_empty_registry_acks_not_delivered() {
        let cap = CapturingPush::default();
        let reg = Arc::new(StaticRegistry(vec![]));
        let sink = UnifiedPushFanoutSink::with_transport(Arc::new(cap.clone()), reg);
        let ack = sink.raise(safe_event("a3")).await.unwrap();
        assert!(!ack.delivered);
        assert!(cap.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn fanout_rejects_media_before_any_send() {
        let cap = CapturingPush::default();
        let reg = Arc::new(StaticRegistry(vec![EP1.into()]));
        let sink = UnifiedPushFanoutSink::with_transport(Arc::new(cap.clone()), reg);
        // An oversized "sha256" (raw bytes masquerading as a hash) trips
        // assert_no_media — the fan-out must reject it BEFORE contacting any
        // endpoint.
        let mut bad = safe_event("bad");
        bad.evidence = Some(Evidence {
            sha256: vec![0u8; 200],
            ..Default::default()
        });
        assert!(sink.raise(bad).await.is_err());
        assert!(cap.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn single_sink_posts_to_its_endpoint() {
        let cap = CapturingPush::default();
        let sink = UnifiedPushSink::with_transport(EP1, Arc::new(cap.clone()));
        let ack = sink.raise(safe_event("solo")).await.unwrap();
        assert!(ack.delivered);
        let sent = cap.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, EP1, "send hit the configured endpoint URL");
    }
}
