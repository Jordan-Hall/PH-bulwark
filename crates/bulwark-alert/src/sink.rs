//! The guardian alert sink.
//!
//! [`EmailAlertSink`] implements [`AlertSink`](crate::AlertSink): it renders an
//! [`AlertEvent`] to a redacted email and hands it to a [`MailTransport`],
//! applying dedupe + burst coalescing along the way. It is transport-agnostic
//! (any `MailTransport` works — SMTP today, Gmail API later) and clock-agnostic
//! (the limiter takes an injectable `Instant`).

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::Mutex;

use bulwark_proto::v1::{AlertAck, AlertAckBatch, AlertBatch, AlertEvent};

use crate::config::AlertConfig;
use crate::error::Result;
use crate::ratelimit::{Decision, RateLimiter};
use crate::render::{render_digest, render_event};
use crate::transport::{MailTransport, OutgoingMail, SmtpTransport};
use crate::AlertSink;

/// Email-backed alert sink. Construct with [`EmailAlertSink::new`] (SMTP) or
/// [`EmailAlertSink::with_transport`] (any [`MailTransport`], e.g. for tests or
/// a future Gmail-API backend).
pub struct EmailAlertSink {
    cfg: AlertConfig,
    transport: Arc<dyn MailTransport>,
    limiter: Mutex<RateLimiter>,
}

impl EmailAlertSink {
    /// Build a sink that sends over SMTP per `cfg`. Validates the config and
    /// constructs the rustls SMTP transport up front.
    pub fn new(cfg: AlertConfig) -> Result<Self> {
        cfg.validate()?;
        let transport = Arc::new(SmtpTransport::new(&cfg.smtp)?);
        Ok(Self::with_transport(cfg, transport))
    }

    /// Build a sink over an arbitrary transport. Used by tests (a capturing
    /// transport) and by future backends (Gmail API) behind the same trait.
    pub fn with_transport(cfg: AlertConfig, transport: Arc<dyn MailTransport>) -> Self {
        let limiter = RateLimiter::new(cfg.rate_limit.clone());
        Self {
            cfg,
            transport,
            limiter: Mutex::new(limiter),
        }
    }

    fn ack(alert_id: &str, delivered: bool, deduped: bool, detail: &str) -> AlertAck {
        AlertAck {
            alert_id: alert_id.to_string(),
            delivered,
            deduped,
            detail: detail.to_string(),
        }
    }

    async fn deliver_one(&self, event: &AlertEvent) -> Result<()> {
        let rendered = render_event(event, &self.cfg.subject_prefix)?;
        self.transport
            .send(OutgoingMail {
                from: self.cfg.from.clone(),
                to: self.cfg.recipients.clone(),
                email: rendered,
            })
            .await
    }

    async fn deliver_digest(&self, events: &[AlertEvent]) -> Result<()> {
        let rendered = render_digest(events, &self.cfg.subject_prefix)?;
        self.transport
            .send(OutgoingMail {
                from: self.cfg.from.clone(),
                to: self.cfg.recipients.clone(),
                email: rendered,
            })
            .await
    }

    /// Flush any buffered (coalesced) events as one digest email. Safe to call
    /// on a timer (every `burst_window`) or manually; a no-op when empty.
    pub async fn flush_digest(&self) -> Result<Option<AlertAckBatch>> {
        self.flush_digest_at(Instant::now()).await
    }

    /// `flush_digest` with an injectable clock (tests).
    pub async fn flush_digest_at(&self, now: Instant) -> Result<Option<AlertAckBatch>> {
        let events = {
            let mut limiter = self.limiter.lock().await;
            if !limiter.has_pending_digest() {
                return Ok(None);
            }
            limiter.note_digest_sent(now);
            limiter.drain_digest()
        };

        self.deliver_digest(&events).await?;
        let acks = events
            .iter()
            .map(|e| Self::ack(&e.alert_id, true, false, "delivered in digest"))
            .collect();
        Ok(Some(AlertAckBatch { acks }))
    }

    /// `raise` with an injectable clock (tests).
    pub async fn raise_at(&self, event: AlertEvent, now: Instant) -> Result<AlertAck> {
        let decision = {
            let mut limiter = self.limiter.lock().await;
            limiter.admit(&event, now)
        };

        match decision {
            Decision::Deduped => Ok(Self::ack(
                &event.alert_id,
                false,
                true,
                "duplicate alert suppressed",
            )),
            Decision::Coalesced => Ok(Self::ack(
                &event.alert_id,
                false,
                true,
                "coalesced into pending digest",
            )),
            Decision::SendNow => {
                self.deliver_one(&event).await?;
                Ok(Self::ack(&event.alert_id, true, false, "delivered"))
            }
        }
    }
}

#[async_trait]
impl AlertSink for EmailAlertSink {
    async fn raise(&self, event: AlertEvent) -> Result<AlertAck> {
        self.raise_at(event, Instant::now()).await
    }

    async fn raise_batch(&self, batch: AlertBatch) -> Result<AlertAckBatch> {
        // The batch path is the digest path (RaiseAlerts): render all the
        // supplied events into a single roll-up email. Dedupe still applies so a
        // backfill can't re-send already-seen alerts.
        let now = Instant::now();
        let mut to_send: Vec<AlertEvent> = Vec::with_capacity(batch.events.len());
        let mut acks: Vec<AlertAck> = Vec::with_capacity(batch.events.len());

        {
            let mut limiter = self.limiter.lock().await;
            for event in batch.events {
                match limiter.admit(&event, now) {
                    Decision::Deduped => acks.push(Self::ack(
                        &event.alert_id,
                        false,
                        true,
                        "duplicate alert suppressed",
                    )),
                    // In the batch path both SendNow and Coalesced go into the
                    // single digest email; the distinction only matters for the
                    // single-alert fast path.
                    Decision::SendNow | Decision::Coalesced => to_send.push(event),
                }
            }
        }

        if !to_send.is_empty() {
            self.deliver_digest(&to_send).await?;
            for event in &to_send {
                acks.push(Self::ack(
                    &event.alert_id,
                    true,
                    false,
                    "delivered in digest",
                ));
            }
        }

        Ok(AlertAckBatch { acks })
    }
}

/// Fan an alert out to several [`AlertSink`]s (e.g. email + FCM push) best-effort.
/// One sink's failure is logged and does NOT abort the others; the ack from the
/// FIRST sink that succeeds is returned (email is the system of record when
/// present). Used by the server to deliver via every configured channel.
pub struct CompositeSink {
    sinks: Vec<Arc<dyn AlertSink>>,
}

impl CompositeSink {
    pub fn new(sinks: Vec<Arc<dyn AlertSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl AlertSink for CompositeSink {
    async fn raise(&self, event: AlertEvent) -> Result<AlertAck> {
        let mut primary: Option<AlertAck> = None;
        for sink in &self.sinks {
            match sink.raise(event.clone()).await {
                Ok(ack) => {
                    if primary.is_none() {
                        primary = Some(ack);
                    }
                }
                Err(e) => tracing::warn!(alert_id = %event.alert_id, error = %e,
                    "one alert sink failed in composite (continuing)"),
            }
        }
        Ok(primary.unwrap_or_else(|| AlertAck {
            alert_id: event.alert_id,
            delivered: false,
            deduped: false,
            detail: "all alert sinks failed".to_string(),
        }))
    }

    async fn raise_batch(&self, batch: AlertBatch) -> Result<AlertAckBatch> {
        let mut primary: Option<AlertAckBatch> = None;
        for sink in &self.sinks {
            match sink.raise_batch(batch.clone()).await {
                Ok(acks) => {
                    if primary.is_none() {
                        primary = Some(acks);
                    }
                }
                Err(e) => tracing::warn!(error = %e,
                    "one alert sink failed in composite batch (continuing)"),
            }
        }
        Ok(primary.unwrap_or(AlertAckBatch { acks: Vec::new() }))
    }
}
