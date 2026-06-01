//! # aegis-alert
//!
//! Guardian alerting for Aegis: turn an [`AlertEvent`] into a clear,
//! **redacted** email and deliver it over SMTP (async, rustls TLS), with
//! dedupe + burst-coalescing into digests.
//!
//! ## What this crate guarantees
//!
//! - **Two product triggers.** [`AlertKind::Intervention`] (a blocker acted)
//!   and [`AlertKind::GroomingSuspected`] (the grooming engine crossed the
//!   alert threshold) are both rendered, with different framing
//!   (see [`render`]).
//! - **Hard privacy invariant.** It is structurally impossible for this crate
//!   to email explicit media or unredacted content. The renderer
//!   ([`render::render_event`] / [`render::render_digest`]) emits **only** the
//!   safe scalar fields, the `redacted_context` string, and SAFE evidence
//!   (hashes + a *note* that a safe thumbnail exists in the dashboard — never
//!   the thumbnail bytes). [`render::assert_no_media`] runs first and hard-fails
//!   on anything that looks like raw bytes / a media blob. This mirrors
//!   `docs/security/data-handling.md` §1–2 (class C0 must never leave the box).
//! - **No backhaul.** The only outbound connection is to the configured SMTP
//!   server. No telemetry, no analytics, no third-party endpoint.
//! - **No AI / ML.** Pure deterministic rendering + rate-limiting.
//! - **No hardcoded secrets.** SMTP credentials come from
//!   [`config::SmtpAuth::from_env`] / the OS keystore at runtime and are never
//!   serialized to a config file.
//!
//! ## Public API
//!
//! - [`AlertSink`] — the trait (mirrors `docs/design/interfaces.md`).
//! - [`EmailAlertSink`] — the SMTP implementation; also accepts any
//!   [`transport::MailTransport`] so a Gmail-API backend can drop in later.
//! - [`config::AlertConfig`] — all configuration (SMTP, recipients, thresholds).
//!
//! ## Relationship to the interface contract
//!
//! `docs/design/interfaces.md` defines `AlertSink` with `aegis_core::Result`.
//! Per the Wave C build constraints this crate does not depend on `aegis-core`,
//! so the trait here uses the crate-local [`error::Result`]. The method
//! shapes (`raise`, `raise_batch`) and ownership are identical; wiring the
//! crates together is a one-line error conversion.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod ratelimit;
pub mod render;
pub mod sink;
pub mod transport;

use async_trait::async_trait;

pub use aegis_proto::v1::{
    AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AlertKind, Category, Evidence, Severity,
};

pub use config::{AlertConfig, RateLimitConfig, SmtpAuth, SmtpConfig, TlsMode};
pub use error::{AlertError, Result};
pub use sink::EmailAlertSink;
pub use transport::{MailTransport, OutgoingMail, SmtpTransport};

/// Raises guardian alerts with **redacted context only**, rate-limited /
/// digested. Mirrors the contract in `docs/design/interfaces.md`.
///
/// Implementors MUST carry `redacted_context` + hash/safe-thumbnail
/// [`Evidence`] only — never explicit media. [`EmailAlertSink`] enforces this
/// at render time.
#[async_trait]
pub trait AlertSink: Send + Sync {
    /// Raise one alert (rate-limited / deduped). Returns an [`AlertAck`] whose
    /// `deduped` flag reports suppression by the rate-limit / digest logic.
    async fn raise(&self, event: AlertEvent) -> Result<AlertAck>;

    /// Flush a digest batch — the `RaiseAlerts` path: a periodic roll-up of
    /// (typically LOG-level) events into a single email.
    async fn raise_batch(&self, batch: AlertBatch) -> Result<AlertAckBatch>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::{assert_no_media, render_digest, render_event};
    use crate::transport::OutgoingMail;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    // ---- test helpers -----------------------------------------------------

    /// A transport that captures everything it's asked to "send" instead of
    /// touching the network. Lets us assert on rendered bodies.
    #[derive(Clone, Default)]
    struct CapturingTransport {
        sent: Arc<StdMutex<Vec<OutgoingMail>>>,
    }

    impl CapturingTransport {
        fn sent(&self) -> Vec<OutgoingMail> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MailTransport for CapturingTransport {
        async fn send(&self, mail: OutgoingMail) -> Result<()> {
            self.sent.lock().unwrap().push(mail);
            Ok(())
        }
    }

    fn test_config() -> AlertConfig {
        AlertConfig {
            smtp: SmtpConfig::new("localhost", 2525),
            from: "Aegis <aegis@home.example>".to_string(),
            recipients: vec!["guardian@example.com".to_string()],
            subject_prefix: "[Aegis]".to_string(),
            rate_limit: RateLimitConfig {
                dedupe_window: Duration::from_secs(300),
                burst_window: Duration::from_secs(60),
                max_immediate_per_window: 2,
                digest_max_events: 50,
            },
        }
    }

    fn safe_evidence() -> Evidence {
        Evidence {
            sha256: vec![0xde, 0xad, 0xbe, 0xef],
            perceptual_hash: vec![0x01, 0x02, 0x03, 0x04],
            // A SAFE (blurred) thumbnail may be present; the renderer must NOT
            // inline these bytes. We use a recognisable marker so a test can
            // prove the bytes never appear in the email.
            safe_thumbnail: SECRET_THUMB_BYTES.to_vec(),
            text_snippet: "hey what's your [REDACTED] … keep this our secret".to_string(),
            model_id: "grooming-rules".to_string(),
            model_version: "1.4".to_string(),
        }
    }

    /// A byte pattern we treat as "explicit media bytes" for the invariant
    /// tests. If this sequence ever appears in a rendered body, the safety
    /// invariant is broken.
    const SECRET_THUMB_BYTES: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0x13, 0x37, 0xCA, 0xFE];

    fn intervention_event() -> AlertEvent {
        AlertEvent {
            alert_id: "intv-1".to_string(),
            kind: AlertKind::Intervention as i32,
            category: Category::AdultImage as i32,
            severity: Severity::High as i32,
            app: "example.com".to_string(),
            device_id: "kids-tablet".to_string(),
            ts: 1_717_200_000_000, // 2024-06-01T00:00:00Z
            redacted_context: "Blocked an adult image on a web page.".to_string(),
            evidence: Some(safe_evidence()),
        }
    }

    fn grooming_event() -> AlertEvent {
        AlertEvent {
            alert_id: "groom-1".to_string(),
            kind: AlertKind::GroomingSuspected as i32,
            category: Category::Grooming as i32,
            severity: Severity::High as i32,
            app: "messenger".to_string(),
            device_id: "kids-phone".to_string(),
            ts: 1_717_200_000_000,
            redacted_context: "Conversation shows secrecy + platform-switching patterns."
                .to_string(),
            evidence: Some(safe_evidence()),
        }
    }

    // ---- rendering: both kinds, redacted-only ----------------------------

    #[test]
    fn renders_intervention_email_with_safe_fields_only() {
        let event = intervention_event();
        let rendered = render_event(&event, "[Aegis]").unwrap();

        // Safe fields are present.
        assert!(rendered.subject.contains("Aegis blocked something"));
        assert!(rendered.subject.contains("Adult image"));
        assert!(rendered.body.contains("example.com"));
        assert!(rendered.body.contains("kids-tablet"));
        assert!(rendered.body.contains("2024-06-01T00:00:00Z"));
        assert!(rendered
            .body
            .contains("Blocked an adult image on a web page."));
        // Hash is hex-rendered.
        assert!(rendered.body.contains("deadbeef"));
        // Model attribution present.
        assert!(rendered.body.contains("grooming-rules"));
    }

    #[test]
    fn renders_grooming_email_with_distinct_framing() {
        let event = grooming_event();
        let rendered = render_event(&event, "[Aegis]").unwrap();

        assert!(rendered.subject.contains("Possible grooming detected"));
        assert!(rendered.subject.contains("Grooming"));
        // Grooming-specific guidance (reporting path) only appears for grooming.
        assert!(rendered.body.contains("grooming-suspicion"));
        assert!(rendered.body.to_lowercase().contains("ncmec"));

        // The intervention email must NOT contain that grooming guidance.
        let intv = render_event(&intervention_event(), "[Aegis]").unwrap();
        assert!(!intv.body.contains("grooming-suspicion"));
    }

    #[test]
    fn body_contains_no_media_bytes_only_redacted_fields() {
        for event in [intervention_event(), grooming_event()] {
            let rendered = render_event(&event, "[Aegis]").unwrap();

            // HARD INVARIANT: the safe-thumbnail bytes must NEVER appear in the
            // rendered email — neither raw nor as a recognisable hex run.
            assert!(
                !rendered.body.as_bytes().windows(SECRET_THUMB_BYTES.len()).any(
                    |w| w == SECRET_THUMB_BYTES
                ),
                "raw thumbnail bytes leaked into the email body"
            );
            let hex_thumb: String = SECRET_THUMB_BYTES
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert!(
                !rendered.body.to_lowercase().contains(&hex_thumb),
                "thumbnail bytes leaked into the email body as hex"
            );

            // The body acknowledges the thumbnail exists but is not attached.
            assert!(rendered.body.contains("not attached to this email"));
            // And states the no-media guarantee.
            assert!(rendered
                .body
                .to_lowercase()
                .contains("no images, video, audio"));
        }
    }

    #[test]
    fn assert_no_media_rejects_data_uri_in_context() {
        let mut event = intervention_event();
        event.redacted_context =
            "see this data:image/jpeg;base64,/9j/4AAQSkZJRg==".to_string();
        let err = assert_no_media(&event).unwrap_err();
        assert!(matches!(err, AlertError::UnsafeContent(_)));
        // And the full render path also refuses.
        assert!(render_event(&event, "[Aegis]").is_err());
    }

    #[test]
    fn assert_no_media_rejects_binary_snippet() {
        let mut event = intervention_event();
        let mut ev = event.evidence.take().unwrap();
        // A "snippet" that is actually raw bytes (lots of control chars + NUL).
        ev.text_snippet = String::from_utf8_lossy(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8]).to_string();
        event.evidence = Some(ev);
        assert!(matches!(
            assert_no_media(&event),
            Err(AlertError::UnsafeContent(_))
        ));
    }

    #[test]
    fn assert_no_media_rejects_oversized_hash() {
        let mut event = intervention_event();
        let mut ev = event.evidence.take().unwrap();
        ev.sha256 = vec![0u8; 200]; // way bigger than any real hash
        event.evidence = Some(ev);
        assert!(matches!(
            assert_no_media(&event),
            Err(AlertError::UnsafeContent(_))
        ));
    }

    #[test]
    fn digest_render_is_redacted_and_lists_all() {
        let events = vec![intervention_event(), grooming_event()];
        let rendered = render_digest(&events, "[Aegis]").unwrap();
        assert!(rendered.subject.contains("2 alert(s)"));
        assert!(rendered.body.contains("Aegis blocked something"));
        assert!(rendered.body.contains("Possible grooming detected"));
        // No thumbnail bytes in the digest either.
        assert!(!rendered
            .body
            .as_bytes()
            .windows(SECRET_THUMB_BYTES.len())
            .any(|w| w == SECRET_THUMB_BYTES));
    }

    // ---- rate-limit / dedupe / digest ------------------------------------

    #[tokio::test]
    async fn dedupes_same_alert_id() {
        let transport = CapturingTransport::default();
        let sink =
            EmailAlertSink::with_transport(test_config(), Arc::new(transport.clone()));

        let t0 = Instant::now();
        let ack1 = sink.raise_at(intervention_event(), t0).await.unwrap();
        assert!(ack1.delivered && !ack1.deduped);

        // Same alert_id again within the window → deduped, not re-sent.
        let ack2 = sink.raise_at(intervention_event(), t0).await.unwrap();
        assert!(!ack2.delivered && ack2.deduped);

        assert_eq!(transport.sent().len(), 1, "duplicate must not be re-sent");
    }

    #[tokio::test]
    async fn coalesces_burst_into_digest() {
        let transport = CapturingTransport::default();
        let sink =
            EmailAlertSink::with_transport(test_config(), Arc::new(transport.clone()));

        let t0 = Instant::now();
        // Config allows 2 immediate sends per burst window. Send 5 distinct ids.
        for i in 0..5 {
            let mut e = intervention_event();
            e.alert_id = format!("burst-{i}");
            let ack = sink.raise_at(e, t0).await.unwrap();
            if i < 2 {
                assert!(ack.delivered, "first {i} should send immediately");
            } else {
                assert!(ack.deduped, "overflow should coalesce (deduped flag set)");
            }
        }

        // 2 immediate emails so far; 3 buffered for the digest.
        assert_eq!(transport.sent().len(), 2);

        let digest = sink.flush_digest_at(t0).await.unwrap();
        let acks = digest.expect("a digest should have been flushed");
        assert_eq!(acks.acks.len(), 3, "3 coalesced events in the digest");

        let sent = transport.sent();
        assert_eq!(sent.len(), 3, "2 immediate + 1 digest email");
        // The last email is the digest roll-up.
        assert!(sent.last().unwrap().email.subject.contains("digest"));
    }

    #[tokio::test]
    async fn raise_batch_sends_single_digest() {
        let transport = CapturingTransport::default();
        let sink =
            EmailAlertSink::with_transport(test_config(), Arc::new(transport.clone()));

        let mut events = Vec::new();
        for i in 0..4 {
            let mut e = grooming_event();
            e.alert_id = format!("batch-{i}");
            events.push(e);
        }
        let acks = sink
            .raise_batch(AlertBatch { events })
            .await
            .unwrap();
        assert_eq!(acks.acks.len(), 4);
        // One digest email for the whole batch.
        assert_eq!(transport.sent().len(), 1);
        assert!(transport.sent()[0].email.subject.contains("digest"));
    }

    // ---- config / secrets -------------------------------------------------

    #[test]
    fn config_rejects_plaintext_to_remote_host() {
        let mut smtp = SmtpConfig::new("smtp.example.com", 25);
        smtp.tls = TlsMode::None;
        assert!(matches!(smtp.validate(), Err(AlertError::Config(_))));
    }

    #[test]
    fn config_rejects_no_recipients() {
        let mut cfg = test_config();
        cfg.recipients.clear();
        assert!(matches!(cfg.validate(), Err(AlertError::Config(_))));
    }

    #[test]
    fn smtp_auth_debug_is_redacted() {
        let auth = SmtpAuth::new("user@example.com", "super-secret-password");
        let shown = format!("{auth:?}");
        assert!(!shown.contains("super-secret-password"));
        assert!(shown.contains("<redacted>"));
    }
}
