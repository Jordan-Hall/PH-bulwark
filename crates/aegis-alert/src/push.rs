//! Firebase Cloud Messaging (FCM HTTP v1) push alert sink.
//!
//! This module is compiled **only** with the non-default `push` cargo feature.
//! It adds a second [`AlertSink`](crate::AlertSink) backend, [`FcmPushSink`],
//! so the parent phone app receives a real-time push *in addition to* the
//! existing email path — without changing the default (email-only) build.
//!
//! ## Hard privacy invariant (data-handling.md §1–2, class C0)
//!
//! Exactly like the email renderer, this sink NEVER transmits raw media,
//! thumbnails, or message bodies. It sends an FCM **data** message carrying
//! ONLY redacted scalar fields:
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
//! ## OAuth2 (service-account, no hardcoded secrets)
//!
//! FCM HTTP v1 requires a short-lived OAuth2 access token. We mint one by
//! signing a service-account JWT (RS256, scope
//! `https://www.googleapis.com/auth/firebase.messaging`) with `jsonwebtoken`
//! and exchanging it at Google's token endpoint over `reqwest` (rustls TLS).
//! The token is cached until ~60s before expiry. The service-account
//! credentials (`project_id`, `client_email`, `private_key`) are loaded from a
//! JSON file whose path comes from config — they are never hardcoded and never
//! serialized back out.
//!
//! ## Best-effort delivery
//!
//! Every failure path returns an [`AlertError`] (it never panics). Whether a
//! caller treats a push failure as fatal or log-and-continue is the caller's
//! choice; the email path remains the system of record.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use aegis_proto::v1::{
    AlertAck, AlertAckBatch, AlertBatch, AlertEvent, AlertKind, Category, Severity,
};

use crate::error::{AlertError, Result};
use crate::render::assert_no_media;
use crate::AlertSink;

/// Google's OAuth2 token endpoint (service-account JWT-bearer flow).
const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// The single scope FCM HTTP v1 send requires.
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// JWT-bearer grant type for the service-account flow.
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Refresh the cached token this many seconds *before* it actually expires, so
/// we never send a request with an about-to-die token.
const TOKEN_SKEW_SECS: u64 = 60;
/// Service-account JWTs are valid for one hour (Google's maximum).
const JWT_TTL_SECS: u64 = 3600;

/// FCM project id — presence of BOTH this and the SA path is the push on-switch.
pub const ENV_FCM_PROJECT_ID: &str = "AEGIS_FCM_PROJECT_ID";
/// Path to the Google service-account JSON key file.
pub const ENV_FCM_SERVICE_ACCOUNT: &str = "AEGIS_FCM_SERVICE_ACCOUNT";

/// Configuration for the FCM push sink.
///
/// `project_id` is the FCM/GCP project the messages are sent to. The
/// service-account JSON at `service_account_path` supplies the signing key and
/// the issuer (`client_email`); secrets are read from that file at runtime and
/// never committed to a config file (`service_account` is `serde(skip)`-loaded
/// lazily).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FcmConfig {
    /// FCM / GCP project id (the `{project_id}` in the send URL).
    pub project_id: String,
    /// Filesystem path to the service-account JSON key file. The path may be
    /// committed; the *contents* (private key) are a secret loaded at runtime.
    pub service_account_path: PathBuf,
}

impl FcmConfig {
    /// Validate that the required fields are present and the key file exists.
    pub fn validate(&self) -> Result<()> {
        if self.project_id.trim().is_empty() {
            return Err(AlertError::Config("FCM project_id is empty".into()));
        }
        if self.service_account_path.as_os_str().is_empty() {
            return Err(AlertError::Config(
                "FCM service_account_path is empty".into(),
            ));
        }
        if !self.service_account_path.exists() {
            return Err(AlertError::Config(format!(
                "FCM service account file not found: {}",
                self.service_account_path.display()
            )));
        }
        Ok(())
    }

    /// Build an [`FcmConfig`] from the environment, or `None` when push is not
    /// configured. `Err` only on a partial/invalid config — same fail-at-startup
    /// contract as `AlertConfig::from_env`. On-switch: BOTH
    /// `AEGIS_FCM_PROJECT_ID` and `AEGIS_FCM_SERVICE_ACCOUNT` set (or neither);
    /// the SA file's existence is checked by [`FcmConfig::validate`].
    pub fn from_env() -> Result<Option<Self>> {
        let var = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
        match (var(ENV_FCM_PROJECT_ID), var(ENV_FCM_SERVICE_ACCOUNT)) {
            (None, None) => Ok(None),
            (Some(project_id), Some(path)) => {
                let cfg = Self {
                    project_id,
                    service_account_path: PathBuf::from(path),
                };
                cfg.validate()?;
                Ok(Some(cfg))
            }
            _ => Err(AlertError::Config(format!(
                "incomplete FCM config: set BOTH {ENV_FCM_PROJECT_ID} and \
                 {ENV_FCM_SERVICE_ACCOUNT} or neither"
            ))),
        }
    }
}

/// The subset of a Google service-account JSON key we need to sign a JWT.
///
/// `private_key` is a PEM RSA key — a secret. The redacted `Debug` impl keeps it
/// out of logs / crash dumps (data-handling.md class C2).
#[derive(Clone, Deserialize)]
pub struct ServiceAccount {
    pub project_id: String,
    pub client_email: String,
    pub private_key: String,
    /// Optional override for the token endpoint (real key files include it;
    /// we fall back to the well-known [`TOKEN_URI`] when absent).
    #[serde(default)]
    pub token_uri: Option<String>,
}

impl ServiceAccount {
    /// Load and parse a service-account JSON key from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| {
            AlertError::Config(format!(
                "reading FCM service account {}: {e}",
                path.display()
            ))
        })?;
        let sa: ServiceAccount = serde_json::from_slice(&bytes).map_err(|e| {
            AlertError::Config(format!(
                "parsing FCM service account {}: {e}",
                path.display()
            ))
        })?;
        if sa.client_email.trim().is_empty() || sa.private_key.trim().is_empty() {
            return Err(AlertError::Config(
                "FCM service account missing client_email/private_key".into(),
            ));
        }
        Ok(sa)
    }

    fn token_uri(&self) -> &str {
        self.token_uri.as_deref().unwrap_or(TOKEN_URI)
    }
}

// Redacted Debug: never let the PEM private key reach logs (data-handling C2).
impl std::fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("project_id", &self.project_id)
            .field("client_email", &self.client_email)
            .field("private_key", &"<redacted>")
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

/// JWT claims for the service-account JWT-bearer assertion.
#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

/// The token endpoint's success response.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// A cached OAuth2 access token plus the unix-second instant it should be
/// considered expired (already including the refresh skew).
#[derive(Clone)]
struct CachedToken {
    access_token: String,
    /// Unix seconds after which the token must be re-minted.
    refresh_at: u64,
}

/// Transport seam: send ONE redacted FCM data payload to ONE registration token.
/// Mirrors the email path's `MailTransport` — the OAuth2 + HTTP concern lives
/// behind this trait so the sinks can be unit-tested with a capturing mock (no
/// Google credentials, no network).
#[async_trait]
pub trait PushTransport: Send + Sync {
    /// Send the already-redacted `data` map to `token`. The `data` is the output
    /// of the no-media redactor — the transport MUST NOT add media.
    async fn send(&self, token: &str, data: &serde_json::Value) -> Result<()>;
}

/// Production [`PushTransport`]: mints/caches the OAuth2 service-account token and
/// POSTs a data-only message to FCM HTTP v1.
pub struct FcmHttpTransport {
    service_account: ServiceAccount,
    http: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
    /// Send endpoint, derived once from `project_id`.
    send_url: String,
}

impl FcmHttpTransport {
    /// Build the transport for `cfg`: validates config + loads the SA key up front
    /// so a misconfiguration fails at construction, not on first alert.
    pub fn new(cfg: &FcmConfig) -> Result<Self> {
        cfg.validate()?;
        let service_account = ServiceAccount::load(&cfg.service_account_path)?;
        let http = reqwest::Client::builder()
            .https_only(true)
            .build()
            .map_err(|e| AlertError::Push(format!("building HTTP client: {e}")))?;
        let send_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            cfg.project_id
        );
        Ok(Self {
            service_account,
            http,
            token: Mutex::new(None),
            send_url,
        })
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }

    /// Return a valid bearer token, minting + caching a fresh one if the cache
    /// is empty or within [`TOKEN_SKEW_SECS`] of expiry.
    async fn access_token(&self) -> Result<String> {
        let now = Self::now_unix();
        {
            let guard = self.token.lock().await;
            if let Some(tok) = guard.as_ref() {
                if now < tok.refresh_at {
                    return Ok(tok.access_token.clone());
                }
            }
        }
        let minted = self.mint_token(now).await?;
        let mut guard = self.token.lock().await;
        *guard = Some(minted.clone());
        Ok(minted.access_token)
    }

    /// Sign a service-account JWT and exchange it for an OAuth2 access token.
    async fn mint_token(&self, now: u64) -> Result<CachedToken> {
        let claims = JwtClaims {
            iss: &self.service_account.client_email,
            scope: FCM_SCOPE,
            aud: self.service_account.token_uri(),
            iat: now,
            exp: now + JWT_TTL_SECS,
        };
        let key = EncodingKey::from_rsa_pem(self.service_account.private_key.as_bytes())
            .map_err(|e| AlertError::Push(format!("loading RS256 signing key: {e}")))?;
        let assertion = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key)
            .map_err(|e| AlertError::Push(format!("signing service-account JWT: {e}")))?;
        let resp = self
            .http
            .post(self.service_account.token_uri())
            .form(&[
                ("grant_type", JWT_BEARER_GRANT),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| AlertError::Push(format!("token request failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AlertError::Push(format!(
                "token endpoint returned {status}: {}",
                truncate(&body, 256)
            )));
        }
        let token: TokenResponse = resp
            .json()
            .await
            .map_err(|e| AlertError::Push(format!("decoding token response: {e}")))?;
        let refresh_at = now + token.expires_in.saturating_sub(TOKEN_SKEW_SECS);
        Ok(CachedToken {
            access_token: token.access_token,
            refresh_at,
        })
    }
}

#[async_trait]
impl PushTransport for FcmHttpTransport {
    async fn send(&self, token: &str, data: &serde_json::Value) -> Result<()> {
        let bearer = self.access_token().await?;
        // A data-only message (no `notification` block) so the phone app builds
        // the UI from redacted fields and we never put text in a system banner.
        let message = serde_json::json!({ "message": { "token": token, "data": data } });
        let resp = self
            .http
            .post(&self.send_url)
            .bearer_auth(&bearer)
            .json(&message)
            .send()
            .await
            .map_err(|e| AlertError::Push(format!("FCM send request failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AlertError::Push(format!(
                "FCM send returned {status}: {}",
                truncate(&body, 256)
            )));
        }
        Ok(())
    }
}

/// FCM HTTP v1 push [`AlertSink`] for a SINGLE guardian token.
///
/// Construct with [`FcmPushSink::new`]. Delegates the network/OAuth concern to a
/// [`PushTransport`]; [`FcmPushSink::with_transport`] injects a mock in tests.
pub struct FcmPushSink {
    cfg: FcmConfig,
    /// Where to send the redacted notification — the guardian device's rotating
    /// FCM registration token (proto `PushTarget.fcm_token`), supplied at
    /// construction so this crate stays free of any device registry.
    target_token: String,
    transport: Arc<dyn PushTransport>,
}

impl FcmPushSink {
    /// Build a sink for `cfg`, delivering to the guardian `target_token`. Builds
    /// the real FCM transport (validates config + loads the SA key up front).
    pub fn new(cfg: FcmConfig, target_token: impl Into<String>) -> Result<Self> {
        let target_token = target_token.into();
        if target_token.trim().is_empty() {
            return Err(AlertError::Config(
                "FCM target registration token is empty".into(),
            ));
        }
        let transport = Arc::new(FcmHttpTransport::new(&cfg)?);
        Ok(Self {
            cfg,
            target_token,
            transport,
        })
    }

    /// Test/seam constructor over any [`PushTransport`] (no Google creds, no
    /// network). Does not load a service-account key.
    pub fn with_transport(
        cfg: FcmConfig,
        target_token: impl Into<String>,
        transport: Arc<dyn PushTransport>,
    ) -> Self {
        Self {
            cfg,
            target_token: target_token.into(),
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

    /// Build the FCM **data** payload — redacted scalar fields ONLY. No media,
    /// no thumbnails, no message bodies, no evidence (not even hashes).
    fn redacted_data(event: &AlertEvent) -> serde_json::Value {
        let kind = AlertKind::try_from(event.kind).unwrap_or(AlertKind::Unspecified);
        let category = Category::try_from(event.category).unwrap_or(Category::Unspecified);
        let severity = Severity::try_from(event.severity).unwrap_or(Severity::Unspecified);

        // FCM `data` values MUST all be strings.
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

    /// Deliver one event as a redacted FCM data message. Runs the no-media guard
    /// first; on any failure returns an [`AlertError`] (never panics).
    async fn deliver_one(&self, event: &AlertEvent) -> Result<()> {
        // Belt-and-braces: the same hard invariant the email path enforces.
        assert_no_media(event)?;

        let data = Self::redacted_data(event);
        self.transport.send(&self.target_token, &data).await?;
        tracing::info!(
            alert_id = %event.alert_id,
            device_id = %event.device_id,
            "guardian alert pushed via FCM (redacted)"
        );
        Ok(())
    }
}

/// Source of the guardian FCM tokens to fan an alert out to, read AT RAISE TIME
/// (so a token registered after the sink was built still gets alerts). The
/// relay's `AlertHub` implements this over its in-memory `push_targets`.
pub trait TokenRegistry: Send + Sync {
    /// A snapshot of every registered guardian FCM token right now (may be empty).
    fn tokens(&self) -> Vec<String>;
}

/// An [`AlertSink`] that pushes the redacted event to EVERY currently-registered
/// guardian token (read from a [`TokenRegistry`] at raise time) — unlike
/// [`FcmPushSink`], which binds one token at construction. Best-effort: one
/// token's failure never aborts the others; an empty registry is a successful
/// no-op acked `delivered = false`.
pub struct FcmFanoutSink {
    transport: Arc<dyn PushTransport>,
    registry: Arc<dyn TokenRegistry>,
}

impl FcmFanoutSink {
    /// Build over the real FCM transport for `cfg`, reading tokens from `registry`.
    pub fn new(cfg: &FcmConfig, registry: Arc<dyn TokenRegistry>) -> Result<Self> {
        let transport = Arc::new(FcmHttpTransport::new(cfg)?);
        Ok(Self {
            transport,
            registry,
        })
    }

    /// Test/seam constructor over any transport + registry (no Google creds).
    pub fn with_transport(
        transport: Arc<dyn PushTransport>,
        registry: Arc<dyn TokenRegistry>,
    ) -> Self {
        Self {
            transport,
            registry,
        }
    }

    /// Fan one event out to every current token. Returns (delivered, attempted).
    async fn fan_one(&self, event: &AlertEvent) -> Result<(usize, usize)> {
        assert_no_media(event)?; // hard privacy invariant, before any send
        let tokens = self.registry.tokens();
        let attempted = tokens.len();
        if attempted == 0 {
            return Ok((0, 0));
        }
        let data = FcmPushSink::redacted_data(event);
        let mut delivered = 0usize;
        for token in &tokens {
            match self.transport.send(token, &data).await {
                Ok(()) => delivered += 1,
                Err(e) => tracing::warn!(alert_id = %event.alert_id, error = %e,
                    "FCM fan-out failed for one guardian token"),
            }
        }
        Ok((delivered, attempted))
    }
}

#[async_trait]
impl AlertSink for FcmFanoutSink {
    async fn raise(&self, event: AlertEvent) -> Result<AlertAck> {
        let (delivered, attempted) = self.fan_one(&event).await?;
        Ok(FcmPushSink::ack(
            &event.alert_id,
            delivered > 0,
            &format!("pushed to {delivered}/{attempted} guardian device(s)"),
        ))
    }

    async fn raise_batch(&self, batch: AlertBatch) -> Result<AlertAckBatch> {
        let mut acks = Vec::with_capacity(batch.events.len());
        for event in &batch.events {
            match self.fan_one(event).await {
                Ok((delivered, attempted)) => acks.push(FcmPushSink::ack(
                    &event.alert_id,
                    delivered > 0,
                    &format!("pushed to {delivered}/{attempted} guardian device(s)"),
                )),
                Err(e) => acks.push(FcmPushSink::ack(
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
impl AlertSink for FcmPushSink {
    async fn raise(&self, event: AlertEvent) -> Result<AlertAck> {
        self.deliver_one(&event).await?;
        Ok(Self::ack(&event.alert_id, true, "pushed via FCM"))
    }

    async fn raise_batch(&self, batch: AlertBatch) -> Result<AlertAckBatch> {
        // Push has no email-style digest; each event is a separate notification.
        // Best-effort: one event's failure must not abort the rest, so we record
        // a per-event ack rather than bailing on the first error.
        let mut acks = Vec::with_capacity(batch.events.len());
        for event in &batch.events {
            match self.deliver_one(event).await {
                Ok(()) => acks.push(Self::ack(&event.alert_id, true, "pushed via FCM")),
                Err(e) => {
                    tracing::warn!(
                        alert_id = %event.alert_id,
                        error = %e,
                        "FCM push failed for one event in batch"
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

// Keep `cfg` reachable for callers/inspection without an unused-field warning.
impl FcmPushSink {
    /// The configuration this sink was built with.
    pub fn config(&self) -> &FcmConfig {
        &self.cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::v1::{Category, Evidence, Severity};

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
        let data = FcmPushSink::redacted_data(&event);
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
        let data = FcmPushSink::redacted_data(&event);
        assert_eq!(
            data["category"],
            (Category::CsamSuspected as i32).to_string()
        );
        assert_eq!(data["redacted_context"], "Flagged content was blocked.");
        // And the no-media guard accepts this redacted event.
        assert_no_media(&event).unwrap();
    }

    #[test]
    fn fcm_config_validation() {
        let cfg = FcmConfig {
            project_id: String::new(),
            service_account_path: PathBuf::from("/nonexistent"),
        };
        assert!(matches!(cfg.validate(), Err(AlertError::Config(_))));
    }

    #[test]
    fn service_account_debug_redacts_private_key() {
        let sa = ServiceAccount {
            project_id: "proj".into(),
            client_email: "svc@proj.iam.gserviceaccount.com".into(),
            private_key: "-----BEGIN PRIVATE KEY-----SECRET-----END PRIVATE KEY-----".into(),
            token_uri: None,
        };
        let shown = format!("{sa:?}");
        assert!(!shown.contains("SECRET"));
        assert!(shown.contains("<redacted>"));
    }

    // --- Fan-out: mock transport + registry (no Google creds, no network) ------

    #[derive(Clone, Default)]
    struct CapturingPush {
        sent: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
        fail: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    }
    #[async_trait]
    impl PushTransport for CapturingPush {
        async fn send(&self, token: &str, data: &serde_json::Value) -> Result<()> {
            if self.fail.lock().unwrap().contains(token) {
                return Err(AlertError::Push(format!("forced fail for {token}")));
            }
            self.sent
                .lock()
                .unwrap()
                .push((token.to_string(), data.clone()));
            Ok(())
        }
    }

    struct StaticRegistry(Vec<String>);
    impl TokenRegistry for StaticRegistry {
        fn tokens(&self) -> Vec<String> {
            self.0.clone()
        }
    }

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
    async fn fanout_sends_to_every_registered_token() {
        let cap = CapturingPush::default();
        let reg = Arc::new(StaticRegistry(vec!["t1".into(), "t2".into(), "t3".into()]));
        let sink = FcmFanoutSink::with_transport(Arc::new(cap.clone()), reg);
        let ack = sink.raise(safe_event("a1")).await.unwrap();
        assert!(ack.delivered);
        assert_eq!(cap.sent.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn fanout_is_best_effort_one_failure_doesnt_abort() {
        let cap = CapturingPush::default();
        cap.fail.lock().unwrap().insert("t2".into());
        let reg = Arc::new(StaticRegistry(vec!["t1".into(), "t2".into(), "t3".into()]));
        let sink = FcmFanoutSink::with_transport(Arc::new(cap.clone()), reg);
        let ack = sink.raise(safe_event("a2")).await.unwrap();
        assert!(ack.delivered, "2/3 still delivered");
        assert_eq!(cap.sent.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn fanout_empty_registry_acks_not_delivered() {
        let cap = CapturingPush::default();
        let reg = Arc::new(StaticRegistry(vec![]));
        let sink = FcmFanoutSink::with_transport(Arc::new(cap.clone()), reg);
        let ack = sink.raise(safe_event("a3")).await.unwrap();
        assert!(!ack.delivered);
        assert!(cap.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn fanout_rejects_media_before_any_send() {
        let cap = CapturingPush::default();
        let reg = Arc::new(StaticRegistry(vec!["t1".into()]));
        let sink = FcmFanoutSink::with_transport(Arc::new(cap.clone()), reg);
        // An oversized "sha256" (raw bytes masquerading as a hash) trips
        // assert_no_media — the fan-out must reject it BEFORE contacting any token.
        let mut bad = safe_event("bad");
        bad.evidence = Some(Evidence {
            sha256: vec![0u8; 200],
            ..Default::default()
        });
        assert!(sink.raise(bad).await.is_err());
        assert!(cap.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn fcm_config_from_env_off_and_partial() {
        for v in [ENV_FCM_PROJECT_ID, ENV_FCM_SERVICE_ACCOUNT] {
            std::env::remove_var(v);
        }
        assert!(matches!(FcmConfig::from_env(), Ok(None)));
        std::env::set_var(ENV_FCM_PROJECT_ID, "proj"); // only one → partial → Err
        assert!(FcmConfig::from_env().is_err());
        std::env::remove_var(ENV_FCM_PROJECT_ID);
    }
}
