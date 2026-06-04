//! Configuration for the alert sink.
//!
//! Everything the sink needs is captured in [`AlertConfig`]: the SMTP transport
//! settings, the guardian recipient list, and the rate-limit / digest knobs.
//!
//! **Secrets rule (data-handling.md §2, class C2):** SMTP credentials are
//! *never* hardcoded and *never* baked into a config file checked into source.
//! [`SmtpAuth`] holds them in memory only for the lifetime of the process, and
//! [`SmtpAuth::from_env`] reads them from the environment (which a deployment
//! wires from the OS keystore / secret manager). The `Debug` impl is redacted
//! so credentials never leak into logs or crash dumps.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{AlertError, Result};

/// Default environment variable holding the SMTP username.
pub const ENV_SMTP_USERNAME: &str = "AEGIS_SMTP_USERNAME";
/// Default environment variable holding the SMTP password / app-password.
pub const ENV_SMTP_PASSWORD: &str = "AEGIS_SMTP_PASSWORD";

/// How TLS is negotiated with the SMTP server.
///
/// The default and only recommended posture is [`TlsMode::Tls`] (implicit TLS,
/// usually port 465) or [`TlsMode::StartTls`] (explicit upgrade, usually port
/// 587), both backed by **rustls**. [`TlsMode::None`] exists only for talking
/// to a localhost relay in tests and is rejected for any non-loopback host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum TlsMode {
    /// Implicit TLS from connection start (SMTPS, typically port 465).
    #[default]
    Tls,
    /// Plaintext connection upgraded with STARTTLS (typically port 587).
    StartTls,
    /// No transport security. Loopback-only; rejected otherwise.
    None,
}

/// SMTP credentials. Held in memory only; sourced from the environment / OS
/// keystore, never from a committed config file.
#[derive(Clone, Serialize, Deserialize)]
pub struct SmtpAuth {
    pub username: String,
    pub password: String,
}

impl SmtpAuth {
    /// Construct credentials explicitly (e.g. a deployment that already pulled
    /// them from the OS keystore / secret manager).
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Read credentials from the standard Aegis environment variables.
    /// Returns `None` if either variable is unset/empty (an unauthenticated
    /// relay, valid for a localhost test mailcatcher).
    pub fn from_env() -> Option<Self> {
        Self::from_env_named(ENV_SMTP_USERNAME, ENV_SMTP_PASSWORD)
    }

    /// Read credentials from caller-named environment variables.
    pub fn from_env_named(user_var: &str, pass_var: &str) -> Option<Self> {
        let username = std::env::var(user_var).ok().filter(|s| !s.is_empty())?;
        let password = std::env::var(pass_var).ok().filter(|s| !s.is_empty())?;
        Some(Self::new(username, password))
    }
}

// Redacted Debug so credentials never reach logs / crash dumps (data-handling C2).
impl std::fmt::Debug for SmtpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpAuth")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

/// SMTP transport configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// SMTP server hostname (the *only* permitted outbound endpoint for this
    /// crate — see data-handling.md "no telemetry / backhaul").
    pub host: String,
    /// SMTP port. Conventionally 465 (implicit TLS) or 587 (STARTTLS).
    pub port: u16,
    /// TLS negotiation mode.
    #[serde(default)]
    pub tls: TlsMode,
    /// Credentials. Skipped during (de)serialization so they are never written
    /// to a config file; populate via [`SmtpConfig::with_auth`] /
    /// [`SmtpAuth::from_env`] at startup instead.
    #[serde(skip)]
    pub auth: Option<SmtpAuth>,
}

impl SmtpConfig {
    /// A minimal config for `host:port` with TLS, no auth yet.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            tls: TlsMode::Tls,
            auth: None,
        }
    }

    /// Attach credentials resolved at runtime (env / keystore).
    pub fn with_auth(mut self, auth: SmtpAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    fn is_loopback(&self) -> bool {
        let h = self.host.to_ascii_lowercase();
        h == "localhost" || h == "127.0.0.1" || h == "::1"
    }

    /// Validate the transport settings. Plaintext is allowed only to loopback.
    pub fn validate(&self) -> Result<()> {
        if self.host.trim().is_empty() {
            return Err(AlertError::Config("SMTP host is empty".into()));
        }
        if self.tls == TlsMode::None && !self.is_loopback() {
            return Err(AlertError::Config(format!(
                "refusing plaintext SMTP to non-loopback host {:?}; \
                 use TlsMode::Tls or StartTls",
                self.host
            )));
        }
        Ok(())
    }
}

/// Rate-limit + digest thresholds. All tunable; sensible defaults provided.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// How long an `alert_id` is remembered for dedupe. A repeat of the same id
    /// inside this window is suppressed (`deduped = true`).
    #[serde(with = "humanish_secs", default = "RateLimitConfig::default_dedupe")]
    pub dedupe_window: Duration,

    /// Burst window for coalescing. Single `raise` calls that arrive faster than
    /// [`Self::max_immediate_per_window`] are buffered and rolled up into a
    /// digest instead of sending one email each.
    #[serde(with = "humanish_secs", default = "RateLimitConfig::default_burst")]
    pub burst_window: Duration,

    /// How many individual alerts may be sent immediately within a burst window
    /// before the rest are coalesced into a digest.
    #[serde(default = "RateLimitConfig::default_max_immediate")]
    pub max_immediate_per_window: u32,

    /// Maximum number of events folded into a single digest email.
    #[serde(default = "RateLimitConfig::default_digest_max")]
    pub digest_max_events: usize,
}

impl RateLimitConfig {
    fn default_dedupe() -> Duration {
        Duration::from_secs(300)
    }
    fn default_burst() -> Duration {
        Duration::from_secs(60)
    }
    fn default_max_immediate() -> u32 {
        3
    }
    fn default_digest_max() -> usize {
        50
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            dedupe_window: Self::default_dedupe(),
            burst_window: Self::default_burst(),
            max_immediate_per_window: Self::default_max_immediate(),
            digest_max_events: Self::default_digest_max(),
        }
    }
}

/// Top-level alert sink configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertConfig {
    /// SMTP transport settings + (runtime-injected) credentials.
    pub smtp: SmtpConfig,
    /// `From:` address shown to the guardian (e.g. "Aegis <aegis@home.example>").
    pub from: String,
    /// Guardian recipient address(es). At least one is required.
    pub recipients: Vec<String>,
    /// Optional subject prefix, e.g. "[Aegis]".
    #[serde(default = "AlertConfig::default_subject_prefix")]
    pub subject_prefix: String,
    /// Rate-limit / digest behaviour.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

impl AlertConfig {
    fn default_subject_prefix() -> String {
        "[Aegis]".to_string()
    }

    /// Validate the whole configuration up front so a misconfiguration fails at
    /// startup rather than when the first alert fires.
    pub fn validate(&self) -> Result<()> {
        self.smtp.validate()?;
        if self.from.trim().is_empty() {
            return Err(AlertError::Config("`from` address is empty".into()));
        }
        if self.recipients.iter().all(|r| r.trim().is_empty()) {
            return Err(AlertError::Config(
                "no guardian recipients configured".into(),
            ));
        }
        Ok(())
    }
}

/// Serde helper: represent a `Duration` as whole seconds in config files
/// (`figment`-friendly) while keeping the typed `Duration` in code.
mod humanish_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}
