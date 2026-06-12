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
pub const ENV_SMTP_USERNAME: &str = "BULWARK_SMTP_USERNAME";
/// Default environment variable holding the SMTP password / app-password.
pub const ENV_SMTP_PASSWORD: &str = "BULWARK_SMTP_PASSWORD";
/// SMTP host — presence of this is the on-switch for the email alert sink.
pub const ENV_SMTP_HOST: &str = "BULWARK_SMTP_HOST";
/// SMTP port (optional; defaults by TLS mode).
pub const ENV_SMTP_PORT: &str = "BULWARK_SMTP_PORT";
/// TLS mode: `tls` | `starttls` | `none` (optional; default `tls`).
pub const ENV_SMTP_TLS: &str = "BULWARK_SMTP_TLS";
/// `From:` address shown to the guardian.
pub const ENV_ALERT_FROM: &str = "BULWARK_ALERT_FROM";
/// Comma-separated guardian recipient address(es).
pub const ENV_ALERT_RECIPIENTS: &str = "BULWARK_ALERT_RECIPIENTS";
/// Optional subject prefix (default `[Bulwark]`).
pub const ENV_ALERT_SUBJECT_PREFIX: &str = "BULWARK_ALERT_SUBJECT_PREFIX";

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

    /// Read credentials from the standard Bulwark environment variables.
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
    /// `From:` address shown to the guardian (e.g. "Bulwark <bulwark@home.example>").
    pub from: String,
    /// Guardian recipient address(es). At least one is required.
    pub recipients: Vec<String>,
    /// Optional subject prefix, e.g. "[Bulwark]".
    #[serde(default = "AlertConfig::default_subject_prefix")]
    pub subject_prefix: String,
    /// Rate-limit / digest behaviour.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

impl AlertConfig {
    fn default_subject_prefix() -> String {
        "[PH Bulwark]".to_string()
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

    /// Build an [`AlertConfig`] from the environment, or `None` when the email
    /// sink is not configured. Returns `Err` only when partially/invalidly set, so
    /// a misconfiguration fails at startup rather than on the first alert.
    ///
    /// On-switch: `BULWARK_SMTP_HOST` + `BULWARK_ALERT_FROM` + `BULWARK_ALERT_RECIPIENTS`
    /// must ALL be present (or none of them). Optional: `BULWARK_SMTP_PORT`,
    /// `BULWARK_SMTP_TLS` (`tls`|`starttls`|`none`), `BULWARK_SMTP_USERNAME` /
    /// `BULWARK_SMTP_PASSWORD` (auth), `BULWARK_ALERT_SUBJECT_PREFIX`.
    pub fn from_env() -> Result<Option<Self>> {
        let var = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
        // Key the alert-email switch on the ALERT-specific vars, NOT on
        // BULWARK_SMTP_HOST: that host is shared with the password-reset mailer
        // (`reset_mailer` reuses it), so SMTP_HOST being set for reset must not
        // force the guardian-alert sink on. The alert sink turns on only when
        // BOTH a from-address and recipients are configured; SMTP_HOST is then
        // required as the transport.
        match (var(ENV_ALERT_FROM), var(ENV_ALERT_RECIPIENTS)) {
            (None, None) => Ok(None), // alert sink off (SMTP_HOST may still back reset email)
            (Some(from), Some(recipients_raw)) => {
                let host = var(ENV_SMTP_HOST).ok_or_else(|| {
                    AlertError::Config(format!(
                        "guardian-alert email needs {ENV_SMTP_HOST} when \
                         {ENV_ALERT_FROM} + {ENV_ALERT_RECIPIENTS} are set"
                    ))
                })?;
                let recipients: Vec<String> = recipients_raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                let tls = match var(ENV_SMTP_TLS).as_deref() {
                    Some("starttls") => TlsMode::StartTls,
                    Some("none") => TlsMode::None,
                    None | Some("tls") => TlsMode::Tls,
                    Some(other) => {
                        return Err(AlertError::Config(format!(
                            "{ENV_SMTP_TLS}={other:?} (want tls|starttls|none)"
                        )))
                    }
                };
                let default_port = if tls == TlsMode::StartTls { 587 } else { 465 };
                let port = match var(ENV_SMTP_PORT) {
                    Some(p) => p
                        .parse::<u16>()
                        .map_err(|e| AlertError::Config(format!("{ENV_SMTP_PORT}={p:?}: {e}")))?,
                    None => default_port,
                };

                let mut smtp = SmtpConfig::new(host, port);
                smtp.tls = tls;
                if let Some(auth) = SmtpAuth::from_env() {
                    smtp = smtp.with_auth(auth);
                }

                let cfg = Self {
                    smtp,
                    from,
                    recipients,
                    subject_prefix: var(ENV_ALERT_SUBJECT_PREFIX)
                        .unwrap_or_else(Self::default_subject_prefix),
                    rate_limit: RateLimitConfig::default(),
                };
                cfg.validate()?;
                Ok(Some(cfg))
            }
            _ => Err(AlertError::Config(format!(
                "incomplete email-alert config: set BOTH {ENV_ALERT_FROM} and \
                 {ENV_ALERT_RECIPIENTS} (or neither). {ENV_SMTP_HOST} alone is \
                 fine — it backs the password-reset mailer."
            ))),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // These env vars are unique to the email-sink config; only this test mutates
    // them. All cases run in one test (std::env is process-global) to avoid races.
    #[test]
    fn from_env_off_on_and_invalid() {
        let all = [
            ENV_SMTP_HOST,
            ENV_ALERT_FROM,
            ENV_ALERT_RECIPIENTS,
            ENV_SMTP_PORT,
            ENV_SMTP_TLS,
            ENV_ALERT_SUBJECT_PREFIX,
        ];
        for k in all {
            std::env::remove_var(k);
        }

        // Unset → sink off.
        assert!(matches!(AlertConfig::from_env(), Ok(None)));

        // SMTP_HOST alone (set for the password-reset mailer) must NOT turn the
        // guardian-alert sink on or error — the alert switch keys on ALERT_FROM
        // + ALERT_RECIPIENTS, not the shared SMTP host. (Regression: a prod
        // deploy that set SMTP_HOST for reset email crash-looped on this.)
        std::env::set_var(ENV_SMTP_HOST, "smtp.example.com");
        assert!(
            matches!(AlertConfig::from_env(), Ok(None)),
            "SMTP_HOST without ALERT_FROM/RECIPIENTS = reset-only, alert sink off"
        );
        std::env::remove_var(ENV_SMTP_HOST);

        // Full trio → Some, with parsed recipients + default TLS/port.
        std::env::set_var(ENV_SMTP_HOST, "smtp.example.com");
        std::env::set_var(ENV_ALERT_FROM, "Bulwark <bulwark@home.example>");
        std::env::set_var(ENV_ALERT_RECIPIENTS, "a@home.example, b@home.example");
        let cfg = AlertConfig::from_env().expect("ok").expect("configured");
        assert_eq!(cfg.smtp.host, "smtp.example.com");
        assert_eq!(cfg.recipients, vec!["a@home.example", "b@home.example"]);
        assert_eq!(cfg.smtp.tls, TlsMode::Tls);
        assert_eq!(cfg.smtp.port, 465);

        // starttls → default port 587.
        std::env::set_var(ENV_SMTP_TLS, "starttls");
        assert_eq!(AlertConfig::from_env().unwrap().unwrap().smtp.port, 587);
        std::env::remove_var(ENV_SMTP_TLS);

        // Partial config (host+from but no recipients) → hard error at startup.
        std::env::remove_var(ENV_ALERT_RECIPIENTS);
        assert!(AlertConfig::from_env().is_err());

        for k in all {
            std::env::remove_var(k);
        }
    }
}
