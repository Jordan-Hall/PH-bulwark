//! Content-free password-reset mailer for guardian accounts.
//!
//! This is the OPTIONAL email path that sits ALONGSIDE the saved recovery code.
//! When a deployment configures SMTP, a guardian who can't find their recovery
//! code can ask the server to email a short-lived reset code to their account
//! address (see [`crate::accounts`] `request_password_reset`). The email is the
//! ordinary "forgot password" message any family app sends: a subject + a plain
//! body carrying the reset code and how to use it — and nothing else.
//!
//! SAFETY: this mailer is **content-free**. It carries ONLY the reset code and
//! generic instructions — never any child data, never a message/media excerpt,
//! never even the account email in the body (the recipient already knows their
//! own address). The reset code is never logged. We reuse `bulwark-alert`'s
//! `MailTransport` seam (lettre + rustls), so the same async SMTP client and the
//! same mockable trait back both guardian alerts and account-protection email.

use std::sync::Arc;

use async_trait::async_trait;
use bulwark_alert::config::{SmtpAuth, SmtpConfig, TlsMode};
use bulwark_alert::render::RenderedEmail;
use bulwark_alert::transport::{MailTransport, OutgoingMail, SmtpTransport};

/// Standard environment variables that switch the email reset path ON. We reuse
/// `bulwark-alert`'s SMTP host/port/tls/credential variables so a deployment
/// configures one SMTP server for BOTH guardian alerts and account email.
/// `BULWARK_RESET_FROM` is the `From:` address for the reset message (falls back
/// to the alert `From:` so a single setting covers both).
pub const ENV_RESET_FROM: &str = "BULWARK_RESET_FROM";
/// Optional subject for the reset email (default below). Content-free.
pub const ENV_RESET_SUBJECT: &str = "BULWARK_RESET_SUBJECT";

const DEFAULT_RESET_SUBJECT: &str = "PH Bulwark — your password reset code";

/// A built mailer that can email a guardian their reset code. Cloneable so the
/// `AccountsService` can hold one cheaply; the transport is shared behind an `Arc`.
#[derive(Clone)]
pub struct ResetMailer {
    transport: Arc<dyn MailTransport>,
    from: String,
    subject: String,
}

impl ResetMailer {
    /// Build a mailer over an explicit transport (used by tests with a capturing
    /// transport so a unit/e2e test NEVER touches a real SMTP server).
    pub fn with_transport(
        transport: Arc<dyn MailTransport>,
        from: impl Into<String>,
        subject: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            from: from.into(),
            subject: subject.into(),
        }
    }

    /// Build a mailer from the environment, or `None` when SMTP is not configured.
    ///
    /// On-switch: `BULWARK_SMTP_HOST` must be set (the same host that backs guardian
    /// alerts). The `From:` address is `BULWARK_RESET_FROM`, falling back to
    /// `BULWARK_ALERT_FROM` so one setting covers both. TLS mode + port + optional
    /// credentials reuse the alert SMTP variables. Returns `None` (the recovery-code
    /// path stays the only self-service reset) when no SMTP host is configured.
    pub fn from_env() -> Option<Self> {
        let var = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());

        let host = var(bulwark_alert::config::ENV_SMTP_HOST)?;
        // Reuse the alert From: when a dedicated reset From: isn't set.
        let from = var(ENV_RESET_FROM).or_else(|| var(bulwark_alert::config::ENV_ALERT_FROM))?;

        let tls = match var(bulwark_alert::config::ENV_SMTP_TLS).as_deref() {
            Some("starttls") => TlsMode::StartTls,
            Some("none") => TlsMode::None,
            // Default to implicit TLS — anything unrecognized is treated as the
            // safe default rather than failing the whole account path.
            _ => TlsMode::Tls,
        };
        let default_port = if tls == TlsMode::StartTls { 587 } else { 465 };
        let port = var(bulwark_alert::config::ENV_SMTP_PORT)
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);

        let mut smtp = SmtpConfig::new(host, port);
        smtp.tls = tls;
        if let Some(auth) = SmtpAuth::from_env() {
            smtp = smtp.with_auth(auth);
        }

        let transport = match SmtpTransport::new(&smtp) {
            Ok(t) => Arc::new(t) as Arc<dyn MailTransport>,
            Err(e) => {
                // A misconfigured reset SMTP must not take the whole account service
                // down — log and fall back to the recovery-code-only path.
                tracing::warn!(error = %e, "email password-reset disabled: SMTP transport unavailable");
                return None;
            }
        };

        let subject = var(ENV_RESET_SUBJECT).unwrap_or_else(|| DEFAULT_RESET_SUBJECT.to_string());
        Some(Self::with_transport(transport, from, subject))
    }

    /// Email `code` to `recipient`. Content-free: subject + plain body with the
    /// code and how to use it, nothing else. The code is NEVER logged.
    pub async fn send_reset_code(
        &self,
        recipient: &str,
        code: &str,
        ttl_minutes: i64,
    ) -> Result<(), String> {
        let mail = OutgoingMail {
            from: self.from.clone(),
            to: vec![recipient.to_string()],
            email: RenderedEmail {
                subject: self.subject.clone(),
                body: reset_body(code, ttl_minutes),
            },
        };
        self.transport
            .send(mail)
            .await
            .map_err(|e| format!("reset email send failed: {e}"))
    }
}

/// The plain-text reset email body. Content-free guardian-account guidance only —
/// the reset code, its lifetime, and a single-use note. No child data, no excerpts.
fn reset_body(code: &str, ttl_minutes: i64) -> String {
    format!(
        "Someone asked to reset the password for your PH Bulwark guardian account.\n\
         \n\
         Your reset code is:\n\
         \n\
         {code}\n\
         \n\
         Enter this code in the app to set a new password. It is valid for about \
         {ttl_minutes} minutes and can be used only once.\n\
         \n\
         If you didn't ask for this, you can ignore this email — your password \
         will not change and your account stays protected.\n"
    )
}

/// A mailer that drops the message (used when SMTP is not configured but the call
/// site still wants a non-optional handle). Never sends anything.
#[derive(Clone, Default)]
pub struct NullResetMailer;

#[async_trait]
impl MailTransport for NullResetMailer {
    async fn send(&self, _mail: OutgoingMail) -> bulwark_alert::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Captures sent mail instead of touching the network — the mockable seam.
    #[derive(Clone, Default)]
    struct CapturingTransport {
        sent: Arc<StdMutex<Vec<OutgoingMail>>>,
    }

    #[async_trait]
    impl MailTransport for CapturingTransport {
        async fn send(&self, mail: OutgoingMail) -> bulwark_alert::Result<()> {
            self.sent.lock().unwrap().push(mail);
            Ok(())
        }
    }

    #[tokio::test]
    async fn body_carries_the_code_and_is_content_free() {
        let cap = CapturingTransport::default();
        let mailer = ResetMailer::with_transport(
            Arc::new(cap.clone()),
            "PH Bulwark <noreply@home.example>",
            "reset",
        );
        mailer
            .send_reset_code("guardian@example.com", "ABCD-1234", 30)
            .await
            .unwrap();

        let sent = cap.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let m = &sent[0];
        assert_eq!(m.to, vec!["guardian@example.com".to_string()]);
        // The reset code IS in the body (the recipient needs it)…
        assert!(m.email.body.contains("ABCD-1234"));
        assert!(m.email.body.contains("30 minutes"));
        // …but the account email is NOT echoed into the body, and there is no
        // child/content data — only generic account-protection guidance.
        assert!(!m.email.body.contains("guardian@example.com"));
        assert!(m.email.body.to_lowercase().contains("reset"));
    }
}
