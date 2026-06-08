//! Mail transport abstraction.
//!
//! [`MailTransport`] is the seam that lets the alert sink send a rendered email
//! without caring *how* it leaves the box. Today there is one implementation,
//! [`SmtpTransport`], built on **lettre**'s async (`tokio1`) SMTP client with
//! **rustls** TLS. A Gmail-API transport can be added later as a second
//! implementation of this same trait — the sink ([`crate::EmailAlertSink`])
//! depends only on the trait, so no sink code changes when that lands.
//!
//! Network policy: the *only* outbound connection this crate makes is to the
//! configured SMTP server (data-handling.md "no telemetry / vendor backhaul").

use async_trait::async_trait;
use lettre::address::Address;
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};

use crate::config::{SmtpConfig, TlsMode};
use crate::error::{AlertError, Result};
use crate::render::RenderedEmail;

/// A destination + the rendered content to deliver to it.
#[derive(Clone, Debug)]
pub struct OutgoingMail {
    pub from: String,
    pub to: Vec<String>,
    pub email: RenderedEmail,
}

/// How a rendered alert email actually leaves the machine.
///
/// Implement this trait to add a new delivery backend (e.g. a Gmail-API
/// transport). The sink only ever calls [`MailTransport::send`].
#[async_trait]
pub trait MailTransport: Send + Sync {
    async fn send(&self, mail: OutgoingMail) -> Result<()>;
}

/// lettre-backed async SMTP transport (rustls TLS).
pub struct SmtpTransport {
    inner: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpTransport {
    /// Build a transport from [`SmtpConfig`]. Validates the config (TLS posture,
    /// host) before constructing the lettre client.
    pub fn new(cfg: &SmtpConfig) -> Result<Self> {
        cfg.validate()?;

        let builder = match cfg.tls {
            TlsMode::Tls => {
                // Implicit TLS (SMTPS) — wrapper from connection start.
                let params = TlsParameters::new(cfg.host.clone())
                    .map_err(|e| AlertError::Transport(format!("TLS params: {e}")))?;
                AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
                    .map_err(|e| AlertError::Transport(format!("SMTP relay: {e}")))?
                    .tls(Tls::Wrapper(params))
            }
            TlsMode::StartTls => {
                let params = TlsParameters::new(cfg.host.clone())
                    .map_err(|e| AlertError::Transport(format!("TLS params: {e}")))?;
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
                    .map_err(|e| AlertError::Transport(format!("SMTP starttls: {e}")))?
                    .tls(Tls::Required(params))
            }
            TlsMode::None => {
                // Loopback-only (already enforced by cfg.validate()). For a
                // local test mailcatcher with no TLS.
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host)
            }
        };

        let builder = builder.port(cfg.port);

        let builder = if let Some(auth) = &cfg.auth {
            builder.credentials(Credentials::new(
                auth.username.clone(),
                auth.password.clone(),
            ))
        } else {
            builder
        };

        Ok(Self {
            inner: builder.build(),
        })
    }
}

#[async_trait]
impl MailTransport for SmtpTransport {
    async fn send(&self, mail: OutgoingMail) -> Result<()> {
        let message = build_message(&mail)?;
        self.inner
            .send(message)
            .await
            .map_err(|e| AlertError::Transport(format!("SMTP send failed: {e}")))?;
        tracing::info!(
            recipients = mail.to.len(),
            subject = %mail.email.subject,
            "guardian alert email delivered"
        );
        Ok(())
    }
}

/// Build a lettre [`Message`] from the outgoing mail. Plain-text body only
/// (keeps the safety surface minimal; the renderer guarantees no media bytes).
fn build_message(mail: &OutgoingMail) -> Result<Message> {
    let from: Mailbox = parse_mailbox(&mail.from)?;

    let mut builder = Message::builder().from(from).subject(&mail.email.subject);
    for to in &mail.to {
        if to.trim().is_empty() {
            continue;
        }
        builder = builder.to(parse_mailbox(to)?);
    }

    builder
        .multipart(MultiPart::mixed().singlepart(SinglePart::plain(mail.email.body.clone())))
        .map_err(|e| AlertError::Transport(format!("building message: {e}")))
}

/// Parse a `"Display Name <addr@host>"` or bare `addr@host` into a [`Mailbox`].
fn parse_mailbox(s: &str) -> Result<Mailbox> {
    let s = s.trim();
    if let Some((name, rest)) = s.split_once('<') {
        let addr = rest.trim_end_matches('>').trim();
        let address: Address = addr
            .parse()
            .map_err(|e| AlertError::Config(format!("bad address {addr:?}: {e}")))?;
        let name = name.trim();
        let display = if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        };
        Ok(Mailbox::new(display, address))
    } else {
        let address: Address = s
            .parse()
            .map_err(|e| AlertError::Config(format!("bad address {s:?}: {e}")))?;
        Ok(Mailbox::new(None, address))
    }
}
