//! aegis-supervision — official family-platform supervision connectors.
//!
//! Supplementary, **coarse** signals from the platforms' own family APIs
//! (Google Family Link, Microsoft Family Safety, Apple Screen Time, Meta Family
//! Center) where they exist. These are opt-in, API-key/OAuth-gated, and limited
//! (mostly screen-time / app-install / friend-request events) — NOT a substitute
//! for the network + on-device paths. Honest about coverage per
//! docs/research/platform-feasibility.md §6 caveats.
//!
//! Disabled by default; each connector is a stub until credentials are wired.
//! `#![forbid(unsafe_code)]`, no AI, no telemetry beyond the configured platform.
#![forbid(unsafe_code)]

use aegis_core::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A coarse signal lifted from a platform's family API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SupervisionSignal {
    pub platform: String,     // "google" | "microsoft" | "apple" | "meta"
    pub kind: String,         // e.g. "friend_request", "app_install", "screen_time_exceeded"
    pub subject_device: String,
    pub summary: String,      // human-readable, no sensitive content
    pub ts: i64,
}

/// One platform connector. Disabled connectors return an empty poll.
#[async_trait]
pub trait SupervisionConnector: Send + Sync {
    fn platform(&self) -> &'static str;
    fn enabled(&self) -> bool;
    /// Pull new coarse signals since the last poll. Empty when disabled.
    async fn poll(&self) -> Result<Vec<SupervisionSignal>>;
}

/// Credentials for a connector (OAuth tokens / API keys). Loaded from
/// aegis-core Config / OS keystore — never hardcoded. Absent = disabled.
#[derive(Debug, Clone, Default)]
pub struct ConnectorCreds {
    pub enabled: bool,
    pub oauth_token: Option<String>,
}

macro_rules! stub_connector {
    ($name:ident, $platform:literal, $doc:literal) => {
        #[doc = $doc]
        pub struct $name {
            creds: ConnectorCreds,
        }
        impl $name {
            pub fn new(creds: ConnectorCreds) -> Self {
                Self { creds }
            }
        }
        #[async_trait]
        impl SupervisionConnector for $name {
            fn platform(&self) -> &'static str {
                $platform
            }
            fn enabled(&self) -> bool {
                self.creds.enabled && self.creds.oauth_token.is_some()
            }
            async fn poll(&self) -> Result<Vec<SupervisionSignal>> {
                if !self.enabled() {
                    return Ok(Vec::new());
                }
                // SEAM: real OAuth + HTTP poll of the platform family API goes
                // here (needs reqwest + per-platform scopes). Returns coarse
                // signals only. Coverage is limited — documented to the guardian.
                tracing::debug!(platform = $platform, "supervision poll (no-op stub)");
                Ok(Vec::new())
            }
        }
    };
}

stub_connector!(GoogleFamilyLink, "google", "Google Family Link connector (coarse signals).");
stub_connector!(MicrosoftFamilySafety, "microsoft", "Microsoft Family Safety connector.");
stub_connector!(AppleScreenTime, "apple", "Apple Screen Time connector (very limited API).");
stub_connector!(MetaFamilyCenter, "meta", "Meta Family Center connector (limited API).");

/// Aggregates all configured connectors and polls them.
#[derive(Default)]
pub struct SupervisionHub {
    connectors: Vec<Box<dyn SupervisionConnector>>,
}

impl SupervisionHub {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, c: Box<dyn SupervisionConnector>) -> &mut Self {
        self.connectors.push(c);
        self
    }
    /// Poll every enabled connector; concatenate signals.
    pub async fn poll_all(&self) -> Result<Vec<SupervisionSignal>> {
        let mut out = Vec::new();
        for c in &self.connectors {
            if c.enabled() {
                out.extend(c.poll().await?);
            }
        }
        Ok(out)
    }
    pub fn enabled_platforms(&self) -> Vec<&'static str> {
        self.connectors
            .iter()
            .filter(|c| c.enabled())
            .map(|c| c.platform())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_connectors_yield_nothing() {
        let mut hub = SupervisionHub::new();
        hub.add(Box::new(GoogleFamilyLink::new(ConnectorCreds::default())));
        hub.add(Box::new(MetaFamilyCenter::new(ConnectorCreds::default())));
        assert!(hub.enabled_platforms().is_empty());
        assert!(hub.poll_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn enabled_connector_polls() {
        let creds = ConnectorCreds {
            enabled: true,
            oauth_token: Some("token".into()),
        };
        let c = GoogleFamilyLink::new(creds);
        assert!(c.enabled());
        assert!(c.poll().await.unwrap().is_empty()); // stub returns empty for now
    }
}
