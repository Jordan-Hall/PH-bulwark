//! aegis-client — the device-side orchestration loop.
//!
//! Wires the pieces into the end-to-end pipeline:
//!
//! ```text
//! Interceptor.next_flow ─► FlowClassifier.classify ─► AnalysisUnit
//!        ▲                                                  │
//!        │                              text → local (aegis-text)
//!  Interceptor.apply ◄── PolicyEngine.decide ◄── Verdict ◄─┤ image/audio/video → OffloadRouter → cluster
//!        │                       │
//!        └─ Action               └─ AlertSink (guardian email) + Store (redacted audit)
//! ```
//!
//! INTEGRATION NOTE (for the integrator / Wave D): two shared types were defined
//! independently by `aegis-net` and `aegis-flow` (`CapturedFlow`, `FlowPayload`)
//! and the `Analyzer`/trait contracts were mirrored per-crate. They should be
//! **hoisted into `aegis-core`** so this crate links one vocabulary. Until then
//! the `adapt_flow` seam below converts between them. Marked `// SEAM:`.
//!
//! `#![forbid(unsafe_code)]`. No AI beyond the small dedicated analyzers; text
//! analysis is the deterministic rule engine and always runs locally.
#![forbid(unsafe_code)]

use std::sync::Arc;

use aegis_core::Result;
use aegis_flow::{AnalysisUnit, DefaultFlowClassifier, FlowClassifier};
use aegis_net::{Interceptor, InterceptDecision};
use aegis_proto::v1::{Action, AlertKind, AnalysisRequest, MediaKind, SourceChannel, Verdict};

/// Client tunables (device identity, cluster endpoint, age profile, paths).
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub device_id: String,
    /// gRPC endpoint of the (possibly local) server cluster for heavy media.
    pub cluster_endpoint: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            device_id: "device-local".to_string(),
            cluster_endpoint: Some("https://127.0.0.1:8443".to_string()),
        }
    }
}

/// Maps a policy `Action` onto the interceptor decision applied to the flow.
fn action_to_decision(action: Action, rewritten: Option<Vec<u8>>) -> InterceptDecision {
    match action {
        Action::Block => InterceptDecision::Drop,
        Action::Blur | Action::Mute => match rewritten {
            Some(bytes) => InterceptDecision::Rewrite(bytes),
            None => InterceptDecision::Drop, // can't redact safely → drop
        },
        // ALLOW / WARN / LOG / UNSPECIFIED → let it through (WARN overlay is UI).
        _ => InterceptDecision::Forward,
    }
}

/// The orchestration pipeline. Owns the local analyzers + policy; `alert` and
/// `store` are optional so a bare loop runs without SMTP/DB configured.
pub struct Pipeline {
    cfg: ClientConfig,
    classifier: DefaultFlowClassifier,
    text: aegis_text::TextAnalyzer,
    policy: aegis_policy::Policy,
    age_profile: aegis_policy::AgeProfile,
    alert: Option<Arc<dyn aegis_alert::AlertSink>>,
    store: Option<Arc<dyn aegis_store::Store>>,
}

impl Pipeline {
    pub fn new(cfg: ClientConfig) -> Self {
        Self {
            cfg,
            classifier: DefaultFlowClassifier::with_defaults(),
            text: aegis_text::TextAnalyzer::new(),
            policy: aegis_policy::Policy::default(),
            age_profile: aegis_policy::AgeProfile::default(),
            alert: None,
            store: None,
        }
    }

    pub fn with_alert(mut self, sink: Arc<dyn aegis_alert::AlertSink>) -> Self {
        self.alert = Some(sink);
        self
    }

    pub fn with_store(mut self, store: Arc<dyn aegis_store::Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Analyse one unit → Verdict. Text runs locally (deterministic rules);
    /// heavy media would route to the cluster via aegis-infer's OffloadRouter
    /// (SEAM: cluster client wired here when the endpoint is configured).
    async fn analyze(&self, unit: &AnalysisUnit) -> Verdict {
        match unit {
            AnalysisUnit::Text(span) => {
                let request_id = format!("{}-{}", self.cfg.device_id, span.thread_id);
                self.text.analyze_span(&request_id, span, span_ts(span))
            }
            // SEAM: route IMAGE/AUDIO/VIDEO to the cluster (aegis-infer OffloadRouter
            // → Analysis.Analyze). Until the cluster client is wired, fail open.
            _ => Verdict {
                category: aegis_proto::v1::Category::Safe as i32,
                action: Action::Allow as i32,
                rationale: "heavy-media cluster path not yet wired".to_string(),
                ..Default::default()
            },
        }
    }

    /// Run one captured flow all the way through and return the actions applied.
    pub async fn handle_flow(
        &self,
        flow: aegis_flow::CapturedFlow,
        interceptor: &dyn Interceptor,
    ) -> Result<()> {
        let flow_id = flow.flow_id;
        let source_channel = flow.source_channel();
        let units = self.classifier.classify(flow).await?;

        for unit in &units {
            let verdict = self.analyze(unit).await;

            let ctx = aegis_policy::PolicyContext {
                device: self.cfg.device_id.clone().into(),
                source_channel,
                age_profile: self.age_profile.clone(),
            };
            let action = self.policy.decide(&verdict, &ctx);
            let alert_kind = self.policy.alert_for(&verdict, action, &ctx);

            interceptor
                .apply(flow_id, action_to_decision(action, None))
                .await?;

            if let (Some(sink), Some(kind)) = (&self.alert, alert_kind) {
                let event = build_alert(&self.cfg.device_id, &verdict, kind);
                let _ = sink.raise(event).await; // alerting failure must not break filtering
            }

            if let Some(store) = &self.store {
                let _ = store
                    .record(aegis_store::StoredEvent {
                        device: self.cfg.device_id.clone().into(),
                        verdict: verdict.clone(),
                        action,
                        alert: alert_kind,
                        ts: span_now(),
                    })
                    .await;
            }
        }
        Ok(())
    }

    /// The main loop: pull flows from the interceptor and process them until
    /// shutdown. The interceptor must already be `start()`ed.
    pub async fn run(&self, interceptor: Arc<dyn Interceptor>) -> Result<()> {
        loop {
            match interceptor.next_flow().await? {
                Some(net_flow) => {
                    let flow = adapt_flow(net_flow);
                    if let Err(e) = self.handle_flow(flow, interceptor.as_ref()).await {
                        tracing::warn!(error = %e, "flow handling failed; failing open");
                    }
                }
                None => break, // interceptor closed
            }
        }
        Ok(())
    }
}

/// SEAM: convert `aegis_net::CapturedFlow` → `aegis_flow::CapturedFlow`.
/// These are currently two distinct structs (see INTEGRATION NOTE). The
/// integrator should unify them in `aegis-core`; this adapter exists so the
/// loop type-checks once field names are aligned.
fn adapt_flow(net_flow: aegis_net::CapturedFlow) -> aegis_flow::CapturedFlow {
    // Both carry flow_id / source_channel / app-or-host / readable / payload.
    aegis_flow::CapturedFlow {
        flow_id: net_flow.flow_id,
        source_channel: net_flow.source_channel,
        app_or_host: net_flow.app_or_host,
        readable: net_flow.readable,
        payload: convert_payload(net_flow.payload),
    }
}

/// SEAM: payload conversion mirrors `adapt_flow`. Unify in aegis-core.
fn convert_payload(p: aegis_net::FlowPayload) -> aegis_flow::FlowPayload {
    // Field-for-field once the two definitions are reconciled.
    aegis_flow::FlowPayload::from_net(p)
}

fn build_alert(device_id: &str, verdict: &Verdict, kind: AlertKind) -> aegis_proto::v1::AlertEvent {
    aegis_proto::v1::AlertEvent {
        alert_id: format!("{}-{}", device_id, verdict.request_id),
        kind: kind as i32,
        category: verdict.category,
        severity: verdict.severity,
        app: String::new(),
        device_id: device_id.to_string(),
        ts: span_now(),
        // redacted summary only — never raw content (Evidence carries hashes/safe thumb).
        redacted_context: verdict.rationale.clone(),
        evidence: verdict.evidence.clone(),
    }
}

fn span_ts(span: &aegis_proto::v1::TextSpan) -> i64 {
    let _ = span;
    span_now()
}

fn span_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// Keep the imports meaningful for downstream wiring helpers.
#[allow(unused_imports)]
use aegis_proto::v1::{AnalysisRequest as _AnalysisRequest, MediaKind as _MediaKind};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_mapping() {
        assert!(matches!(
            action_to_decision(Action::Block, None),
            InterceptDecision::Drop
        ));
        assert!(matches!(
            action_to_decision(Action::Allow, None),
            InterceptDecision::Forward
        ));
        assert!(matches!(
            action_to_decision(Action::Blur, Some(vec![1, 2, 3])),
            InterceptDecision::Rewrite(_)
        ));
        // blur with nothing safe to substitute → drop, never forward raw
        assert!(matches!(
            action_to_decision(Action::Blur, None),
            InterceptDecision::Drop
        ));
    }
}
