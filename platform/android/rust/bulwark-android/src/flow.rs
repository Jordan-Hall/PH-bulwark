//! The Android flow consumer — closes the protection loop over the VPN data
//! path (audit 2026-06-10 C2).
//!
//! MIRRORS `bulwark-client::Pipeline` (deliberately NOT imported: that crate
//! pulls bulwark-store/rusqlite, which must stay out of this cdylib's tree):
//! `next_flow()` → analyze → policy → `apply()` + alert. Text runs the same
//! deterministic `TextAnalyzer` + `Policy` the accessibility path uses.
//!
//! ## Media decision (honest fail-open)
//! The proxy decision-gates scorable still images and video segments; without a
//! consumer they stall the 5s gate window and then fail-closed DROP — a silent
//! device-wide imagery blackhole that tells the guardian nothing. This bridge
//! has NO on-device media scorer yet (bulwark-vision/onnx is not in this dep
//! tree), so a fail-closed answer adds zero detection while breaking the web.
//! Policy here: answer the gate IMMEDIATELY with Forward (fail open, the
//! project's documented un-runnable-analyzer default) + a ONE-TIME content-free
//! guardian alert that media passes unscored, + a tracing note per flow. Text +
//! accessibility still cover the grooming threat model; swap to real scoring is
//! a drop-in replacement of `decide_flow`'s media arm.
//!
//! ## Honest scope
//! Gated media and bounded text/html pages can be retro-blocked by `apply`
//! (html fails open after 2s if unanswered — `proxy::gate_policy`); other text
//! (json/js/plain) is emit-only in the proxy (already forwarded), so a Drop
//! there is recorded but cannot recall the bytes — the ALERT is the protective
//! output for those flows.

use std::sync::Arc;

use bulwark_net::{CapturedFlow, FlowPayload, InterceptDecision, Interceptor};
use bulwark_policy::PolicyContext;
use bulwark_proto::v1::{Action, AlertEvent, TextSpan};
use bulwark_proto::DeviceId;

/// What one captured flow resolves to.
pub struct FlowOutcome {
    pub decision: InterceptDecision,
    pub alert: Option<AlertEvent>,
    /// True when this was a media flow forwarded UNSCORED (no on-device model).
    pub media_gap: bool,
}

impl FlowOutcome {
    fn forward() -> Self {
        FlowOutcome {
            decision: InterceptDecision::Forward,
            alert: None,
            media_gap: false,
        }
    }
}

/// Declared-textual content types we run through the text analyzer.
fn is_textual(ct: &str) -> bool {
    ct.starts_with("text/")
        || matches!(
            ct,
            "application/json"
                | "application/x-www-form-urlencoded"
                | "application/xml"
                | "application/xhtml+xml"
        )
}

/// Media content types the proxy may have decision-gated (images/video).
fn is_media(ct: &str) -> bool {
    ct.starts_with("image/") || ct.starts_with("video/")
}

/// Pure per-flow decision (host-unit-tested): text → deterministic analyzer +
/// policy; gated media → Forward + media-gap note (see module docs); everything
/// else forwards. Never panics; anything un-analysable fails OPEN.
pub fn decide_flow(flow: &CapturedFlow) -> FlowOutcome {
    let FlowPayload::Http(head) = &flow.payload else {
        // A raw StreamChunk is a media segment by construction — same unscored
        // fail-open as the gated-media arm below.
        return FlowOutcome {
            decision: InterceptDecision::Forward,
            alert: None,
            media_gap: true,
        };
    };
    let ct = head.content_type();

    // GATED media (scorable images / video segments): answer the gate NOW with
    // Forward — letting the 5s timeout fail-closed would silently drop every
    // image/segment on the device (the audit's blackhole). One-time alert +
    // per-flow trace keep the gap honest.
    if ct.as_deref().is_some_and(is_media) {
        return FlowOutcome {
            decision: InterceptDecision::Forward,
            alert: None,
            media_gap: true,
        };
    }

    // Pinned / E2E flows are unreadable here; the accessibility path covers them.
    if !flow.readable {
        return FlowOutcome::forward();
    }

    let body = head.body_peek.as_ref();
    if body.is_empty() {
        return FlowOutcome::forward();
    }
    let text = match ct.as_deref() {
        Some(ct) if is_textual(ct) => String::from_utf8_lossy(body).into_owned(),
        Some(_) => return FlowOutcome::forward(), // declared non-text, non-media
        // Undeclared type: only analyze if it really is UTF-8 text.
        None => match std::str::from_utf8(body) {
            Ok(s) => s.to_owned(),
            Err(_) => return FlowOutcome::forward(),
        },
    };

    let Some(engine) = crate::engine() else {
        return FlowOutcome::forward(); // analyzer unavailable -> fail open
    };

    // Same deterministic pipeline as analyzeText; per-HOST grooming memory.
    let span = TextSpan {
        text,
        lang: String::new(),
        app: flow.app_or_host.clone(),
        thread_id: flow.app_or_host.clone(),
        from_minor: false,
        prior_excerpts: Vec::new(),
    };
    let verdict = engine.text.analyze_span("net", &span, 0);
    let ctx = PolicyContext::new(
        DeviceId(String::new()),
        flow.source_channel,
        crate::current_age_profile(),
    );
    let decision = engine.policy.evaluate(&verdict, &ctx);

    let alert = decision.raise_alert.map(|kind| AlertEvent {
        alert_id: format!("net-{}-{}", flow.flow_id, crate::relay::now_ms()),
        kind: kind as i32,
        category: verdict.category,
        severity: decision.severity as i32,
        app: flow.app_or_host.clone(),
        ts: crate::relay::now_ms(),
        // CONTENT-FREE policy reason — never the analyzer excerpt (same rule as
        // verdict_json: some rules echo quoted source phrases).
        redacted_context: decision.reason.clone(),
        ..Default::default()
    });

    let intercept = match decision.action {
        // No on-device redaction/remediation here -> flagged content is dropped,
        // never forwarded raw (mirrors bulwark-client's action_to_decision).
        Action::Block | Action::Blur | Action::Mute => InterceptDecision::Drop,
        _ => InterceptDecision::Forward,
    };
    FlowOutcome {
        decision: intercept,
        alert,
        media_gap: false,
    }
}

/// One-time, content-free guardian notice that media passes unscored on this
/// device, plus a per-flow trace. Honest coverage — never silent.
fn note_media_gap_once(flow: &CapturedFlow) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static NOTICED: AtomicBool = AtomicBool::new(false);
    tracing::debug!(
        flow_id = flow.flow_id,
        host = %flow.app_or_host,
        "media flow forwarded UNSCORED (no on-device media model yet)"
    );
    if !NOTICED.swap(true, Ordering::Relaxed) {
        crate::enqueue_protection_alert(
            "media-unscored",
            "Images and video are currently passing through unscored on this \
             device (on-device media scoring is not available yet). Text and \
             on-screen monitoring remain active.",
        );
    }
}

/// JSON shape the Kotlin alert poller / AlertNotifier reads (alert_id, kind,
/// category ordinals, redacted_context) — matches enqueue_protection_alert.
fn local_alert_json(ev: &AlertEvent) -> String {
    serde_json::json!({
        "alert_id": ev.alert_id,
        "kind": ev.kind,
        "category": ev.category,
        "redacted_context": ev.redacted_context,
    })
    .to_string()
}

/// THE consumer loop `startVpn` spawns: drain `next_flow()`, answer the
/// decision gate, queue + relay alerts. Ends when the interceptor shuts down
/// (flow channel closed). Never panics; per-flow failures fail open.
pub async fn run_flow_consumer(interceptor: Arc<dyn Interceptor>) {
    tracing::info!("flow consumer started (decision gate is now answered)");
    loop {
        match interceptor.next_flow().await {
            Ok(Some(flow)) => {
                let flow_id = flow.flow_id;
                let outcome = decide_flow(&flow);
                // Answer the gate FIRST (it holds a live response, 5s budget);
                // alert I/O afterwards.
                if let Err(e) = interceptor.apply(flow_id, outcome.decision).await {
                    tracing::warn!(error = %e, flow_id, "failed to apply flow decision");
                }
                if outcome.media_gap {
                    note_media_gap_once(&flow);
                }
                if let Some(event) = outcome.alert {
                    crate::enqueue_alert_json(local_alert_json(&event));
                    crate::relay::relay_alert_best_effort(event);
                }
            }
            Ok(None) => break, // channel closed: proxy stopped
            Err(e) => {
                tracing::warn!(error = %e, "next_flow failed; flow consumer exiting");
                break;
            }
        }
    }
    tracing::info!("flow consumer ended");
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_core::flow::{Header, HttpHead};
    use bulwark_proto::v1::Category;

    fn http_flow(
        id: u64,
        host: &str,
        readable: bool,
        ct: Option<&str>,
        body: &[u8],
    ) -> CapturedFlow {
        let mut headers = Vec::new();
        if let Some(ct) = ct {
            headers.push(Header {
                name: "content-type".to_owned(),
                value: ct.to_owned(),
            });
        }
        CapturedFlow {
            flow_id: id,
            source_channel: bulwark_proto::SourceChannel::Web,
            app_or_host: host.to_owned(),
            readable,
            payload: FlowPayload::Http(HttpHead {
                method: Some("GET".to_owned()),
                path: Some("/".to_owned()),
                status: None,
                headers,
                body_peek: body.to_vec().into(),
            }),
        }
    }

    #[test]
    fn gated_media_forwards_immediately_with_gap_note() {
        let flow = http_flow(
            1,
            "cdn.example",
            true,
            Some("image/jpeg"),
            &[0xFF; 32 * 1024],
        );
        let out = decide_flow(&flow);
        assert!(matches!(out.decision, InterceptDecision::Forward));
        assert!(out.media_gap, "unscored media must be flagged as a gap");
        assert!(out.alert.is_none());

        let video = http_flow(2, "cdn.example", true, Some("video/mp2t"), &[7u8; 4096]);
        assert!(decide_flow(&video).media_gap);
    }

    #[test]
    fn flagged_text_drops_and_raises_a_redacted_alert() {
        // Same phrase the lib tests prove is CSAM_SUSPECTED + BLOCK.
        let raw = "send me a pic of you in your room";
        let flow = http_flow(3, "chat.example", true, Some("text/plain"), raw.as_bytes());
        let out = decide_flow(&flow);
        assert!(matches!(out.decision, InterceptDecision::Drop));
        let alert = out.alert.expect("a blocking verdict must alert");
        assert_eq!(alert.category, Category::CsamSuspected as i32);
        assert_ne!(alert.kind, 0);
        assert!(!alert.redacted_context.is_empty());
        assert!(
            !alert.redacted_context.contains("send me a pic"),
            "raw text leaked: {}",
            alert.redacted_context
        );
        assert!(!local_alert_json(&alert).contains("send me a pic"));
    }

    #[test]
    fn safe_text_forwards_without_alert() {
        let flow = http_flow(
            4,
            "news.example",
            true,
            Some("text/html"),
            b"are you coming to football practice tonight?",
        );
        let out = decide_flow(&flow);
        assert!(matches!(out.decision, InterceptDecision::Forward));
        assert!(out.alert.is_none());
        assert!(!out.media_gap);
    }

    #[test]
    fn unreadable_and_binary_flows_fail_open() {
        let pinned = http_flow(5, "signal.org", false, Some("text/plain"), b"ciphertext");
        assert!(matches!(
            decide_flow(&pinned).decision,
            InterceptDecision::Forward
        ));
        // Undeclared binary: not analyzed, forwarded.
        let binary = http_flow(6, "x.example", true, None, &[0u8, 159, 146, 150]);
        let out = decide_flow(&binary);
        assert!(matches!(out.decision, InterceptDecision::Forward));
        assert!(out.alert.is_none());
    }

    /// The loop answers the decision gate: a scripted interceptor records the
    /// applied decisions and the consumer ends when the flows run out.
    #[test]
    fn consumer_loop_applies_decisions_and_ends() {
        struct Scripted {
            flows: std::sync::Mutex<std::collections::VecDeque<CapturedFlow>>,
            applied: std::sync::Mutex<Vec<(u64, InterceptDecision)>>,
        }
        #[async_trait::async_trait]
        impl Interceptor for Scripted {
            async fn start(&self) -> bulwark_core::Result<()> {
                Ok(())
            }
            async fn next_flow(&self) -> bulwark_core::Result<Option<CapturedFlow>> {
                Ok(self.flows.lock().unwrap().pop_front())
            }
            async fn apply(
                &self,
                flow_id: u64,
                decision: InterceptDecision,
            ) -> bulwark_core::Result<()> {
                self.applied.lock().unwrap().push((flow_id, decision));
                Ok(())
            }
            fn is_pinned(&self, _h: &str) -> bool {
                false
            }
            async fn shutdown(&self) -> bulwark_core::Result<()> {
                Ok(())
            }
        }

        let scripted = Arc::new(Scripted {
            flows: std::sync::Mutex::new(
                vec![
                    http_flow(10, "cdn.example", true, Some("image/png"), &[1u8; 20_000]),
                    http_flow(
                        11,
                        "chat.example",
                        true,
                        Some("text/plain"),
                        b"send me a pic of you in your room",
                    ),
                ]
                .into(),
            ),
            applied: std::sync::Mutex::new(Vec::new()),
        });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(run_flow_consumer(scripted.clone()));

        let applied = scripted.applied.lock().unwrap();
        assert_eq!(applied.len(), 2, "every flow must get a gate answer");
        assert!(matches!(applied[0], (10, InterceptDecision::Forward)));
        assert!(matches!(applied[1], (11, InterceptDecision::Drop)));
    }
}
