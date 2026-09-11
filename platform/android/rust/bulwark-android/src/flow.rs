//! Android VPN flow consumer.
//!
//! Text is judged locally. Complete image/video units surfaced by `bulwark-net`
//! are sent through authenticated cluster Analysis over the shared HTTP/2 channel.
//! Unknown/late media is blocked, never mislabeled SAFE. Work is bounded-concurrent
//! so one slow video segment does not head-of-line block unrelated response gates.

use std::sync::Arc;

use bulwark_net::{CapturedFlow, FlowPayload, InterceptDecision, Interceptor};
use bulwark_policy::PolicyContext;
use bulwark_proto::v1::{
    Action, AlertEvent, Category, MediaKind, SourceChannel, TextSpan, Verdict,
};
use bulwark_proto::DeviceId;

const MAX_INFLIGHT_FLOWS: usize = 4;

/// A resolved policy result for one captured flow.
pub struct FlowOutcome {
    pub decision: InterceptDecision,
    pub alert: Option<AlertEvent>,
    /// True when protection coverage degraded and media was blocked rather than
    /// falsely reported safe.
    pub media_gap: bool,
}

impl FlowOutcome {
    fn forward() -> Self {
        Self {
            decision: InterceptDecision::Forward,
            alert: None,
            media_gap: false,
        }
    }

    fn coverage_block() -> Self {
        Self {
            decision: InterceptDecision::Drop,
            alert: None,
            media_gap: true,
        }
    }
}

struct MediaWork {
    kind: MediaKind,
    mime_type: String,
    bytes: Vec<u8>,
    deadline_ms: u32,
}

fn is_textual(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || matches!(
            content_type,
            "application/json"
                | "application/x-www-form-urlencoded"
                | "application/xml"
                | "application/xhtml+xml"
        )
}

fn media_kind(content_type: &str) -> Option<MediaKind> {
    if content_type.starts_with("image/") {
        Some(MediaKind::Image)
    } else if content_type.starts_with("video/") {
        Some(MediaKind::Video)
    } else if content_type.starts_with("audio/") {
        Some(MediaKind::Audio)
    } else {
        None
    }
}

fn media_deadline(source: SourceChannel, kind: MediaKind) -> u32 {
    match (source, kind) {
        (SourceChannel::LiveStream, _) => 650,
        (_, MediaKind::Image) => 750,
        (_, MediaKind::Audio) => 850,
        (_, MediaKind::Video) => 1_200,
        _ => 750,
    }
}

/// Extract only complete media objects. The interceptor substitutes the full body
/// into `body_peek` only for media explicitly admitted by its size/MIME gates.
fn media_work(flow: &CapturedFlow) -> Option<MediaWork> {
    match &flow.payload {
        FlowPayload::StreamChunk {
            data,
            mime_type,
            ..
        } => {
            let mime = mime_type
                .clone()
                .unwrap_or_else(|| "video/mp4".to_string());
            let kind = media_kind(&mime).unwrap_or(MediaKind::Video);
            Some(MediaWork {
                kind,
                mime_type: mime,
                bytes: data.to_vec(),
                deadline_ms: media_deadline(flow.source_channel, kind),
            })
        }
        FlowPayload::Http(head) => {
            let mime = head.content_type()?;
            let kind = media_kind(&mime)?;
            if head.body_peek.is_empty() {
                return None;
            }
            Some(MediaWork {
                kind,
                mime_type: mime,
                bytes: head.body_peek.to_vec(),
                deadline_ms: media_deadline(flow.source_channel, kind),
            })
        }
    }
}

fn policy_context(flow: &CapturedFlow) -> PolicyContext {
    let device_id = crate::relay::target()
        .map(|target| target.device_id)
        .unwrap_or_default();
    PolicyContext::new(
        DeviceId(device_id),
        flow.source_channel,
        crate::current_age_profile(),
    )
}

fn alert_for(
    flow: &CapturedFlow,
    verdict: &Verdict,
    decision: &bulwark_policy::PolicyDecision,
) -> Option<AlertEvent> {
    decision.raise_alert.map(|kind| AlertEvent {
        alert_id: format!(
            "net-{}-{}-{}",
            flow.flow_id,
            verdict.request_id,
            crate::relay::now_ms()
        ),
        kind: kind as i32,
        category: verdict.category,
        severity: decision.severity as i32,
        app: flow.app_or_host.clone(),
        ts: crate::relay::now_ms(),
        redacted_context: decision.reason.clone(),
        evidence: verdict.evidence.clone(),
        local_segment_uri: verdict.local_segment_uri.clone(),
        ..Default::default()
    })
}

fn outcome_from_verdict(flow: &CapturedFlow, verdict: Verdict) -> FlowOutcome {
    let Some(engine) = crate::engine() else {
        return FlowOutcome::coverage_block();
    };
    let policy = engine.policy.evaluate(&verdict, &policy_context(flow));
    let rewrite = (!verdict.remediated_media.is_empty())
        .then(|| verdict.remediated_media.clone());
    let decision = match policy.action {
        Action::Block => InterceptDecision::Drop,
        Action::Blur | Action::Mute => rewrite
            .map(InterceptDecision::Rewrite)
            .unwrap_or(InterceptDecision::Drop),
        _ => InterceptDecision::Forward,
    };
    FlowOutcome {
        decision,
        alert: alert_for(flow, &verdict, &policy),
        media_gap: verdict.category() == Category::Unspecified,
    }
}

async fn decide_media(flow: &CapturedFlow, work: MediaWork) -> FlowOutcome {
    let request_id = format!(
        "android-{}-{}-{}",
        flow.flow_id,
        match work.kind {
            MediaKind::Image => "image",
            MediaKind::Audio => "audio",
            MediaKind::Video => "video",
            _ => "media",
        },
        crate::relay::now_ms()
    );
    match crate::relay::analyze_media(
        work.kind,
        flow.source_channel,
        work.mime_type,
        work.bytes,
        work.deadline_ms,
        request_id,
    )
    .await
    {
        Ok(verdict) => outcome_from_verdict(flow, verdict),
        Err(error) => {
            tracing::warn!(
                flow_id = flow.flow_id,
                kind = ?work.kind,
                %error,
                "media analysis unavailable before gate deadline; blocking"
            );
            FlowOutcome::coverage_block()
        }
    }
}

fn decide_text(flow: &CapturedFlow) -> FlowOutcome {
    let FlowPayload::Http(head) = &flow.payload else {
        return FlowOutcome::forward();
    };
    if !flow.readable {
        return FlowOutcome::forward();
    }

    let content_type = head.content_type();
    let body = head.body_peek.as_ref();
    if body.is_empty() {
        return FlowOutcome::forward();
    }
    let text = match content_type.as_deref() {
        Some(content_type) if is_textual(content_type) => {
            String::from_utf8_lossy(body).into_owned()
        }
        Some(_) => return FlowOutcome::forward(),
        None => match std::str::from_utf8(body) {
            Ok(text) => text.to_owned(),
            Err(_) => return FlowOutcome::forward(),
        },
    };

    let Some(engine) = crate::engine() else {
        return FlowOutcome::forward();
    };
    let device = crate::relay::target()
        .map(|target| target.device_id)
        .unwrap_or_else(|| "android-unenrolled".to_string());
    let app = if flow.app_or_host.trim().is_empty() {
        "network".to_string()
    } else {
        flow.app_or_host.clone()
    };
    let span = TextSpan {
        text,
        lang: String::new(),
        app: app.clone(),
        thread_id: format!("{device}\u{1f}{app}\u{1f}network"),
        from_minor: false,
        prior_excerpts: Vec::new(),
    };
    let verdict = engine.text.analyze_span(
        &format!("net-{}", flow.flow_id),
        &span,
        crate::relay::now_ms(),
    );
    outcome_from_verdict(flow, verdict)
}

/// Pure/local decision helper for host tests. Production media decisions use the
/// async cluster path; here media conservatively resolves to Drop.
pub fn decide_flow(flow: &CapturedFlow) -> FlowOutcome {
    if media_work(flow).is_some() {
        FlowOutcome::coverage_block()
    } else {
        decide_text(flow)
    }
}

async fn decide_flow_async(flow: &CapturedFlow) -> FlowOutcome {
    if let Some(work) = media_work(flow) {
        decide_media(flow, work).await
    } else {
        decide_text(flow)
    }
}

fn note_media_gap_once(flow: &CapturedFlow) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static NOTICED: AtomicBool = AtomicBool::new(false);
    tracing::warn!(
        flow_id = flow.flow_id,
        host = %flow.app_or_host,
        "media blocked because protected analysis was unavailable or inconclusive"
    );
    if !NOTICED.swap(true, Ordering::Relaxed) {
        crate::enqueue_protection_alert(
            "media-analysis-unavailable",
            "Bulwark could not safely analyse protected image/video traffic in time, so it was blocked. Protection is still active; check the server connection if this continues.",
        );
    }
}

fn local_alert_json(event: &AlertEvent) -> String {
    serde_json::json!({
        "alert_id": event.alert_id,
        "kind": event.kind,
        "category": event.category,
        "redacted_context": event.redacted_context,
    })
    .to_string()
}

async fn process_flow(interceptor: Arc<dyn Interceptor>, flow: CapturedFlow) {
    let flow_id = flow.flow_id;
    let outcome = decide_flow_async(&flow).await;
    if let Err(error) = interceptor.apply(flow_id, outcome.decision).await {
        tracing::warn!(%error, flow_id, "failed to apply flow decision");
    }
    if outcome.media_gap {
        note_media_gap_once(&flow);
    }
    if let Some(event) = outcome.alert {
        crate::enqueue_alert_json(local_alert_json(&event));
        crate::relay::relay_alert_best_effort(event);
    }
}

/// Drain captured flows with at most four analysis decisions in flight. This
/// removes head-of-line blocking while bounding memory, network work and model
/// pressure on a child device.
pub async fn run_flow_consumer(interceptor: Arc<dyn Interceptor>) {
    tracing::info!(
        max_inflight = MAX_INFLIGHT_FLOWS,
        "flow consumer started; protected media gate active"
    );
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        while tasks.len() >= MAX_INFLIGHT_FLOWS {
            let _ = tasks.join_next().await;
        }

        match interceptor.next_flow().await {
            Ok(Some(flow)) => {
                let interceptor = interceptor.clone();
                tasks.spawn(async move {
                    process_flow(interceptor, flow).await;
                });
            }
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, "next_flow failed; flow consumer exiting");
                break;
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    tracing::info!("flow consumer ended");
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_core::flow::{Header, HttpHead};

    fn http_flow(
        id: u64,
        host: &str,
        readable: bool,
        content_type: Option<&str>,
        body: &[u8],
    ) -> CapturedFlow {
        let mut headers = Vec::new();
        if let Some(content_type) = content_type {
            headers.push(Header {
                name: "content-type".to_owned(),
                value: content_type.to_owned(),
            });
        }
        CapturedFlow {
            flow_id: id,
            source_channel: SourceChannel::Web,
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
    fn image_and_video_are_protected_not_forwarded_unscored() {
        let image = http_flow(
            1,
            "cdn.example",
            true,
            Some("image/jpeg"),
            &[0xff; 32 * 1024],
        );
        assert!(matches!(
            decide_flow(&image).decision,
            InterceptDecision::Drop
        ));
        assert!(media_work(&image).is_some());

        let video = http_flow(
            2,
            "cdn.example",
            true,
            Some("video/mp2t"),
            &[7; 64 * 1024],
        );
        let work = media_work(&video).expect("video work");
        assert_eq!(work.kind, MediaKind::Video);
        assert!(work.deadline_ms <= 1_200);
    }

    #[test]
    fn flagged_text_is_redacted_and_not_false_csam() {
        let raw = "send me a pic of you in your room";
        let flow = http_flow(3, "chat.example", true, Some("text/plain"), raw.as_bytes());
        let outcome = decide_flow(&flow);
        let alert = outcome.alert.expect("grooming risk alerts guardian");
        assert_eq!(alert.category, Category::Grooming as i32);
        assert!(!alert.redacted_context.contains(raw));
        assert!(!local_alert_json(&alert).contains(raw));
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
        let outcome = decide_flow(&flow);
        assert!(matches!(
            outcome.decision,
            InterceptDecision::Forward
        ));
        assert!(outcome.alert.is_none());
    }

    #[test]
    fn stream_chunks_are_video_covered() {
        let flow = CapturedFlow {
            flow_id: 5,
            source_channel: SourceChannel::VideoStream,
            app_or_host: "video.example".into(),
            readable: true,
            payload: FlowPayload::StreamChunk {
                data: vec![1u8; 256 * 1024].into(),
                mime_type: Some("video/mp4".into()),
                url: Some("/segment-1.m4s".into()),
            },
        };
        let work = media_work(&flow).expect("stream media is scored");
        assert_eq!(work.kind, MediaKind::Video);
        assert_eq!(work.mime_type, "video/mp4");
    }

    #[test]
    fn concurrency_bound_is_small() {
        assert_eq!(MAX_INFLIGHT_FLOWS, 4);
    }
}
