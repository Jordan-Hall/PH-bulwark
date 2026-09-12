//! Android Local VPN flow consumer and guardian policy synchronization.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use bulwark_net::{CapturedFlow, FlowPayload, InterceptDecision, Interceptor};
use bulwark_policy::PolicyContext;
use bulwark_proto::v1::child_control_client::ChildControlClient;
use bulwark_proto::v1::{
    Action, AlertEvent, Category, ChildConfigFilter, MediaKind, SourceChannel, TextSpan, Verdict,
};
use bulwark_proto::DeviceId;
use tonic::transport::Channel;

const MAX_INFLIGHT_FLOWS: usize = 4;
const DEVICE_POLICY_HEADER: &str = "x-bulwark-policy-bin";
const POLICY_TTL_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Default)]
struct LocalPolicySnapshot {
    version: u64,
    expires_ts: i64,
    hosts: HashSet<String>,
    hashes: HashSet<String>,
}

fn policy_cell() -> &'static RwLock<LocalPolicySnapshot> {
    static POLICY: OnceLock<RwLock<LocalPolicySnapshot>> = OnceLock::new();
    POLICY.get_or_init(|| RwLock::new(LocalPolicySnapshot::default()))
}

fn clear_local_policy() {
    if let Ok(mut policy) = policy_cell().write() {
        *policy = LocalPolicySnapshot::default();
    }
}

fn replace_local_policy(version: u64, hosts: HashSet<String>, hashes: HashSet<String>) {
    if let Ok(mut policy) = policy_cell().write() {
        *policy = LocalPolicySnapshot {
            version,
            expires_ts: crate::relay::now_ms().saturating_add(POLICY_TTL_MS),
            hosts,
            hashes,
        };
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn guardian_approved(flow: &CapturedFlow, verdict: &Verdict) -> bool {
    if verdict.category() == Category::CsamSuspected {
        return false;
    }
    let Ok(policy) = policy_cell().read() else {
        return false;
    };
    if policy.expires_ts <= crate::relay::now_ms() {
        return false;
    }
    let host = flow.app_or_host.trim().to_ascii_lowercase();
    if !host.is_empty() && policy.hosts.contains(&host) {
        return true;
    }
    verdict.evidence.as_ref().is_some_and(|evidence| {
        !evidence.sha256.is_empty() && policy.hashes.contains(&hex(&evidence.sha256))
    })
}

async fn fetch_policy_metadata(
    channel: Channel,
    device_id: &str,
    applied_version: u64,
    device_token: &str,
) -> Result<(u64, HashSet<String>, HashSet<String>), String> {
    let mut client = ChildControlClient::new(channel);
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        client.get_child_config(ChildConfigFilter {
            device_id: device_id.to_string(),
            have_version: applied_version,
            device_token: device_token.to_string(),
        }),
    )
    .await
    .map_err(|_| "device policy sync timed out".to_string())?
    .map_err(|status| format!("device policy sync rejected: {}", status.code()))?;

    let bytes = response
        .metadata()
        .get_bin(DEVICE_POLICY_HEADER)
        .ok_or_else(|| "server omitted device policy snapshot".to_string())?
        .to_bytes()
        .map_err(|_| "device policy metadata was invalid".to_string())?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| "device policy snapshot was invalid JSON".to_string())?;
    if !value
        .get("complete")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err("server could not provide a complete device policy snapshot".to_string());
    }
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let strings = |name: &str| -> HashSet<String> {
        value
            .get(name)
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(|entry| entry.trim().to_ascii_lowercase())
            .filter(|entry| !entry.is_empty())
            .collect()
    };
    Ok((
        version,
        strings("approved_hosts"),
        strings("approved_sha256_hex"),
    ))
}

async fn sync_device_policy_rpc(
    endpoint: String,
    device_id: String,
    applied_version: u64,
    ca_path: String,
    device_token: String,
) -> Result<u64, String> {
    let device_id = device_id.trim();
    let device_token = device_token.trim();
    if device_id.is_empty() || device_token.is_empty() {
        clear_local_policy();
        return Err("paired device credentials are required".to_string());
    }
    let channel = crate::cluster_endpoint(&endpoint, &ca_path)?
        .connect()
        .await
        .map_err(|error| format!("could not reach server for policy sync: {error}"))?;
    match fetch_policy_metadata(channel, device_id, applied_version, device_token).await {
        Ok((version, hosts, hashes)) => {
            replace_local_policy(version, hosts, hashes);
            Ok(version)
        }
        Err(error) => {
            clear_local_policy();
            Err(error)
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_syncDevicePolicy(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    endpoint_value: jni::objects::JString,
    device_id_value: jni::objects::JString,
    applied_version: jni::sys::jlong,
    ca_path_value: jni::objects::JString,
    device_token_value: jni::objects::JString,
) -> jni::sys::jstring {
    let endpoint = crate::jstring_to_string(&mut env, &endpoint_value).unwrap_or_default();
    let device_id = crate::jstring_to_string(&mut env, &device_id_value).unwrap_or_default();
    let ca_path = crate::jstring_to_string(&mut env, &ca_path_value).unwrap_or_default();
    let device_token =
        crate::jstring_to_string(&mut env, &device_token_value).unwrap_or_default();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            clear_local_policy();
            return crate::string_to_jstring(
                &mut env,
                &serde_json::json!({"ok": false, "error": error.to_string()}).to_string(),
            );
        }
    };
    let result = runtime.block_on(sync_device_policy_rpc(
        endpoint,
        device_id,
        applied_version.max(0) as u64,
        ca_path,
        device_token,
    ));
    let json = match result {
        Ok(version) => serde_json::json!({"ok": true, "version": version}).to_string(),
        Err(error) => serde_json::json!({"ok": false, "error": error}).to_string(),
    };
    crate::string_to_jstring(&mut env, &json)
}

pub struct FlowOutcome {
    pub decision: InterceptDecision,
    pub alert: Option<AlertEvent>,
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
    if guardian_approved(flow, &verdict) {
        return FlowOutcome::forward();
    }
    let Some(engine) = crate::engine() else {
        return FlowOutcome::coverage_block();
    };
    let policy = engine.policy.evaluate(&verdict, &policy_context(flow));
    let rewrite = (!verdict.remediated_media.is_empty()).then(|| verdict.remediated_media.clone());
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
    if !flow.readable || head.body_peek.is_empty() {
        return FlowOutcome::forward();
    }
    let body = head.body_peek.as_ref();
    let text = match head.content_type().as_deref() {
        Some(content_type) if is_textual(content_type) => String::from_utf8_lossy(body).into_owned(),
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
    let verdict = engine.text.analyze_span(
        &format!("net-{}", flow.flow_id),
        &TextSpan {
            text,
            lang: String::new(),
            app: app.clone(),
            thread_id: format!("{device}\u{1f}{app}\u{1f}network"),
            from_minor: false,
            prior_excerpts: Vec::new(),
        },
        crate::relay::now_ms(),
    );
    outcome_from_verdict(flow, verdict)
}

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
            "Bulwark could not safely analyse protected media in time, so it was blocked.",
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

pub async fn run_flow_consumer(interceptor: Arc<dyn Interceptor>) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_core::flow::{Header, HttpHead};

    fn http_flow(id: u64, host: &str, content_type: Option<&str>, body: &[u8]) -> CapturedFlow {
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
            readable: true,
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
    fn media_is_never_forwarded_unscored() {
        let image = http_flow(1, "cdn.example", Some("image/jpeg"), &[0xff; 32 * 1024]);
        assert!(matches!(decide_flow(&image).decision, InterceptDecision::Drop));
        let video = http_flow(2, "cdn.example", Some("video/mp2t"), &[7; 64 * 1024]);
        assert_eq!(media_work(&video).unwrap().kind, MediaKind::Video);
    }

    #[test]
    fn safe_text_forwards() {
        clear_local_policy();
        let flow = http_flow(
            3,
            "news.example",
            Some("text/plain"),
            b"are you coming to football practice tonight?",
        );
        assert!(matches!(decide_flow(&flow).decision, InterceptDecision::Forward));
    }

    #[test]
    fn stale_policy_does_not_allow() {
        replace_local_policy(
            1,
            ["example.test".to_string()].into_iter().collect(),
            HashSet::new(),
        );
        if let Ok(mut policy) = policy_cell().write() {
            policy.expires_ts = 0;
        }
        let verdict = Verdict {
            category: Category::AdultText as i32,
            ..Default::default()
        };
        let flow = http_flow(4, "example.test", Some("text/plain"), b"x");
        assert!(!guardian_approved(&flow, &verdict));
    }

    #[test]
    fn policy_version_is_replaced_not_accumulated() {
        replace_local_policy(
            1,
            ["one.test".to_string()].into_iter().collect(),
            HashSet::new(),
        );
        replace_local_policy(
            2,
            ["two.test".to_string()].into_iter().collect(),
            HashSet::new(),
        );
        let policy = policy_cell().read().unwrap();
        assert_eq!(policy.version, 2);
        assert!(!policy.hosts.contains("one.test"));
        assert!(policy.hosts.contains("two.test"));
    }
}
