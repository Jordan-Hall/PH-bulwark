//! bulwark-client — device-side capture → analysis → policy → enforcement.
#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use bulwark_core::{Analyzer, Result};
use bulwark_flow::{AnalysisUnit, DefaultFlowClassifier, FlowClassifier};
use bulwark_infer::{
    ClientTlsIdentity, DefaultOffloadRouter, NullAnalyzer, OffloadClient, OffloadRouter,
};
use bulwark_net::{InterceptDecision, Interceptor};
use bulwark_policy::PolicyEngine;
use bulwark_proto::v1::{
    analysis_request::Media, Action, AlertKind, AnalysisRequest, Category, Evidence, InlineMedia,
    MediaKind, Severity, Verdict,
};
pub use bulwark_video::SegmentStore;
use bulwark_vision::Scorer;

pub mod tamper;
pub use tamper::{DesktopProbe, ProtectionProbe};

const NSFW_BLOCK_THRESHOLD: f32 = 0.7;
const DEFAULT_IMAGE_CACHE_ENTRIES: usize = 4096;

#[cfg(feature = "onnx")]
const NSFW_INPUT_SIZE: u32 = 224;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub device_id: String,
    pub cluster_endpoint: Option<String>,
    pub tls: Option<ClientTlsIdentity>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            device_id: "device-local".to_string(),
            cluster_endpoint: Some("https://127.0.0.1:8443".to_string()),
            tls: None,
        }
    }
}

pub fn load_cluster_tls_from_env() -> Option<ClientTlsIdentity> {
    let read = |var: &str| -> Option<Vec<u8>> {
        let path = std::env::var(var).ok().filter(|value| !value.is_empty())?;
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                tracing::warn!(var, path, %error, "cluster mTLS material unavailable");
                None
            }
        }
    };
    Some(ClientTlsIdentity {
        client_cert_pem: read("BULWARK_CLIENT_CERT")?,
        client_key_pem: read("BULWARK_CLIENT_KEY")?,
        ca_cert_pem: read("BULWARK_CLIENT_CA")?,
        server_domain: std::env::var("BULWARK_CLUSTER_DOMAIN")
            .ok()
            .filter(|value| !value.is_empty())?,
    })
}

pub async fn build_offload_router(cfg: &ClientConfig) -> Option<Arc<dyn OffloadRouter>> {
    let endpoint = cfg.cluster_endpoint.as_deref()?;
    let tls = cfg.tls.as_ref()?;
    match OffloadClient::connect(endpoint, tls).await {
        Ok(client) => {
            tracing::info!(endpoint, "authenticated cluster-offload router active");
            Some(Arc::new(DefaultOffloadRouter::new(
                Arc::new(NullAnalyzer),
                client,
            )))
        }
        Err(error) => {
            tracing::error!(endpoint, %error, "cluster offload unavailable; heavy-media coverage is degraded");
            None
        }
    }
}

/// An execution/coverage failure is explicitly UNKNOWN and conservatively blocked.
/// It is never encoded as Category::Safe.
fn coverage_gap(request_id: impl Into<String>, rationale: impl Into<String>) -> Verdict {
    Verdict {
        request_id: request_id.into(),
        category: Category::Unspecified as i32,
        action: Action::Block as i32,
        severity: Severity::Medium as i32,
        score: 0.0,
        rationale: rationale.into(),
        ..Default::default()
    }
}

fn action_to_decision(action: Action, rewritten: Option<Vec<u8>>) -> InterceptDecision {
    match action {
        Action::Block => InterceptDecision::Drop,
        Action::Blur | Action::Mute => rewritten
            .map(InterceptDecision::Rewrite)
            .unwrap_or(InterceptDecision::Drop),
        _ => InterceptDecision::Forward,
    }
}

/// Bounded FIFO score cache. We cache only the model output, never the policy
/// action/category, so a policy/age-profile change is applied on every hit.
struct ImageScoreCache {
    capacity: usize,
    scores: HashMap<[u8; 32], f32>,
    order: VecDeque<[u8; 32]>,
}

impl ImageScoreCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            scores: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&self, hash: &[u8; 32]) -> Option<f32> {
        self.scores.get(hash).copied()
    }

    fn insert(&mut self, hash: [u8; 32], score: f32) {
        if self.scores.contains_key(&hash) {
            self.scores.insert(hash, score);
            return;
        }
        while self.scores.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.scores.remove(&oldest);
            } else {
                break;
            }
        }
        self.order.push_back(hash);
        self.scores.insert(hash, score);
    }
}

pub struct Pipeline {
    cfg: ClientConfig,
    classifier: DefaultFlowClassifier,
    text: bulwark_text::TextAnalyzer,
    policy: bulwark_policy::Policy,
    age_profile: bulwark_policy::AgeProfile,
    alert: Option<Arc<dyn bulwark_alert::AlertSink>>,
    store: Option<Arc<dyn bulwark_store::Store>>,
    nsfw: Box<dyn Scorer>,
    video: Option<Arc<dyn Analyzer>>,
    offload: Option<Arc<dyn OffloadRouter>>,
    image_scores: Mutex<ImageScoreCache>,
}

impl Pipeline {
    pub fn new(cfg: ClientConfig) -> Self {
        let capacity = std::env::var("BULWARK_IMAGE_CACHE_ENTRIES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_IMAGE_CACHE_ENTRIES);
        Self {
            cfg,
            classifier: DefaultFlowClassifier::with_defaults(),
            text: bulwark_text::TextAnalyzer::new()
                .expect("bulwark-text built-in lexicon must load"),
            policy: bulwark_policy::Policy::default(),
            age_profile: bulwark_policy::AgeProfile::default(),
            alert: None,
            store: None,
            nsfw: build_nsfw_scorer(),
            video: None,
            offload: None,
            image_scores: Mutex::new(ImageScoreCache::new(capacity)),
        }
    }

    pub fn with_alert(mut self, sink: Arc<dyn bulwark_alert::AlertSink>) -> Self {
        self.alert = Some(sink);
        self
    }

    pub fn with_store(mut self, store: Arc<dyn bulwark_store::Store>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_video_analyzer(mut self, analyzer: Arc<dyn Analyzer>) -> Self {
        self.video = Some(analyzer);
        self
    }

    pub fn with_segment_store(mut self, store: SegmentStore) -> Self {
        #[cfg(feature = "ffmpeg")]
        let analyzer = bulwark_video::VideoAnalyzer::with_demuxer(
            bulwark_video::VideoConfig::default(),
            bulwark_video::ffmpeg::FfmpegDemuxer::new(),
        )
        .with_segment_store(store);
        #[cfg(not(feature = "ffmpeg"))]
        let analyzer = bulwark_video::VideoAnalyzer::new().with_segment_store(store);
        self.video = Some(Arc::new(analyzer));
        self
    }

    pub fn with_default_segment_store(self) -> Self {
        match SegmentStore::default_location() {
            Ok(store) => self.with_segment_store(store),
            Err(error) => {
                tracing::warn!(%error, "review clip storage unavailable; continuing without raw retention");
                self
            }
        }
    }

    pub fn with_offload(mut self, router: Arc<dyn OffloadRouter>) -> Self {
        self.offload = Some(router);
        self
    }

    pub fn with_nsfw_scorer(mut self, scorer: Box<dyn Scorer>) -> Self {
        self.nsfw = scorer;
        self
    }

    async fn analyze(&self, unit: &AnalysisUnit) -> Verdict {
        match unit {
            AnalysisUnit::Text(span) => {
                let mut scoped = span.clone();
                // Conversation state is namespaced by authenticated installation +
                // application + conversation id. Same thread ids in other apps or
                // devices can no longer poison this device's state machine.
                scoped.thread_id = format!(
                    "{}\u{1f}{}\u{1f}{}",
                    self.cfg.device_id,
                    span.app.trim(),
                    span.thread_id.trim()
                );
                let request_id = format!("{}-text-{}", self.cfg.device_id, short_hash_hex(scoped.thread_id.as_bytes()));
                self.text.analyze_span(&request_id, &scoped, span_now())
            }
            AnalysisUnit::Image(media) => self.analyze_image(media),
            AnalysisUnit::VideoSegment {
                media, segment_id, ..
            } => match &self.video {
                Some(analyzer) => {
                    self.analyze_video(analyzer.as_ref(), media, *segment_id)
                        .await
                }
                None => coverage_gap(
                    format!("{}-video-{}", self.cfg.device_id, short_hash_hex(&media.data)),
                    "video analyzer unavailable; content was not analysed",
                ),
            },
            AnalysisUnit::Audio(media) => match &self.offload {
                Some(router) => {
                    self.analyze_offload(router.as_ref(), media, MediaKind::Audio)
                        .await
                }
                None => coverage_gap(
                    format!("{}-audio-{}", self.cfg.device_id, short_hash_hex(&media.data)),
                    "audio analyzer/offload unavailable; content was not analysed",
                ),
            },
        }
    }

    async fn analyze_offload(
        &self,
        router: &dyn OffloadRouter,
        media: &InlineMedia,
        kind: MediaKind,
    ) -> Verdict {
        let request_id = format!(
            "{}-{}-{}",
            self.cfg.device_id,
            kind_tag(kind),
            short_hash_hex(&media.data)
        );
        let req = AnalysisRequest {
            request_id: request_id.clone(),
            media_kind: kind as i32,
            device_id: self.cfg.device_id.clone(),
            ts: span_now(),
            media: Some(Media::InlineMedia(media.clone())),
            ..Default::default()
        };
        match router.analyze(req).await {
            Ok(verdict) if verdict.category() != Category::Unspecified => verdict,
            Ok(verdict) => coverage_gap(
                request_id,
                if verdict.rationale.is_empty() {
                    "remote analysis returned incomplete coverage"
                } else {
                    verdict.rationale.as_str()
                },
            ),
            Err(error) => {
                tracing::error!(%error, kind = ?kind, "offload analysis failed; blocking uncovered media");
                coverage_gap(request_id, "remote analysis failed; content was not analysed")
            }
        }
    }

    async fn analyze_video(
        &self,
        analyzer: &dyn Analyzer,
        media: &InlineMedia,
        segment_id: Option<u64>,
    ) -> Verdict {
        let tag = segment_id
            .map(|id| format!("seg{id}"))
            .unwrap_or_else(|| short_hash_hex(&media.data));
        let request_id = format!("{}-video-{tag}", self.cfg.device_id);
        let req = AnalysisRequest {
            request_id: request_id.clone(),
            media_kind: MediaKind::Video as i32,
            device_id: self.cfg.device_id.clone(),
            ts: span_now(),
            media: Some(Media::InlineMedia(media.clone())),
            ..Default::default()
        };
        match analyzer.analyze(req).await {
            Ok(verdict) if verdict.category() != Category::Unspecified => verdict,
            Ok(verdict) => coverage_gap(
                request_id,
                if verdict.rationale.is_empty() {
                    "video analysis incomplete"
                } else {
                    verdict.rationale.as_str()
                },
            ),
            Err(error) => {
                tracing::error!(%error, "video analysis failed; blocking uncovered segment");
                coverage_gap(request_id, "video analysis failed; content was not analysed")
            }
        }
    }

    fn analyze_image(&self, media: &InlineMedia) -> Verdict {
        let bytes = &media.data;
        let request_id = format!("{}-img-{}", self.cfg.device_id, short_hash_hex(bytes));
        if self.nsfw.model_id() == "stub-noop" {
            return coverage_gap(
                request_id,
                "no local image model is available; image was not scored",
            );
        }

        let hash = sha256_array(bytes);
        let score = self
            .image_scores
            .lock()
            .ok()
            .and_then(|cache| cache.get(&hash))
            .unwrap_or_else(|| {
                let score = self.nsfw.score(bytes);
                if score.is_finite() {
                    if let Ok(mut cache) = self.image_scores.lock() {
                        cache.insert(hash, score);
                    }
                }
                score
            });
        if !score.is_finite() {
            return coverage_gap(request_id, "image model returned an invalid score");
        }

        // The cache stores only this model score. Category/action are recomputed on
        // every call, so policy changes are never frozen into cached content.
        let category = if score >= NSFW_BLOCK_THRESHOLD {
            Category::AdultImage
        } else {
            Category::Safe
        };
        let action = if category == Category::Safe {
            Action::Allow
        } else {
            Action::Block
        };
        let severity = if action == Action::Block {
            bulwark_proto::severity_for_score(score)
        } else {
            Severity::Info
        };
        Verdict {
            request_id,
            category: category as i32,
            action: action as i32,
            severity: severity as i32,
            score,
            rationale: format!(
                "local image model score {score:.3} vs threshold {NSFW_BLOCK_THRESHOLD:.2}"
            ),
            evidence: Some(build_image_evidence(category, bytes, self.nsfw.model_id())),
            ..Default::default()
        }
    }

    pub async fn handle_flow(
        &self,
        flow: bulwark_flow::CapturedFlow,
        interceptor: &dyn Interceptor,
    ) -> Result<()> {
        let _ = self.handle_flow_reporting(flow, interceptor).await?;
        Ok(())
    }

    pub async fn handle_flow_reporting(
        &self,
        flow: bulwark_flow::CapturedFlow,
        interceptor: &dyn Interceptor,
    ) -> Result<Vec<BlockReport>> {
        let flow_id = flow.flow_id;
        let source_channel = flow.source_channel;
        let host = flow.app_or_host.clone();
        let units = self.classifier.classify(flow).await?;
        let mut reports = Vec::new();

        for unit in &units {
            let verdict = self.analyze(unit).await;
            let rewrite = (!verdict.remediated_media.is_empty())
                .then(|| verdict.remediated_media.clone());
            let ctx = bulwark_policy::PolicyContext {
                device: self.cfg.device_id.clone().into(),
                source_channel,
                age_profile: self.age_profile,
            };
            let action = self.policy.decide(&verdict, &ctx);
            let alert_kind = self.policy.alert_for(&verdict, action, &ctx);

            interceptor
                .apply(flow_id, action_to_decision(action, rewrite.clone()))
                .await?;

            if let AnalysisUnit::VideoSegment {
                segment_id: Some(segment_id),
                ..
            } = unit
            {
                if let Err(error) = self
                    .classifier
                    .apply(*segment_id, action, rewrite.clone().map(Into::into))
                {
                    tracing::warn!(%error, segment_id, "failed to release buffered video segment");
                }
            }

            if action == Action::Block {
                reports.push(BlockReport {
                    host: host.clone(),
                    category: verdict.category(),
                    score: verdict.score,
                });
            }

            if let (Some(sink), Some(kind)) = (&self.alert, alert_kind) {
                let event = build_alert(&self.cfg.device_id, &host, &verdict, kind);
                if let Err(error) = sink.raise(event).await {
                    tracing::error!(%error, "filtering succeeded but guardian alert delivery failed");
                }
            }

            if let Some(store) = &self.store {
                if let Err(error) = store
                    .record(bulwark_store::StoredEvent {
                        device: self.cfg.device_id.clone().into(),
                        verdict: verdict.clone(),
                        action,
                        alert: alert_kind,
                        ts: span_now(),
                    })
                    .await
                {
                    tracing::warn!(%error, "redacted local audit write failed");
                }
            }
        }
        Ok(reports)
    }

    pub async fn run(&self, interceptor: Arc<dyn Interceptor>) -> Result<()> {
        while let Some(flow) = interceptor.next_flow().await? {
            let flow_id = flow.flow_id;
            if let Err(error) = self.handle_flow(flow, interceptor.as_ref()).await {
                tracing::error!(%error, flow_id, "flow processing failed; dropping flow conservatively");
                if let Err(drop_error) = interceptor.apply(flow_id, InterceptDecision::Drop).await {
                    tracing::error!(%drop_error, flow_id, "failed to apply conservative drop after pipeline error");
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct BlockReport {
    pub host: String,
    pub category: Category,
    pub score: f32,
}

fn build_alert(
    device_id: &str,
    host: &str,
    verdict: &Verdict,
    kind: AlertKind,
) -> bulwark_proto::v1::AlertEvent {
    bulwark_proto::v1::AlertEvent {
        alert_id: format!("{}-{}", device_id, verdict.request_id),
        kind: kind as i32,
        category: verdict.category,
        severity: verdict.severity,
        app: host.to_string(),
        device_id: device_id.to_string(),
        ts: span_now(),
        redacted_context: verdict.rationale.clone(),
        evidence: verdict.evidence.clone(),
        local_segment_uri: verdict.local_segment_uri.clone(),
        ..Default::default()
    }
}

fn span_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn build_nsfw_scorer() -> Box<dyn Scorer> {
    #[cfg(feature = "onnx")]
    {
        match bulwark_vision::onnx::OnnxScorer::from_env(NSFW_INPUT_SIZE) {
            Ok(scorer) => {
                tracing::info!(model = %scorer.model_id(), "local ONNX image scorer active");
                return Box::new(scorer);
            }
            Err(error) => {
                tracing::error!(%error, "no usable image model; images will be blocked as uncovered");
            }
        }
    }
    #[cfg(not(feature = "onnx"))]
    tracing::error!("client built without ONNX image coverage; images will be blocked as uncovered");
    Box::new(bulwark_vision::StubScorer)
}

/// Evidence defaults to hash-only. A downscaled copy is not automatically safe;
/// adding guardian previews requires a separately verified redaction/safety stage.
fn build_image_evidence(_category: Category, image_bytes: &[u8], model_id: &str) -> Evidence {
    Evidence {
        sha256: sha256(image_bytes),
        safe_thumbnail: Vec::new(),
        model_id: model_id.to_string(),
        ..Default::default()
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref().try_into().unwrap_or([0u8; 32])
}

fn kind_tag(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Audio => "audio",
        MediaKind::Image => "img",
        MediaKind::Video => "video",
        _ => "media",
    }
}

fn short_hash_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let hash = sha256_array(bytes);
    let mut value = String::with_capacity(16);
    for byte in &hash[..8] {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_gap_is_never_safe() {
        let verdict = coverage_gap("r", "missing model");
        assert_eq!(verdict.category(), Category::Unspecified);
        assert_eq!(verdict.action(), Action::Block);
    }

    #[test]
    fn score_cache_is_bounded() {
        let mut cache = ImageScoreCache::new(2);
        cache.insert([1; 32], 0.1);
        cache.insert([2; 32], 0.2);
        cache.insert([3; 32], 0.3);
        assert!(cache.get(&[1; 32]).is_none());
        assert_eq!(cache.scores.len(), 2);
    }

    #[test]
    fn blocked_images_are_hash_only_by_default() {
        let evidence = build_image_evidence(Category::AdultImage, b"bytes", "m");
        assert_eq!(evidence.sha256.len(), 32);
        assert!(evidence.safe_thumbnail.is_empty());
    }
}
