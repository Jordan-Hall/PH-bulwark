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
//! NOTE: `CapturedFlow`/`FlowPayload` are now canonical in `aegis-core::flow`
//! (re-exported by `aegis-net` and `aegis-flow`), so the interceptor's output
//! feeds the classifier directly — no adapter needed. The per-crate `Analyzer`
//! trait copies still want hoisting into `aegis-core` (docs/integration-todo.md §1).
//!
//! `#![forbid(unsafe_code)]`. No AI beyond the small dedicated analyzers; text
//! analysis is the deterministic rule engine and always runs locally.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aegis_core::{Analyzer, Result};
use aegis_flow::{AnalysisUnit, DefaultFlowClassifier, FlowClassifier};
use aegis_net::{InterceptDecision, Interceptor};
use aegis_policy::PolicyEngine; // trait providing Policy::decide / Policy::alert_for
use aegis_proto::v1::{
    analysis_request::Media, Action, AlertKind, AnalysisRequest, Category, Evidence, InlineMedia,
    MediaKind, Severity, Verdict,
};
pub use aegis_video::SegmentStore;
use aegis_vision::Scorer;

/// NSFW probability at/above which a still image is blocked. Matches the
/// `aegis-vision` default threshold so the device-side fast path and any cluster
/// path band identically.
const NSFW_BLOCK_THRESHOLD: f32 = 0.7;

/// Square edge (px) the local NSFW model expects (ViT/MobileNet NSFW cards).
/// Only referenced when the real ONNX scorer is compiled in (`onnx` feature).
#[cfg(feature = "onnx")]
const NSFW_INPUT_SIZE: u32 = 224;

/// Longest edge (px) of the SAFE preview re-encoded into a non-CSAM block alert.
const PREVIEW_MAX_EDGE: u32 = 256;

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

/// The cached outcome of scoring one image, keyed by its content hash. We cache
/// the policy-relevant verdict primitives (the decision triple) so a repeat of
/// the SAME image bytes is answered instantly without re-running the model — this
/// is the "hash everything we block or allow" the owner asked for. Evidence
/// (thumbnail/hash) is rebuilt cheaply per hit from the same bytes.
type ImageDecision = (Action, Category, f32);

/// A SAFE/Allow verdict for an un-analysed (or errored) heavy-media unit. We fail
/// OPEN — an analyzer we can't run must never silently block legitimate traffic;
/// the `rationale` records the gap for the coverage dashboard.
fn fail_open_verdict(rationale: &str) -> Verdict {
    Verdict {
        category: Category::Safe as i32,
        action: Action::Allow as i32,
        rationale: rationale.to_string(),
        ..Default::default()
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
    /// Local NSFW image scorer. Real (`OnnxScorer`) only with the `onnx` feature
    /// AND a model at `AEGIS_NSFW_MODEL`; otherwise the fail-OPEN stub (score 0.0
    /// → Allow), so the default build classifies images but never false-blocks.
    nsfw: Box<dyn Scorer>,
    /// Buffered-video analyzer for `VideoSegment` units. `None` → video fails open
    /// (default), matching the audio seam. When set (see [`Pipeline::with_segment_store`]
    /// / [`Pipeline::with_video_analyzer`]) a blocked/borderline NON-CSAM segment is
    /// retained locally and its `blob://` ref rides on the verdict's
    /// `local_segment_uri` so the guardian app can replay the clip.
    video: Option<Arc<dyn Analyzer>>,
    /// Process-wide CONTENT-HASH decision cache: sha256(image bytes) → the
    /// scored decision triple. The same image is never re-scored — a hit returns
    /// the cached verdict instantly (no model run), which makes repeated imagery
    /// (logos, hero shots, anything re-fetched) effectively free and is the
    /// "hash everything we block or allow" the owner asked for.
    image_cache: Mutex<HashMap<[u8; 32], ImageDecision>>,
}

impl Pipeline {
    pub fn new(cfg: ClientConfig) -> Self {
        Self {
            cfg,
            classifier: DefaultFlowClassifier::with_defaults(),
            text: aegis_text::TextAnalyzer::new().expect("aegis-text built-in lexicon must load"),
            policy: aegis_policy::Policy::default(),
            age_profile: aegis_policy::AgeProfile::default(),
            alert: None,
            store: None,
            nsfw: build_nsfw_scorer(),
            video: None,
            image_cache: Mutex::new(HashMap::new()),
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

    /// Route `VideoSegment` units through `analyzer` (any [`aegis_core::Analyzer`]
    /// handling `MediaKind::VIDEO`). Primarily for tests / custom dispatch; most
    /// callers want [`Pipeline::with_segment_store`].
    pub fn with_video_analyzer(mut self, analyzer: Arc<dyn Analyzer>) -> Self {
        self.video = Some(analyzer);
        self
    }

    /// Enable buffered-video analysis backed by a local [`SegmentStore`]: blocked
    /// /borderline NON-CSAM segments are retained so the guardian app can replay
    /// them (the `blob://` ref is propagated on `verdict.local_segment_uri`). Uses
    /// the default [`aegis_video::VideoAnalyzer`]; real frame/audio sampling needs
    /// the `ffmpeg`/`onnx` features (otherwise the segment fails open, unstored).
    pub fn with_segment_store(mut self, store: SegmentStore) -> Self {
        self.video = Some(Arc::new(
            aegis_video::VideoAnalyzer::new().with_segment_store(store),
        ));
        self
    }

    /// Override the local NSFW scorer. Primarily for tests (inject a deterministic
    /// scorer); production uses the env-selected scorer from [`Pipeline::new`].
    pub fn with_nsfw_scorer(mut self, scorer: Box<dyn Scorer>) -> Self {
        self.nsfw = scorer;
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
            // Still images are scored LOCALLY by the small NSFW model (no cluster
            // round-trip, no raw media leaves the device). A high score blocks the
            // image and attaches a SAFE downscaled preview (non-CSAM only).
            AnalysisUnit::Image(media) => self.analyze_image(media),
            // A buffered video segment → the video analyzer (when configured via
            // `with_segment_store`/`with_video_analyzer`): it samples frames/audio
            // and, on a blocked/borderline NON-CSAM verdict, retains the clip and
            // sets `local_segment_uri`. Unconfigured → fail open (audio seam below).
            AnalysisUnit::VideoSegment { media, .. } => match &self.video {
                Some(analyzer) => self.analyze_video(analyzer.as_ref(), media).await,
                None => fail_open_verdict("video analyzer not configured (fail open)"),
            },
            // SEAM: route AUDIO to the cluster (aegis-infer OffloadRouter →
            // Analysis.Analyze). Until the cluster client is wired, fail open.
            _ => fail_open_verdict("heavy-media cluster path not yet wired"),
        }
    }

    /// Run a `VideoSegment` through `analyzer` and propagate its verdict. A failed
    /// analysis fails OPEN (never blocks on an analyzer error) and logs the gap.
    async fn analyze_video(&self, analyzer: &dyn Analyzer, media: &InlineMedia) -> Verdict {
        let req = AnalysisRequest {
            request_id: format!("{}-video", self.cfg.device_id),
            media_kind: MediaKind::Video as i32,
            media: Some(Media::InlineMedia(media.clone())),
            ..Default::default()
        };
        match analyzer.analyze(req).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "aegis-client: video analysis failed; failing open");
                fail_open_verdict("video analysis error (fail open)")
            }
        }
    }

    /// Score a still image locally and build its verdict.
    ///
    /// A score `>= NSFW_BLOCK_THRESHOLD` → [`Category::AdultImage`] +
    /// [`Action::Block`]; otherwise SAFE/Allow. On a NON-CSAM block we attach a
    /// small re-encoded preview of the blocked image in `Evidence.safe_thumbnail`
    /// so the parent alert can show WHAT was blocked.
    ///
    /// HARD LEGAL RULE: suspected CSAM ([`Category::CsamSuspected`]) NEVER has its
    /// bytes previewed — `safe_thumbnail` stays EMPTY. The local NSFW model only
    /// emits `AdultImage`, but [`build_image_evidence`] gates the thumbnail on the
    /// category unconditionally so the guarantee holds for any future scorer too.
    fn analyze_image(&self, media: &InlineMedia) -> Verdict {
        let bytes = &media.data;
        let hash = sha256_array(bytes);

        // SEAM: a persisted, parent-APPROVED allowlist (aegis-policy::allowlist,
        // keyed by this same content hash) should be consulted FIRST here — when
        // a guardian taps "Approve" on a blocked image in the parent app, that
        // hash is recorded and any future fetch of the identical bytes is allowed
        // without re-scoring. The cross-process allowlist sync is a later pass;
        // for now the in-process cache below provides the same shape (hash →
        // decision) so wiring the allowlist is a drop-in replacement of this read.
        // e.g.:  if let Some(v) = self.allowlist.approved(&hash) { return allow_verdict(...); }

        // CONTENT-HASH DECISION CACHE: a repeat of the same image bytes returns
        // the cached decision instantly — no model run. "Hash everything."
        if let Some(cached) = self.cached_decision(&hash) {
            return self.image_verdict_from(cached, bytes);
        }

        // Miss → score once, store the decision keyed by hash, then build it.
        let score = self.nsfw.score(bytes);
        let nsfw = score >= NSFW_BLOCK_THRESHOLD;
        let category = if nsfw {
            Category::AdultImage
        } else {
            Category::Safe
        };
        let action = if nsfw { Action::Block } else { Action::Allow };
        let decision: ImageDecision = (action, category, score);
        self.cache_store(hash, decision);

        self.image_verdict_from(decision, bytes)
    }

    /// Build an image [`Verdict`] from a (possibly cached) decision triple and the
    /// original bytes. Evidence (hash + SAFE thumbnail, CSAM-gated) is rebuilt from
    /// the bytes so a cache hit yields an identical verdict to a fresh score.
    fn image_verdict_from(&self, decision: ImageDecision, bytes: &[u8]) -> Verdict {
        let (action, category, score) = decision;
        let severity = if action == Action::Block {
            aegis_proto::severity_for_score(score)
        } else {
            Severity::Info
        };
        let evidence = build_image_evidence(category, bytes, self.nsfw.model_id());
        Verdict {
            request_id: format!("{}-img", self.cfg.device_id),
            category: category as i32,
            action: action as i32,
            severity: severity as i32,
            score,
            rationale: format!(
                "local nsfw score {score:.3} vs threshold {NSFW_BLOCK_THRESHOLD:.2}"
            ),
            evidence: Some(evidence),
            ..Default::default()
        }
    }

    /// Store a freshly-scored image decision under its content hash.
    fn cache_store(&self, hash: [u8; 32], decision: ImageDecision) {
        if let Ok(mut map) = self.image_cache.lock() {
            map.insert(hash, decision);
        }
    }

    /// Copy out a cached decision for `hash`, if present (lock held briefly).
    fn cached_decision(&self, hash: &[u8; 32]) -> Option<ImageDecision> {
        self.image_cache.lock().ok()?.get(hash).copied()
    }

    /// Run one captured flow all the way through and return the actions applied.
    pub async fn handle_flow(
        &self,
        flow: aegis_flow::CapturedFlow,
        interceptor: &dyn Interceptor,
    ) -> Result<()> {
        let _ = self.handle_flow_reporting(flow, interceptor).await?;
        Ok(())
    }

    /// Like [`handle_flow`](Self::handle_flow) but returns a [`BlockReport`] for
    /// every unit that was BLOCKED, so a caller (the runnable proxy) can print /
    /// relay per-block detail (host + category + score) without re-deriving it.
    pub async fn handle_flow_reporting(
        &self,
        flow: aegis_flow::CapturedFlow,
        interceptor: &dyn Interceptor,
    ) -> Result<Vec<BlockReport>> {
        let flow_id = flow.flow_id;
        let source_channel = flow.source_channel;
        let host = flow.app_or_host.clone();
        let units = self.classifier.classify(flow).await?;

        let mut reports = Vec::new();
        for unit in &units {
            let verdict = self.analyze(unit).await;

            let ctx = aegis_policy::PolicyContext {
                device: self.cfg.device_id.clone().into(),
                source_channel,
                age_profile: self.age_profile,
            };
            let action = self.policy.decide(&verdict, &ctx);
            let alert_kind = self.policy.alert_for(&verdict, action, &ctx);

            interceptor
                .apply(flow_id, action_to_decision(action, None))
                .await?;

            if action == Action::Block {
                reports.push(BlockReport {
                    host: host.clone(),
                    category: Category::try_from(verdict.category).unwrap_or(Category::Unspecified),
                    score: verdict.score,
                });
            }

            if let (Some(sink), Some(kind)) = (&self.alert, alert_kind) {
                let event = build_alert(&self.cfg.device_id, &host, &verdict, kind);
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
        Ok(reports)
    }

    /// The main loop: pull flows from the interceptor and process them until
    /// shutdown. The interceptor must already be `start()`ed.
    pub async fn run(&self, interceptor: Arc<dyn Interceptor>) -> Result<()> {
        // net + flow now share aegis_core::flow::CapturedFlow, so the
        // interceptor's output feeds the classifier directly (no adapter).
        while let Some(flow) = interceptor.next_flow().await? {
            if let Err(e) = self.handle_flow(flow, interceptor.as_ref()).await {
                tracing::warn!(error = %e, "flow handling failed; failing open");
            }
        }
        Ok(())
    }
}

/// A single BLOCK outcome surfaced to the runnable proxy for printing / relaying.
#[derive(Clone, Debug)]
pub struct BlockReport {
    /// Host the blocked flow belonged to (may be empty on a response-leg flow).
    pub host: String,
    /// The category that triggered the block.
    pub category: Category,
    /// The analyzer's normalized score (0.0–1.0).
    pub score: f32,
}

fn build_alert(
    device_id: &str,
    host: &str,
    verdict: &Verdict,
    kind: AlertKind,
) -> aegis_proto::v1::AlertEvent {
    aegis_proto::v1::AlertEvent {
        alert_id: format!("{}-{}", device_id, verdict.request_id),
        kind: kind as i32,
        category: verdict.category,
        severity: verdict.severity,
        app: host.to_string(),
        device_id: device_id.to_string(),
        ts: span_now(),
        // redacted summary only — never raw content (Evidence carries hashes/safe thumb).
        redacted_context: verdict.rationale.clone(),
        evidence: verdict.evidence.clone(),
        // Carry the local video-segment ref (if the analyzer stored one) so the
        // guardian app can replay the blocked clip from local storage.
        local_segment_uri: verdict.local_segment_uri.clone(),
        // child_id/family_id are resolved cluster-side from device_id (the client
        // doesn't hold the family model); leave empty here.
        ..Default::default()
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

/// Build the local NSFW scorer for this build:
/// * `--features onnx` + a model at `AEGIS_NSFW_MODEL` that loads → real
///   [`OnnxScorer`](aegis_vision::onnx::OnnxScorer).
/// * otherwise → the fail-OPEN [`StubScorer`](aegis_vision::StubScorer) (0.0 →
///   Allow), so the default build (and any host that can't load `onnxruntime.dll`)
///   stays green and never false-blocks.
fn build_nsfw_scorer() -> Box<dyn Scorer> {
    #[cfg(feature = "onnx")]
    {
        match aegis_vision::onnx::OnnxScorer::from_env(NSFW_INPUT_SIZE) {
            Ok(scorer) => {
                tracing::info!(
                    model = %scorer.model_id(),
                    "aegis-client: local ONNX NSFW scorer active"
                );
                return Box::new(scorer);
            }
            Err(e) => {
                tracing::warn!(
                    "aegis-client: no usable NSFW model ({e}); image scoring fails OPEN (stub)"
                );
            }
        }
    }
    #[cfg(not(feature = "onnx"))]
    {
        tracing::warn!(
            "aegis-client: built without `onnx`; image scoring fails OPEN (stub). \
             Rebuild with --features onnx and set {} for real blocking.",
            aegis_vision::MODEL_PATH_ENV
        );
    }
    Box::new(aegis_vision::StubScorer)
}

/// Build the [`Evidence`] for an image verdict.
///
/// Always carries the content SHA-256 + model id. On a NON-CSAM block we ALSO
/// attach a small re-encoded preview in `safe_thumbnail` so the parent alert can
/// show what was blocked.
///
/// HARD LEGAL RULE: for [`Category::CsamSuspected`] the thumbnail stays EMPTY —
/// the raw image bytes are NEVER previewed, transmitted, or re-encoded. This is
/// enforced here so it holds regardless of how the category was derived.
fn build_image_evidence(category: Category, image_bytes: &[u8], model_id: &str) -> Evidence {
    let safe_thumbnail = match category {
        // NEVER preview suspected CSAM — block + hash + report path only.
        Category::CsamSuspected => Vec::new(),
        // For every OTHER blocking category, attach a downscaled preview so the
        // parent can see what was blocked. SAFE categories get no preview (nothing
        // was blocked) to avoid pointlessly re-encoding allowed traffic.
        Category::AdultImage => safe_preview(image_bytes).unwrap_or_default(),
        _ => Vec::new(),
    };
    Evidence {
        sha256: sha256(image_bytes),
        safe_thumbnail,
        model_id: model_id.to_string(),
        ..Default::default()
    }
}

/// Downscale `image_bytes` so its longest edge is at most [`PREVIEW_MAX_EDGE`]
/// and re-encode it as JPEG — a small SAFE preview for the live alert. Returns
/// `None` if the image can't be decoded (fail-safe: no preview rather than the
/// raw bytes). The preview is a fresh re-encode; the original bytes are never
/// passed through verbatim.
fn safe_preview(image_bytes: &[u8]) -> Option<Vec<u8>> {
    let img = image::load_from_memory(image_bytes).ok()?;
    let preview = img.thumbnail(PREVIEW_MAX_EDGE, PREVIEW_MAX_EDGE);
    let rgb = preview.to_rgb8();
    let mut out: Vec<u8> = Vec::new();
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 70);
    use image::ImageEncoder;
    encoder
        .write_image(
            rgb.as_raw(),
            rgb.width(),
            rgb.height(),
            image::ExtendedColorType::Rgb8,
        )
        .ok()?;
    Some(out)
}

/// SHA-256 of content, for `Evidence.sha256` (hash-only audit).
fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

/// SHA-256 of content as a fixed `[u8; 32]`, the key for the image decision cache
/// (and the future content-keyed allowlist). SHA-256 is always 32 bytes, so the
/// conversion never fails; we fall back to zeroes defensively rather than panic.
fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref().try_into().unwrap_or([0u8; 32])
}

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

    /// A deterministic scorer for tests.
    struct FixedScorer(f32);
    impl Scorer for FixedScorer {
        fn score(&self, _: &[u8]) -> f32 {
            self.0
        }
        fn model_id(&self) -> &str {
            "test-fixed"
        }
    }

    /// A scorer that counts how many times it actually ran, to prove the
    /// content-hash cache short-circuits a repeat of the same image.
    struct CountingScorer {
        score: f32,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl Scorer for CountingScorer {
        fn score(&self, _: &[u8]) -> f32 {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.score
        }
        fn model_id(&self) -> &str {
            "test-counting"
        }
    }

    /// A small valid PNG so the preview re-encoder has something to decode.
    fn tiny_png() -> Vec<u8> {
        let mut img = image::RgbImage::new(64, 48);
        for px in img.pixels_mut() {
            *px = image::Rgb([200, 120, 40]);
        }
        let mut out = Vec::new();
        use image::ImageEncoder;
        image::codecs::png::PngEncoder::new(&mut out)
            .write_image(img.as_raw(), 64, 48, image::ExtendedColorType::Rgb8)
            .unwrap();
        out
    }

    fn pipeline_with(score: f32) -> Pipeline {
        Pipeline::new(ClientConfig::default()).with_nsfw_scorer(Box::new(FixedScorer(score)))
    }

    #[tokio::test]
    async fn high_nsfw_score_blocks_with_adult_image_category() {
        let p = pipeline_with(0.95);
        let unit = AnalysisUnit::Image(InlineMedia {
            data: tiny_png(),
            mime_type: "image/png".into(),
            ..Default::default()
        });
        let v = p.analyze(&unit).await;
        assert_eq!(v.category, Category::AdultImage as i32);
        assert_eq!(v.action, Action::Block as i32);
        // A non-CSAM block carries a SAFE re-encoded preview.
        let ev = v.evidence.unwrap();
        assert_eq!(ev.sha256.len(), 32);
        assert!(
            !ev.safe_thumbnail.is_empty(),
            "non-CSAM block must attach a preview"
        );
        // The preview is a fresh JPEG re-encode (SOI marker), not the PNG input.
        assert_eq!(&ev.safe_thumbnail[..3], &[0xFF, 0xD8, 0xFF]);
    }

    #[tokio::test]
    async fn repeat_image_hits_cache_and_is_not_rescored() {
        let counting = Arc::new(CountingScorer {
            score: 0.95,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        // Box a thin forwarder so the Pipeline owns a Scorer while we keep the
        // Arc to inspect the call count.
        struct Fwd(Arc<CountingScorer>);
        impl Scorer for Fwd {
            fn score(&self, b: &[u8]) -> f32 {
                self.0.score(b)
            }
            fn model_id(&self) -> &str {
                self.0.model_id()
            }
        }
        let p = Pipeline::new(ClientConfig::default())
            .with_nsfw_scorer(Box::new(Fwd(counting.clone())));

        let unit = AnalysisUnit::Image(InlineMedia {
            data: tiny_png(),
            mime_type: "image/png".into(),
            ..Default::default()
        });

        let v1 = p.analyze(&unit).await;
        let v2 = p.analyze(&unit).await; // identical bytes → cache hit
        let v3 = p.analyze(&unit).await; // and again

        // The model ran EXACTLY once for three identical images.
        assert_eq!(
            counting.calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the same image must be scored only once (hash-cache hit)"
        );
        // Cached verdicts match the first (decision + score identical).
        assert_eq!(v2.category, v1.category);
        assert_eq!(v2.action, v1.action);
        assert_eq!(v2.score, v1.score);
        assert_eq!(v3.action, Action::Block as i32);
        // Evidence is still rebuilt on a hit (hash present, preview attached).
        assert_eq!(v2.evidence.as_ref().unwrap().sha256.len(), 32);
        assert!(!v2.evidence.unwrap().safe_thumbnail.is_empty());
    }

    #[tokio::test]
    async fn low_nsfw_score_allows_with_no_preview() {
        let p = pipeline_with(0.10);
        let unit = AnalysisUnit::Image(InlineMedia {
            data: tiny_png(),
            mime_type: "image/png".into(),
            ..Default::default()
        });
        let v = p.analyze(&unit).await;
        assert_eq!(v.category, Category::Safe as i32);
        assert_eq!(v.action, Action::Allow as i32);
        // Nothing blocked → no preview re-encoded.
        assert!(v.evidence.unwrap().safe_thumbnail.is_empty());
    }

    /// A `VideoSegment` is routed to the configured video analyzer, and the
    /// `blob://` segment ref it produces survives into the guardian `AlertEvent`
    /// (the parent `SegmentPlayer` resolves it). Uses a deterministic stub for the
    /// analyzer; the real store/CSAM-gating is covered in `aegis-video`.
    #[tokio::test]
    async fn video_segment_routes_to_analyzer_and_propagates_segment_uri() {
        let uri = format!("blob://{}", "a".repeat(64));

        struct StubVideo {
            uri: String,
        }
        #[async_trait::async_trait]
        impl Analyzer for StubVideo {
            fn handles(&self) -> &[MediaKind] {
                const K: [MediaKind; 1] = [MediaKind::Video];
                &K
            }
            async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
                assert_eq!(req.media_kind, MediaKind::Video as i32);
                Ok(Verdict {
                    request_id: req.request_id,
                    category: Category::AdultImage as i32,
                    action: Action::Block as i32,
                    local_segment_uri: self.uri.clone(),
                    ..Default::default()
                })
            }
        }

        let p = Pipeline::new(ClientConfig::default())
            .with_video_analyzer(Arc::new(StubVideo { uri: uri.clone() }));
        let unit = AnalysisUnit::VideoSegment {
            media: InlineMedia {
                data: vec![0u8; 8],
                mime_type: "video/mp4".into(),
                ..Default::default()
            },
            deadline_ms: 0,
            segment_id: None,
        };

        let v = p.analyze(&unit).await;
        assert_eq!(v.action, Action::Block as i32);
        assert_eq!(v.local_segment_uri, uri);

        // The ref must ride on the AlertEvent so the guardian app can replay it.
        let alert = build_alert("kids-tablet", "example.com", &v, AlertKind::Unspecified);
        assert_eq!(alert.local_segment_uri, uri);
    }

    /// With no video analyzer configured, a `VideoSegment` fails OPEN (allow, no
    /// segment ref) — an un-runnable analyzer must never block legitimate traffic.
    #[tokio::test]
    async fn video_segment_without_analyzer_fails_open() {
        let p = Pipeline::new(ClientConfig::default());
        let unit = AnalysisUnit::VideoSegment {
            media: InlineMedia {
                data: vec![0u8; 8],
                mime_type: "video/mp4".into(),
                ..Default::default()
            },
            deadline_ms: 0,
            segment_id: None,
        };
        let v = p.analyze(&unit).await;
        assert_eq!(v.action, Action::Allow as i32);
        assert!(v.local_segment_uri.is_empty());
    }

    #[test]
    fn csam_evidence_never_carries_a_thumbnail() {
        // HARD LEGAL RULE: even handed the (image) bytes, a CSAM-suspected verdict
        // leaves safe_thumbnail EMPTY — block + hash only, never a preview.
        let ev = build_image_evidence(Category::CsamSuspected, &tiny_png(), "test");
        assert_eq!(ev.sha256.len(), 32, "hash still recorded");
        assert!(ev.safe_thumbnail.is_empty(), "CSAM must NEVER be previewed");
    }

    #[test]
    fn adult_image_evidence_carries_a_reencoded_preview() {
        let ev = build_image_evidence(Category::AdultImage, &tiny_png(), "test");
        assert!(!ev.safe_thumbnail.is_empty());
        // JPEG SOI marker — a fresh re-encode.
        assert_eq!(&ev.safe_thumbnail[..3], &[0xFF, 0xD8, 0xFF]);
    }

    #[test]
    fn preview_is_downscaled_within_max_edge() {
        // A 64x48 source downscales so its longest edge is <= PREVIEW_MAX_EDGE.
        let prev = safe_preview(&tiny_png()).unwrap();
        let decoded = image::load_from_memory(&prev).unwrap();
        assert!(decoded.width() <= PREVIEW_MAX_EDGE && decoded.height() <= PREVIEW_MAX_EDGE);
    }

    #[test]
    fn preview_fails_safe_on_undecodable_bytes() {
        // Not an image → no preview (never the raw bytes).
        assert!(safe_preview(b"not an image at all").is_none());
    }
}
