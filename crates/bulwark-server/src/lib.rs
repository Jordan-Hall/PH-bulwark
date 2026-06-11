//! bulwark-server — the clusterable analysis backend.
//!
//! One binary, three roles (`lb` | `worker` | `all-in-one`, see PLAN §1). It
//! hosts the gRPC services from `bulwark-proto` over **mTLS** and dispatches
//! `AnalysisRequest`s by `media_kind` to the registered [`Analyzer`]s:
//!   * TEXT  → `bulwark-text` (deterministic grooming rules; classifier optional)
//!   * IMAGE/AUDIO/VIDEO → `bulwark-vision`/`-audio`/`-video` (registered when built)
//!
//! `all-in-one` additionally mounts `ClusterControl` (single-node) and
//! `AlertRelay`. No AI beyond the small dedicated analyzers. `#![forbid(unsafe_code)]`.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bulwark_core::{Analyzer, Result as CoreResult};
use bulwark_proto::v1::{
    AnalysisRequest, DeviceProfile, ExecutionProvider, MediaKind, OffloadPolicy, Verdict,
};

pub mod accounts;
pub mod child_control;
pub mod persist;
pub mod relay;
pub mod reset_mailer;
pub mod service;
pub mod tamper;

pub use accounts::{AccountStore, AccountsService};
pub use child_control::{ChildConfigStore, ChildControlService};
pub use relay::{AlertHub, ReviewService};
pub use reset_mailer::ResetMailer;
pub use tamper::TamperService;

/// Which role this process plays. Chosen by `--role` / `BULWARK_ROLE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRole {
    /// Load balancer / gateway: terminates client mTLS, routes to workers.
    Lb,
    /// Analysis worker: runs the models, claims from the work queue.
    Worker,
    /// Home single-node: everything in one process.
    AllInOne,
}

impl ServerRole {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "lb" => Some(Self::Lb),
            "worker" => Some(Self::Worker),
            "all-in-one" | "all_in_one" | "allinone" => Some(Self::AllInOne),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub role: ServerRole,
    pub bind: String, // host:port
    /// Transport security material (PEM). cert+key → server-authenticated TLS;
    /// adding `client_ca_pem` also requires client certs (mTLS). None → plaintext
    /// (dev only — the binary refuses accounts mode without TLS material).
    pub tls_cert_pem: Option<Vec<u8>>,
    pub tls_key_pem: Option<Vec<u8>>,
    pub client_ca_pem: Option<Vec<u8>>,
    /// Enable parent ACCOUNTS mode: mount the Accounts service and scope
    /// Review (pending stream + decisions) to a guardian session token.
    ///
    /// Default `false` = legacy device-scoped relay: a client connects with an
    /// empty token and receives/decides alerts for its device (single-home / dev).
    /// Set `true` (productised multi-tenant) only once guardian sessions exist —
    /// otherwise the token check rejects every default empty-token client. See the
    /// round-3/round-7 review threads on PR #1.
    pub accounts_enabled: bool,
    /// When set (`BULWARK_STATE_DIR`), guardian accounts are persisted as JSON under
    /// this directory and reloaded on startup (the `persist` module). `None`
    /// (default) = pure in-memory, so dev/tests are unaffected.
    pub state_dir: Option<std::path::PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            role: ServerRole::AllInOne,
            bind: "127.0.0.1:8443".to_string(),
            tls_cert_pem: None,
            tls_key_pem: None,
            client_ca_pem: None,
            accounts_enabled: false,
            state_dir: None,
        }
    }
}

/// Dispatches by `MediaKind` to the registered analyzer.
#[derive(Default, Clone)]
pub struct AnalyzerRegistry {
    by_kind: HashMap<i32, Arc<dyn Analyzer>>,
}

impl AnalyzerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, analyzer: Arc<dyn Analyzer>) -> &mut Self {
        for k in analyzer.handles() {
            self.by_kind.insert(*k as i32, analyzer.clone());
        }
        self
    }

    pub fn analyzer_for(&self, kind: i32) -> Option<Arc<dyn Analyzer>> {
        self.by_kind.get(&kind).cloned()
    }

    /// All-in-one default wiring: text analysis is always available.
    pub fn with_text() -> Self {
        let mut r = Self::new();
        r.register(Arc::new(TextAnalyzerAdapter::new()));
        r
    }

    /// Default wiring plus buffered-video dispatch (`MediaKind::VIDEO` →
    /// [`bulwark_video::VideoAnalyzer`]). Without bulwark-video's `ffmpeg` feature the
    /// analyzer fails open, so registering it is safe; it makes the worker dispatch
    /// VIDEO units instead of returning "no analyzer".
    ///
    /// `store`: where blocked/borderline NON-CSAM clips are retained so a verdict
    /// can carry `local_segment_uri`. Pass `Some` ONLY when the reviewer (guardian
    /// app) can read that location — i.e. an **all-in-one** node where the parent
    /// app resolves `blob://` from the same disk. For a distributed worker the
    /// parent is remote and a local `blob://` is unreachable, so pass `None`
    /// (segment retention then stays the device-side client's job; remote video
    /// review needs a clip-fetch API — tracked as a follow-up).
    pub fn with_text_and_video(store: Option<bulwark_video::SegmentStore>) -> Self {
        let mut r = Self::with_text();
        // Decode + score real video frames/audio with the ffmpeg demuxer when built
        // with `ffmpeg` (the binary is provisioned at deploy); otherwise the
        // NullDemuxer leaves video undecoded → policy fail-CLOSES.
        #[cfg(feature = "ffmpeg")]
        let mut video = bulwark_video::VideoAnalyzer::with_demuxer(
            bulwark_video::VideoConfig::default(),
            bulwark_video::ffmpeg::FfmpegDemuxer::new(),
        );
        #[cfg(not(feature = "ffmpeg"))]
        let mut video = bulwark_video::VideoAnalyzer::new();
        if let Some(store) = store {
            video = video.with_segment_store(store);
        }
        // Transcribe the video's OWN audio track with whisper (same model as the
        // standalone audio analyzer). Needs `ffmpeg` to extract the windows; without a
        // model the video audio stays fail-CLOSED.
        #[cfg(feature = "whisper")]
        if let Some(stt) = bulwark_audio::whisper::WhisperTranscriber::from_env() {
            video = video.with_audio_transcriber(Box::new(stt));
        }
        r.register(Arc::new(video));
        // Real on-worker image NSFW scoring when built with `onnx` + a pinned model
        // (BULWARK_NSFW_MODEL). Without a model the vision analyzer emits Unspecified,
        // which policy fail-CLOSES — so IMAGE is never silently allowed. Without the
        // feature, IMAGE stays unregistered → also fail-closed via `inconclusive`.
        #[cfg(feature = "onnx")]
        r.register(Arc::new(bulwark_vision::VisionAnalyzer::from_env(
            bulwark_vision::VisionConfig::default(),
        )));
        // Real on-worker AUDIO scoring when built with `whisper` + a model
        // (BULWARK_WHISPER_MODEL): transcribe speech → bulwark-text. With no model the
        // analyzer emits Unspecified → policy fail-CLOSES; without the feature, AUDIO
        // stays unregistered → also fail-closed via `inconclusive`.
        #[cfg(feature = "whisper")]
        {
            use bulwark_audio::whisper::WhisperTranscriber;
            use bulwark_audio::AudioAnalyzer;
            let audio: Arc<dyn Analyzer> = match WhisperTranscriber::from_env() {
                Some(stt) => Arc::new(AudioAnalyzer::with_transcriber(stt)),
                None => Arc::new(AudioAnalyzer::new()),
            };
            r.register(audio);
        }
        r
    }
}

/// Adapts `bulwark-text` to the server [`Analyzer`] trait. TEXT only.
pub struct TextAnalyzerAdapter {
    inner: bulwark_text::TextAnalyzer,
}

impl TextAnalyzerAdapter {
    pub fn new() -> Self {
        Self {
            inner: bulwark_text::TextAnalyzer::new()
                .expect("bulwark-text built-in lexicon must load"),
        }
    }
}

impl Default for TextAnalyzerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Analyzer for TextAnalyzerAdapter {
    fn handles(&self) -> &[MediaKind] {
        const KINDS: [MediaKind; 1] = [MediaKind::Text];
        &KINDS
    }

    async fn analyze(&self, req: AnalysisRequest) -> CoreResult<Verdict> {
        let span = req.text_span.clone().unwrap_or_default();
        // Integration seam: bulwark-text exposes `analyze_span(request_id, &TextSpan, ts)`.
        Ok(self.inner.analyze_span(&req.request_id, &span, req.ts))
    }
}

/// Simple offload policy heuristic from a device profile. Mobile/low-power and
/// GPU-less devices offload heavy media; text always stays local.
pub fn default_offload_policy(profile: &DeviceProfile) -> OffloadPolicy {
    let is_mobile = matches!(profile.platform.as_str(), "android" | "ios");
    let has_gpu = profile.exec_providers.iter().any(|p| {
        *p != ExecutionProvider::Cpu as i32 && *p != ExecutionProvider::Unspecified as i32
    });
    OffloadPolicy {
        run_text_local: true, // grooming rules are cheap + explainable
        run_image_local: has_gpu && !is_mobile,
        run_audio_local: has_gpu && !is_mobile,
        run_video_local: false, // heavy: prefer cluster everywhere
        max_local_rtt_ms: 120,
        min_battery_pct: 20,
        cluster_queue_backpressure: 256,
        ttl_secs: 300,
        preferred_local_providers: profile.exec_providers.clone(),
        policy_id: format!("auto-{}", profile.device_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_parsing() {
        assert_eq!(ServerRole::parse("all-in-one"), Some(ServerRole::AllInOne));
        assert_eq!(ServerRole::parse("WORKER"), Some(ServerRole::Worker));
        assert_eq!(ServerRole::parse("nope"), None);
    }

    #[test]
    fn offload_policy_mobile_offloads_heavy_keeps_text_local() {
        let p = DeviceProfile {
            platform: "android".into(),
            exec_providers: vec![
                ExecutionProvider::Nnapi as i32,
                ExecutionProvider::Cpu as i32,
            ],
            ..Default::default()
        };
        let pol = default_offload_policy(&p);
        assert!(pol.run_text_local);
        assert!(!pol.run_video_local);
        assert!(!pol.run_image_local, "mobile should offload images");
    }

    #[tokio::test]
    async fn registry_dispatches_text() {
        let reg = AnalyzerRegistry::with_text();
        assert!(reg.analyzer_for(MediaKind::Text as i32).is_some());
        assert!(reg.analyzer_for(MediaKind::Video as i32).is_none());
    }

    #[test]
    fn accounts_mode_is_off_by_default() {
        // Safety default: a local/dev server must NOT require a guardian session
        // token, or a default empty-token client connects but never gets alerts
        // (the round-7 regression). Productised multi-tenant opts in explicitly.
        assert!(!ServerConfig::default().accounts_enabled);
    }

    #[tokio::test]
    async fn registry_with_video_dispatches_text_and_video() {
        let reg = AnalyzerRegistry::with_text_and_video(None);
        assert!(reg.analyzer_for(MediaKind::Text as i32).is_some());
        assert!(
            reg.analyzer_for(MediaKind::Video as i32).is_some(),
            "video units must dispatch to the video analyzer, not fall through"
        );
    }
}
