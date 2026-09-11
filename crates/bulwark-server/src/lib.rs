//! bulwark-server — authenticated analysis + family-safety backend.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bulwark_core::{Analyzer, Result as CoreResult};
use bulwark_proto::v1::{
    analysis_request::Media, AnalysisRequest, DeviceProfile, ExecutionProvider, MediaKind,
    OffloadPolicy, Verdict,
};

pub mod accounts;
pub mod auth;
pub mod child_control;
pub mod family_safety;
pub mod persist;
pub mod relay;
pub mod reset_mailer;
pub mod safety_cases;
pub mod service;
pub mod staff;
pub mod tamper;
pub mod wg_provision;

pub use accounts::{AccountStore, AccountsService};
pub use auth::{authenticate_device, authenticate_device_metadata, DevicePrincipal};
pub use child_control::{ChildConfigStore, ChildControlService};
pub use family_safety::{FamilySafetyService, SafetyBroadcastStore};
pub use relay::{AlertHub, ReviewService};
pub use reset_mailer::ResetMailer;
pub use safety_cases::SafetyCaseStore;
pub use staff::{StaffAdminService, StaffStore};
pub use tamper::TamperService;
pub use wg_provision::{WgPeerStore, WgProvisionService};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRole {
    Lb,
    Worker,
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
    pub bind: String,
    pub tls_cert_pem: Option<Vec<u8>>,
    pub tls_key_pem: Option<Vec<u8>>,
    pub client_ca_pem: Option<Vec<u8>>,
    pub accounts_enabled: bool,
    pub state_dir: Option<std::path::PathBuf>,
    pub staff_enabled: bool,
    /// Production is intentionally stricter than dev: enrolled identities,
    /// mTLS, durable state, no legacy unscoped review path, and no public
    /// ClusterControl surface are mandatory.
    pub production_mode: bool,
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
            staff_enabled: false,
            production_mode: false,
        }
    }
}

#[derive(Default, Clone)]
pub struct AnalyzerRegistry {
    by_kind: HashMap<i32, Arc<dyn Analyzer>>,
}

impl AnalyzerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, analyzer: Arc<dyn Analyzer>) -> &mut Self {
        for kind in analyzer.handles() {
            self.by_kind.insert(*kind as i32, analyzer.clone());
        }
        self
    }

    pub fn analyzer_for(&self, kind: i32) -> Option<Arc<dyn Analyzer>> {
        self.by_kind.get(&kind).cloned()
    }

    pub fn with_text() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(TextAnalyzerAdapter::new()));
        registry
    }

    /// Production video retention is wrapped OUTSIDE VideoAnalyzer so ownership
    /// comes from AnalysisRequest.device_id and never from a process-global store
    /// assumption. SegmentStore itself defaults to retention-disabled.
    pub fn with_text_and_video(store: Option<bulwark_video::SegmentStore>) -> Self {
        let mut registry = Self::with_text();

        #[cfg(feature = "ffmpeg")]
        let mut video = bulwark_video::VideoAnalyzer::with_demuxer(
            bulwark_video::VideoConfig::default(),
            bulwark_video::ffmpeg::FfmpegDemuxer::new(),
        );
        #[cfg(not(feature = "ffmpeg"))]
        let mut video = bulwark_video::VideoAnalyzer::new();

        #[cfg(feature = "whisper")]
        if let Some(stt) = bulwark_audio::whisper::WhisperTranscriber::from_env() {
            video = video.with_audio_transcriber(Box::new(stt));
        }

        let mut video: Arc<dyn Analyzer> = Arc::new(video);
        if let Some(store) = store {
            video = Arc::new(RetainingVideoAnalyzer { inner: video, store });
        }
        registry.register(video);

        #[cfg(feature = "onnx")]
        registry.register(Arc::new(bulwark_vision::VisionAnalyzer::from_env(
            bulwark_vision::VisionConfig::default(),
        )));

        #[cfg(feature = "whisper")]
        {
            use bulwark_audio::whisper::WhisperTranscriber;
            use bulwark_audio::AudioAnalyzer;
            let audio: Arc<dyn Analyzer> = match WhisperTranscriber::from_env() {
                Some(stt) => Arc::new(AudioAnalyzer::with_transcriber(stt)),
                None => Arc::new(AudioAnalyzer::new()),
            };
            registry.register(audio);
        }

        registry
    }
}

struct RetainingVideoAnalyzer {
    inner: Arc<dyn Analyzer>,
    store: bulwark_video::SegmentStore,
}

#[async_trait]
impl Analyzer for RetainingVideoAnalyzer {
    fn handles(&self) -> &[MediaKind] {
        const KINDS: [MediaKind; 1] = [MediaKind::Video];
        &KINDS
    }

    async fn analyze(&self, req: AnalysisRequest) -> CoreResult<Verdict> {
        let request_id = req.request_id.clone();
        let device_id = req.device_id.trim().to_string();
        let segment = match req.media.as_ref() {
            Some(Media::InlineMedia(media)) => media.data.clone(),
            _ => Vec::new(),
        };

        let mut verdict = self.inner.analyze(req).await?;
        if !device_id.is_empty() && !segment.is_empty() {
            let owner = bulwark_video::store::SegmentOwner {
                device_id,
                alert_id: request_id,
                ..Default::default()
            };
            match self.store.store_scoped_if_allowed(
                &owner,
                verdict.category(),
                verdict.action(),
                &segment,
            ) {
                Ok(Some(stored)) => verdict.local_segment_uri = stored.uri,
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "review clip retention failed; verdict still enforced")
                }
            }
        }
        Ok(verdict)
    }
}

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
        Ok(self.inner.analyze_span(&req.request_id, &span, req.ts))
    }
}

pub fn default_offload_policy(profile: &DeviceProfile) -> OffloadPolicy {
    let is_mobile = matches!(profile.platform.as_str(), "android" | "ios");
    let has_gpu = profile.exec_providers.iter().any(|provider| {
        *provider != ExecutionProvider::Cpu as i32
            && *provider != ExecutionProvider::Unspecified as i32
    });
    OffloadPolicy {
        run_text_local: true,
        run_image_local: has_gpu && !is_mobile,
        run_audio_local: has_gpu && !is_mobile,
        run_video_local: false,
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
        let profile = DeviceProfile {
            platform: "android".into(),
            exec_providers: vec![
                ExecutionProvider::Nnapi as i32,
                ExecutionProvider::Cpu as i32,
            ],
            ..Default::default()
        };
        let policy = default_offload_policy(&profile);
        assert!(policy.run_text_local);
        assert!(!policy.run_video_local);
        assert!(!policy.run_image_local);
    }

    #[tokio::test]
    async fn registry_dispatches_text() {
        let registry = AnalyzerRegistry::with_text();
        assert!(registry.analyzer_for(MediaKind::Text as i32).is_some());
        assert!(registry.analyzer_for(MediaKind::Video as i32).is_none());
    }

    #[test]
    fn production_is_explicit() {
        let cfg = ServerConfig::default();
        assert!(!cfg.accounts_enabled);
        assert!(!cfg.production_mode);
    }

    #[tokio::test]
    async fn registry_with_video_dispatches_text_and_video() {
        let registry = AnalyzerRegistry::with_text_and_video(None);
        assert!(registry.analyzer_for(MediaKind::Text as i32).is_some());
        assert!(registry.analyzer_for(MediaKind::Video as i32).is_some());
    }
}
