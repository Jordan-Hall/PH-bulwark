//! aegis-server — the clusterable analysis backend.
//!
//! One binary, three roles (`lb` | `worker` | `all-in-one`, see PLAN §1). It
//! hosts the gRPC services from `aegis-proto` over **mTLS** and dispatches
//! `AnalysisRequest`s by `media_kind` to the registered [`Analyzer`]s:
//!   * TEXT  → `aegis-text` (deterministic grooming rules; classifier optional)
//!   * IMAGE/AUDIO/VIDEO → `aegis-vision`/`-audio`/`-video` (registered when built)
//!
//! `all-in-one` additionally mounts `ClusterControl` (single-node) and
//! `AlertRelay`. No AI beyond the small dedicated analyzers. `#![forbid(unsafe_code)]`.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use aegis_core::{Analyzer, Result as CoreResult};
use aegis_proto::v1::{
    AnalysisRequest, DeviceProfile, ExecutionProvider, MediaKind, OffloadPolicy, Verdict,
};
use async_trait::async_trait;

pub mod accounts;
pub mod relay;
pub mod service;

pub use accounts::{AccountStore, AccountsService};
pub use relay::{AlertHub, ReviewService};

/// Which role this process plays. Chosen by `--role` / `AEGIS_ROLE`.
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
    /// mTLS material (PEM). When all three are set the server requires client
    /// certs; otherwise it binds plaintext (dev only — logged loudly).
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
    /// [`aegis_video::VideoAnalyzer`]). Without aegis-video's `ffmpeg` feature the
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
    pub fn with_text_and_video(store: Option<aegis_video::SegmentStore>) -> Self {
        let mut r = Self::with_text();
        let mut video = aegis_video::VideoAnalyzer::new();
        if let Some(store) = store {
            video = video.with_segment_store(store);
        }
        r.register(Arc::new(video));
        r
    }
}

/// Adapts `aegis-text` to the server [`Analyzer`] trait. TEXT only.
pub struct TextAnalyzerAdapter {
    inner: aegis_text::TextAnalyzer,
}

impl TextAnalyzerAdapter {
    pub fn new() -> Self {
        Self {
            inner: aegis_text::TextAnalyzer::new().expect("aegis-text built-in lexicon must load"),
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
        // Integration seam: aegis-text exposes `analyze_span(request_id, &TextSpan, ts)`.
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
