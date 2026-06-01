//! The [`OffloadRouter`] trait and its default implementation.
//!
//! [`DefaultOffloadRouter`] wires the three seams together:
//! * the pure decision table ([`crate::policy::decide`]) — *where* a unit runs;
//! * a local [`Analyzer`] — the on-device first-pass when the decision is Local;
//! * an [`OffloadClient`] — the mTLS gRPC door to the cluster when it's Cluster.
//!
//! It caches the negotiated [`OffloadPolicy`] (until its TTL or an explicit
//! [`OffloadRouter::refresh`]) and applies it per unit against live RTT +
//! cluster backpressure. See `docs/design/interfaces.md` for the contract and
//! `architecture.md` §4 for the latency budget the rules implement.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use aegis_proto::v1::{
    AnalysisRequest, DeviceProfile, MediaKind, OffloadPolicy, RefreshOffloadRequest, Verdict,
};

use crate::analyzer::Analyzer;
use crate::client::OffloadClient;
use crate::error::{InferError, Result};
use crate::policy::{decide, LiveConditions, PolicySnapshot, Route};

/// Decides local vs. cluster per unit, negotiates + caches the
/// [`OffloadPolicy`], and is the client's single door to the `Analysis` /
/// `Offload` gRPC services. Mirrors the contract in
/// `docs/design/interfaces.md`.
#[async_trait]
pub trait OffloadRouter: Send + Sync {
    /// Negotiate an offload policy from this device's capabilities
    /// (the [`DeviceProfile`] built by `aegis-core`). Caches until TTL /
    /// [`OffloadRouter::refresh`].
    async fn negotiate(&self, profile: DeviceProfile) -> Result<OffloadPolicy>;

    /// Decide where a given unit runs, honouring the cached policy + live RTT
    /// + cluster backpressure (latency budget in architecture.md §4).
    fn route(&self, kind: MediaKind, rtt_ms: u32, queue_depth: u32) -> Route;

    /// Analyse a unit, transparently running locally or calling the cluster
    /// `Analysis` service per [`OffloadRouter::route`].
    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict>;

    /// Re-negotiate after TTL or a material capability change (battery, RTT).
    async fn refresh(&self, req: RefreshOffloadRequest) -> Result<OffloadPolicy>;
}

/// Mutable, per-device state the router carries between calls: the live
/// power/link conditions and the cached policy. Updated by `negotiate` /
/// `refresh` and by the client feeding fresh RTT/battery measurements.
#[derive(Clone, Debug, Default)]
struct RouterState {
    policy: Option<OffloadPolicy>,
    /// Battery snapshot (mirrors the profile's `battery_pct` / `on_battery`).
    battery_pct: i32,
    on_battery: bool,
}

/// The default [`OffloadRouter`]: cached policy + pure decision table + a local
/// analyzer + an mTLS offload client.
///
/// Construct with [`DefaultOffloadRouter::new`] (offload available) or
/// [`DefaultOffloadRouter::local_only`] (no cluster reachable — every routable
/// unit runs through the local analyzer, fail-safe).
pub struct DefaultOffloadRouter {
    /// On-device first-pass model seam.
    local: Arc<dyn Analyzer>,
    /// mTLS gRPC client; `None` for a local-only router.
    client: Option<OffloadClient>,
    /// Cached policy + live battery state.
    state: RwLock<RouterState>,
}

impl DefaultOffloadRouter {
    /// A router that can offload to the cluster via `client` and run a local
    /// first-pass via `local`.
    pub fn new(local: Arc<dyn Analyzer>, client: OffloadClient) -> Self {
        Self {
            local,
            client: Some(client),
            state: RwLock::new(RouterState::default()),
        }
    }

    /// A local-only router (no cluster). Every routable unit runs locally; this
    /// is the fail-safe posture when the cluster is unreachable.
    pub fn local_only(local: Arc<dyn Analyzer>) -> Self {
        Self {
            local,
            client: None,
            state: RwLock::new(RouterState {
                // With no cluster, force-local by making heavy work look "local"
                // and the link look infinitely slow.
                policy: Some(local_only_policy()),
                battery_pct: -1,
                on_battery: false,
            }),
        }
    }

    /// Seed the router with a pre-negotiated policy without a round trip (used
    /// when a policy was persisted across restarts, and by tests).
    pub fn with_cached_policy(self, policy: OffloadPolicy) -> Self {
        // Block-on-free: we own `self`, so this is a fresh lock with no waiters.
        self.state
            .try_write()
            .expect("fresh router state lock")
            .policy = Some(policy);
        self
    }

    /// Update the live battery snapshot the decision table reads (the client
    /// feeds this from `DeviceProfile` / platform probes between negotiations).
    pub async fn set_battery(&self, battery_pct: i32, on_battery: bool) {
        let mut st = self.state.write().await;
        st.battery_pct = battery_pct;
        st.on_battery = on_battery;
    }

    /// Snapshot the current cached policy, if any.
    pub async fn cached_policy(&self) -> Option<OffloadPolicy> {
        self.state.read().await.policy.clone()
    }

    /// The decision-table inputs from the current cached policy + live signals.
    /// Returns `None` when no policy has been negotiated yet.
    fn route_with_state(
        st: &RouterState,
        kind: MediaKind,
        rtt_ms: u32,
        queue_depth: u32,
    ) -> Option<Route> {
        let policy = st.policy.as_ref()?;
        let snap = PolicySnapshot::from_policy(policy);
        let live = LiveConditions {
            rtt_ms,
            queue_depth,
            battery_pct: st.battery_pct,
            on_battery: st.on_battery,
        };
        Some(decide(kind, &snap, &live))
    }
}

#[async_trait]
impl OffloadRouter for DefaultOffloadRouter {
    async fn negotiate(&self, profile: DeviceProfile) -> Result<OffloadPolicy> {
        // Remember the device's power state for routing decisions.
        {
            let mut st = self.state.write().await;
            st.battery_pct = profile.battery_pct;
            st.on_battery = profile.on_battery;
        }

        let policy = match &self.client {
            Some(client) => client.negotiate_offload(profile).await?,
            // Local-only: no cluster to negotiate with; keep the force-local policy.
            None => local_only_policy(),
        };

        self.state.write().await.policy = Some(policy.clone());
        Ok(policy)
    }

    fn route(&self, kind: MediaKind, rtt_ms: u32, queue_depth: u32) -> Route {
        // `route` is sync per the contract; read the cached state with a
        // best-effort non-blocking lock. If a writer holds it (a concurrent
        // negotiate/refresh) or no policy exists yet, fail safe to Local.
        match self.state.try_read() {
            Ok(st) => Self::route_with_state(&st, kind, rtt_ms, queue_depth)
                .unwrap_or(Route::Local),
            Err(_) => Route::Local,
        }
    }

    async fn analyze(&self, req: AnalysisRequest) -> Result<Verdict> {
        let kind = MediaKind::try_from(req.media_kind).unwrap_or(MediaKind::Unspecified);

        // Decide from a consistent snapshot of the cached policy + live battery.
        // `analyze` has no live RTT/queue arguments (the contract carries them on
        // `route`), so we pass the neutral 0/0 baseline here: the high-RTT and
        // backpressure rules do not fire, and the decision rests on the policy
        // hints + battery. Callers with fresh link/queue measurements should
        // consult `route(kind, rtt, queue)` and dispatch accordingly.
        let route = {
            let st = self.state.read().await;
            Self::route_with_state(&st, kind, 0, 0).unwrap_or(Route::Local)
        };

        match route {
            Route::Local => self.local.analyze(req).await,
            Route::Cluster => match &self.client {
                Some(client) => client.analyze(req).await,
                None => {
                    // No cluster: fall back to local rather than fail.
                    self.local.analyze(req).await
                }
            },
        }
    }

    async fn refresh(&self, req: RefreshOffloadRequest) -> Result<OffloadPolicy> {
        // Fold the fresh measurements into the live state first.
        {
            let mut st = self.state.write().await;
            st.battery_pct = req.battery_pct;
            st.on_battery = req.battery_pct >= 0; // best-effort: a real % implies battery
        }

        let policy = match &self.client {
            Some(client) => client.refresh_offload(req).await?,
            None => return Err(InferError::NoPolicy.into()),
        };

        self.state.write().await.policy = Some(policy.clone());
        Ok(policy)
    }
}

/// The synthetic "everything local" policy a local-only router holds: every kind
/// runs local, the RTT budget is zero (so any link looks too slow → local), and
/// there is no battery floor.
fn local_only_policy() -> OffloadPolicy {
    OffloadPolicy {
        run_text_local: true,
        run_image_local: true,
        run_audio_local: true,
        run_video_local: true,
        max_local_rtt_ms: 0,
        min_battery_pct: 0,
        cluster_queue_backpressure: 0,
        ttl_secs: 0,
        preferred_local_providers: Vec::new(),
        policy_id: "local-only".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::NullAnalyzer;
    use aegis_proto::v1::SourceChannel;

    fn mobile_policy() -> OffloadPolicy {
        OffloadPolicy {
            run_text_local: true,
            run_image_local: false,
            run_audio_local: false,
            run_video_local: false,
            max_local_rtt_ms: 60,
            min_battery_pct: 20,
            cluster_queue_backpressure: 50,
            ttl_secs: 120,
            preferred_local_providers: Vec::new(),
            policy_id: "mobile-1".into(),
        }
    }

    fn req(kind: MediaKind) -> AnalysisRequest {
        AnalysisRequest {
            request_id: "r".into(),
            media_kind: kind as i32,
            source_channel: SourceChannel::Web as i32,
            device_id: "d".into(),
            ts: 0,
            text_span: None,
            media: None,
            deadline_ms: 0,
        }
    }

    #[tokio::test]
    async fn route_falls_back_to_local_when_no_policy() {
        let r = DefaultOffloadRouter {
            local: Arc::new(NullAnalyzer),
            client: None,
            state: RwLock::new(RouterState::default()),
        };
        // No policy negotiated yet → fail safe to Local.
        assert_eq!(r.route(MediaKind::Image, 5, 0), Route::Local);
    }

    #[tokio::test]
    async fn route_uses_cached_policy_and_live_battery() {
        let r = DefaultOffloadRouter::local_only(Arc::new(NullAnalyzer))
            .with_cached_policy(mobile_policy());
        r.set_battery(10, true).await;

        // Mobile + low battery + fast link + idle cluster → image offloads.
        assert_eq!(r.route(MediaKind::Image, 10, 0), Route::Cluster);
        // Text always local.
        assert_eq!(r.route(MediaKind::Text, 10, 0), Route::Local);
        // High RTT forces local even for image.
        assert_eq!(r.route(MediaKind::Image, 200, 0), Route::Local);
        // Backpressure forces local.
        assert_eq!(r.route(MediaKind::Image, 10, 99), Route::Local);
    }

    #[tokio::test]
    async fn local_only_router_runs_everything_locally() {
        let r = DefaultOffloadRouter::local_only(Arc::new(NullAnalyzer));
        // Even heavy media routes Local with no cluster.
        assert_eq!(r.route(MediaKind::Video, 5, 0), Route::Local);
        // And analyze() succeeds via the local analyzer.
        let v = r.analyze(req(MediaKind::Image)).await.unwrap();
        assert_eq!(v.worker_id, "local:null");
    }

    #[tokio::test]
    async fn local_only_negotiate_keeps_force_local_policy() {
        let r = DefaultOffloadRouter::local_only(Arc::new(NullAnalyzer));
        let profile = DeviceProfile {
            battery_pct: 5,
            on_battery: true,
            ..Default::default()
        };
        let p = r.negotiate(profile).await.unwrap();
        assert_eq!(p.policy_id, "local-only");
        // Battery state was captured.
        assert_eq!(r.route(MediaKind::Video, 5, 0), Route::Local);
    }

    #[tokio::test]
    async fn refresh_without_cluster_errors() {
        let r = DefaultOffloadRouter::local_only(Arc::new(NullAnalyzer));
        let err = r
            .refresh(RefreshOffloadRequest {
                device_id: "d".into(),
                policy_id: "local-only".into(),
                rtt_ms: 10,
                battery_pct: 50,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, aegis_core::Error::Other(_)));
    }
}
