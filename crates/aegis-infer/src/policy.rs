//! The local-vs-cluster routing decision — pure, synchronous, unit-testable.
//!
//! This module holds the *decision table* the [`OffloadRouter`](crate::OffloadRouter)
//! applies per analysis unit. It takes the cached [`OffloadPolicy`] (negotiated
//! from this device's [`DeviceProfile`]), the live RTT, and the cluster's
//! estimated queue depth, and returns [`Route::Local`] or [`Route::Cluster`].
//!
//! It does **no I/O and runs no model** — it is exactly the predicate
//! `OffloadRouter::route` exposes, factored out so it can be exhaustively tested
//! and reasoned about. See the latency budget + guard-rails in
//! `docs/design/architecture.md` §4.
//!
//! ## Routing decision table
//!
//! Inputs: `kind` (MediaKind), the cached `OffloadPolicy`, live `rtt_ms`, live
//! cluster `queue_depth`, plus the device facts captured in the policy/profile.
//!
//! | Rule (in priority order) | Decision |
//! |---|---|
//! | `kind == TEXT` (grooming rules are cheap + explainable) | **always Local** |
//! | RTT `> max_local_rtt_ms` (link too slow to beat local) | **Local** |
//! | cluster `queue_depth > cluster_queue_backpressure` | **Local** |
//! | heavy media (IMAGE/AUDIO/VIDEO) AND `on_battery` below `min_battery_pct` | **Cluster** |
//! | heavy media AND policy hint says run-this-kind-local | **Local** |
//! | heavy media AND policy hint says offload (e.g. mobile/low-power) | **Cluster** |
//! | otherwise | **Local** (fail-safe: local-first, no network dependency) |
//!
//! The order matters: a slow link or a backpressured cluster forces **local**
//! *even for heavy media on a low battery* — degraded local analysis beats a
//! verdict that misses the deadline. Text never offloads regardless.

use aegis_proto::v1::{MediaKind, OffloadPolicy};

/// Where a single analysis unit should run.
///
/// Mirrors the `Route` enum in `docs/design/interfaces.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// Run the tiny first-pass model on-device (or the deterministic rules).
    Local,
    /// Offload to the cluster's `Analysis` service over mTLS.
    Cluster,
}

impl Route {
    /// True for [`Route::Local`].
    pub fn is_local(self) -> bool {
        matches!(self, Route::Local)
    }
}

/// Live, fast-changing inputs to a routing decision that are *not* baked into
/// the negotiated [`OffloadPolicy`]: the measured round-trip and the cluster's
/// current estimated queue depth (fed from `HealthStatus.queue_depth` via the
/// client). Battery is carried on the policy snapshot (see [`PolicySnapshot`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct LiveConditions {
    /// Most recent measured RTT to the cluster gateway, in milliseconds.
    pub rtt_ms: u32,
    /// Estimated cluster work-queue depth (backpressure signal).
    pub queue_depth: u32,
    /// Current battery percentage (`0..=100`), or `-1` if on mains / unknown.
    pub battery_pct: i32,
    /// Whether the device is currently on battery (vs. mains).
    pub on_battery: bool,
}

/// The pieces of the negotiated policy the decision table reads, decoupled from
/// the full proto message so the predicate is trivially testable. Built with
/// [`PolicySnapshot::from_policy`].
#[derive(Clone, Copy, Debug)]
pub struct PolicySnapshot {
    run_text_local: bool,
    run_image_local: bool,
    run_audio_local: bool,
    run_video_local: bool,
    max_local_rtt_ms: u32,
    min_battery_pct: u32,
    cluster_queue_backpressure: u32,
}

impl PolicySnapshot {
    /// Extract the routing-relevant fields from a negotiated [`OffloadPolicy`].
    pub fn from_policy(p: &OffloadPolicy) -> Self {
        PolicySnapshot {
            run_text_local: p.run_text_local,
            run_image_local: p.run_image_local,
            run_audio_local: p.run_audio_local,
            run_video_local: p.run_video_local,
            max_local_rtt_ms: p.max_local_rtt_ms,
            min_battery_pct: p.min_battery_pct,
            cluster_queue_backpressure: p.cluster_queue_backpressure,
        }
    }

    /// The policy's per-kind "run locally" hint for a heavy media kind.
    fn run_local_hint(&self, kind: MediaKind) -> bool {
        match kind {
            MediaKind::Text => true, // text is handled before this is consulted
            MediaKind::Image => self.run_image_local,
            MediaKind::Audio => self.run_audio_local,
            MediaKind::Video => self.run_video_local,
            MediaKind::Unspecified => self.run_text_local,
        }
    }
}

/// Whether a media kind is "heavy" (a candidate for offload). Text grooming
/// rules are always cheap and explainable → never heavy.
pub fn is_heavy(kind: MediaKind) -> bool {
    matches!(kind, MediaKind::Image | MediaKind::Audio | MediaKind::Video)
}

/// The routing decision table (see the module-level table for the full rules).
///
/// Pure and total: every input combination yields a [`Route`]. This is the body
/// of [`OffloadRouter::route`](crate::OffloadRouter::route).
pub fn decide(kind: MediaKind, policy: &PolicySnapshot, live: &LiveConditions) -> Route {
    // 1. Text always runs locally: the eight grooming indicator rules are cheap,
    //    deterministic, explainable, and feasible even on mobile (architecture.md
    //    §4 guard-rails). Only the *backing classifier* is ever a candidate for
    //    offload, and that path is driven separately by aegis-text.
    if kind == MediaKind::Text {
        return Route::Local;
    }

    // Non-heavy, non-text (e.g. UNSPECIFIED) → honour the text-local hint as a
    // conservative default; nothing here is worth a round trip on its own.
    if !is_heavy(kind) {
        return if policy.run_local_hint(kind) {
            Route::Local
        } else {
            Route::Cluster
        };
    }

    // --- Heavy media (IMAGE / AUDIO / VIDEO) from here down. ---

    // 2. Link too slow: if RTT already exceeds the local budget, the network
    //    round trip cannot beat running locally — prefer local even if slower.
    if live.rtt_ms > policy.max_local_rtt_ms {
        return Route::Local;
    }

    // 3. Cluster backpressured: a deep queue means an offload would sit waiting.
    //    Prefer local (architecture.md §4: queue_depth > backpressure → local).
    if live.queue_depth > policy.cluster_queue_backpressure {
        return Route::Local;
    }

    // 4. Low battery on a heavy kind: force-offload to spare the device. Only
    //    applies when actually on battery and below the floor (mains/unknown
    //    battery_pct < 0 never trips this).
    if live.on_battery
        && live.battery_pct >= 0
        && (live.battery_pct as u32) < policy.min_battery_pct
    {
        return Route::Cluster;
    }

    // 5. Otherwise honour the negotiated per-kind hint: a capable desktop runs
    //    more locally (run_*_local = true); a mobile/low-power profile offloads
    //    heavy work (run_*_local = false, set by the cluster from the profile).
    if policy.run_local_hint(kind) {
        Route::Local
    } else {
        Route::Cluster
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::v1::ExecutionProvider;

    /// A "capable desktop" policy: the cluster told it to run everything but
    /// video locally, with a generous RTT budget.
    fn desktop_policy() -> OffloadPolicy {
        OffloadPolicy {
            run_text_local: true,
            run_image_local: true,
            run_audio_local: true,
            run_video_local: false,
            max_local_rtt_ms: 50,
            min_battery_pct: 0, // on mains; battery floor irrelevant
            cluster_queue_backpressure: 100,
            ttl_secs: 300,
            preferred_local_providers: vec![ExecutionProvider::Directml as i32],
            policy_id: "desktop-1".into(),
        }
    }

    /// A "mobile, low-power" policy: offload all heavy media, keep text local,
    /// force-offload below 20% battery.
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
            preferred_local_providers: vec![ExecutionProvider::Nnapi as i32],
            policy_id: "mobile-1".into(),
        }
    }

    fn live(rtt: u32, queue: u32, batt: i32, on_battery: bool) -> LiveConditions {
        LiveConditions {
            rtt_ms: rtt,
            queue_depth: queue,
            battery_pct: batt,
            on_battery,
        }
    }

    // ---- text always local -----------------------------------------------

    #[test]
    fn text_is_always_local_on_mobile_low_battery() {
        let snap = PolicySnapshot::from_policy(&mobile_policy());
        // Worst case for offload pressure: low battery, fast link, idle cluster.
        let r = decide(MediaKind::Text, &snap, &live(5, 0, 3, true));
        assert_eq!(r, Route::Local);
    }

    #[test]
    fn text_is_always_local_on_desktop() {
        let snap = PolicySnapshot::from_policy(&desktop_policy());
        assert_eq!(
            decide(MediaKind::Text, &snap, &live(5, 0, -1, false)),
            Route::Local
        );
    }

    // ---- mobile + low battery: offload image/video, keep text local ------

    #[test]
    fn mobile_low_battery_offloads_image_and_video_keeps_text_local() {
        let snap = PolicySnapshot::from_policy(&mobile_policy());
        // 10% battery, on battery, healthy fast link, idle cluster.
        let cond = live(10, 0, 10, true);

        assert_eq!(decide(MediaKind::Image, &snap, &cond), Route::Cluster);
        assert_eq!(decide(MediaKind::Video, &snap, &cond), Route::Cluster);
        assert_eq!(decide(MediaKind::Audio, &snap, &cond), Route::Cluster);
        // Text stays local even here.
        assert_eq!(decide(MediaKind::Text, &snap, &cond), Route::Local);
    }

    // ---- desktop runs more locally ---------------------------------------

    #[test]
    fn desktop_runs_image_and_audio_locally() {
        let snap = PolicySnapshot::from_policy(&desktop_policy());
        let cond = live(5, 0, -1, false); // on mains, fast link, idle cluster
        assert_eq!(decide(MediaKind::Image, &snap, &cond), Route::Local);
        assert_eq!(decide(MediaKind::Audio, &snap, &cond), Route::Local);
        // Even a capable desktop offloads video per its negotiated policy.
        assert_eq!(decide(MediaKind::Video, &snap, &cond), Route::Cluster);
    }

    // ---- high RTT forces local -------------------------------------------

    #[test]
    fn high_rtt_forces_local_even_for_offloaded_kind() {
        let snap = PolicySnapshot::from_policy(&mobile_policy());
        // Mobile would normally offload images, but the link is slower than the
        // 60ms budget → run local even on a low battery.
        let cond = live(120, 0, 10, true);
        assert_eq!(decide(MediaKind::Image, &snap, &cond), Route::Local);
        assert_eq!(decide(MediaKind::Video, &snap, &cond), Route::Local);
    }

    // ---- backpressure forces local ---------------------------------------

    #[test]
    fn backpressure_forces_local_even_for_offloaded_kind() {
        let snap = PolicySnapshot::from_policy(&mobile_policy());
        // Fast link, but the cluster queue (80) is past the backpressure
        // threshold (50) → run local rather than pile onto the queue.
        let cond = live(10, 80, 10, true);
        assert_eq!(decide(MediaKind::Image, &snap, &cond), Route::Local);
        assert_eq!(decide(MediaKind::Audio, &snap, &cond), Route::Local);
    }

    #[test]
    fn rtt_takes_priority_over_low_battery() {
        // High RTT must win over the low-battery force-offload rule: a missed
        // deadline is worse than a little extra battery use.
        let snap = PolicySnapshot::from_policy(&mobile_policy());
        let cond = live(200, 0, 1, true); // critically low battery, but dead link
        assert_eq!(decide(MediaKind::Image, &snap, &cond), Route::Local);
    }

    #[test]
    fn healthy_mobile_above_battery_floor_still_offloads_per_policy() {
        let snap = PolicySnapshot::from_policy(&mobile_policy());
        // 90% battery, healthy link/cluster: the policy hint (offload image)
        // still applies because mobile lacks the local capability.
        let cond = live(15, 5, 90, true);
        assert_eq!(decide(MediaKind::Image, &snap, &cond), Route::Cluster);
    }

    #[test]
    fn mains_power_never_trips_battery_offload() {
        let snap = PolicySnapshot::from_policy(&desktop_policy());
        // battery_pct -1 (mains) must not trip the low-battery branch.
        let cond = live(5, 0, -1, false);
        assert_eq!(decide(MediaKind::Image, &snap, &cond), Route::Local);
    }

    #[test]
    fn is_heavy_classifies_kinds() {
        assert!(!is_heavy(MediaKind::Text));
        assert!(is_heavy(MediaKind::Image));
        assert!(is_heavy(MediaKind::Audio));
        assert!(is_heavy(MediaKind::Video));
    }
}
