//! Transparent-capture **egress selection** — where captured traffic goes after
//! the smoltcp netstack ([`super::netstack`]) lifts it off the TUN.
//!
//! (Not to be confused with [`super::transparent`] — the Linux SERVER-side
//! `SO_ORIGINAL_DST` redirect front-end on a region box. THIS module is the
//! DEVICE-side egress chooser for the on-device capture pump.)
//!
//! The on-device transparent capture path already terminates each captured TCP
//! flow in smoltcp and CONNECTs it to the in-process TLS-inspecting proxy
//! ([`super::netstack::run_netstack`]). This module adds the OTHER leg the
//! permissive netstack needs to be "complete": the **boringtun WireGuard
//! transport** to a PH Bulwark Cloud region for
//! [`ChildConfig.filter_location == FILTER_ON_SERVER`], where the region (not
//! the device) runs the content filter and NATs the traffic out under its own
//! IP. It is the device-side consumer of the [`super::wg_pump`] pump.
//!
//! ## FAIL-CLOSED CONTRACT (sacrosanct — the whole point of this module)
//! Hard rule (CLAUDE.md, MEMORY `filters-always-active`): **a child is NEVER
//! routed through an unfiltered path.** Server-tunnel egress therefore carries
//! traffic ONLY when the region's own grant says it is actually filtering the
//! forwarded flows (`WgPeerGrant.filter_active == true`, phase 3 of
//! docs/design/server-vpn-mode-and-ca-trust.md §4). While that flag is FALSE —
//! its honest default until the bulwark-net engine is validated in the region's
//! `wg0` forward path — server mode resolves to [`FilterEgress::Block`]: the
//! captured traffic is **dropped**, never tunnelled to an unfiltered exit and
//! never silently fallen back to on-device. There is no egress path here that
//! reaches the network without a confirmed filter in front of it.
//!
//! ## SCOPE (honest — this is one increment of a multi-increment, device-validated issue #144)
//! This lands the device-side egress **selector** (pure, host-tested) plus the
//! server-tunnel **egress runner** that bridges captured raw IP packets into the
//! [`super::wg_pump::WgPump`] and injects the region's decrypted returns back to
//! the TUN. STILL TODO (tracked, NOT in this increment):
//!   * **No `netstack` wiring yet.** [`super::netstack::run_netstack`] still
//!     always uses the on-device proxy path; selecting the server runner per
//!     child-config is the next increment (kept out of `netstack.rs` here to
//!     minimise churn in that security-critical file while a concurrent change
//!     lands DNS/SNI filtering there).
//!   * **No on-device `filter_active` plumbing.** The `RegisterWgPeer` grant's
//!     `filter_active` is produced server-side ([`bulwark_server::wg_provision`])
//!     but is not yet threaded from the device's WgProvision client into
//!     [`decide_egress`]. Until it is, the selector's server arm is exercised by
//!     tests only and the real path stays on-device.
//!   * **No on-device validation.** Per the issue + vpn-data-path-plan.md, the
//!     full server-mode data path must be validated on a real device + a real
//!     region before any child is flipped to `FILTER_ON_SERVER`.
//!
//! Because `filter_active` is honestly false today, a faithful end-to-end wiring
//! of this module is INERT: server mode blocks. That is correct and intended —
//! the fail-closed gate is the deliverable, not an afterthought.

/// Where the transparent-capture path sends a child's traffic, decided from the
/// guardian's `filter_location` and (for server mode) the region's honest
/// `filter_active` grant. The variants are mutually exclusive and total.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterEgress {
    /// On-device filtering (today's default): captured TCP terminates in the
    /// smoltcp netstack and CONNECTs to the in-process TLS-inspecting proxy
    /// ([`super::netstack::run_netstack`]). Traffic exits via the child's own IP.
    OnDevice,
    /// Server-side filtering: captured raw IP packets are forwarded through the
    /// boringtun WireGuard tunnel to the region, which inspects + NATs them out.
    /// Reached ONLY when the region's grant confirms it is actually filtering
    /// (`filter_active == true`); never otherwise.
    ServerTunnel,
    /// Fail-closed: drop the traffic. Returned whenever server-side filtering is
    /// requested but NOT confirmed active — a child must never be routed through
    /// an unfiltered exit, and there is deliberately no on-device fallback here
    /// (silently switching modes would mask a misconfigured region).
    Block,
}

/// The guardian's desired filter location (mirror of the proto
/// `FilterLocation` enum — kept as a local copy so this crate does not depend on
/// the proto enum's numeric encoding and the decision stays pure + total).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterLocation {
    /// Inspect on the device (default). Maps to proto `FILTER_ON_DEVICE = 0`.
    OnDevice,
    /// Route through the chosen region and inspect there. Maps to proto
    /// `FILTER_ON_SERVER = 1`.
    OnServer,
}

/// Decide the egress for captured traffic. **Pure + total + fail-closed.**
///
/// * `location` — the guardian's `ChildConfig.filter_location`.
/// * `server_filter_active` — the region's HONEST `WgPeerGrant.filter_active`:
///   `true` only when the bulwark-net engine is confirmed inspecting that
///   region's `wg0` forward path. Aspirational/unknown ⇒ pass `false`.
///
/// On-device always selects [`FilterEgress::OnDevice`]. Server mode selects
/// [`FilterEgress::ServerTunnel`] ONLY when `server_filter_active` is `true`;
/// otherwise it FAILS CLOSED to [`FilterEgress::Block`] (never on-device
/// fallback, never an unfiltered tunnel). This is the one decision that keeps
/// the "filters always active" invariant for server mode.
pub fn decide_egress(location: FilterLocation, server_filter_active: bool) -> FilterEgress {
    match location {
        FilterLocation::OnDevice => FilterEgress::OnDevice,
        FilterLocation::OnServer if server_filter_active => FilterEgress::ServerTunnel,
        // Server filtering requested but the region is NOT confirmed filtering:
        // drop the traffic. No fallback to on-device (would mask the gap) and no
        // unfiltered tunnel (the forbidden path).
        FilterLocation::OnServer => FilterEgress::Block,
    }
}

// ---------------------------------------------------------------------------
// Server-tunnel egress runner (feature `wg-client`).
//
// This is the device-side consumer of `wg_pump`: it owns the bridge between the
// smoltcp-captured raw IP packets and the boringtun tunnel, both ways. It is the
// "boringtun transport -> return path" leg named in issue #144.
// ---------------------------------------------------------------------------

#[cfg(feature = "wg-client")]
pub use server_egress::{run_server_filter_egress_gated, ServerEgressChannels};

#[cfg(feature = "wg-client")]
mod server_egress {
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::super::wg::WgClientConfig;
    use super::super::wg_pump::WgPump;
    use crate::{NetError, Result};

    /// Per-direction channel depth between the capture loop and the WG pump.
    /// Bounded so a stalled region applies backpressure / bounded-memory drops
    /// (the pump's own policy) instead of growing without limit on the device.
    const EGRESS_CHANNEL: usize = 64;

    /// The two ends the capture loop holds while server-tunnel egress runs:
    /// push captured plaintext IP packets in via `to_region`; receive the
    /// region's decrypted IP packets (to inject back into the TUN) via
    /// `from_region`. Both are bounded; dropping either stops the pump cleanly.
    pub struct ServerEgressChannels {
        /// Captured raw IP packets → the region (boringtun encapsulates them).
        pub to_region: mpsc::Sender<Vec<u8>>,
        /// The region's decrypted IP packets ← the tunnel (inject into the TUN).
        pub from_region: mpsc::Receiver<Vec<u8>>,
    }

    /// Bring up the server-tunnel egress and run it until `shutdown` cancels (or
    /// the tunnel honestly fails). Returns the [`ServerEgressChannels`] the
    /// capture loop bridges through, plus a join handle for the pump task.
    ///
    /// FAIL-CLOSED PRECONDITION: the caller MUST have already resolved
    /// [`super::decide_egress`] to [`super::FilterEgress::ServerTunnel`] — i.e.
    /// the region's `filter_active` is confirmed true. This function does not
    /// re-check the flag (it has no grant here), it only OWNS the transport once
    /// the gate has passed. Calling it for an unconfirmed region would route a
    /// child through an unfiltered exit; [`run_server_filter_egress_gated`] is
    /// the safe entry point that enforces the gate in one call.
    ///
    /// The pump never reaches the network until boringtun completes a handshake,
    /// and a handshake/timeout failure ends the pump with an honest error rather
    /// than passing traffic — so the egress is itself fail-closed end to end.
    ///
    /// MODULE-PRIVATE on purpose: the ONLY public way to open this transport is
    /// [`run_server_filter_egress_gated`], so the `filter_active` gate cannot be
    /// bypassed by a caller dialing the pump directly.
    fn run_server_filter_egress(
        cfg: WgClientConfig,
        shutdown: CancellationToken,
    ) -> (ServerEgressChannels, tokio::task::JoinHandle<Result<()>>) {
        // to_region: capture loop -> pump (encapsulate + send to the region).
        let (to_region, pump_rx) = mpsc::channel::<Vec<u8>>(EGRESS_CHANNEL);
        // from_region: pump (decapsulated returns) -> capture loop (inject to TUN).
        let (pump_tx, from_region) = mpsc::channel::<Vec<u8>>(EGRESS_CHANNEL);

        let handle =
            tokio::spawn(async move { WgPump::run(cfg, pump_rx, pump_tx, shutdown).await });

        (
            ServerEgressChannels {
                to_region,
                from_region,
            },
            handle,
        )
    }

    /// Fail-closed entry point: run server-tunnel egress ONLY if
    /// `server_filter_active` is confirmed true; otherwise return an error and
    /// open NO transport (the caller must then block the traffic). This is the
    /// single call site that ties [`super::decide_egress`] to actually owning the
    /// boringtun socket, so the gate cannot be bypassed by constructing the pump
    /// directly from the capture loop.
    pub fn run_server_filter_egress_gated(
        cfg: WgClientConfig,
        server_filter_active: bool,
        shutdown: CancellationToken,
    ) -> Result<(ServerEgressChannels, tokio::task::JoinHandle<Result<()>>)> {
        match super::decide_egress(super::FilterLocation::OnServer, server_filter_active) {
            super::FilterEgress::ServerTunnel => Ok(run_server_filter_egress(cfg, shutdown)),
            // Block (filter_active false) — refuse to open the tunnel. The
            // capture loop drops the traffic rather than tunnelling it to an
            // unfiltered exit. `OnDevice` is unreachable for an OnServer location.
            _ => Err(NetError::unsupported(
                "server-side filtering is not confirmed active for this region \
                 (WgPeerGrant.filter_active == false) — refusing to open an \
                 unfiltered tunnel (fail-closed); traffic is blocked",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_device_location_always_filters_on_device() {
        // On-device mode ignores the server flag entirely — it never tunnels.
        assert_eq!(
            decide_egress(FilterLocation::OnDevice, false),
            FilterEgress::OnDevice
        );
        assert_eq!(
            decide_egress(FilterLocation::OnDevice, true),
            FilterEgress::OnDevice
        );
    }

    #[test]
    fn server_mode_tunnels_only_when_the_region_confirms_filtering() {
        // The ONE place server-tunnel egress is selected: filter_active == true.
        assert_eq!(
            decide_egress(FilterLocation::OnServer, true),
            FilterEgress::ServerTunnel
        );
    }

    /// CENTERPIECE (the fail-closed invariant this whole module exists for):
    /// server-side filtering requested but the region is NOT confirmed filtering
    /// (`filter_active == false`, its honest default today) must resolve to
    /// BLOCK — never an unfiltered tunnel, never a silent on-device fallback.
    #[test]
    fn server_mode_fails_closed_when_region_filtering_is_not_active() {
        assert_eq!(
            decide_egress(FilterLocation::OnServer, false),
            FilterEgress::Block,
            "a child must NEVER be routed through an unfiltered exit: \
             server mode with filter_active=false MUST block, not tunnel or \
             fall back to on-device"
        );
    }

    /// The decision is total: every (location, flag) input maps to exactly one
    /// egress, and only the confirmed-server case ever reaches a network path.
    #[test]
    fn decision_is_total_and_only_confirmed_server_reaches_the_tunnel() {
        for &active in &[false, true] {
            // On-device never blocks and never tunnels.
            assert_eq!(
                decide_egress(FilterLocation::OnDevice, active),
                FilterEgress::OnDevice
            );
        }
        // The tunnel is reachable iff the region confirms it is filtering.
        let tunnels: Vec<bool> = [false, true]
            .iter()
            .map(|&a| decide_egress(FilterLocation::OnServer, a) == FilterEgress::ServerTunnel)
            .collect();
        assert_eq!(
            tunnels,
            vec![false, true],
            "the tunnel egress is selected only when filter_active is true"
        );
    }

    #[cfg(feature = "wg-client")]
    mod server_egress_gate {
        use std::net::Ipv4Addr;

        use tokio::net::UdpSocket;
        use tokio_util::sync::CancellationToken;

        use super::super::server_egress::run_server_filter_egress_gated;
        use crate::vpn::wg::{WgClientConfig, WgKeypair};

        /// A config whose endpoint is a LOOPBACK `host:port` (never the real
        /// region hostname) so [`WgPump::run`] resolves it without DNS and dials
        /// nothing off-box. `endpoint` is a bound-but-silent local UDP port.
        fn test_cfg(endpoint: &str) -> WgClientConfig {
            let mut cfg = WgClientConfig::new(
                WgKeypair::generate().public_key(),
                WgKeypair::generate(),
                Ipv4Addr::new(10, 8, 0, 2),
            );
            cfg.server_endpoint = endpoint.to_string();
            cfg
        }

        /// The gated entry point must REFUSE to open any transport when the
        /// region's filtering is not confirmed active — proving the fail-closed
        /// gate is enforced at the one place that owns the boringtun socket, not
        /// just in the pure decision. No pump task is spawned; nothing dials.
        #[tokio::test]
        async fn gated_egress_refuses_to_open_a_tunnel_when_filter_inactive() {
            let shutdown = CancellationToken::new();
            let res = run_server_filter_egress_gated(test_cfg("127.0.0.1:51820"), false, shutdown);
            assert!(
                res.is_err(),
                "filter_active=false must refuse to open the tunnel (fail-closed)"
            );
        }

        /// With filtering confirmed active the gate opens the transport (the
        /// pump task is spawned and the bridge channels are returned). The
        /// endpoint is a bound-but-silent loopback port (no DNS, no off-box
        /// dial); the pump never reaches the network until a handshake completes,
        /// so we cancel immediately and confirm a clean stop.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn gated_egress_opens_the_transport_when_filter_active() {
            // Bind a real local UDP port and keep it alive: the pump connects to
            // it but it never answers, so there is no ICMP refusal and no network.
            let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let endpoint = silent.local_addr().unwrap().to_string();
            let shutdown = CancellationToken::new();
            let res = run_server_filter_egress_gated(test_cfg(&endpoint), true, shutdown.clone());
            let (channels, handle) = res.expect("filter_active=true opens the transport");
            // The bridge channels exist; cancel before any handshake retry budget
            // elapses so the pump stops cleanly (Ok) rather than erroring out.
            shutdown.cancel();
            drop(channels);
            let joined = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
                .await
                .expect("pump exits promptly on cancel")
                .expect("pump task does not panic");
            assert!(
                joined.is_ok(),
                "cancellation is a clean stop for the egress pump"
            );
            // Kept the silent port bound for the whole run so the pump's connect
            // had a real (un-refusing) peer; release it now.
            drop(silent);
        }
    }
}
