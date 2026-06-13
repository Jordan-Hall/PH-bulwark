//! Userspace WireGuard **socket pump** (feature `wg-client`, default OFF) —
//! the increment after the [`super::wg`] scaffold: this one actually moves
//! packets. One async task owns one connected UDP socket to the family's
//! filter region and drives the [`WgTunnel`] noise state machine:
//!
//! * **outbound** — plaintext IP packets from the caller's bounded channel are
//!   encapsulated and sent to the region (pre-handshake packets are queued by
//!   boringtun, bounded at 256, and flushed when the session establishes);
//! * **inbound** — datagrams from the region are decapsulated, honouring
//!   boringtun's queued-response contract (after a `WriteToNetwork` keep
//!   calling `decapsulate(None, &[], ..)` until `Done`), and the decrypted IP
//!   packets go to `tx_decrypted`;
//! * **timers** — a 100 ms tick drives [`WgTunnel::update_timers`]
//!   (boringtun's contract: retransmits, rekeys, keepalives) and sends
//!   whatever it emits;
//! * **bring-up** — the pump initiates the handshake immediately and retries
//!   on a bounded backoff ladder ([`handshake_backoff`]); after
//!   [`HANDSHAKE_MAX_ATTEMPTS`] unanswered attempts it returns an HONEST
//!   error (never a silent retry-forever);
//! * **shutdown** — cancelling the [`CancellationToken`] stops the pump
//!   cleanly (`Ok(())`), as does either side's channel closing.
//!
//! ## Buffer discipline (a filter must never OOM the supervised device)
//! Two buffers are allocated once and reused for every packet: a receive
//! buffer ([`MAX_DATAGRAM`]) and a crypt buffer with [`WG_OVERHEAD`] headroom
//! (also ≥ 148 bytes, the largest handshake message). Both channels are the
//! caller's **bounded** `mpsc`s; when the decrypted-packet consumer falls
//! behind, packets are **dropped with a counter + `tracing::warn`** instead of
//! buffering without bound (the peer's transport layer retransmits).
//!
//! ## NOT yet wired (honest — later increments)
//! * **No data-path integration.** `run_android_data_path` / `run_netstack`
//!   do not feed this pump yet; nothing routes captured flows into `rx`.
//! * **No key provisioning.** The caller supplies a ready [`WgClientConfig`];
//!   keystore wrapping + region registration are later increments.
//! * **No kill-switch.** If the pump exits, nothing here blocks the device's
//!   traffic — fail-closed routing is the integration increment's job.
//! * **No roaming / re-resolution.** The endpoint is resolved once at start;
//!   a region IP change needs a pump restart by the supervisor.
//! * **No automatic reconnect.** A post-establishment session expiry
//!   (boringtun's `ConnectionExpired`, ~90 s without a rekey answer) surfaces
//!   as an error; restart policy belongs to the caller.
//!
//! On Android the UDP socket must be excluded from the VPN itself
//! (`VpnService.protect(fd)`) or tunnel datagrams would loop back into the
//! TUN; [`WgPump::run_with_socket`] exists so the integration increment can
//! protect the socket before handing it over (and so tests can wire two pumps
//! over loopback with pre-bound ports).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::TunnResult;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{interval, sleep_until, Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use super::wg::{WgClientConfig, WgTunnel, WG_OVERHEAD};
use crate::{NetError, Result};

/// boringtun's timer contract: drive `update_timers` roughly every 100 ms.
const TIMER_TICK: Duration = Duration::from_millis(100);

/// Largest UDP datagram we accept or build (boringtun's own device layer uses
/// the same 2^16-1 bound). The crypt buffer adds [`WG_OVERHEAD`] on top, which
/// also satisfies encapsulate's "no less than 148 bytes" handshake headroom.
const MAX_DATAGRAM: usize = 65_535;

/// Handshake bring-up: how many initiations we send (1 initial + retries on
/// the [`handshake_backoff`] ladder) before returning an honest error.
const HANDSHAKE_MAX_ATTEMPTS: u32 = 5;

/// Defensive cap on the `decapsulate(None, &[], ..)` drain loop. boringtun's
/// internal queue is bounded (256), so hitting this means a contract breach —
/// we warn and move on rather than spin forever.
const DRAIN_CAP: usize = 512;

/// Backpressure drops are counted per pump and warned about on the first drop
/// and every `DROP_WARN_EVERY`th after, so a stalled consumer can't turn the
/// log into its own flood.
const DROP_WARN_EVERY: u64 = 256;

/// Backoff ladder for handshake bring-up: 2 s, 4 s, 8 s, 16 s, 16 s … capped.
/// boringtun itself retransmits initiations every 5 s (`REKEY_TIMEOUT`) via
/// `update_timers`; this ladder only bounds how long we wait before declaring
/// an honest failure. The whole budget (≈ 46 s for 5 attempts) deliberately
/// stays under boringtun's 90 s `REKEY_ATTEMPT_TIME`, so OUR error fires
/// first with a message that names the endpoint.
fn handshake_backoff(attempt: u32) -> Duration {
    Duration::from_secs(2u64 << attempt.min(3))
}

/// Total bring-up budget across all [`HANDSHAKE_MAX_ATTEMPTS`] waits.
fn handshake_total_wait() -> Duration {
    (0..HANDSHAKE_MAX_ATTEMPTS).map(handshake_backoff).sum()
}

/// Build the crate error for a WireGuard transport failure. `NetError` has no
/// dedicated WG variant yet, so the documented catch-all (`Other`) carries the
/// classification in the message (`NetError` is `#[non_exhaustive]`; promoting
/// this to a first-class variant later is non-breaking).
fn wg_err(msg: impl std::fmt::Display) -> NetError {
    NetError::Other(anyhow::anyhow!("WireGuard transport: {msg}"))
}

/// `true` for UDP errors that a connected socket surfaces transiently when the
/// peer is momentarily unreachable (ICMP port-unreachable arrives as
/// `ConnectionRefused`/`ConnectionReset` on Linux/Windows). The pump logs and
/// keeps going — boringtun's timers retransmit; anything else is a real fault.
fn is_transient_udp_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
    )
}

/// Resolve the region's `host:port` endpoint to the first usable socket
/// address (literal IPs resolve without touching DNS). Resolution happens
/// exactly once, at pump start — see the module docs on roaming.
async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let mut addrs = lookup_host(endpoint)
        .await
        .map_err(|e| wg_err(format!("resolving region endpoint {endpoint}: {e}")))?;
    addrs.next().ok_or_else(|| {
        wg_err(format!(
            "region endpoint {endpoint} resolved to no addresses"
        ))
    })
}

/// The socket pump for one device↔region WireGuard tunnel. Constructed and
/// consumed by [`WgPump::run`] / [`WgPump::run_with_socket`]; holds the noise
/// state machine, the connected UDP socket, and the drop counters.
pub struct WgPump {
    tunnel: WgTunnel,
    socket: UdpSocket,
    peer_ip: IpAddr,
    established: bool,
    /// Decrypted packets dropped because `tx_decrypted` was full.
    drops: u64,
    /// Datagrams the noise layer rejected (replay/garbage/wrong key).
    decap_errors: u64,
}

impl WgPump {
    /// Run the pump until `shutdown` cancels, a channel closes, or the tunnel
    /// honestly fails (handshake bring-up exhausted / session expired / hard
    /// socket error). Resolves `cfg.server_endpoint`, binds an ephemeral UDP
    /// socket of the matching family, connects it, and pumps:
    /// plaintext IP packets in via `rx`, decrypted IP packets out via
    /// `tx_decrypted` (both channels should be **bounded** — the pump never
    /// buffers more than one packet per direction itself).
    pub async fn run(
        cfg: WgClientConfig,
        rx: mpsc::Receiver<Vec<u8>>,
        tx_decrypted: mpsc::Sender<Vec<u8>>,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let endpoint = resolve_endpoint(&cfg.server_endpoint).await?;
        let bind: SocketAddr = if endpoint.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| wg_err(format!("binding UDP socket: {e}")))?;
        socket
            .connect(endpoint)
            .await
            .map_err(|e| wg_err(format!("connecting UDP socket to {endpoint}: {e}")))?;
        Self::run_with_socket(cfg, socket, rx, tx_decrypted, shutdown).await
    }

    /// [`WgPump::run`] over a caller-supplied, already-**connected** UDP
    /// socket. This is the entry point for (a) Android, where the socket must
    /// be `VpnService.protect`ed before any datagram leaves it, and (b) the
    /// loopback pair tests. `cfg.server_endpoint` is ignored here — the
    /// socket's connected peer is authoritative.
    pub async fn run_with_socket(
        cfg: WgClientConfig,
        socket: UdpSocket,
        mut rx: mpsc::Receiver<Vec<u8>>,
        tx_decrypted: mpsc::Sender<Vec<u8>>,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let peer = socket.peer_addr().map_err(|e| {
            wg_err(format!(
                "socket must be connected to the region endpoint: {e}"
            ))
        })?;
        let mut pump = Self {
            tunnel: WgTunnel::new(&cfg),
            socket,
            peer_ip: peer.ip(),
            established: false,
            drops: 0,
            decap_errors: 0,
        };
        pump.run_loop(&mut rx, &tx_decrypted, &shutdown, peer).await
    }

    /// The select loop. Buffers are allocated once here and reused for every
    /// packet in both directions.
    async fn run_loop(
        &mut self,
        rx: &mut mpsc::Receiver<Vec<u8>>,
        tx_decrypted: &mpsc::Sender<Vec<u8>>,
        shutdown: &CancellationToken,
        peer: SocketAddr,
    ) -> Result<()> {
        let mut recv_buf = vec![0u8; MAX_DATAGRAM];
        let mut crypt_buf = vec![0u8; MAX_DATAGRAM + WG_OVERHEAD];

        tracing::info!(%peer, "WG pump: starting (handshake bring-up)");
        let mut attempt: u32 = 0;
        self.send_handshake_initiation(false, &mut crypt_buf)
            .await?;
        let mut retry_at = Instant::now() + handshake_backoff(attempt);

        let mut tick = interval(TIMER_TICK);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!(%peer, "WG pump: shutdown requested; stopping");
                    return Ok(());
                }
                maybe = rx.recv() => {
                    let Some(pkt) = maybe else {
                        tracing::info!(%peer, "WG pump: plaintext source closed; stopping");
                        return Ok(());
                    };
                    self.handle_outbound(&pkt, &mut crypt_buf).await?;
                }
                recvd = self.socket.recv(&mut recv_buf) => {
                    match recvd {
                        Ok(n) => {
                            if !self.handle_inbound(&recv_buf[..n], &mut crypt_buf, tx_decrypted).await? {
                                tracing::info!(%peer, "WG pump: decrypted-packet consumer closed; stopping");
                                return Ok(());
                            }
                            if !self.established && self.tunnel.time_since_last_handshake().is_some() {
                                self.established = true;
                                tracing::info!(%peer, attempts = attempt + 1, "WG pump: handshake complete; tunnel up");
                            }
                        }
                        Err(e) if is_transient_udp_error(&e) => {
                            tracing::warn!(%peer, error = %e, "WG pump: transient UDP recv error; continuing");
                        }
                        Err(e) => return Err(wg_err(format!("UDP recv from {peer}: {e}"))),
                    }
                }
                _ = tick.tick() => {
                    self.handle_timers(&mut crypt_buf).await?;
                }
                _ = sleep_until(retry_at), if !self.established => {
                    attempt += 1;
                    if attempt >= HANDSHAKE_MAX_ATTEMPTS {
                        return Err(wg_err(format!(
                            "no completed handshake with {peer} after {HANDSHAKE_MAX_ATTEMPTS} \
                             initiations over ~{}s — giving up; check connectivity and that this \
                             device's public key is registered with the region",
                            handshake_total_wait().as_secs()
                        )));
                    }
                    tracing::warn!(
                        %peer,
                        attempt = attempt + 1,
                        max = HANDSHAKE_MAX_ATTEMPTS,
                        "WG pump: handshake unanswered; re-initiating"
                    );
                    self.send_handshake_initiation(true, &mut crypt_buf).await?;
                    retry_at = Instant::now() + handshake_backoff(attempt);
                }
            }
        }
    }

    /// Encrypt one plaintext IP packet and send it. Pre-session packets are
    /// queued by boringtun (bounded at 256; new packets are dropped while the
    /// queue is full) and flushed when the handshake completes.
    async fn handle_outbound(&mut self, packet: &[u8], crypt_buf: &mut [u8]) -> Result<()> {
        if packet.len() + WG_OVERHEAD > crypt_buf.len() {
            // boringtun PANICS on an undersized dst; a >64 KiB "IP packet" is
            // bogus on any path that feeds this pump (TUN MTU ~1500).
            tracing::warn!(
                len = packet.len(),
                "WG pump: oversized plaintext packet dropped"
            );
            return Ok(());
        }
        match self.tunnel.encapsulate(packet, crypt_buf) {
            // No session yet: packet queued inside boringtun; an initiation
            // (if one was emitted) comes back as WriteToNetwork instead.
            TunnResult::Done => Ok(()),
            TunnResult::WriteToNetwork(data) => self.send_udp(data).await,
            TunnResult::Err(e) => {
                tracing::warn!(error = ?e, "WG pump: encapsulate failed; packet dropped");
                Ok(())
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                tracing::warn!("WG pump: unexpected WriteToTunnel from encapsulate (ignored)");
                Ok(())
            }
        }
    }

    /// Decapsulate one received datagram, draining boringtun's queued
    /// responses per its contract (repeat with an empty datagram after every
    /// `WriteToNetwork` until `Done`). Returns `Ok(false)` when the decrypted
    /// consumer has gone away (clean stop for the caller).
    async fn handle_inbound(
        &mut self,
        datagram: &[u8],
        crypt_buf: &mut [u8],
        tx_decrypted: &mpsc::Sender<Vec<u8>>,
    ) -> Result<bool> {
        let mut first = true;
        for _ in 0..DRAIN_CAP {
            let (src_addr, src): (Option<IpAddr>, &[u8]) = if first {
                (Some(self.peer_ip), datagram)
            } else {
                (None, &[])
            };
            first = false;
            match self.tunnel.decapsulate(src_addr, src, crypt_buf) {
                TunnResult::Done => return Ok(true),
                // Handshake response/initiation reply, cookie, keepalive, or a
                // queued data packet flushed by session establishment.
                TunnResult::WriteToNetwork(data) => self.send_udp(data).await?,
                TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                    return Ok(self.deliver_decrypted(pkt, tx_decrypted));
                }
                TunnResult::Err(e) => {
                    self.decap_errors += 1;
                    if self.decap_errors % DROP_WARN_EVERY == 1 {
                        tracing::warn!(
                            error = ?e,
                            total = self.decap_errors,
                            "WG pump: datagram rejected by the noise layer (dropped)"
                        );
                    }
                    return Ok(true);
                }
            }
        }
        tracing::warn!(
            cap = DRAIN_CAP,
            "WG pump: decapsulate drain cap hit (boringtun contract breach?); moving on"
        );
        Ok(true)
    }

    /// Drive boringtun's timers (retransmits / rekeys / keepalives) and send
    /// whatever they emit. A `ConnectionExpired` is an honest hard failure:
    /// the region stopped answering rekeys (~90 s) and the tunnel is dead.
    async fn handle_timers(&mut self, crypt_buf: &mut [u8]) -> Result<()> {
        match self.tunnel.update_timers(crypt_buf) {
            TunnResult::Done => Ok(()),
            TunnResult::WriteToNetwork(data) => self.send_udp(data).await,
            TunnResult::Err(WireGuardError::ConnectionExpired) => Err(wg_err(format!(
                "session with {} expired (no rekey answer from the region) — tunnel down",
                self.peer_ip
            ))),
            TunnResult::Err(e) => {
                tracing::warn!(error = ?e, "WG pump: timer error (continuing)");
                Ok(())
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                tracing::warn!("WG pump: unexpected WriteToTunnel from update_timers (ignored)");
                Ok(())
            }
        }
    }

    /// Format a handshake initiation (`force` re-emits even with one in
    /// flight) and send it.
    async fn send_handshake_initiation(&mut self, force: bool, crypt_buf: &mut [u8]) -> Result<()> {
        match self.tunnel.format_handshake_initiation(crypt_buf, force) {
            TunnResult::Done => Ok(()), // one already in flight
            TunnResult::WriteToNetwork(data) => self.send_udp(data).await,
            TunnResult::Err(e) => Err(wg_err(format!("formatting handshake initiation: {e:?}"))),
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => Err(wg_err(
                "unexpected WriteToTunnel from format_handshake_initiation",
            )),
        }
    }

    /// Send one datagram to the connected peer. Transient unreachable-peer
    /// errors are logged and swallowed (boringtun's timers retransmit);
    /// anything else is an honest hard failure.
    async fn send_udp(&self, data: &[u8]) -> Result<()> {
        match self.socket.send(data).await {
            Ok(_) => Ok(()),
            Err(e) if is_transient_udp_error(&e) => {
                tracing::warn!(peer = %self.peer_ip, error = %e, "WG pump: transient UDP send error; continuing");
                Ok(())
            }
            Err(e) => Err(wg_err(format!("UDP send to {}: {e}", self.peer_ip))),
        }
    }

    /// Hand one decrypted IP packet to the consumer. Backpressure = drop with
    /// counter + warn (bounded memory); a closed consumer returns `false` so
    /// the pump stops cleanly.
    fn deliver_decrypted(&mut self, packet: &[u8], tx: &mpsc::Sender<Vec<u8>>) -> bool {
        match tx.try_send(packet.to_vec()) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.drops += 1;
                if self.drops % DROP_WARN_EVERY == 1 {
                    tracing::warn!(
                        total_dropped = self.drops,
                        "WG pump: decrypted-packet consumer backpressured; dropping (bounded-memory policy)"
                    );
                }
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::super::wg::{WgClientConfig, WgKeypair};
    use super::*;

    /// Minimal-but-valid IPv4 packet: boringtun parses the version nibble and
    /// the total-length field to classify decrypted packets (checksums are
    /// not validated), so the plaintext must be a real IP header.
    fn test_ipv4_packet(payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // v4, IHL=5
        p[2] = (total >> 8) as u8;
        p[3] = (total & 0xff) as u8;
        p[8] = 64; // TTL
        p[9] = 17; // UDP (never parsed past the IP header here)
        p[12..16].copy_from_slice(&[10, 8, 0, 2]);
        p[16..20].copy_from_slice(&[10, 8, 0, 3]);
        p[20..].copy_from_slice(payload);
        p
    }

    /// Two pumps wired via in-process loopback UDP sockets complete a REAL
    /// noise handshake and round-trip packets both ways — no external network,
    /// same cfg(test) loopback-socket convention as the crate's proxy tests.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_pair_handshakes_and_round_trips() {
        let a_keys = WgKeypair::generate();
        let b_keys = WgKeypair::generate();

        let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a_sock.local_addr().unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        a_sock.connect(b_addr).await.unwrap();
        b_sock.connect(a_addr).await.unwrap();

        let mut a_cfg = WgClientConfig::new(
            b_keys.public_key(),
            a_keys.clone(),
            Ipv4Addr::new(10, 8, 0, 2),
        );
        a_cfg.server_endpoint = b_addr.to_string();
        let mut b_cfg =
            WgClientConfig::new(a_keys.public_key(), b_keys, Ipv4Addr::new(10, 8, 0, 3));
        b_cfg.server_endpoint = a_addr.to_string();

        let (a_plain_tx, a_plain_rx) = mpsc::channel::<Vec<u8>>(16);
        let (a_dec_tx, mut a_dec_rx) = mpsc::channel::<Vec<u8>>(16);
        let (b_plain_tx, b_plain_rx) = mpsc::channel::<Vec<u8>>(16);
        let (b_dec_tx, mut b_dec_rx) = mpsc::channel::<Vec<u8>>(16);

        let shutdown = CancellationToken::new();
        let a_task = tokio::spawn(WgPump::run_with_socket(
            a_cfg,
            a_sock,
            a_plain_rx,
            a_dec_tx,
            shutdown.clone(),
        ));
        let b_task = tokio::spawn(WgPump::run_with_socket(
            b_cfg,
            b_sock,
            b_plain_rx,
            b_dec_tx,
            shutdown.clone(),
        ));

        // A -> B, sent BEFORE the handshake completes: boringtun queues it and
        // the pump flushes it when the session establishes.
        let ping = test_ipv4_packet(b"bulwark-ping");
        a_plain_tx.send(ping.clone()).await.unwrap();
        let got = timeout(Duration::from_secs(10), b_dec_rx.recv())
            .await
            .expect("handshake + A->B packet within 10s")
            .expect("B's decrypted channel is open");
        assert_eq!(got, ping);

        // B -> A over the now-established session.
        let pong = test_ipv4_packet(b"bulwark-pong");
        b_plain_tx.send(pong.clone()).await.unwrap();
        let got = timeout(Duration::from_secs(10), a_dec_rx.recv())
            .await
            .expect("B->A packet within 10s")
            .expect("A's decrypted channel is open");
        assert_eq!(got, pong);

        shutdown.cancel();
        let a = timeout(Duration::from_secs(5), a_task)
            .await
            .expect("A exits promptly")
            .expect("A does not panic");
        let b = timeout(Duration::from_secs(5), b_task)
            .await
            .expect("B exits promptly")
            .expect("B does not panic");
        a.expect("A stops cleanly");
        b.expect("B stops cleanly");
    }

    /// Cancellation must stop the pump promptly and CLEANLY even mid
    /// handshake bring-up (no peer ever answers).
    #[tokio::test]
    async fn shutdown_cancels_cleanly_mid_bringup() {
        // Bound but never reads: keeps the port real so no ICMP refusals.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(silent.local_addr().unwrap()).await.unwrap();

        let cfg = WgClientConfig::new(
            WgKeypair::generate().public_key(),
            WgKeypair::generate(),
            Ipv4Addr::new(10, 8, 0, 9),
        );
        let (_plain_tx, plain_rx) = mpsc::channel::<Vec<u8>>(4);
        let (dec_tx, _dec_rx) = mpsc::channel::<Vec<u8>>(4);
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(WgPump::run_with_socket(
            cfg,
            sock,
            plain_rx,
            dec_tx,
            shutdown.clone(),
        ));

        // Let the pump start and send its first (unanswered) initiation.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.cancel();
        let res = timeout(Duration::from_secs(2), task)
            .await
            .expect("pump observes cancellation promptly")
            .expect("pump does not panic");
        res.expect("cancellation is a CLEAN stop, not an error");
        drop(silent);
    }

    #[test]
    fn handshake_backoff_is_monotonic_capped_and_under_boringtun_expiry() {
        let waits: Vec<u64> = (0..HANDSHAKE_MAX_ATTEMPTS)
            .map(|a| handshake_backoff(a).as_secs())
            .collect();
        assert_eq!(waits[0], 2);
        assert!(waits.windows(2).all(|w| w[0] <= w[1]));
        assert!(waits.iter().all(|&s| s <= 16));
        // The whole bring-up budget fires BEFORE boringtun's 90 s
        // REKEY_ATTEMPT_TIME ConnectionExpired, so our endpoint-naming honest
        // error is the one the caller sees.
        assert!(handshake_total_wait().as_secs() < 90);
    }

    /// Literal endpoints resolve without DNS; garbage is an error, not a hang.
    #[tokio::test]
    async fn resolve_endpoint_handles_literals_without_dns() {
        let addr = resolve_endpoint("127.0.0.1:51820").await.unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:51820");
        assert!(resolve_endpoint("not an endpoint").await.is_err());
    }
}
