//! Userspace **WireGuard client** scaffold (feature `wg-client`, default OFF) —
//! Phase-5 groundwork for `ChildConfig.filter_location == FILTER_ON_SERVER`,
//! where the child's captured traffic is tunnelled to the family's filter
//! region instead of being inspected on-device.
//!
//! This wraps the noise/tunnel state machine from Cloudflare's `boringtun`
//! (BSD-3-Clause, permissive — the transport leg pre-approved in the workspace
//! Cargo.toml's "PERMISSIVE ONLY" block) in repo-shaped types: a client config
//! ([`WgClientConfig`]), a device keypair ([`WgKeypair`]), and a byte-level
//! tunnel wrapper ([`WgTunnel`]) with encapsulate/decapsulate passthroughs.
//! Everything here is constructible and unit-tested **offline** — the noise
//! handshake messages are formatted into caller buffers, never sent.
//!
//! ## NOT yet wired (honest — later increments)
//! * **No socket pump.** Nothing opens a UDP socket, transmits a handshake, or
//!   retries; [`WgTunnel`] only transforms byte buffers in memory.
//! * **No data-path integration.** `run_android_data_path` / `run_netstack`
//!   do not call into this module yet — captured flows still terminate at the
//!   local TLS-inspecting proxy regardless of `filter_location`.
//! * **No timer task.** The future pump must drive [`WgTunnel::update_timers`]
//!   roughly every 100 ms (boringtun's contract) and send whatever it emits.
//! * **No key provisioning.** The device keypair is generated in memory by the
//!   caller; wrapping the private key in the OS keystore (the same discipline
//!   as the inspection CA) and registering the public key with the region at
//!   pairing time are later increments.
//! * **No pre-shared key.** [`WgTunnel::new`] passes `preshared_key: None`;
//!   if the region later requires a PSK, thread it through [`WgClientConfig`].
//!
//! ## Key discipline (crown-jewel rules apply — threat-model Asset 1 sibling)
//! The device's WireGuard **private key is never serialized, logged, or
//! `Debug`-printed**: no type here implements `serde` traits, and every `Debug`
//! impl is hand-written to redact key material. `boringtun::noise::Tunn`
//! derives `Debug` across its handshake state, so [`WgTunnel`] deliberately
//! never exposes the inner `Tunn` and substitutes a redacted `Debug` of its
//! own. (`x25519_dalek::StaticSecret` is zeroized on drop via its default
//! `zeroize` feature, which boringtun enables.)

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// Default WireGuard endpoint of the filter region (`host:port`, UDP). Kept as
/// a string — the scaffold performs **no DNS resolution** (no network in this
/// increment); the future socket pump resolves it when it opens the socket.
pub const DEFAULT_SERVER_ENDPOINT: &str = "vpn.predatorhunters.co.uk:51820";

/// Default persistent-keepalive interval in seconds (the WireGuard-conventional
/// 25 s) so the child's NAT/firewall mapping stays open between flows.
pub const DEFAULT_KEEPALIVE_SECS: u16 = 25;

/// Per-packet encryption overhead WireGuard adds to a tunnelled IP packet.
/// [`WgTunnel::encapsulate`]'s `dst` buffer must be at least
/// `src.len() + WG_OVERHEAD` bytes (boringtun's documented requirement).
pub const WG_OVERHEAD: usize = 32;

/// The device's static WireGuard keypair (Curve25519).
///
/// The private half is **module-private and unreachable from outside**: there
/// is no getter, no serde, and [`Debug`](fmt::Debug) prints `REDACTED`. Only
/// the public half ([`WgKeypair::public_key`]) may leave the process (it is
/// what pairing registers with the region).
#[derive(Clone)]
pub struct WgKeypair {
    /// Never exposed. Zeroized on drop by x25519-dalek's `zeroize` feature.
    private: StaticSecret,
    public: PublicKey,
}

impl WgKeypair {
    /// Generate a fresh device keypair from the OS CSPRNG.
    ///
    /// In-memory only — persisting the private key (OS-keystore-wrapped, like
    /// the inspection CA) is a later increment; until then a restart means a
    /// new keypair and re-registration.
    pub fn generate() -> Self {
        Self::from_private(StaticSecret::random_from_rng(rand_core::OsRng))
    }

    /// Rebuild a keypair from 32 raw private-key bytes (e.g. unwrapped from an
    /// OS keystore in a later increment). The bytes are moved into the secret
    /// type immediately; callers should not retain their copy.
    pub fn from_private_bytes(bytes: [u8; 32]) -> Self {
        Self::from_private(StaticSecret::from(bytes))
    }

    fn from_private(private: StaticSecret) -> Self {
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    /// The public half — safe to share; pairing registers it with the region.
    pub fn public_key(&self) -> PublicKey {
        self.public
    }
}

impl fmt::Debug for WgKeypair {
    /// Redacted on purpose: only the (shareable) public key is shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgKeypair")
            .field("public", &PubKeyHex(&self.public))
            .field("private", &"REDACTED")
            .finish()
    }
}

/// Hex rendering for a (public!) key in Debug output. Private keys never get
/// one of these.
struct PubKeyHex<'a>(&'a PublicKey);

impl fmt::Debug for PubKeyHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Client-side configuration for one device↔region WireGuard tunnel.
///
/// Carries everything [`WgTunnel::new`] needs; the endpoint string is for the
/// FUTURE socket pump and is not resolved or contacted here. No serde on
/// purpose — the embedded [`WgKeypair`] holds the device private key, and
/// config persistence must go through the OS-keystore path (later increment),
/// never a serialized struct.
#[derive(Clone)]
pub struct WgClientConfig {
    /// Region endpoint, `host:port` (UDP). Default [`DEFAULT_SERVER_ENDPOINT`].
    pub server_endpoint: String,
    /// The region's static public key (from pairing / ChildConfig push).
    pub server_public_key: PublicKey,
    /// This device's static keypair (private half stays inside).
    pub keypair: WgKeypair,
    /// The tunnel-interior IPv4 address the region assigned this device at
    /// pairing (one `10.8.0.x` per device from the region's `10.8.0.0/24`).
    pub assigned_address: Ipv4Addr,
    /// Persistent-keepalive interval in seconds (`None` disables). Default
    /// [`DEFAULT_KEEPALIVE_SECS`] so NAT mappings survive idle periods.
    pub persistent_keepalive_secs: Option<u16>,
}

impl WgClientConfig {
    /// Config for the default region endpoint ([`DEFAULT_SERVER_ENDPOINT`])
    /// with the conventional keepalive. Override fields directly for tests or
    /// non-default regions.
    pub fn new(
        server_public_key: PublicKey,
        keypair: WgKeypair,
        assigned_address: Ipv4Addr,
    ) -> Self {
        Self {
            server_endpoint: DEFAULT_SERVER_ENDPOINT.to_string(),
            server_public_key,
            keypair,
            assigned_address,
            persistent_keepalive_secs: Some(DEFAULT_KEEPALIVE_SECS),
        }
    }
}

impl fmt::Debug for WgClientConfig {
    /// Redacted via [`WgKeypair`]'s Debug — endpoint/addresses/public keys
    /// only, never the device private key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgClientConfig")
            .field("server_endpoint", &self.server_endpoint)
            .field("server_public_key", &PubKeyHex(&self.server_public_key))
            .field("keypair", &self.keypair)
            .field("assigned_address", &self.assigned_address)
            .field(
                "persistent_keepalive_secs",
                &self.persistent_keepalive_secs,
            )
            .finish()
    }
}

/// The WireGuard noise/tunnel state machine for one device↔region tunnel —
/// a thin wrapper over [`boringtun::noise::Tunn`] that keeps boringtun types
/// off the rest of the crate and keeps `Tunn`'s key-bearing derived `Debug`
/// unreachable.
///
/// Pure byte-in/byte-out: every method formats protocol messages into a
/// caller-supplied buffer and reports what to do with them via [`TunnResult`]
/// (`WriteToNetwork` → send to `server_endpoint` over UDP; `WriteToTunnelV4/6`
/// → hand the decrypted IP packet back to the netstack). The socket pump that
/// acts on those results is a later increment — see the module docs.
pub struct WgTunnel {
    tunn: Tunn,
}

impl WgTunnel {
    /// Build the client state machine for `cfg`. Infallible and offline —
    /// no handshake is attempted until the (future) pump drives one.
    ///
    /// boringtun specifics: `preshared_key: None` (none provisioned yet),
    /// `index: 0` (single tunnel per device — the index only disambiguates
    /// multi-tunnel peers), `rate_limiter: None` (client side; the limiter is
    /// for servers fending off handshake floods).
    pub fn new(cfg: &WgClientConfig) -> Self {
        Self {
            tunn: Tunn::new(
                cfg.keypair.private.clone(),
                cfg.server_public_key,
                None,
                cfg.persistent_keepalive_secs,
                0,
                None,
            ),
        }
    }

    /// Encrypt one plaintext IP packet (from the netstack) for the region.
    /// `dst` must be at least `packet.len() +` [`WG_OVERHEAD`] bytes.
    ///
    /// With no established session the packet is queued internally and a
    /// handshake initiation comes back as `WriteToNetwork` instead — still no
    /// I/O; the caller owns sending it.
    pub fn encapsulate<'a>(&mut self, packet: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunn.encapsulate(packet, dst)
    }

    /// Decrypt one UDP datagram received from the region. `dst` must be at
    /// least `datagram.len()` bytes. After a `WriteToNetwork` result the
    /// caller must keep calling `decapsulate(None, &[], dst)` until it returns
    /// `Done` (boringtun's queued-response contract).
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.tunn.decapsulate(src_addr, datagram, dst)
    }

    /// Drive retries/keepalives/rekeys. The future pump calls this ~every
    /// 100 ms and transmits any `WriteToNetwork` it returns; until that pump
    /// exists this is exercised by tests only. `dst` needs ≥ 148 bytes (the
    /// largest timer-emitted message is a handshake initiation).
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunn.update_timers(dst)
    }

    /// Format a handshake initiation into `dst` (≥ 148 bytes) without sending
    /// it. `force_resend` re-emits even if one is already in flight.
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        self.tunn.format_handshake_initiation(dst, force_resend)
    }

    /// Time since the last completed handshake — `None` until the first one
    /// completes (always `None` in this increment: nothing transports the
    /// handshake yet).
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.tunn.time_since_last_handshake()
    }
}

impl fmt::Debug for WgTunnel {
    /// Redacted: `Tunn`'s derived `Debug` would render handshake/key state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgTunnel")
            .field("noise", &"REDACTED")
            .field(
                "last_handshake",
                &self.tunn.time_since_last_handshake(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WireGuard handshake-initiation message size (protocol constant) and its
    /// type byte — lets the tests assert real noise output, fully offline.
    const HANDSHAKE_INIT_LEN: usize = 148;
    const HANDSHAKE_INIT_TYPE: u8 = 1;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn test_config() -> WgClientConfig {
        let device = WgKeypair::generate();
        let server = WgKeypair::generate();
        WgClientConfig::new(server.public_key(), device, Ipv4Addr::new(10, 8, 0, 23))
    }

    #[test]
    fn defaults_point_at_the_region() {
        let cfg = test_config();
        assert_eq!(cfg.server_endpoint, "vpn.predatorhunters.co.uk:51820");
        assert_eq!(cfg.persistent_keepalive_secs, Some(25));
        assert_eq!(cfg.assigned_address.octets()[..3], [10, 8, 0]);
    }

    #[test]
    fn generated_keypairs_are_distinct_and_deterministic_from_bytes() {
        // Fresh keys differ (CSPRNG actually ran)…
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        assert_ne!(a.public_key().as_bytes(), b.public_key().as_bytes());
        // …and the keystore-restore path is deterministic.
        let c = WgKeypair::from_private_bytes([7u8; 32]);
        let d = WgKeypair::from_private_bytes([7u8; 32]);
        assert_eq!(c.public_key().as_bytes(), d.public_key().as_bytes());
    }

    #[test]
    fn handshake_initiation_formats_offline() {
        // Pure state machine: a real 148-byte initiation lands in OUR buffer;
        // nothing is sent and no handshake can complete (no transport yet).
        let mut tun = WgTunnel::new(&test_config());
        let mut buf = [0u8; 256];
        match tun.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(pkt) => {
                assert_eq!(pkt.len(), HANDSHAKE_INIT_LEN);
                assert_eq!(pkt[0], HANDSHAKE_INIT_TYPE);
            }
            _ => panic!("expected WriteToNetwork(handshake initiation)"),
        }
        assert!(tun.time_since_last_handshake().is_none());
    }

    #[test]
    fn encapsulate_without_a_session_initiates_a_handshake() {
        // boringtun queues the plaintext packet and asks us to send an
        // initiation instead — the scaffold's passthrough preserves that.
        let mut tun = WgTunnel::new(&test_config());
        let plaintext = [0u8; 64]; // stand-in IP packet; content is opaque here
        let mut buf = [0u8; 64 + WG_OVERHEAD + 256];
        match tun.encapsulate(&plaintext, &mut buf) {
            TunnResult::WriteToNetwork(pkt) => {
                assert_eq!(pkt.len(), HANDSHAKE_INIT_LEN);
                assert_eq!(pkt[0], HANDSHAKE_INIT_TYPE);
            }
            _ => panic!("expected WriteToNetwork(handshake initiation)"),
        }
    }

    #[test]
    fn debug_never_renders_private_key_material() {
        // Crown-jewel discipline: Debug-format every type that touches the
        // private key and prove the key bytes (raw AND clamped forms) are
        // absent while the redaction marker is present.
        let raw = [0x42u8; 32];
        let kp = WgKeypair::from_private_bytes(raw);
        let clamped_hex = hex(&kp.private.to_bytes()); // module-private access
        let raw_hex = hex(&raw);

        let cfg = WgClientConfig::new(
            WgKeypair::generate().public_key(),
            kp.clone(),
            Ipv4Addr::new(10, 8, 0, 2),
        );
        let tun = WgTunnel::new(&cfg);
        let rendered = format!("{kp:?} | {cfg:?} | {tun:?}").to_lowercase();

        assert!(!rendered.contains(&raw_hex), "raw private key leaked");
        assert!(!rendered.contains(&clamped_hex), "private key leaked");
        assert!(rendered.contains("redacted"));
        // The PUBLIC key is allowed (and useful) in Debug output.
        assert!(rendered.contains(&hex(kp.public_key().as_bytes())));
    }
}
