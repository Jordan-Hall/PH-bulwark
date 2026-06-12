//! WgProvision — WireGuard peer provisioning for server-routed filtering
//! (`FilterLocation::FILTER_ON_SERVER`): the child device registers its WG
//! PUBLIC key and learns its assigned tunnel address + the region's endpoint
//! material. See docs/design/server-vpn-mode-and-ca-trust.md §1/§4.
//!
//! KEY INVARIANT (mirrors the per-install inspection CA): only the device's
//! PUBLIC key ever crosses the wire — the keypair is generated on-device
//! (boringtun) and the private key never leaves it. The request shape has no
//! field a private key could even ride in.
//!
//! AUTH (same device gate as [`crate::child_control::ChildControlService`]):
//! the caller must present the per-device token minted at pairing
//! ([`AccountStore::verify_device_token`]; devices enrolled before tokens
//! existed pass under its logged legacy grace). A device can enroll only its
//! OWN peer — there is no cross-device surface.
//!
//! DECOUPLED FROM wg(8) — THE FILE CONTRACT: this handler never shells out to
//! `wg`/`wg-quick`. It persists the DESIRED peer set write-through to
//! `wg_peers.json` under `BULWARK_STATE_DIR` (`/var/lib/bulwark/wg_peers.json`
//! on a region box), sorted by assigned address (= allocation order):
//!
//! ```text
//! { "peers": [ { "device_id": "…", "address": "10.8.0.2",
//!                "public_key": "<base64>", "updated_ts": 0 }, … ] }
//! ```
//!
//! An on-box reconciler (cron/SSM, root) applies it with
//! `deploy/wireguard/wg-peers.sh`:
//!
//! ```text
//! jq -r '.peers[] | [.device_id, .public_key] | @tsv' /var/lib/bulwark/wg_peers.json \
//!   | while IFS=$'\t' read -r dev key; do bulwark-wg-peers add-peer "$dev" "$key"; done
//! ```
//!
//! `add-peer` is idempotent (same device+key = no-op) and rotation-aware (same
//! device, new key = swap key, keep IP), so replaying the whole file is safe.
//! Because this increment never removes peers, the desired set stays a
//! CONTIGUOUS lowest-free block from 10.8.0.2 — applied in file order to an
//! empty/consistent wg0.conf it converges on exactly the granted addresses.
//! A deregistration flow MUST NOT ship before wg-peers.sh grows an explicit
//! `add-peer --ip` pin (address gaps would break order-based convergence) —
//! tracked follow-up.
//!
//! HONESTY (`WgPeerGrant.filter_active`): the grant states whether this region
//! ACTUALLY filters the forwarded flows (bulwark-net in the wg0 forward path —
//! phase 3). Until then it is FALSE and the child app keeps filtering
//! on-device (or declines the tunnel) — a guardian who expects filtering is
//! never silently routed through an unfiltered exit.
//!
//! State is **in-memory** (`Arc<Mutex<…>>`) with optional write-through JSON
//! persistence — the SAME shape as [`crate::child_control::ChildConfigStore`].
//! We deliberately do NOT pull in `bulwark-store`/rusqlite (env error 4551 on
//! the Windows host); `bulwark-server` must keep building.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::accounts::AccountStore;
use crate::persist::JsonFile;
use bulwark_proto::v1::wg_provision_server::WgProvision;
use bulwark_proto::v1::{RegisterWgPeerRequest, WgPeerGrant};
use tonic::{Request, Response, Status};

/// The region's tunnel subnet (server = `10.8.0.1/24`). MUST match
/// `deploy/wireguard/wg-peers.sh` `SUBNET_PREFIX` — both allocators hand out
/// host addresses in the same block.
const WG_SUBNET_PREFIX: &str = "10.8.0";
/// First assignable host octet (`.1` is the server itself).
const WG_FIRST_HOST: u8 = 2;
/// Last assignable host octet (`.255` is broadcast).
const WG_LAST_HOST: u8 = 254;

/// Region endpoint handed out when `BULWARK_WG_ENDPOINT` doesn't override it.
const DEFAULT_WG_ENDPOINT: &str = "vpn.predatorhunters.co.uk:51820";
/// PersistentKeepalive the client should set (NAT hole-keeping; matches the
/// client config wg-peers.sh prints).
const DEFAULT_WG_KEEPALIVE_SECS: u32 = 25;

/// A WireGuard public key: exactly 32 bytes, standard base64 (44 chars, one
/// trailing `=`). Mirrors wg-peers.sh's `valid_wg_key`, decode-based (no regex).
fn valid_wg_public_key(key: &str) -> bool {
    key.len() == 44
        && key.ends_with('=')
        && data_encoding::BASE64
            .decode(key.as_bytes())
            .map(|b| b.len() == 32)
            .unwrap_or(false)
}

/// Lowest free host octet in `10.8.0.<2..=254>`, or `None` when the subnet is
/// full. Pure so the exhaustion edge is unit-testable without 253 enrollments.
fn lowest_free_octet(used: &HashSet<u8>) -> Option<u8> {
    (WG_FIRST_HOST..=WG_LAST_HOST).find(|o| !used.contains(o))
}

/// One device's desired peer enrollment. Doubles as the persisted snapshot row
/// (the JSON file IS the reconciler contract — keep the field names stable).
/// Content-free: an id, a tunnel address, a PUBLIC key, a timestamp.
#[derive(Clone, Serialize, Deserialize)]
struct PeerRow {
    device_id: String,
    /// Bare IPv4 (`"10.8.0.7"`); the client configures it as a /32 and
    /// wg-peers.sh writes it as `AllowedIPs = <address>/32`.
    address: String,
    /// The device's CURRENT WireGuard public key (base64). Rotation replaces
    /// it in place; the address never moves.
    public_key: String,
    /// Unix ms of the last register/rotation (audit; not load-bearing).
    updated_ts: i64,
}

#[derive(Default)]
struct Inner {
    /// device_id → its peer row (assigned address + current public key).
    by_device: HashMap<String, PeerRow>,
}

/// Cloneable handle to the in-memory desired-peer state. Every clone shares
/// the same map — the SAME shape as [`crate::child_control::ChildConfigStore`].
#[derive(Clone)]
pub struct WgPeerStore {
    inner: Arc<Mutex<Inner>>,
    /// `Some` → write-through JSON persistence (the reconciler file contract);
    /// `None` (default) → pure in-memory.
    persist: Option<JsonFile>,
}

impl Default for WgPeerStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WgPeerStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            persist: None,
        }
    }

    /// Durable store rooted at `dir`: loads `wg_peers.json` on startup and
    /// write-throughs every change. A corrupt file starts empty (logged); only
    /// an unusable directory is fatal — same contract as
    /// [`AccountStore::with_state_dir`].
    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let file = JsonFile::new(dir, "wg_peers.json")?;
        let snap: WgPeerSnapshot = file.load_or_default();
        let mut inner = Inner::default();
        for row in snap.peers {
            inner.by_device.insert(row.device_id.clone(), row);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            persist: Some(file),
        })
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Persist the current state under the held lock (consistent). UNLIKE the
    /// account/config stores (where in-memory stays authoritative), the JSON
    /// file here IS the reconciler's only input — a grant that never reaches
    /// it is a promise the tunnel can never keep, so a write failure must FAIL
    /// the registration (the caller rolls the in-memory change back).
    fn persist_locked(&self, inner: &Inner) -> Result<(), Status> {
        if let Some(file) = &self.persist {
            if let Err(e) = file.store(&inner.snapshot()) {
                tracing::error!(error = %e, "failed to persist wg peers — refusing the grant");
                return Err(Status::unavailable(
                    "could not record the peer enrollment on this region — try again",
                ));
            }
        }
        Ok(())
    }

    /// Register (or refresh) one device's WG peer. Pure allocation — the
    /// caller (the gRPC service) authenticates the device FIRST.
    ///
    ///   * unknown device → allocates the lowest free `10.8.0.x` (stable from
    ///     then on);
    ///   * same device + same key → idempotent no-op (same address, no write);
    ///   * same device + NEW key → key rotation: address kept, key swapped
    ///     (exactly wg-peers.sh's rotation semantics);
    ///   * key already enrolled for a DIFFERENT device → `AlreadyExists`
    ///     (one key ↔ one device, mirroring wg-peers.sh).
    ///
    /// Returns the assigned address (bare IPv4, e.g. `"10.8.0.2"`).
    pub fn register_peer(&self, device_id: &str, public_key: &str) -> Result<String, Status> {
        let device_id = device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        let public_key = public_key.trim().to_string();
        if !valid_wg_public_key(&public_key) {
            return Err(Status::invalid_argument(
                "wg_public_key must be a valid WireGuard public key (44-char base64 of 32 bytes)",
            ));
        }

        let mut inner = self.inner.lock().expect("wg-peer mutex poisoned");

        // One key <-> one device (mirrors wg-peers.sh): a key already enrolled
        // for a DIFFERENT device is refused — otherwise two devices would
        // contest one tunnel identity.
        if inner
            .by_device
            .values()
            .any(|p| p.public_key == public_key && p.device_id != device_id)
        {
            return Err(Status::already_exists(
                "this WireGuard key is already registered to another device",
            ));
        }

        // Existing enrollment: idempotent same-key no-op, or in-place rotation.
        let rotated = match inner.by_device.get_mut(&device_id) {
            Some(existing) if existing.public_key == public_key => {
                // Idempotent re-register: same address, nothing to persist.
                return Ok(existing.address.clone());
            }
            Some(existing) => {
                // Key rotation (reinstall / re-pair): the device keeps its
                // stable tunnel address; only the key changes.
                let prev_key = std::mem::replace(&mut existing.public_key, public_key.clone());
                let prev_ts = std::mem::replace(&mut existing.updated_ts, Self::now_ms());
                Some((existing.address.clone(), prev_key, prev_ts))
            }
            None => None,
        };
        if let Some((address, prev_key, prev_ts)) = rotated {
            if let Err(e) = self.persist_locked(&inner) {
                // Roll the rotation back so a later retry re-attempts the
                // write instead of short-circuiting on the idempotent path.
                if let Some(existing) = inner.by_device.get_mut(&device_id) {
                    existing.public_key = prev_key;
                    existing.updated_ts = prev_ts;
                }
                return Err(e);
            }
            return Ok(address);
        }

        // New device: lowest free host address in the subnet (same order as
        // wg-peers.sh's next_free_ip, so the two allocators converge).
        let used: HashSet<u8> = inner
            .by_device
            .values()
            .filter_map(|p| p.address.rsplit('.').next()?.parse::<u8>().ok())
            .collect();
        let octet = lowest_free_octet(&used).ok_or_else(|| {
            Status::resource_exhausted(
                "tunnel subnet 10.8.0.0/24 is exhausted (253 peers) — grow the subnet first",
            )
        })?;
        let address = format!("{WG_SUBNET_PREFIX}.{octet}");
        inner.by_device.insert(
            device_id.clone(),
            PeerRow {
                device_id: device_id.clone(),
                address: address.clone(),
                public_key,
                updated_ts: Self::now_ms(),
            },
        );
        if let Err(e) = self.persist_locked(&inner) {
            // Roll the allocation back: the address was never durably granted,
            // so it must not be consumed from the pool (and a retry must not
            // hit the idempotent path and return Ok without persisting).
            inner.by_device.remove(&device_id);
            return Err(e);
        }
        Ok(address)
    }
}

// ---------------------------------------------------------------------------
// Durable snapshot (serde JSON) = the on-box reconciler's input file. Sorted
// by assigned address so file order IS allocation order (lowest-free), which
// is what makes a plain replay through wg-peers.sh converge. Content-free.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct WgPeerSnapshot {
    peers: Vec<PeerRow>,
}

impl Inner {
    fn snapshot(&self) -> WgPeerSnapshot {
        let mut peers: Vec<PeerRow> = self.by_device.values().cloned().collect();
        // Numeric sort on the host octet — a string sort would put .10 before .2.
        peers.sort_by_key(|p| {
            p.address
                .rsplit('.')
                .next()
                .and_then(|o| o.parse::<u8>().ok())
                .unwrap_or(u8::MAX)
        });
        WgPeerSnapshot { peers }
    }
}

// ---------------------------------------------------------------------------
// Region material (env-configured at deploy)
// ---------------------------------------------------------------------------

/// What this region tells enrolling devices about itself. Read once at startup
/// from `BULWARK_WG_*` env (see [`WgRegionConfig::from_env`]).
#[derive(Clone, Debug)]
pub struct WgRegionConfig {
    /// The region's WireGuard PUBLIC key (`/etc/wireguard/server.pub` on the
    /// box). EMPTY = provisioning unconfigured: `RegisterWgPeer` fails
    /// `FailedPrecondition` rather than minting a grant the device can't use.
    pub server_public_key: String,
    /// `host:port` the client dials, e.g. `"vpn.predatorhunters.co.uk:51820"`.
    pub server_endpoint: String,
    /// PersistentKeepalive seconds for the client config.
    pub keepalive_secs: u32,
    /// HONESTY FLAG: whether the bulwark-net engine actually inspects this
    /// region's wg0 forward path (phase 3). NEVER set true aspirationally —
    /// the client refuses to route a filtered child through an unfiltered
    /// exit, and a lie here would silently bypass that protection.
    pub filter_active: bool,
}

impl Default for WgRegionConfig {
    fn default() -> Self {
        Self {
            server_public_key: String::new(),
            server_endpoint: DEFAULT_WG_ENDPOINT.to_string(),
            keepalive_secs: DEFAULT_WG_KEEPALIVE_SECS,
            filter_active: false,
        }
    }
}

impl WgRegionConfig {
    /// Read the region material from the environment:
    ///   * `BULWARK_WG_SERVER_PUBLIC_KEY` — the region's WG public key
    ///     (REQUIRED for grants; unset/invalid → RegisterWgPeer fails honest).
    ///   * `BULWARK_WG_ENDPOINT` — default `vpn.predatorhunters.co.uk:51820`.
    ///   * `BULWARK_WG_KEEPALIVE_SECS` — default 25.
    ///   * `BULWARK_WG_FILTER_ACTIVE` — default FALSE. Set `1`/`true` ONLY
    ///     once the bulwark-net engine actually sits in the wg0 forward path
    ///     (phase 3 of docs/design/server-vpn-mode-and-ca-trust.md §4).
    pub fn from_env() -> Self {
        let mut server_public_key = std::env::var("BULWARK_WG_SERVER_PUBLIC_KEY")
            .map(|v| v.trim().to_string())
            .unwrap_or_default();
        if !server_public_key.is_empty() && !valid_wg_public_key(&server_public_key) {
            tracing::warn!(
                "BULWARK_WG_SERVER_PUBLIC_KEY is not a valid WireGuard public key; \
                 ignoring it (RegisterWgPeer fails until it is fixed)"
            );
            server_public_key = String::new();
        }
        let server_endpoint = std::env::var("BULWARK_WG_ENDPOINT")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_WG_ENDPOINT.to_string());
        let keepalive_secs = std::env::var("BULWARK_WG_KEEPALIVE_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_WG_KEEPALIVE_SECS);
        let filter_active = std::env::var("BULWARK_WG_FILTER_ACTIVE")
            .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false);
        if server_public_key.is_empty() {
            tracing::warn!(
                "WgProvision mounted without BULWARK_WG_SERVER_PUBLIC_KEY — \
                 RegisterWgPeer will fail until the region's WG public key is configured"
            );
        }
        tracing::info!(
            filter_active,
            endpoint = %server_endpoint,
            "WgProvision region material loaded"
        );
        Self {
            server_public_key,
            server_endpoint,
            keepalive_secs,
            filter_active,
        }
    }
}

// ---------------------------------------------------------------------------
// gRPC service
// ---------------------------------------------------------------------------

/// Implements `bulwark_proto::v1::wg_provision_server::WgProvision` over a
/// [`WgPeerStore`], authenticating devices against an [`AccountStore`].
#[derive(Clone)]
pub struct WgProvisionService {
    store: WgPeerStore,
    accounts: AccountStore,
    region: WgRegionConfig,
}

impl WgProvisionService {
    /// `accounts` is the SAME store that backs the Accounts service / Tamper /
    /// ChildControl, so device-token verification is one source of truth.
    pub fn new(store: WgPeerStore, accounts: AccountStore, region: WgRegionConfig) -> Self {
        Self {
            store,
            accounts,
            region,
        }
    }

    /// Env-configured construction (the deploy path).
    pub fn from_env(store: WgPeerStore, accounts: AccountStore) -> Self {
        Self::new(store, accounts, WgRegionConfig::from_env())
    }

    /// Gate: the caller must present the per-device token minted at pairing
    /// (`PairResult.device_token`). Unknown devices and wrong tokens are
    /// unauthenticated; devices enrolled before tokens existed pass under the
    /// accounts store's logged legacy grace — the SAME gate as
    /// [`crate::child_control::ChildControlService`].
    fn verify_device(&self, device_id: &str, device_token: &str) -> Result<(), Status> {
        if self.accounts.verify_device_token(device_id, device_token) {
            Ok(())
        } else {
            Err(Status::unauthenticated(
                "unknown device or invalid device token",
            ))
        }
    }
}

#[tonic::async_trait]
impl WgProvision for WgProvisionService {
    async fn register_wg_peer(
        &self,
        req: Request<RegisterWgPeerRequest>,
    ) -> Result<Response<WgPeerGrant>, Status> {
        let r = req.into_inner();
        if r.device_id.trim().is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        // Devices authenticate FIRST — an unauthenticated caller learns
        // nothing, not even whether this region is configured for tunnelling,
        // and can never consume an address from the pool.
        self.verify_device(&r.device_id, &r.device_token)?;
        // HONESTY GATE: never mint a grant the device can't actually use (no
        // server public key = no dialable peer).
        if self.region.server_public_key.is_empty() {
            return Err(Status::failed_precondition(
                "this region is not configured for WireGuard provisioning yet",
            ));
        }
        let address = self.store.register_peer(&r.device_id, &r.wg_public_key)?;
        Ok(Response::new(WgPeerGrant {
            assigned_address: address,
            server_public_key: self.region.server_public_key.clone(),
            server_endpoint: self.region.server_endpoint.clone(),
            keepalive_secs: self.region.keepalive_secs,
            filter_active: self.region.filter_active,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 44-char base64 of 32 deterministic bytes — a structurally valid WG key.
    fn test_key(seed: u8) -> String {
        data_encoding::BASE64.encode(&[seed; 32])
    }

    /// Stand up an accounts store with one PAIRED device — a real
    /// pairing-minted device token, so the auth gate is actually exercised
    /// (AddChild's legacy grace would accept ANY token). Returns
    /// `(accounts, device_token)`.
    fn accounts_with_paired_device(device_id: &str) -> (AccountStore, String) {
        let accounts = AccountStore::new();
        accounts
            .create_account("p@x.com", "password123", "P")
            .unwrap();
        let (token, _aid, _) = accounts.login("p@x.com", "password123").unwrap();
        let (code, _expires) = accounts.create_pair_code(&token, "Kid").unwrap();
        let (_child_id, _family_id, device_token) =
            accounts.redeem_pair_code(&code, device_id).unwrap();
        (accounts, device_token)
    }

    fn region(configured: bool) -> WgRegionConfig {
        WgRegionConfig {
            server_public_key: if configured {
                test_key(200)
            } else {
                String::new()
            },
            server_endpoint: "vpn.predatorhunters.co.uk:51820".to_string(),
            keepalive_secs: 25,
            filter_active: false,
        }
    }

    #[test]
    fn allocates_lowest_free_and_reregister_is_idempotent() {
        let store = WgPeerStore::new();
        assert_eq!(
            store.register_peer("dev-1", &test_key(1)).unwrap(),
            "10.8.0.2"
        );
        assert_eq!(
            store.register_peer("dev-2", &test_key(2)).unwrap(),
            "10.8.0.3"
        );
        // Same device + same key → the SAME address, not a fresh allocation.
        assert_eq!(
            store.register_peer("dev-1", &test_key(1)).unwrap(),
            "10.8.0.2"
        );
        // And the pool didn't advance: the next device gets .4.
        assert_eq!(
            store.register_peer("dev-3", &test_key(3)).unwrap(),
            "10.8.0.4"
        );
    }

    #[test]
    fn key_rotation_keeps_the_stable_address_and_frees_the_old_key() {
        let store = WgPeerStore::new();
        assert_eq!(
            store.register_peer("dev-1", &test_key(1)).unwrap(),
            "10.8.0.2"
        );
        // New key for the same device = rotation: address unchanged.
        assert_eq!(
            store.register_peer("dev-1", &test_key(9)).unwrap(),
            "10.8.0.2"
        );
        // The replaced key is no longer claimed — another device may use it.
        assert_eq!(
            store.register_peer("dev-2", &test_key(1)).unwrap(),
            "10.8.0.3"
        );
    }

    #[test]
    fn one_key_one_device() {
        let store = WgPeerStore::new();
        store.register_peer("dev-1", &test_key(1)).unwrap();
        let err = store.register_peer("dev-2", &test_key(1)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let store = WgPeerStore::new();
        assert_eq!(
            store.register_peer("", &test_key(1)).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            store
                .register_peer("dev-1", "not-a-key")
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        // Right length, not base64.
        let junk = format!("{}{}", "!".repeat(43), "=");
        assert_eq!(
            store.register_peer("dev-1", &junk).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        // A 64-hex blob (the shape of a dumped raw key) is also refused.
        assert_eq!(
            store
                .register_peer("dev-1", &"a".repeat(64))
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn allocation_helper_finds_gaps_and_reports_exhaustion() {
        let full: HashSet<u8> = (2..=254).collect();
        assert_eq!(lowest_free_octet(&full), None, "253 peers = subnet full");
        let used: HashSet<u8> = [2u8, 3, 5].into_iter().collect();
        assert_eq!(lowest_free_octet(&used), Some(4), "lowest gap wins");
        assert_eq!(
            lowest_free_octet(&HashSet::new()),
            Some(2),
            ".1 is the server"
        );
    }

    #[test]
    fn peers_persist_and_reload_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-wgpeers-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let s1 = WgPeerStore::with_state_dir(&dir).unwrap();
        assert_eq!(s1.register_peer("dev-1", &test_key(1)).unwrap(), "10.8.0.2");
        assert_eq!(s1.register_peer("dev-2", &test_key(2)).unwrap(), "10.8.0.3");
        // Rotate dev-1's key before the "restart".
        assert_eq!(s1.register_peer("dev-1", &test_key(9)).unwrap(), "10.8.0.2");
        drop(s1); // simulate a restart

        let s2 = WgPeerStore::with_state_dir(&dir).unwrap();
        // Address stability survives the restart (idempotent re-register).
        assert_eq!(s2.register_peer("dev-1", &test_key(9)).unwrap(), "10.8.0.2");
        // A new device continues from the next free address — no reuse.
        assert_eq!(s2.register_peer("dev-3", &test_key(3)).unwrap(), "10.8.0.4");
        // The reconciler file carries the ROTATED key, not the replaced one.
        let json = std::fs::read_to_string(dir.join("wg_peers.json")).unwrap();
        assert!(json.contains(&test_key(9)), "rotated key persisted");
        assert!(!json.contains(&test_key(1)), "replaced key is gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_failure_fails_the_grant_and_rolls_back() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-wgpeers-rofail-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Squat a DIRECTORY on the store's file name: the atomic temp+rename in
        // JsonFile::store cannot replace a directory, so every write fails —
        // a portable stand-in for "state dir went read-only / disk full".
        std::fs::create_dir_all(dir.join("wg_peers.json")).unwrap();

        let store = WgPeerStore::with_state_dir(&dir).unwrap();
        // The file IS the reconciler contract: an unpersistable enrollment must
        // be REFUSED, not granted-and-lost.
        let err = store.register_peer("dev-1", &test_key(1)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        // And rolled back: a retry must re-attempt the write (same error), not
        // short-circuit on the idempotent path and return Ok without persisting.
        let err = store.register_peer("dev-1", &test_key(1)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn register_requires_a_valid_device_token() {
        let (accounts, device_token) = accounts_with_paired_device("dev-1");
        let svc = WgProvisionService::new(WgPeerStore::new(), accounts, region(true));

        // Wrong token → unauthenticated.
        let err = svc
            .register_wg_peer(Request::new(RegisterWgPeerRequest {
                device_id: "dev-1".into(),
                device_token: "wrong-token".into(),
                wg_public_key: test_key(1),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        // Unknown device → also unauthenticated (same opaque message).
        let err = svc
            .register_wg_peer(Request::new(RegisterWgPeerRequest {
                device_id: "ghost-device".into(),
                device_token: device_token.clone(),
                wg_public_key: test_key(1),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        // The real device with its pairing-minted token gets the FIRST address
        // — proof the rejected attempts above never consumed from the pool.
        let grant = svc
            .register_wg_peer(Request::new(RegisterWgPeerRequest {
                device_id: "dev-1".into(),
                device_token,
                wg_public_key: test_key(1),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(grant.assigned_address, "10.8.0.2");
        assert_eq!(grant.server_public_key, test_key(200));
        assert_eq!(grant.server_endpoint, "vpn.predatorhunters.co.uk:51820");
        assert_eq!(grant.keepalive_secs, 25);
        assert!(
            !grant.filter_active,
            "filter_active stays HONESTLY false until phase 3 filter-in-path is live"
        );
    }

    #[tokio::test]
    async fn unconfigured_region_refuses_to_mint_grants() {
        let (accounts, device_token) = accounts_with_paired_device("dev-1");
        let svc = WgProvisionService::new(WgPeerStore::new(), accounts, region(false));
        let err = svc
            .register_wg_peer(Request::new(RegisterWgPeerRequest {
                device_id: "dev-1".into(),
                device_token,
                wg_public_key: test_key(1),
            }))
            .await
            .unwrap_err();
        // FailedPrecondition (not a fake grant): no server public key = nothing
        // the device could dial. Honest about the gap.
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }
}
