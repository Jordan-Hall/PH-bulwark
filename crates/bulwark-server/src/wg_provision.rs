//! Authenticated WireGuard peer provisioning for `FILTER_ON_SERVER`.
//!
//! The device sends only its public WireGuard key. The region returns a stable
//! tunnel address and public endpoint material. When `filter_active` is true the
//! response also carries the region's public TLS-inspection root in gRPC binary
//! metadata. A region is never allowed to advertise active filtering without
//! that CA being present and readable.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::accounts::AccountStore;
use crate::persist::JsonFile;
use bulwark_proto::v1::wg_provision_server::WgProvision;
use bulwark_proto::v1::{RegisterWgPeerRequest, WgPeerGrant};
use tonic::{Request, Response, Status};

const WG_SUBNET_PREFIX: &str = "10.8.0";
const WG_FIRST_HOST: u8 = 2;
const WG_LAST_HOST: u8 = 254;
const DEFAULT_WG_ENDPOINT: &str = "vpn.predatorhunters.co.uk:51820";
const DEFAULT_WG_KEEPALIVE_SECS: u32 = 25;
const INSPECTION_CA_BIN_HEADER: &str = "x-bulwark-inspection-ca-bin";
const INSPECTION_CA_SHA256_HEADER: &str = "x-bulwark-inspection-ca-sha256";

fn valid_wg_public_key(key: &str) -> bool {
    key.len() == 44
        && key.ends_with('=')
        && data_encoding::BASE64
            .decode(key.as_bytes())
            .map(|bytes| bytes.len() == 32)
            .unwrap_or(false)
}

fn lowest_free_octet(used: &HashSet<u8>) -> Option<u8> {
    (WG_FIRST_HOST..=WG_LAST_HOST).find(|octet| !used.contains(octet))
}

fn reserved_octets_from_env() -> HashSet<u8> {
    let raw = match std::env::var("BULWARK_WG_RESERVED_ADDRS") {
        Ok(value) => value,
        Err(_) => return HashSet::new(),
    };
    let reserved = reserved_octets_from_env_str(&raw);
    if !reserved.is_empty() {
        tracing::info!(?reserved, "reserving unmanaged WireGuard peer addresses");
    }
    reserved
}

fn reserved_octets_from_env_str(raw: &str) -> HashSet<u8> {
    raw.split(',')
        .filter_map(|token| {
            let token = token.trim();
            if token.is_empty() {
                return None;
            }
            token.rsplit('.').next().and_then(|part| part.parse::<u8>().ok())
        })
        .filter(|octet| (WG_FIRST_HOST..=WG_LAST_HOST).contains(octet))
        .collect()
}

#[derive(Clone, Serialize, Deserialize)]
struct PeerRow {
    device_id: String,
    address: String,
    public_key: String,
    updated_ts: i64,
}

#[derive(Default)]
struct Inner {
    by_device: HashMap<String, PeerRow>,
}

#[derive(Clone)]
pub struct WgPeerStore {
    inner: Arc<Mutex<Inner>>,
    persist: Option<JsonFile>,
    reserved: Arc<HashSet<u8>>,
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
            reserved: Arc::new(HashSet::new()),
        }
    }

    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let file = JsonFile::new(dir, "wg_peers.json")?;
        let snapshot: WgPeerSnapshot = file.load_strict()?.unwrap_or_default();
        let mut inner = Inner::default();
        for row in snapshot.peers {
            inner.by_device.insert(row.device_id.clone(), row);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            persist: Some(file),
            reserved: Arc::new(HashSet::new()),
        })
    }

    pub fn with_reserved_from_env(mut self) -> Self {
        self.reserved = Arc::new(reserved_octets_from_env());
        self
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0)
    }

    fn persist_locked(&self, inner: &Inner) -> Result<(), Status> {
        if let Some(file) = &self.persist {
            if let Err(error) = file.store(&inner.snapshot()) {
                tracing::error!(%error, "failed to persist WireGuard peer state");
                return Err(Status::unavailable(
                    "could not durably record the WireGuard peer enrollment",
                ));
            }
        }
        Ok(())
    }

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
        if inner
            .by_device
            .values()
            .any(|peer| peer.public_key == public_key && peer.device_id != device_id)
        {
            return Err(Status::already_exists(
                "this WireGuard key is already registered to another device",
            ));
        }

        let rotated = match inner.by_device.get_mut(&device_id) {
            Some(existing) if existing.public_key == public_key => {
                return Ok(existing.address.clone());
            }
            Some(existing) => {
                let previous_key = std::mem::replace(&mut existing.public_key, public_key.clone());
                let previous_ts = std::mem::replace(&mut existing.updated_ts, Self::now_ms());
                Some((existing.address.clone(), previous_key, previous_ts))
            }
            None => None,
        };

        if let Some((address, previous_key, previous_ts)) = rotated {
            if let Err(error) = self.persist_locked(&inner) {
                if let Some(existing) = inner.by_device.get_mut(&device_id) {
                    existing.public_key = previous_key;
                    existing.updated_ts = previous_ts;
                }
                return Err(error);
            }
            return Ok(address);
        }

        let mut used = (*self.reserved).clone();
        used.extend(inner.by_device.values().filter_map(|peer| {
            peer.address
                .rsplit('.')
                .next()
                .and_then(|part| part.parse::<u8>().ok())
        }));
        let octet = lowest_free_octet(&used).ok_or_else(|| {
            Status::resource_exhausted(
                "tunnel subnet 10.8.0.0/24 is exhausted (253 peers); grow the subnet first",
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
        if let Err(error) = self.persist_locked(&inner) {
            inner.by_device.remove(&device_id);
            return Err(error);
        }
        Ok(address)
    }

    pub fn peer_count(&self) -> u32 {
        self.inner
            .lock()
            .expect("wg peer mutex poisoned")
            .by_device
            .len() as u32
    }

    /// Resolve a WireGuard inner source address to its authenticated enrollment.
    /// Region filter attribution uses this rather than trusting a device-supplied id.
    pub fn device_id_for_address(&self, address: &str) -> Option<String> {
        let address = address.trim();
        self.inner
            .lock()
            .ok()?
            .by_device
            .values()
            .find(|peer| peer.address == address)
            .map(|peer| peer.device_id.clone())
    }
}

#[derive(Serialize, Deserialize, Default)]
struct WgPeerSnapshot {
    peers: Vec<PeerRow>,
}

impl Inner {
    fn snapshot(&self) -> WgPeerSnapshot {
        let mut peers: Vec<_> = self.by_device.values().cloned().collect();
        peers.sort_by_key(|peer| {
            peer.address
                .rsplit('.')
                .next()
                .and_then(|part| part.parse::<u8>().ok())
                .unwrap_or(u8::MAX)
        });
        WgPeerSnapshot { peers }
    }
}

#[derive(Clone, Debug)]
pub struct WgRegionConfig {
    pub server_public_key: String,
    pub server_endpoint: String,
    pub keepalive_secs: u32,
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
    pub fn from_env() -> Self {
        let mut server_public_key = std::env::var("BULWARK_WG_SERVER_PUBLIC_KEY")
            .map(|value| value.trim().to_string())
            .unwrap_or_default();
        if !server_public_key.is_empty() && !valid_wg_public_key(&server_public_key) {
            tracing::warn!("invalid BULWARK_WG_SERVER_PUBLIC_KEY; disabling provisioning");
            server_public_key.clear();
        }
        let server_endpoint = std::env::var("BULWARK_WG_ENDPOINT")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_WG_ENDPOINT.to_string());
        let keepalive_secs = std::env::var("BULWARK_WG_KEEPALIVE_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_WG_KEEPALIVE_SECS);
        let filter_active = std::env::var("BULWARK_WG_FILTER_ACTIVE")
            .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false);
        tracing::info!(filter_active, endpoint = %server_endpoint, "WireGuard region config loaded");
        Self {
            server_public_key,
            server_endpoint,
            keepalive_secs,
            filter_active,
        }
    }
}

fn inspection_ca_path() -> Option<PathBuf> {
    std::env::var_os("BULWARK_WG_INSPECTION_CA_PEM")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("BULWARK_STATE_DIR")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .map(|dir| dir.join("wg_inspection_ca.pem"))
        })
}

fn inspection_ca_material() -> Result<(Vec<u8>, String), Status> {
    let path = inspection_ca_path().ok_or_else(|| {
        Status::failed_precondition(
            "server filtering is active but BULWARK_WG_INSPECTION_CA_PEM/BULWARK_STATE_DIR is not configured",
        )
    })?;
    let pem = std::fs::read(&path).map_err(|error| {
        Status::failed_precondition(format!(
            "server filtering is active but inspection CA {} is unavailable: {error}",
            path.display()
        ))
    })?;
    if !pem
        .windows("-----BEGIN CERTIFICATE-----".len())
        .any(|window| window == b"-----BEGIN CERTIFICATE-----")
    {
        return Err(Status::failed_precondition(
            "configured server inspection CA is not PEM certificate material",
        ));
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, &pem);
    let fingerprint = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((pem, fingerprint))
}

#[derive(Clone)]
pub struct WgProvisionService {
    store: WgPeerStore,
    accounts: AccountStore,
    region: WgRegionConfig,
}

impl WgProvisionService {
    pub fn new(store: WgPeerStore, accounts: AccountStore, region: WgRegionConfig) -> Self {
        Self {
            store,
            accounts,
            region,
        }
    }

    pub fn from_env(store: WgPeerStore, accounts: AccountStore) -> Self {
        Self::new(store, accounts, WgRegionConfig::from_env())
    }

    fn verify_device(&self, device_id: &str, device_token: &str) -> Result<(), Status> {
        if crate::auth::verify_device_token_strict(&self.accounts, device_id, device_token) {
            Ok(())
        } else {
            Err(Status::unauthenticated(
                "unknown, legacy-unpaired, or invalid device credential",
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
        let request = req.into_inner();
        if request.device_id.trim().is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        self.verify_device(&request.device_id, &request.device_token)?;
        if self.region.server_public_key.is_empty() {
            return Err(Status::failed_precondition(
                "this region is not configured for WireGuard provisioning",
            ));
        }

        // Resolve the CA BEFORE allocating/persisting a peer. An active-filter
        // grant without this certificate would route a child into an HTTPS
        // blackhole and could not satisfy the server-filter contract.
        let inspection_ca = if self.region.filter_active {
            Some(inspection_ca_material()?)
        } else {
            None
        };

        let address = self
            .store
            .register_peer(&request.device_id, &request.wg_public_key)?;
        let mut response = Response::new(WgPeerGrant {
            assigned_address: address,
            server_public_key: self.region.server_public_key.clone(),
            server_endpoint: self.region.server_endpoint.clone(),
            keepalive_secs: self.region.keepalive_secs,
            filter_active: self.region.filter_active,
        });

        if let Some((pem, fingerprint)) = inspection_ca {
            response.metadata_mut().insert_bin(
                INSPECTION_CA_BIN_HEADER,
                tonic::metadata::MetadataValue::from_bytes(&pem),
            );
            let fingerprint = tonic::metadata::MetadataValue::try_from(fingerprint.as_str())
                .map_err(|_| Status::internal("inspection CA fingerprint metadata encoding failed"))?;
            response
                .metadata_mut()
                .insert(INSPECTION_CA_SHA256_HEADER, fingerprint);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> String {
        data_encoding::BASE64.encode(&[seed; 32])
    }

    fn accounts_with_paired_device(device_id: &str) -> (AccountStore, String) {
        let accounts = AccountStore::new();
        accounts
            .create_account("p@x.com", "password123", "P")
            .unwrap();
        let (token, _account_id, _) = accounts.login("p@x.com", "password123").unwrap();
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
        assert_eq!(store.register_peer("dev-1", &test_key(1)).unwrap(), "10.8.0.2");
        assert_eq!(store.register_peer("dev-2", &test_key(2)).unwrap(), "10.8.0.3");
        assert_eq!(store.register_peer("dev-1", &test_key(1)).unwrap(), "10.8.0.2");
        assert_eq!(store.register_peer("dev-3", &test_key(3)).unwrap(), "10.8.0.4");
    }

    #[test]
    fn key_rotation_keeps_the_stable_address_and_frees_the_old_key() {
        let store = WgPeerStore::new();
        assert_eq!(store.register_peer("dev-1", &test_key(1)).unwrap(), "10.8.0.2");
        assert_eq!(store.register_peer("dev-1", &test_key(9)).unwrap(), "10.8.0.2");
        assert_eq!(store.register_peer("dev-2", &test_key(1)).unwrap(), "10.8.0.3");
    }

    #[test]
    fn one_key_one_device() {
        let store = WgPeerStore::new();
        store.register_peer("dev-1", &test_key(1)).unwrap();
        let error = store.register_peer("dev-2", &test_key(1)).unwrap_err();
        assert_eq!(error.code(), tonic::Code::AlreadyExists);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let store = WgPeerStore::new();
        assert_eq!(
            store.register_peer("", &test_key(1)).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            store.register_peer("dev-1", "not-a-key").unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let junk = format!("{}{}", "!".repeat(43), "=");
        assert_eq!(
            store.register_peer("dev-1", &junk).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            store.register_peer("dev-1", &"a".repeat(64)).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn allocation_helper_finds_gaps_and_reports_exhaustion() {
        let full: HashSet<u8> = (2..=254).collect();
        assert_eq!(lowest_free_octet(&full), None);
        let used: HashSet<u8> = [2u8, 3, 5].into_iter().collect();
        assert_eq!(lowest_free_octet(&used), Some(4));
        assert_eq!(lowest_free_octet(&HashSet::new()), Some(2));
    }

    #[test]
    fn reserved_octets_are_skipped_by_the_allocator() {
        let store = WgPeerStore {
            inner: Arc::new(Mutex::new(Inner::default())),
            persist: None,
            reserved: Arc::new([2u8].into_iter().collect()),
        };
        assert_eq!(store.register_peer("dev-1", &test_key(1)).unwrap(), "10.8.0.3");
        assert_eq!(store.register_peer("dev-2", &test_key(2)).unwrap(), "10.8.0.4");
    }

    #[test]
    fn reserved_addrs_env_parses_full_ips_and_bare_octets() {
        let reserved = reserved_octets_from_env_str("10.8.0.2, 5 , bad, 999, ");
        assert!(reserved.contains(&2) && reserved.contains(&5));
        assert_eq!(reserved.len(), 2);
    }

    #[test]
    fn address_can_be_resolved_back_to_device() {
        let store = WgPeerStore::new();
        store.register_peer("dev-1", &test_key(1)).unwrap();
        assert_eq!(store.device_id_for_address("10.8.0.2").as_deref(), Some("dev-1"));
        assert!(store.device_id_for_address("10.8.0.99").is_none());
    }

    #[test]
    fn corrupt_peer_file_is_fatal_not_silently_empty() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-wgpeers-corrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("wg_peers.json"), b"{ this is not json").unwrap();
        assert!(WgPeerStore::with_state_dir(&dir).is_err());

        let fresh = std::env::temp_dir().join(format!(
            "bulwark-wgpeers-fresh-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&fresh).unwrap();
        let store = WgPeerStore::with_state_dir(&fresh).unwrap();
        assert_eq!(store.register_peer("dev-1", &test_key(1)).unwrap(), "10.8.0.2");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&fresh);
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
        let first = WgPeerStore::with_state_dir(&dir).unwrap();
        assert_eq!(first.register_peer("dev-1", &test_key(1)).unwrap(), "10.8.0.2");
        assert_eq!(first.register_peer("dev-2", &test_key(2)).unwrap(), "10.8.0.3");
        assert_eq!(first.register_peer("dev-1", &test_key(9)).unwrap(), "10.8.0.2");
        drop(first);

        let second = WgPeerStore::with_state_dir(&dir).unwrap();
        assert_eq!(second.register_peer("dev-1", &test_key(9)).unwrap(), "10.8.0.2");
        assert_eq!(second.register_peer("dev-3", &test_key(3)).unwrap(), "10.8.0.4");
        let json = std::fs::read_to_string(dir.join("wg_peers.json")).unwrap();
        assert!(json.contains(&test_key(9)));
        assert!(!json.contains(&test_key(1)));
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
        let file = JsonFile::new(&dir, "wg_peers.json").unwrap();
        std::fs::create_dir_all(dir.join("wg_peers.json")).unwrap();
        let store = WgPeerStore {
            inner: Arc::new(Mutex::new(Inner::default())),
            persist: Some(file),
            reserved: Arc::new(HashSet::new()),
        };
        assert_eq!(
            store.register_peer("dev-1", &test_key(1)).unwrap_err().code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            store.register_peer("dev-1", &test_key(1)).unwrap_err().code(),
            tonic::Code::Unavailable
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn register_requires_a_valid_device_token() {
        let (accounts, device_token) = accounts_with_paired_device("dev-1");
        let service = WgProvisionService::new(WgPeerStore::new(), accounts, region(true));

        let error = service
            .register_wg_peer(Request::new(RegisterWgPeerRequest {
                device_id: "dev-1".into(),
                device_token: "wrong-token".into(),
                wg_public_key: test_key(1),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);

        let error = service
            .register_wg_peer(Request::new(RegisterWgPeerRequest {
                device_id: "ghost-device".into(),
                device_token: device_token.clone(),
                wg_public_key: test_key(1),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);

        let grant = service
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
        assert!(!grant.filter_active);
    }

    #[tokio::test]
    async fn unconfigured_region_refuses_to_mint_grants() {
        let (accounts, device_token) = accounts_with_paired_device("dev-1");
        let service = WgProvisionService::new(WgPeerStore::new(), accounts, region(false));
        let error = service
            .register_wg_peer(Request::new(RegisterWgPeerRequest {
                device_id: "dev-1".into(),
                device_token,
                wg_public_key: test_key(1),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }
}