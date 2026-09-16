//! Authenticated WireGuard provisioning for guardian-authorized Remote VPN mode.
//!
//! Remote VPN has two authentication layers. The pairing-minted device credential
//! bootstraps a short-lived VPN lease; subsequent renewals use the rotating lease
//! token instead of repeatedly sending the long-lived device credential. Every
//! lease is signed by the region, bound to the exact device id and WireGuard
//! public key, expires quickly, and is only minted while the guardian's durable
//! child config explicitly enables `FILTER_ON_SERVER`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use data_encoding::{BASE64, BASE64URL_NOPAD};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};

use crate::accounts::AccountStore;
use crate::persist::JsonFile;
use bulwark_proto::v1::wg_provision_server::WgProvision;
use bulwark_proto::v1::{FilterLocation, RegisterWgPeerRequest, WgPeerGrant};
use tonic::{Request, Response, Status};

const WG_SUBNET_PREFIX: &str = "10.8.0";
const WG_FIRST_HOST: u8 = 2;
const WG_LAST_HOST: u8 = 254;
const DEFAULT_WG_ENDPOINT: &str = "vpn.predatorhunters.co.uk:51820";
const DEFAULT_WG_KEEPALIVE_SECS: u32 = 25;
const DEFAULT_SESSION_TTL_SECS: u64 = 30 * 60;
const MIN_SESSION_TTL_SECS: u64 = 5 * 60;
const MAX_SESSION_TTL_SECS: u64 = 24 * 60 * 60;

const INSPECTION_CA_BIN_HEADER: &str = "x-bulwark-inspection-ca-bin";
const INSPECTION_CA_SHA256_HEADER: &str = "x-bulwark-inspection-ca-sha256";
const VPN_SESSION_HEADER: &str = "x-bulwark-vpn-session";
const VPN_SESSION_EXPIRES_HEADER: &str = "x-bulwark-vpn-session-expires-ms";
const VPN_SESSION_RENEW_HEADER: &str = "x-bulwark-vpn-renew-after-ms";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn valid_wg_public_key(key: &str) -> bool {
    key.len() == 44
        && key.ends_with('=')
        && BASE64
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
            token
                .rsplit('.')
                .next()
                .and_then(|part| part.parse::<u8>().ok())
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
    #[serde(default)]
    expires_ts: i64,
}

#[derive(Default)]
struct Inner {
    by_device: HashMap<String, PeerRow>,
}

/// Durable desired WireGuard peer state consumed by the privileged reconciler.
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

    fn persist_locked(&self, inner: &Inner) -> Result<(), Status> {
        if let Some(file) = &self.persist {
            file.store(&inner.snapshot()).map_err(|error| {
                tracing::error!(%error, "failed to persist WireGuard peer state");
                Status::unavailable("could not durably record the WireGuard peer lease")
            })?;
        }
        Ok(())
    }

    /// Compatibility helper for non-production tests/tools. Production grants
    /// use [`Self::register_peer_with_expiry`].
    pub fn register_peer(&self, device_id: &str, public_key: &str) -> Result<String, Status> {
        self.register_peer_with_expiry(device_id, public_key, i64::MAX)
    }

    /// Register, rotate, or renew a peer while retaining its stable tunnel IP.
    /// The persisted expiry is authoritative for the on-box lease reconciler.
    pub fn register_peer_with_expiry(
        &self,
        device_id: &str,
        public_key: &str,
        expires_ts: i64,
    ) -> Result<String, Status> {
        let device_id = device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        let public_key = public_key.trim().to_string();
        if !valid_wg_public_key(&public_key) {
            return Err(Status::invalid_argument(
                "wg_public_key must be a valid WireGuard public key",
            ));
        }
        if expires_ts <= now_ms() {
            return Err(Status::invalid_argument(
                "WireGuard lease expiry must be in the future",
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

        if let Some(existing) = inner.by_device.get(&device_id).cloned() {
            if existing.public_key == public_key && existing.expires_ts == expires_ts {
                return Ok(existing.address);
            }
            let address = existing.address.clone();
            inner.by_device.insert(
                device_id.clone(),
                PeerRow {
                    device_id,
                    address: address.clone(),
                    public_key,
                    updated_ts: now_ms(),
                    expires_ts,
                },
            );
            if let Err(error) = self.persist_locked(&inner) {
                inner.by_device.insert(existing.device_id.clone(), existing);
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
                "tunnel subnet 10.8.0.0/24 is exhausted; grow the subnet first",
            )
        })?;
        let address = format!("{WG_SUBNET_PREFIX}.{octet}");
        inner.by_device.insert(
            device_id.clone(),
            PeerRow {
                device_id: device_id.clone(),
                address: address.clone(),
                public_key,
                updated_ts: now_ms(),
                expires_ts,
            },
        );
        if let Err(error) = self.persist_locked(&inner) {
            inner.by_device.remove(&device_id);
            return Err(error);
        }
        Ok(address)
    }

    /// Remove expired desired peers. The privileged reconciler also checks the
    /// persisted expiry, so revocation does not rely on this method being called.
    pub fn prune_expired(&self, at_ms: i64) -> Result<usize, Status> {
        let mut inner = self.inner.lock().expect("wg-peer mutex poisoned");
        let before = inner.by_device.len();
        let previous: Vec<PeerRow> = inner.by_device.values().cloned().collect();
        inner
            .by_device
            .retain(|_, peer| peer.expires_ts > at_ms || peer.expires_ts == i64::MAX);
        let removed = before.saturating_sub(inner.by_device.len());
        if removed > 0 {
            if let Err(error) = self.persist_locked(&inner) {
                inner.by_device.clear();
                for peer in previous {
                    inner.by_device.insert(peer.device_id.clone(), peer);
                }
                return Err(error);
            }
        }
        Ok(removed)
    }

    pub fn peer_count(&self) -> u32 {
        let at = now_ms();
        self.inner
            .lock()
            .expect("wg peer mutex poisoned")
            .by_device
            .values()
            .filter(|peer| peer.expires_ts > at || peer.expires_ts == i64::MAX)
            .count() as u32
    }

    /// Resolve an active WireGuard inner address back to the enrolled device.
    pub fn device_id_for_address(&self, address: &str) -> Option<String> {
        let address = address.trim();
        let at = now_ms();
        self.inner
            .lock()
            .ok()?
            .by_device
            .values()
            .find(|peer| {
                peer.address == address && (peer.expires_ts > at || peer.expires_ts == i64::MAX)
            })
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
            tracing::warn!("invalid BULWARK_WG_SERVER_PUBLIC_KEY; disabling Remote VPN");
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
        tracing::info!(filter_active, endpoint = %server_endpoint, "Remote VPN region config loaded");
        Self {
            server_public_key,
            server_endpoint,
            keepalive_secs,
            filter_active,
        }
    }
}

#[derive(Clone)]
struct SessionAuth {
    key: Option<Arc<hmac::Key>>,
    ttl_ms: i64,
    renew_after_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionClaims {
    version: u8,
    device_id: String,
    wg_key_sha256: String,
    exp_ms: i64,
    nonce: String,
}

struct MintedSession {
    token: String,
    expires_ts: i64,
    renew_after_ms: i64,
}

impl SessionAuth {
    fn from_env() -> Self {
        let key = std::env::var("BULWARK_REMOTE_VPN_SESSION_SECRET")
            .ok()
            .map(|value| value.into_bytes())
            .filter(|value| value.len() >= 32)
            .map(|value| Arc::new(hmac::Key::new(hmac::HMAC_SHA256, &value)));
        if key.is_none() {
            tracing::warn!(
                "BULWARK_REMOTE_VPN_SESSION_SECRET is missing/short; Remote VPN grants are disabled"
            );
        }
        let ttl_secs = std::env::var("BULWARK_REMOTE_VPN_SESSION_TTL_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_SESSION_TTL_SECS)
            .clamp(MIN_SESSION_TTL_SECS, MAX_SESSION_TTL_SECS);
        let ttl_ms = (ttl_secs.saturating_mul(1000)).min(i64::MAX as u64) as i64;
        Self {
            key,
            ttl_ms,
            renew_after_ms: (ttl_ms / 2).max(60_000),
        }
    }

    #[cfg(test)]
    fn from_secret(secret: &[u8], ttl_ms: i64) -> Self {
        Self {
            key: Some(Arc::new(hmac::Key::new(hmac::HMAC_SHA256, secret))),
            ttl_ms,
            renew_after_ms: (ttl_ms / 2).max(1),
        }
    }

    fn key(&self) -> Result<&hmac::Key, Status> {
        self.key.as_deref().ok_or_else(|| {
            Status::failed_precondition(
                "Remote VPN authentication is not configured on this region",
            )
        })
    }

    fn wg_key_hash(public_key: &str) -> String {
        digest::digest(&digest::SHA256, public_key.as_bytes())
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn mint(&self, device_id: &str, public_key: &str) -> Result<MintedSession, Status> {
        let key = self.key()?;
        let expires_ts = now_ms().saturating_add(self.ttl_ms);
        let mut nonce = [0u8; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Status::internal("could not generate Remote VPN session nonce"))?;
        let claims = SessionClaims {
            version: 1,
            device_id: device_id.to_string(),
            wg_key_sha256: Self::wg_key_hash(public_key),
            exp_ms: expires_ts,
            nonce: BASE64URL_NOPAD.encode(&nonce),
        };
        let payload = serde_json::to_vec(&claims)
            .map_err(|_| Status::internal("could not serialize Remote VPN session"))?;
        let payload = BASE64URL_NOPAD.encode(&payload);
        let signature = hmac::sign(key, payload.as_bytes());
        Ok(MintedSession {
            token: format!("{}.{}", payload, BASE64URL_NOPAD.encode(signature.as_ref())),
            expires_ts,
            renew_after_ms: self.renew_after_ms,
        })
    }

    fn verify(&self, token: &str, device_id: &str, public_key: &str) -> Result<(), Status> {
        let key = self.key()?;
        let (payload, signature) = token
            .trim()
            .split_once('.')
            .ok_or_else(|| Status::unauthenticated("invalid Remote VPN session"))?;
        let signature = BASE64URL_NOPAD
            .decode(signature.as_bytes())
            .map_err(|_| Status::unauthenticated("invalid Remote VPN session"))?;
        hmac::verify(key, payload.as_bytes(), &signature)
            .map_err(|_| Status::unauthenticated("invalid Remote VPN session"))?;
        let claims_bytes = BASE64URL_NOPAD
            .decode(payload.as_bytes())
            .map_err(|_| Status::unauthenticated("invalid Remote VPN session"))?;
        let claims: SessionClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|_| Status::unauthenticated("invalid Remote VPN session"))?;
        if claims.version != 1
            || claims.device_id != device_id.trim()
            || claims.wg_key_sha256 != Self::wg_key_hash(public_key.trim())
            || claims.exp_ms <= now_ms()
        {
            return Err(Status::unauthenticated(
                "expired or mismatched Remote VPN session",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize, Default)]
struct ConfigAuthorizationSnapshot {
    #[serde(default)]
    configs: Vec<ConfigAuthorizationRow>,
}

#[derive(Deserialize)]
struct ConfigAuthorizationRow {
    device_id: String,
    filtering_enabled: bool,
    #[serde(default)]
    filter_location: i32,
}

fn state_dir_from_env() -> Option<PathBuf> {
    std::env::var_os("BULWARK_STATE_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn authorize_remote_mode(state_dir: Option<&Path>, device_id: &str) -> Result<(), Status> {
    let state_dir = state_dir.ok_or_else(|| {
        Status::failed_precondition(
            "Remote VPN requires durable server state and a guardian-applied child config",
        )
    })?;
    let path = state_dir.join("child_config.json");
    let bytes = std::fs::read(&path).map_err(|_| {
        Status::failed_precondition("guardian has not authorized Remote VPN for this device")
    })?;
    let snapshot: ConfigAuthorizationSnapshot = serde_json::from_slice(&bytes)
        .map_err(|_| Status::unavailable("child configuration state is unreadable"))?;
    let authorized = snapshot.configs.iter().any(|config| {
        config.device_id.trim() == device_id.trim()
            && config.filtering_enabled
            && config.filter_location == FilterLocation::FilterOnServer as i32
    });
    if !authorized {
        return Err(Status::permission_denied(
            "guardian has not authorized Remote VPN for this device",
        ));
    }
    Ok(())
}

fn inspection_ca_path(state_dir: Option<&Path>) -> Option<PathBuf> {
    std::env::var_os("BULWARK_WG_INSPECTION_CA_PEM")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| state_dir.map(|dir| dir.join("wg_inspection_ca.pem")))
}

fn inspection_ca_material(state_dir: Option<&Path>) -> Result<(Vec<u8>, String), Status> {
    let path = inspection_ca_path(state_dir)
        .ok_or_else(|| Status::failed_precondition("Remote VPN inspection CA is not configured"))?;
    let pem = std::fs::read(&path).map_err(|error| {
        Status::failed_precondition(format!(
            "Remote VPN inspection CA {} is unavailable: {error}",
            path.display()
        ))
    })?;
    if !pem
        .windows("-----BEGIN CERTIFICATE-----".len())
        .any(|window| window == b"-----BEGIN CERTIFICATE-----")
    {
        return Err(Status::failed_precondition(
            "configured Remote VPN inspection CA is not PEM certificate material",
        ));
    }
    let fingerprint = digest::digest(&digest::SHA256, &pem)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((pem, fingerprint))
}

/// Device-authenticated Remote VPN provisioning service.
#[derive(Clone)]
pub struct WgProvisionService {
    store: WgPeerStore,
    accounts: AccountStore,
    region: WgRegionConfig,
    sessions: SessionAuth,
    state_dir: Option<PathBuf>,
}

impl WgProvisionService {
    pub fn new(store: WgPeerStore, accounts: AccountStore, region: WgRegionConfig) -> Self {
        Self {
            store,
            accounts,
            region,
            sessions: SessionAuth::from_env(),
            state_dir: state_dir_from_env(),
        }
    }

    pub fn from_env(store: WgPeerStore, accounts: AccountStore) -> Self {
        Self::new(store, accounts, WgRegionConfig::from_env())
    }

    fn verify_bootstrap_device(&self, device_id: &str, device_token: &str) -> Result<(), Status> {
        if crate::auth::verify_device_token_strict(&self.accounts, device_id, device_token) {
            Ok(())
        } else {
            Err(Status::unauthenticated(
                "unknown, legacy-unpaired, or invalid device credential",
            ))
        }
    }

    fn authenticate_request(
        &self,
        session_token: Option<&str>,
        request: &RegisterWgPeerRequest,
    ) -> Result<(), Status> {
        match session_token.filter(|token| !token.trim().is_empty()) {
            Some(token) => self
                .sessions
                .verify(token, &request.device_id, &request.wg_public_key),
            None => self.verify_bootstrap_device(&request.device_id, &request.device_token),
        }
    }

    fn remote_ready(&self) -> Result<(Vec<u8>, String), Status> {
        if self.region.server_public_key.is_empty() {
            return Err(Status::failed_precondition(
                "this region has no WireGuard server identity",
            ));
        }
        if !self.region.filter_active || !crate::remote_vpn_health::is_ready() {
            return Err(Status::failed_precondition(
                "Remote VPN is unavailable because the live server-side filter is not ready",
            ));
        }
        self.sessions.key()?;
        inspection_ca_material(self.state_dir.as_deref())
    }
}

#[tonic::async_trait]
impl WgProvision for WgProvisionService {
    async fn register_wg_peer(
        &self,
        req: Request<RegisterWgPeerRequest>,
    ) -> Result<Response<WgPeerGrant>, Status> {
        let session_token = req
            .metadata()
            .get(VPN_SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let request = req.into_inner();
        if request.device_id.trim().is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if !valid_wg_public_key(request.wg_public_key.trim()) {
            return Err(Status::invalid_argument("wg_public_key is invalid"));
        }

        self.authenticate_request(session_token.as_deref(), &request)?;
        authorize_remote_mode(self.state_dir.as_deref(), &request.device_id)?;
        let (inspection_ca, inspection_ca_sha256) = self.remote_ready()?;

        let session = self
            .sessions
            .mint(&request.device_id, &request.wg_public_key)?;
        let _ = self.store.prune_expired(now_ms());
        let assigned_address = self.store.register_peer_with_expiry(
            &request.device_id,
            &request.wg_public_key,
            session.expires_ts,
        )?;

        let mut response = Response::new(WgPeerGrant {
            assigned_address,
            server_public_key: self.region.server_public_key.clone(),
            server_endpoint: self.region.server_endpoint.clone(),
            keepalive_secs: self.region.keepalive_secs,
            filter_active: true,
        });

        response.metadata_mut().insert_bin(
            INSPECTION_CA_BIN_HEADER,
            tonic::metadata::MetadataValue::from_bytes(&inspection_ca),
        );
        let ca_hash = tonic::metadata::MetadataValue::try_from(inspection_ca_sha256.as_str())
            .map_err(|_| Status::internal("inspection CA metadata encoding failed"))?;
        response
            .metadata_mut()
            .insert(INSPECTION_CA_SHA256_HEADER, ca_hash);

        let session_value = tonic::metadata::MetadataValue::try_from(session.token.as_str())
            .map_err(|_| Status::internal("VPN session metadata encoding failed"))?;
        response
            .metadata_mut()
            .insert(VPN_SESSION_HEADER, session_value);
        let expires = tonic::metadata::MetadataValue::try_from(session.expires_ts.to_string())
            .map_err(|_| Status::internal("VPN expiry metadata encoding failed"))?;
        response
            .metadata_mut()
            .insert(VPN_SESSION_EXPIRES_HEADER, expires);
        let renew = tonic::metadata::MetadataValue::try_from(session.renew_after_ms.to_string())
            .map_err(|_| Status::internal("VPN renew metadata encoding failed"))?;
        response
            .metadata_mut()
            .insert(VPN_SESSION_RENEW_HEADER, renew);

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> String {
        BASE64.encode(&[seed; 32])
    }

    fn accounts_with_paired_device(device_id: &str) -> (AccountStore, String) {
        let accounts = AccountStore::new();
        accounts
            .create_account("parent@example.test", "password123", "Parent")
            .unwrap();
        let (token, _, _) = accounts
            .login("parent@example.test", "password123")
            .unwrap();
        let (code, _) = accounts.create_pair_code(&token, "Kid").unwrap();
        let (_, _, device_token) = accounts.redeem_pair_code(&code, device_id).unwrap();
        (accounts, device_token)
    }

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_remote_config(dir: &Path, device_id: &str, enabled: bool, remote: bool) {
        let value = serde_json::json!({
            "configs": [{
                "child_id": "child-1",
                "device_id": device_id,
                "filtering_enabled": enabled,
                "server_region": "uk",
                "server_endpoint": "https://region.example.test:8443",
                "profile": 3,
                "require_always_on": true,
                "config_version": 1,
                "updated_ts": 1,
                "updated_by": "guardian-1",
                "filter_location": if remote { 1 } else { 0 }
            }],
            "applied": []
        });
        std::fs::write(
            dir.join("child_config.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn allocates_stable_addresses_and_key_rotation_keeps_ip() {
        let store = WgPeerStore::new();
        let exp = now_ms() + 60_000;
        assert_eq!(
            store
                .register_peer_with_expiry("dev-1", &test_key(1), exp)
                .unwrap(),
            "10.8.0.2"
        );
        assert_eq!(
            store
                .register_peer_with_expiry("dev-2", &test_key(2), exp)
                .unwrap(),
            "10.8.0.3"
        );
        assert_eq!(
            store
                .register_peer_with_expiry("dev-1", &test_key(9), exp + 1)
                .unwrap(),
            "10.8.0.2"
        );
        assert_eq!(
            store.device_id_for_address("10.8.0.2").as_deref(),
            Some("dev-1")
        );
    }

    #[test]
    fn duplicate_wireguard_key_cannot_cross_devices() {
        let store = WgPeerStore::new();
        let exp = now_ms() + 60_000;
        store
            .register_peer_with_expiry("dev-1", &test_key(1), exp)
            .unwrap();
        assert_eq!(
            store
                .register_peer_with_expiry("dev-2", &test_key(1), exp)
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
    }

    #[test]
    fn expired_peers_are_pruned_and_no_longer_attributed() {
        let store = WgPeerStore::new();
        store
            .register_peer_with_expiry("dev-1", &test_key(1), now_ms() + 2)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(3));
        assert!(store.device_id_for_address("10.8.0.2").is_none());
        assert_eq!(store.prune_expired(now_ms()).unwrap(), 1);
        assert_eq!(store.peer_count(), 0);
    }

    #[test]
    fn session_is_bound_to_device_key_and_expiry() {
        let auth = SessionAuth::from_secret(&[7u8; 32], 50);
        let minted = auth.mint("dev-1", &test_key(1)).unwrap();
        assert!(auth.verify(&minted.token, "dev-1", &test_key(1)).is_ok());
        assert!(auth.verify(&minted.token, "dev-2", &test_key(1)).is_err());
        assert!(auth.verify(&minted.token, "dev-1", &test_key(2)).is_err());
        std::thread::sleep(std::time::Duration::from_millis(55));
        assert!(auth.verify(&minted.token, "dev-1", &test_key(1)).is_err());
    }

    #[test]
    fn guardian_config_is_authoritative_for_remote_access() {
        let dir = temp_dir("remote-vpn-authz");
        write_remote_config(&dir, "dev-1", true, true);
        assert!(authorize_remote_mode(Some(&dir), "dev-1").is_ok());
        write_remote_config(&dir, "dev-1", true, false);
        assert_eq!(
            authorize_remote_mode(Some(&dir), "dev-1")
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        write_remote_config(&dir, "dev-1", false, true);
        assert_eq!(
            authorize_remote_mode(Some(&dir), "dev-1")
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_peer_file_is_fatal_not_silently_empty() {
        let dir = temp_dir("wg-corrupt");
        std::fs::write(dir.join("wg_peers.json"), b"{not-json").unwrap();
        assert!(WgPeerStore::with_state_dir(&dir).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn peer_expiry_persists_across_restart() {
        let dir = temp_dir("wg-persist");
        let exp = now_ms() + 120_000;
        let first = WgPeerStore::with_state_dir(&dir).unwrap();
        first
            .register_peer_with_expiry("dev-1", &test_key(1), exp)
            .unwrap();
        drop(first);
        let second = WgPeerStore::with_state_dir(&dir).unwrap();
        assert_eq!(
            second.device_id_for_address("10.8.0.2").as_deref(),
            Some("dev-1")
        );
        let json = std::fs::read_to_string(dir.join("wg_peers.json")).unwrap();
        assert!(json.contains("expires_ts"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn bootstrap_requires_real_pairing_credential_before_policy_checks() {
        let (accounts, _) = accounts_with_paired_device("dev-1");
        let service = WgProvisionService {
            store: WgPeerStore::new(),
            accounts,
            region: WgRegionConfig::default(),
            sessions: SessionAuth::from_secret(&[9u8; 32], 60_000),
            state_dir: None,
        };
        let error = service
            .register_wg_peer(Request::new(RegisterWgPeerRequest {
                device_id: "dev-1".into(),
                device_token: "wrong".into(),
                wg_public_key: test_key(1),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn reserved_addresses_are_skipped() {
        let store = WgPeerStore {
            inner: Arc::new(Mutex::new(Inner::default())),
            persist: None,
            reserved: Arc::new([2u8].into_iter().collect()),
        };
        assert_eq!(
            store
                .register_peer_with_expiry("dev-1", &test_key(1), now_ms() + 60_000)
                .unwrap(),
            "10.8.0.3"
        );
    }
}
