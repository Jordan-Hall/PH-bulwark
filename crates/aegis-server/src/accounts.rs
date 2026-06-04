//! Parent accounts + per-child assigned guardians.
//!
//! A PARENT ACCOUNT is an email + password. The password is **never stored** —
//! we keep only a PBKDF2-HMAC-SHA256 hash with a per-account random salt
//! (`ring`), and verify in constant time. A successful [`AccountStore::login`]
//! mints an opaque random session token.
//!
//! A CHILD belongs to a family and is linked to a supervised `device_id`. One or
//! more guardian accounts are ASSIGNED to each child. Alerts route per-child: the
//! guardian's pending-review stream ([`crate::relay::ReviewService`]) is scoped by
//! the session token to ONLY the children that guardian is assigned to — resolved
//! through the child's `device_id` (the data plane stamps `device_id` on every
//! alert) and/or the alert's explicit `child_id`.
//!
//! State is **in-memory** for this wave (`Arc<Mutex<…>>`). See the `// SEAM:`
//! markers for where durable, audited storage plugs in. We deliberately do NOT
//! pull in `aegis-store`/rusqlite here — it fails to build on the Windows host
//! (os error 4551, environmental) and `aegis-server` must keep building.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::persist::JsonFile;
use aegis_proto::v1::accounts_server::Accounts;
use aegis_proto::v1::{
    AccountAck, AddChildRequest, AssignGuardianRequest, Child, Children, CreateAccountRequest,
    GuardianAck, ListChildrenRequest, LoginRequest, Session,
};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use tonic::{Request, Response, Status};

/// PBKDF2 parameters. SHA-256, 100k iterations, 32-byte output, 16-byte salt.
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const PBKDF2_ITERS: u32 = 100_000;
const HASH_LEN: usize = 32;
const SALT_LEN: usize = 16;
/// Session/id token entropy in bytes (→ hex string of 2× this length).
const TOKEN_BYTES: usize = 32;
const ID_BYTES: usize = 16;
/// Default guardian-session lifetime; override with `AEGIS_SESSION_TTL_SECS`
/// (positive integer seconds). A leaked token is valid at most this long; sessions
/// are also dropped on restart (never persisted).
const DEFAULT_SESSION_TTL_SECS: i64 = 12 * 3600;

/// The configured session TTL in milliseconds (env override, else the default).
fn session_ttl_ms() -> i64 {
    std::env::var("AEGIS_SESSION_TTL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_SESSION_TTL_SECS)
        .saturating_mul(1000)
}

/// Is a session issued at `issued_ms` still valid at `now_ms` for `ttl_ms`? Pure
/// (unit-tested): rejects future-dated and past-TTL tokens.
fn session_live(issued_ms: i64, now_ms: i64, ttl_ms: i64) -> bool {
    now_ms >= issued_ms && now_ms.saturating_sub(issued_ms) < ttl_ms
}

/// Login brute-force throttle defaults; override with `AEGIS_LOGIN_MAX_FAILS` /
/// `AEGIS_LOGIN_WINDOW_SECS`. After `max` failed logins for one email within the
/// window, that email is locked out until the window elapses.
const DEFAULT_LOGIN_MAX_FAILS: u32 = 5;
const DEFAULT_LOGIN_WINDOW_SECS: i64 = 15 * 60;

/// `(max_fails, window_ms)` from the environment, else the defaults.
fn login_throttle_params() -> (u32, i64) {
    let max = std::env::var("AEGIS_LOGIN_MAX_FAILS")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_LOGIN_MAX_FAILS);
    let window = std::env::var("AEGIS_LOGIN_WINDOW_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_LOGIN_WINDOW_SECS)
        .saturating_mul(1000);
    (max, window)
}

/// Per-email failed-login counter within a sliding window.
#[derive(Clone)]
struct LoginThrottle {
    fails: u32,
    window_start_ms: i64,
}

/// Is this email currently locked out? Pure (unit-tested).
fn throttle_locked(t: &LoginThrottle, now_ms: i64, window_ms: i64, max: u32) -> bool {
    t.fails >= max && now_ms.saturating_sub(t.window_start_ms) <= window_ms
}

/// Record one failed login: start a fresh window if the old one elapsed, else
/// increment within it. Pure (unit-tested).
fn record_failure(t: &mut LoginThrottle, now_ms: i64, window_ms: i64) {
    if now_ms.saturating_sub(t.window_start_ms) > window_ms {
        t.fails = 1;
        t.window_start_ms = now_ms;
    } else {
        t.fails = t.fails.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// Errors + public value types
// ---------------------------------------------------------------------------

/// Domain errors the gRPC layer maps onto a tonic [`Status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    /// An account with this email already exists.
    EmailExists,
    /// Email/password didn't match a known account.
    BadCredentials,
    /// The session token is missing, unknown, or expired.
    Unauthorized,
    /// The referenced child/account doesn't exist.
    NotFound,
    /// The caller is not a guardian of the target child.
    NotGuardian,
    /// The `device_id` is already registered to another child (routing by device
    /// must be unambiguous, or two families would see each other's alerts).
    DeviceInUse,
    /// A required field was empty or malformed.
    Validation(&'static str),
    /// Too many failed logins for this email within the window — locked out.
    TooManyAttempts,
}

impl From<AccountError> for Status {
    fn from(e: AccountError) -> Self {
        match e {
            AccountError::EmailExists => {
                Status::already_exists("an account with that email exists")
            }
            AccountError::BadCredentials => Status::unauthenticated("invalid email or password"),
            AccountError::Unauthorized => {
                Status::unauthenticated("invalid or missing session token")
            }
            AccountError::NotFound => Status::not_found("no such child or account"),
            AccountError::NotGuardian => {
                Status::permission_denied("caller is not a guardian of this child")
            }
            AccountError::DeviceInUse => {
                Status::already_exists("device_id is already registered to another child")
            }
            AccountError::Validation(m) => Status::invalid_argument(m),
            AccountError::TooManyAttempts => {
                Status::resource_exhausted("too many login attempts; try again later")
            }
        }
    }
}

/// The children (and their devices) a guardian is allowed to see — used to scope
/// the pending-review stream.
#[derive(Debug, Clone, Default)]
pub struct GuardianScope {
    /// `child_id`s this guardian is assigned to.
    pub child_ids: HashSet<String>,
    /// The supervised `device_id`s of those children (alerts carry `device_id`).
    pub device_ids: HashSet<String>,
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Account {
    account_id: String,
    family_id: String,
    salt: [u8; SALT_LEN],
    hash: [u8; HASH_LEN],
}

#[derive(Clone)]
struct ChildRec {
    child_id: String,
    family_id: String,
    name: String,
    device_id: String,
    guardians: HashSet<String>,
}

impl ChildRec {
    fn to_proto(&self) -> Child {
        let mut guardian_account_ids: Vec<String> = self.guardians.iter().cloned().collect();
        guardian_account_ids.sort(); // stable output
        Child {
            child_id: self.child_id.clone(),
            family_id: self.family_id.clone(),
            child_name: self.name.clone(),
            device_id: self.device_id.clone(),
            guardian_account_ids,
        }
    }
}

/// A live guardian session: which account, and when it was minted (for expiry).
#[derive(Clone)]
struct SessionEntry {
    account_id: String,
    issued_ms: i64,
}

#[derive(Default)]
struct Inner {
    /// email (lowercased) → account.
    by_email: HashMap<String, Account>,
    /// account_id → email (reverse lookup).
    email_by_id: HashMap<String, String>,
    /// session token → (account_id, issued time). Expired tokens are rejected
    /// (see [`session_live`]). Never persisted — dropped on restart.
    sessions: HashMap<String, SessionEntry>,
    /// email (lowercased) → failed-login throttle (brute-force lockout). Cleared
    /// on a successful login; not persisted.
    login_fails: HashMap<String, LoginThrottle>,
    /// child_id → child record.
    children: HashMap<String, ChildRec>,
    /// device_id → child_id (for routing alerts by device to a child).
    device_to_child: HashMap<String, String>,
}

/// Cloneable handle to the in-memory account/guardian state. Every clone shares
/// the same maps.
#[derive(Clone)]
pub struct AccountStore {
    inner: Arc<Mutex<Inner>>,
    rng: Arc<SystemRandom>,
    /// `Some` → write-through JSON persistence (accounts survive a restart);
    /// `None` (default) → pure in-memory, unchanged behaviour.
    persist: Option<JsonFile>,
}

impl Default for AccountStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            rng: Arc::new(SystemRandom::new()),
            persist: None,
        }
    }

    /// Durable store rooted at `dir`: loads `accounts.json` on startup and
    /// write-throughs every account/child/guardian mutation. Session tokens are
    /// NOT persisted — guardians simply re-`login` after a restart (keeps the
    /// at-rest credential surface to the KDF hash only). A corrupt file starts
    /// empty (logged); only an unusable directory is fatal.
    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let file = JsonFile::new(dir, "accounts.json")?;
        let snap: AccountSnapshot = file.load_or_default();
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner::from_snapshot(snap))),
            rng: Arc::new(SystemRandom::new()),
            persist: Some(file),
        })
    }

    /// Persist the current state. Call AFTER a mutation; builds the snapshot under
    /// the held lock (consistent), then writes (a write failure is logged, never
    /// fatal — the in-memory state remains authoritative).
    fn persist_locked(&self, inner: &Inner) {
        if let Some(file) = &self.persist {
            if let Err(e) = file.store(&inner.snapshot()) {
                tracing::warn!(error = %e, "failed to persist accounts; continuing in-memory");
            }
        }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Random lowercase-hex string of `bytes` entropy.
    fn rand_hex(&self, bytes: usize) -> String {
        let mut buf = vec![0u8; bytes];
        self.rng.fill(&mut buf).expect("system RNG must not fail");
        to_hex(&buf)
    }

    fn hash_password(&self, password: &str) -> ([u8; SALT_LEN], [u8; HASH_LEN]) {
        let mut salt = [0u8; SALT_LEN];
        self.rng.fill(&mut salt).expect("system RNG must not fail");
        let mut hash = [0u8; HASH_LEN];
        pbkdf2::derive(
            PBKDF2_ALG,
            NonZeroU32::new(PBKDF2_ITERS).unwrap(),
            &salt,
            password.as_bytes(),
            &mut hash,
        );
        (salt, hash)
    }

    /// Create a parent account. Returns `(account_id, created=true)`, or the
    /// existing id with `created=false` if the email is taken.
    pub fn create_account(
        &self,
        email: &str,
        password: &str,
        _display_name: &str,
    ) -> Result<(String, bool), AccountError> {
        let email_key = normalize_email(email);
        if email_key.is_empty() {
            return Err(AccountError::Validation("email is required"));
        }
        if password.len() < 8 {
            return Err(AccountError::Validation(
                "password must be at least 8 characters",
            ));
        }
        let mut inner = self.inner.lock().expect("account mutex poisoned");
        if let Some(existing) = inner.by_email.get(&email_key) {
            return Ok((existing.account_id.clone(), false));
        }
        let (salt, hash) = self.hash_password(password);
        let account_id = self.rand_hex(ID_BYTES);
        let family_id = self.rand_hex(ID_BYTES);
        inner
            .email_by_id
            .insert(account_id.clone(), email_key.clone());
        inner.by_email.insert(
            email_key,
            Account {
                account_id: account_id.clone(),
                family_id,
                salt,
                hash,
            },
        );
        self.persist_locked(&inner);
        Ok((account_id, true))
    }

    /// Verify credentials and mint a session token on success.
    pub fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(String, String, i64), AccountError> {
        let email_key = normalize_email(email);
        let now = Self::now_ms();
        let (max_fails, window_ms) = login_throttle_params();
        let mut inner = self.inner.lock().expect("account mutex poisoned");

        // Brute-force lockout: once an email has too many recent failures, reject
        // (without even checking the password) until the window elapses.
        if inner
            .login_fails
            .get(&email_key)
            .is_some_and(|t| throttle_locked(t, now, window_ms, max_fails))
        {
            return Err(AccountError::TooManyAttempts);
        }

        // An unknown email and a wrong password are indistinguishable to the caller
        // (both `BadCredentials`) and both count toward the lockout. salt/hash are
        // fixed-size arrays (Copy), so cloning them drops the `by_email` borrow.
        let creds = inner
            .by_email
            .get(&email_key)
            .map(|a| (a.salt, a.hash, a.account_id.clone()));
        let verified = match &creds {
            Some((salt, hash, _)) => pbkdf2::verify(
                PBKDF2_ALG,
                NonZeroU32::new(PBKDF2_ITERS).unwrap(),
                salt,
                password.as_bytes(),
                hash,
            )
            .is_ok(),
            None => false,
        };
        if !verified {
            let t = inner
                .login_fails
                .entry(email_key.clone())
                .or_insert(LoginThrottle {
                    fails: 0,
                    window_start_ms: now,
                });
            record_failure(t, now, window_ms);
            return Err(AccountError::BadCredentials);
        }

        // Success: clear the failure counter and mint a session.
        inner.login_fails.remove(&email_key);
        let account_id = creds.expect("verified implies creds present").2;
        let token = self.rand_hex(TOKEN_BYTES);
        let issued_ms = now;
        inner.sessions.insert(
            token.clone(),
            SessionEntry {
                account_id: account_id.clone(),
                issued_ms,
            },
        );
        Ok((token, account_id, issued_ms))
    }

    /// Resolve a session token to its account_id, or `Unauthorized` (unknown OR
    /// expired — a token past its TTL is treated as if it were never issued).
    fn account_for_token(inner: &Inner, token: &str) -> Result<String, AccountError> {
        let entry = inner
            .sessions
            .get(token.trim())
            .ok_or(AccountError::Unauthorized)?;
        if !session_live(entry.issued_ms, Self::now_ms(), session_ttl_ms()) {
            return Err(AccountError::Unauthorized);
        }
        Ok(entry.account_id.clone())
    }

    /// Add a child to the caller's family; the caller becomes its first guardian.
    pub fn add_child(
        &self,
        token: &str,
        child_name: &str,
        device_id: &str,
    ) -> Result<Child, AccountError> {
        let mut inner = self.inner.lock().expect("account mutex poisoned");
        let account_id = Self::account_for_token(&inner, token)?;
        let family_id = inner
            .by_email
            .values()
            .find(|a| a.account_id == account_id)
            .map(|a| a.family_id.clone())
            .ok_or(AccountError::Unauthorized)?;
        if child_name.trim().is_empty() {
            return Err(AccountError::Validation("child_name is required"));
        }
        // device_id is the link from alerts to this child (alerts route by it), so
        // it is REQUIRED — a blank id makes the child un-routable (guardian streams
        // can't match its alerts). It must also map to exactly ONE child — a reused
        // id would put the same device in two families' scopes and leak alerts.
        let device_id = device_id.trim();
        if device_id.is_empty() {
            return Err(AccountError::Validation("device_id is required"));
        }
        if inner.device_to_child.contains_key(device_id) {
            return Err(AccountError::DeviceInUse);
        }
        let child_id = self.rand_hex(ID_BYTES);
        let mut guardians = HashSet::new();
        guardians.insert(account_id);
        let rec = ChildRec {
            child_id: child_id.clone(),
            family_id,
            name: child_name.trim().to_string(),
            device_id: device_id.trim().to_string(),
            guardians,
        };
        // device_id is guaranteed non-empty (validated above) → always indexed.
        inner
            .device_to_child
            .insert(rec.device_id.clone(), child_id.clone());
        let proto = rec.to_proto();
        inner.children.insert(child_id, rec);
        self.persist_locked(&inner);
        Ok(proto)
    }

    /// Assign another account as a guardian of a child. The caller must already
    /// be a guardian of that child.
    pub fn assign_guardian(
        &self,
        token: &str,
        child_id: &str,
        guardian_account_id: &str,
    ) -> Result<(), AccountError> {
        let mut inner = self.inner.lock().expect("account mutex poisoned");
        let caller = Self::account_for_token(&inner, token)?;
        if !inner.email_by_id.contains_key(guardian_account_id) {
            return Err(AccountError::NotFound);
        }
        let rec = inner
            .children
            .get_mut(child_id)
            .ok_or(AccountError::NotFound)?;
        if !rec.guardians.contains(&caller) {
            return Err(AccountError::NotGuardian);
        }
        rec.guardians.insert(guardian_account_id.to_string());
        self.persist_locked(&inner);
        Ok(())
    }

    /// The children the token's guardian is assigned to.
    pub fn list_children(&self, token: &str) -> Result<Vec<Child>, AccountError> {
        let inner = self.inner.lock().expect("account mutex poisoned");
        let account_id = Self::account_for_token(&inner, token)?;
        let mut out: Vec<Child> = inner
            .children
            .values()
            .filter(|c| c.guardians.contains(&account_id))
            .map(ChildRec::to_proto)
            .collect();
        out.sort_by(|a, b| a.child_id.cmp(&b.child_id));
        Ok(out)
    }

    /// Resolve a token to the set of child_ids + device_ids it may see. Returns
    /// `None` for an unknown OR expired token (caller treats that as "deny").
    pub fn guardian_scope(&self, token: &str) -> Option<GuardianScope> {
        let inner = self.inner.lock().expect("account mutex poisoned");
        let entry = inner.sessions.get(token.trim())?;
        if !session_live(entry.issued_ms, Self::now_ms(), session_ttl_ms()) {
            return None;
        }
        let account_id = entry.account_id.clone();
        let mut scope = GuardianScope::default();
        for c in inner.children.values() {
            if c.guardians.contains(&account_id) {
                scope.child_ids.insert(c.child_id.clone());
                if !c.device_id.is_empty() {
                    scope.device_ids.insert(c.device_id.clone());
                }
            }
        }
        Some(scope)
    }
}

/// Lowercase + trim an email for use as the account key.
fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Lowercase-hex encode (no deps).
fn to_hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode an exactly-`N`-byte lowercase-hex string into `[u8; N]`. `None` on a
/// wrong-length or non-hex string (a corrupt snapshot row is skipped, not fatal).
fn from_hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Durable snapshot (serde JSON). Content-free: the KDF salt+hash (never the
// password), ids, hosts. Session tokens are deliberately NOT persisted.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct AccountSnapshot {
    accounts: Vec<AccountRow>,
    children: Vec<ChildRow>,
}

#[derive(Serialize, Deserialize)]
struct AccountRow {
    email_key: String,
    account_id: String,
    family_id: String,
    salt_hex: String,
    hash_hex: String,
}

#[derive(Serialize, Deserialize)]
struct ChildRow {
    child_id: String,
    family_id: String,
    name: String,
    device_id: String,
    guardians: Vec<String>,
}

impl Inner {
    /// Build a stable (sorted) serde snapshot. Omits `sessions`.
    fn snapshot(&self) -> AccountSnapshot {
        let mut accounts: Vec<AccountRow> = self
            .by_email
            .iter()
            .map(|(email_key, a)| AccountRow {
                email_key: email_key.clone(),
                account_id: a.account_id.clone(),
                family_id: a.family_id.clone(),
                salt_hex: to_hex(&a.salt),
                hash_hex: to_hex(&a.hash),
            })
            .collect();
        accounts.sort_by(|a, b| a.email_key.cmp(&b.email_key));

        let mut children: Vec<ChildRow> = self
            .children
            .values()
            .map(|c| {
                let mut guardians: Vec<String> = c.guardians.iter().cloned().collect();
                guardians.sort();
                ChildRow {
                    child_id: c.child_id.clone(),
                    family_id: c.family_id.clone(),
                    name: c.name.clone(),
                    device_id: c.device_id.clone(),
                    guardians,
                }
            })
            .collect();
        children.sort_by(|a, b| a.child_id.cmp(&b.child_id));

        AccountSnapshot { accounts, children }
    }

    /// Rebuild from a snapshot, deriving the reverse maps; `sessions` starts empty
    /// (tokens are not persisted). Rows with malformed salt/hash are skipped.
    fn from_snapshot(snap: AccountSnapshot) -> Inner {
        let mut inner = Inner::default();
        for row in snap.accounts {
            let (salt, hash) = match (
                from_hex_array::<SALT_LEN>(&row.salt_hex),
                from_hex_array::<HASH_LEN>(&row.hash_hex),
            ) {
                (Some(s), Some(h)) => (s, h),
                _ => {
                    tracing::warn!(account = %row.account_id, "skipping account with malformed salt/hash");
                    continue;
                }
            };
            inner
                .email_by_id
                .insert(row.account_id.clone(), row.email_key.clone());
            inner.by_email.insert(
                row.email_key,
                Account {
                    account_id: row.account_id,
                    family_id: row.family_id,
                    salt,
                    hash,
                },
            );
        }
        for row in snap.children {
            let guardians: HashSet<String> = row.guardians.into_iter().collect();
            if !row.device_id.is_empty() {
                inner
                    .device_to_child
                    .insert(row.device_id.clone(), row.child_id.clone());
            }
            inner.children.insert(
                row.child_id.clone(),
                ChildRec {
                    child_id: row.child_id,
                    family_id: row.family_id,
                    name: row.name,
                    device_id: row.device_id,
                    guardians,
                },
            );
        }
        inner
    }
}

/// Extract a bearer token from the `authorization: Bearer <token>` metadata, if
/// present. Lets clients authenticate without putting the token in the message.
pub fn bearer_token<T>(req: &Request<T>) -> Option<String> {
    let raw = req.metadata().get("authorization")?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// gRPC service
// ---------------------------------------------------------------------------

/// Implements `aegis_proto::v1::accounts_server::Accounts` over an [`AccountStore`].
#[derive(Clone)]
pub struct AccountsService {
    store: AccountStore,
}

impl AccountsService {
    pub fn new(store: AccountStore) -> Self {
        Self { store }
    }

    /// Resolve the effective token for a mutating call: the explicit field first,
    /// then the `authorization` metadata header.
    fn token_or_meta<T>(req: &Request<T>, field: &str) -> String {
        if !field.trim().is_empty() {
            return field.trim().to_string();
        }
        bearer_token(req).unwrap_or_default()
    }
}

#[tonic::async_trait]
impl Accounts for AccountsService {
    async fn create_account(
        &self,
        req: Request<CreateAccountRequest>,
    ) -> Result<Response<AccountAck>, Status> {
        let r = req.into_inner();
        let (account_id, created) =
            self.store
                .create_account(&r.email, &r.password, &r.display_name)?;
        Ok(Response::new(AccountAck {
            account_id,
            created,
            detail: if created {
                "account created".to_string()
            } else {
                "email already registered".to_string()
            },
        }))
    }

    async fn login(&self, req: Request<LoginRequest>) -> Result<Response<Session>, Status> {
        let r = req.into_inner();
        let (token, account_id, issued_ts) = self.store.login(&r.email, &r.password)?;
        Ok(Response::new(Session {
            token,
            account_id,
            issued_ts,
        }))
    }

    async fn add_child(&self, req: Request<AddChildRequest>) -> Result<Response<Child>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        let child = self.store.add_child(&token, &r.child_name, &r.device_id)?;
        Ok(Response::new(child))
    }

    async fn assign_guardian(
        &self,
        req: Request<AssignGuardianRequest>,
    ) -> Result<Response<GuardianAck>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        self.store
            .assign_guardian(&token, &r.child_id, &r.guardian_account_id)?;
        Ok(Response::new(GuardianAck {
            ok: true,
            detail: "guardian assigned".to_string(),
        }))
    }

    async fn list_children(
        &self,
        req: Request<ListChildrenRequest>,
    ) -> Result<Response<Children>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let children = self.store.list_children(&token)?;
        Ok(Response::new(Children { children }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aegis-accounts-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn accounts_persist_and_reload_across_restart() {
        let dir = tmp_dir("reload");
        // Fresh persisted store: account + child + a second guardian.
        let s1 = AccountStore::with_state_dir(&dir).unwrap();
        let (alice, created) = s1.create_account("a@x.com", "passwordone", "A").unwrap();
        assert!(created);
        let (a_tok, _, _) = s1.login("a@x.com", "passwordone").unwrap();
        let child = s1.add_child(&a_tok, "Kid", "kids-tablet").unwrap();
        let (bob, _) = s1.create_account("b@x.com", "passwordtwo", "B").unwrap();
        s1.assign_guardian(&a_tok, &child.child_id, &bob).unwrap();
        drop(s1); // simulate a server restart

        // Reload from the same dir.
        let s2 = AccountStore::with_state_dir(&dir).unwrap();
        // KDF hash survived → login works again; wrong password still rejected.
        let (a_tok2, acct2, _) = s2.login("a@x.com", "passwordone").unwrap();
        assert_eq!(acct2, alice);
        assert_eq!(
            s2.login("a@x.com", "wrong"),
            Err(AccountError::BadCredentials)
        );
        // Child + guardian assignment + device routing survived.
        let kids = s2.list_children(&a_tok2).unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].device_id, "kids-tablet");
        assert!(kids[0].guardian_account_ids.contains(&bob));
        assert_eq!(
            s2.add_child(&a_tok2, "Kid2", "kids-tablet"),
            Err(AccountError::DeviceInUse)
        );
        // Sessions are NOT persisted: the OLD token is invalid after restart.
        assert!(s2.guardian_scope(&a_tok).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_accounts_file_starts_empty_not_panic() {
        let dir = tmp_dir("corrupt");
        std::fs::write(dir.join("accounts.json"), b"{ not json").unwrap();
        let s = AccountStore::with_state_dir(&dir).unwrap(); // must not panic
        assert!(s.create_account("c@x.com", "passwordthree", "C").unwrap().1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_live_window() {
        assert!(session_live(0, 0, 1000)); // issued == now
        assert!(session_live(0, 999, 1000)); // within ttl
        assert!(!session_live(0, 1000, 1000)); // at ttl boundary → expired
        assert!(!session_live(0, 5000, 1000)); // past ttl
        assert!(!session_live(100, 50, 1000)); // future-dated → rejected
    }

    #[test]
    fn expired_session_is_rejected() {
        let s = AccountStore::new();
        s.create_account("a@x.com", "passwordone", "A").unwrap();
        let (tok, _, _) = s.login("a@x.com", "passwordone").unwrap();
        // Fresh token works.
        assert!(s.guardian_scope(&tok).is_some());
        assert!(s.list_children(&tok).is_ok());
        // Age the session past the TTL (in-module access to the private field).
        {
            let mut inner = s.inner.lock().unwrap();
            inner.sessions.get_mut(tok.trim()).unwrap().issued_ms -= session_ttl_ms() + 1000;
        }
        // Now treated as unauthenticated everywhere a token is checked.
        assert!(s.guardian_scope(&tok).is_none());
        assert_eq!(s.list_children(&tok), Err(AccountError::Unauthorized));
        assert_eq!(
            s.add_child(&tok, "Kid", "dev-1"),
            Err(AccountError::Unauthorized)
        );
    }

    #[test]
    fn throttle_locks_after_max_then_releases_after_window() {
        let mut t = LoginThrottle {
            fails: 0,
            window_start_ms: 0,
        };
        for _ in 0..4 {
            record_failure(&mut t, 100, 1000);
        }
        assert!(!throttle_locked(&t, 100, 1000, 5)); // 4 < 5
        record_failure(&mut t, 100, 1000); // 5th
        assert!(throttle_locked(&t, 100, 1000, 5)); // locked within window
        assert!(!throttle_locked(&t, 2000, 1000, 5)); // window elapsed → released
    }

    #[test]
    fn record_failure_resets_after_window() {
        let mut t = LoginThrottle {
            fails: 5,
            window_start_ms: 0,
        };
        record_failure(&mut t, 5000, 1000); // window elapsed → reset to a fresh 1
        assert_eq!(t.fails, 1);
        assert_eq!(t.window_start_ms, 5000);
    }

    #[test]
    fn login_locks_out_after_repeated_failures() {
        let s = AccountStore::new();
        s.create_account("a@x.com", "passwordone", "A").unwrap();
        for _ in 0..DEFAULT_LOGIN_MAX_FAILS {
            assert_eq!(
                s.login("a@x.com", "wrong"),
                Err(AccountError::BadCredentials)
            );
        }
        // Locked: even the CORRECT password is now rejected until the window ends.
        assert_eq!(
            s.login("a@x.com", "passwordone"),
            Err(AccountError::TooManyAttempts)
        );
    }

    #[test]
    fn successful_login_clears_failure_counter() {
        let s = AccountStore::new();
        s.create_account("b@x.com", "passwordtwo", "B").unwrap();
        for _ in 0..(DEFAULT_LOGIN_MAX_FAILS - 1) {
            assert_eq!(
                s.login("b@x.com", "wrong"),
                Err(AccountError::BadCredentials)
            );
        }
        assert!(s.login("b@x.com", "passwordtwo").is_ok()); // success clears the counter
                                                            // After clearing, max-1 more failures still don't lock.
        for _ in 0..(DEFAULT_LOGIN_MAX_FAILS - 1) {
            assert_eq!(
                s.login("b@x.com", "wrong"),
                Err(AccountError::BadCredentials)
            );
        }
        assert!(s.login("b@x.com", "passwordtwo").is_ok());
    }

    #[test]
    fn password_round_trips_and_rejects_wrong() {
        let store = AccountStore::new();
        let (id, created) = store
            .create_account("Parent@Example.com", "hunter2hunter", "P")
            .unwrap();
        assert!(created);
        assert!(!id.is_empty());

        // Duplicate email → created = false, same id.
        let (id2, created2) = store
            .create_account("parent@example.com", "different-pass", "P")
            .unwrap();
        assert!(!created2);
        assert_eq!(id, id2, "email is case-insensitive and unique");

        // Right password logs in; wrong password is rejected.
        let (_tok, acct, _ts) = store.login("parent@example.com", "hunter2hunter").unwrap();
        assert_eq!(acct, id);
        assert_eq!(
            store.login("parent@example.com", "nope"),
            Err(AccountError::BadCredentials)
        );
    }

    #[test]
    fn short_password_is_rejected() {
        let store = AccountStore::new();
        assert_eq!(
            store.create_account("a@b.com", "short", "x"),
            Err(AccountError::Validation(
                "password must be at least 8 characters"
            ))
        );
    }

    #[test]
    fn child_and_guardian_routing_is_isolated() {
        let store = AccountStore::new();
        // Two separate parents.
        let (_alice_id, _) = store
            .create_account("alice@x.com", "alicepass1", "A")
            .unwrap();
        let (alice_tok, _, _) = store.login("alice@x.com", "alicepass1").unwrap();
        let (bob_id, _) = store
            .create_account("bob@x.com", "bobpassword", "B")
            .unwrap();
        let (bob_tok, _, _) = store.login("bob@x.com", "bobpassword").unwrap();

        // Alice adds a child on "kids-tablet"; she is its guardian, Bob is not.
        let child = store.add_child(&alice_tok, "Kiddo", "kids-tablet").unwrap();
        assert_eq!(child.guardian_account_ids.len(), 1);

        let alice_scope = store.guardian_scope(&alice_tok).unwrap();
        assert!(alice_scope.device_ids.contains("kids-tablet"));
        assert!(alice_scope.child_ids.contains(&child.child_id));

        let bob_scope = store.guardian_scope(&bob_tok).unwrap();
        assert!(
            bob_scope.device_ids.is_empty(),
            "Bob guards no children → sees nothing"
        );

        // Bob cannot assign himself (not a guardian).
        assert_eq!(
            store.assign_guardian(&bob_tok, &child.child_id, &bob_id),
            Err(AccountError::NotGuardian)
        );

        // Alice assigns Bob; now Bob's scope includes the child + device.
        store
            .assign_guardian(&alice_tok, &child.child_id, &bob_id)
            .unwrap();
        let bob_scope2 = store.guardian_scope(&bob_tok).unwrap();
        assert!(bob_scope2.device_ids.contains("kids-tablet"));

        // ListChildren reflects assignment for both.
        assert_eq!(store.list_children(&alice_tok).unwrap().len(), 1);
        assert_eq!(store.list_children(&bob_tok).unwrap().len(), 1);
    }

    #[test]
    fn unknown_token_has_no_scope() {
        let store = AccountStore::new();
        assert!(store.guardian_scope("not-a-real-token").is_none());
        assert_eq!(
            store.list_children("not-a-real-token"),
            Err(AccountError::Unauthorized)
        );
    }

    #[test]
    fn add_child_rejects_duplicate_device_id() {
        // A device_id maps to exactly one child — otherwise two families would
        // both match it in StreamPendingReviews and leak alerts across families.
        let store = AccountStore::new();
        let (_a, _) = store.create_account("a@x.com", "passwordone", "A").unwrap();
        let (a_tok, _, _) = store.login("a@x.com", "passwordone").unwrap();
        let (_b, _) = store.create_account("b@x.com", "passwordtwo", "B").unwrap();
        let (b_tok, _, _) = store.login("b@x.com", "passwordtwo").unwrap();

        store.add_child(&a_tok, "Kid A", "shared-device").unwrap();
        // A different family trying to claim the same device id is rejected.
        assert_eq!(
            store.add_child(&b_tok, "Kid B", "shared-device"),
            Err(AccountError::DeviceInUse)
        );
        // A distinct device id is fine.
        assert!(store.add_child(&b_tok, "Kid B", "other-device").is_ok());
    }

    #[test]
    fn add_child_rejects_blank_device_id() {
        // A blank device_id makes the child un-routable (alerts route by device_id).
        let store = AccountStore::new();
        let (_a, _) = store.create_account("a@x.com", "passwordone", "A").unwrap();
        let (tok, _, _) = store.login("a@x.com", "passwordone").unwrap();
        assert_eq!(
            store.add_child(&tok, "Kid", "   "),
            Err(AccountError::Validation("device_id is required"))
        );
    }
}
