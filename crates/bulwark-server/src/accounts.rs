//! Parent accounts + per-child assigned guardians.
//!
//! A PARENT ACCOUNT is an email + password. The password is **never stored** —
//! we keep only a one-way KDF hash and verify in constant time. New and rotated
//! passwords use **Argon2id** (memory-hard, OWASP-recommended), stored as a PHC
//! string (`$argon2id$...`, salt embedded). Accounts created before this upgrade
//! still carry a legacy **PBKDF2-HMAC-SHA256** salt+hash; those verify on login
//! and are TRANSPARENTLY re-hashed to Argon2id + persisted on the next successful
//! login (zero user action). A successful [`AccountStore::login`] mints an opaque
//! random session token.
//!
//! SELF-SERVICE RECOVERY: every account is issued ONE high-entropy recovery code
//! at creation (returned once, stored only as an Argon2id hash). A user who forgets
//! their password proves the code via [`AccountStore::reset_password`] to set a new
//! one — no operator, SSH, or email loop. The code is single-use: a reset
//! invalidates it and issues a fresh one. Reset attempts are rate-limited per
//! email exactly like sign-in, so repeated wrong guesses are refused.
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
//! pull in `bulwark-store`/rusqlite here — it fails to build on the Windows host
//! (os error 4551, environmental) and `bulwark-server` must keep building.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::persist::JsonFile;
use argon2::{Algorithm, Argon2, Params, Version};
use bulwark_proto::v1::accounts_server::Accounts;
use bulwark_proto::v1::{
    AccountAck, AddChildRequest, AssignGuardianRequest, ChangePasswordRequest, Child, Children,
    CreateAccountRequest, CreatePairCodeRequest, GuardianAck, ListChildrenRequest, LoginRequest,
    PairCode, PairResult, RedeemPairCodeRequest, RequestPasswordResetAck,
    RequestPasswordResetRequest, ResetPasswordAck, ResetPasswordRequest, Session,
};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use tonic::{Request, Response, Status};

/// LEGACY PBKDF2 parameters. SHA-256, 100k iterations, 32-byte output, 16-byte
/// salt. Retained ONLY to verify pre-Argon2id accounts on login (then rehash); new
/// passwords never use this path.
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const PBKDF2_ITERS: u32 = 100_000;
const HASH_LEN: usize = 32;
const SALT_LEN: usize = 16;

/// Argon2id parameters. Chosen from the OWASP Password Storage Cheat Sheet's
/// second-listed profile (m=19456 KiB ≈ 19 MiB, t=2, p=1) — memory-hard yet light
/// enough for the t3.small (2 GiB) deploy box to verify many concurrent logins
/// without OOM/thrash. 32-byte output. Salt is per-hash and embedded in the PHC
/// string. The same params hash both passwords and recovery codes.
const ARGON2_MEM_KIB: u32 = 19 * 1024; // 19 MiB
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_LANES: u32 = 1;

/// A configured Argon2id hasher with our pinned params (id variant, v19/0x13).
fn argon2() -> Argon2<'static> {
    let params = Params::new(
        ARGON2_MEM_KIB,
        ARGON2_TIME_COST,
        ARGON2_LANES,
        Some(HASH_LEN),
    )
    .expect("argon2 params are valid constants");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash `secret` (password or recovery code) to a self-describing PHC string
/// (`$argon2id$v=19$m=...$<salt>$<hash>`). The salt is fresh per call.
pub(crate) fn argon2_hash(rng: &SystemRandom, secret: &[u8]) -> Result<String, AccountError> {
    let mut salt_bytes = [0u8; 16];
    rng.fill(&mut salt_bytes)
        .map_err(|_| AccountError::Internal)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| AccountError::Internal)?;
    argon2()
        .hash_password(secret, &salt)
        .map(|h| h.to_string())
        .map_err(|_| AccountError::Internal)
}

/// Constant-time verify of `secret` against a stored Argon2id PHC string. A
/// malformed PHC string (corrupt row) verifies as `false`, never panics.
pub(crate) fn argon2_verify(phc: &str, secret: &[u8]) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => argon2().verify_password(secret, &parsed).is_ok(),
        Err(_) => false,
    }
}
/// Session/id token entropy in bytes (→ hex string of 2× this length).
const TOKEN_BYTES: usize = 32;
const ID_BYTES: usize = 16;

/// Self-service recovery code: 16 random bytes (128 bits) rendered as base32 in
/// 5 dash-separated groups (e.g. `K7MQ2-9XF4T-...`). 128 bits is far beyond
/// exhaustive guessing even before the per-email reset rate limit. Only the
/// Argon2id hash is stored; the plaintext is shown once.
const RECOVERY_CODE_BYTES: usize = 16;
const RECOVERY_GROUP_LEN: usize = 5;

/// EMAILED reset token: 16 random bytes (128 bits) rendered like the recovery
/// code (base32, dash-grouped) so the guardian can type it back. It is the
/// OPTIONAL email-based alternative to the saved recovery code: short-lived,
/// single-use, and stored ONLY as an Argon2id hash + an expiry timestamp on the
/// account. The plaintext is emailed once and never persisted.
const RESET_TOKEN_BYTES: usize = 16;
/// How long an emailed reset token stays valid; override with
/// `BULWARK_RESET_TOKEN_TTL_SECS` (positive integer seconds). Short by design so a
/// code that lingers in an inbox stops working quickly. Default 30 minutes.
const DEFAULT_RESET_TOKEN_TTL_SECS: i64 = 30 * 60;

/// The configured emailed-reset-token TTL in milliseconds (env override, else the
/// default).
fn reset_token_ttl_ms() -> i64 {
    std::env::var("BULWARK_RESET_TOKEN_TTL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_RESET_TOKEN_TTL_SECS)
        .saturating_mul(1000)
}

/// Reset-token TTL in whole minutes (the figure shown in the reset email). Public
/// so the staff guardian-support path renders the same TTL as self-service reset.
pub fn reset_token_ttl_minutes() -> i64 {
    (reset_token_ttl_ms() / 60_000).max(1)
}

/// Content-free guardian metadata for the staff support path — existence, lockout
/// state, recovery/reset flags, and COUNTS only. Never names, ids, tokens, emails,
/// addresses, or any message/alert content.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct GuardianMetaData {
    /// An account with the queried email exists.
    pub exists: bool,
    /// A sign-in lockout (failed-attempt throttle) is currently active.
    pub locked: bool,
    /// A self-service recovery code is set.
    pub has_recovery_code: bool,
    /// An emailed reset token is outstanding.
    pub reset_pending: bool,
    /// Number of children this guardian is assigned to (COUNT only).
    pub child_count: u32,
    /// Number of those children with a supervised device (COUNT only).
    pub device_count: u32,
}

/// Pairing codes are a short-lived, single-use linking credential.
const PAIR_CODE_TTL_SECS: i64 = 15 * 60;
/// Single global key for the pair-code redeem throttle: redemption is
/// unauthenticated (no email/account to key on), so all wrong-code guesses
/// share one counter. Simple by design — a global pause on guessing is
/// acceptable for a 15-minute, single-use, ~39-bit code (belt-and-braces).
const REDEEM_THROTTLE_KEY: &str = "redeem";
const PAIR_CODE_LEN: usize = 8;
/// Unambiguous alphabet for human-typed pair codes (no 0/O/1/I).
const PAIR_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// Default guardian-session lifetime; override with `BULWARK_SESSION_TTL_SECS`
/// (positive integer seconds). A leaked token is valid at most this long. Sessions
/// persist across restarts as sha256 digests only (see [`token_hash`]).
const DEFAULT_SESSION_TTL_SECS: i64 = 12 * 3600;

/// The configured session TTL in milliseconds (env override, else the default).
fn session_ttl_ms() -> i64 {
    std::env::var("BULWARK_SESSION_TTL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_SESSION_TTL_SECS)
        .saturating_mul(1000)
}

/// Is a session issued at `issued_ms` still valid at `now_ms` for `ttl_ms`? Pure
/// (unit-tested): rejects future-dated and past-TTL tokens.
pub(crate) fn session_live(issued_ms: i64, now_ms: i64, ttl_ms: i64) -> bool {
    now_ms >= issued_ms && now_ms.saturating_sub(issued_ms) < ttl_ms
}

/// Sign-in rate-limit defaults; override with `BULWARK_LOGIN_MAX_FAILS` /
/// `BULWARK_LOGIN_WINDOW_SECS`. After `max` failed sign-ins for one email within
/// the window, that email is paused until the window elapses.
const DEFAULT_LOGIN_MAX_FAILS: u32 = 5;
const DEFAULT_LOGIN_WINDOW_SECS: i64 = 15 * 60;

/// `(max_fails, window_ms)` from the environment, else the defaults.
pub(crate) fn login_throttle_params() -> (u32, i64) {
    let max = std::env::var("BULWARK_LOGIN_MAX_FAILS")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_LOGIN_MAX_FAILS);
    let window = std::env::var("BULWARK_LOGIN_WINDOW_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_LOGIN_WINDOW_SECS)
        .saturating_mul(1000);
    (max, window)
}

/// Per-email failed-login counter within a sliding window.
#[derive(Clone)]
pub(crate) struct LoginThrottle {
    pub(crate) fails: u32,
    pub(crate) window_start_ms: i64,
}

/// Is this email currently locked out? Pure (unit-tested).
pub(crate) fn throttle_locked(t: &LoginThrottle, now_ms: i64, window_ms: i64, max: u32) -> bool {
    t.fails >= max && now_ms.saturating_sub(t.window_start_ms) <= window_ms
}

/// Record one failed login: start a fresh window if the old one elapsed, else
/// increment within it. Pure (unit-tested).
pub(crate) fn record_failure(t: &mut LoginThrottle, now_ms: i64, window_ms: i64) {
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
    /// The pairing code is unknown, expired, or already used.
    PairCodeInvalid,
    /// The recovery code didn't match (or no recovery code is set for this email).
    /// Indistinguishable from an unknown email — both deny without a hint.
    BadRecoveryCode,
    /// A cryptographic primitive (RNG / Argon2id) failed unexpectedly. Should be
    /// unreachable in practice; surfaced as an internal error, never a credential leak.
    Internal,
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
            AccountError::PairCodeInvalid => {
                Status::not_found("pairing code is invalid, expired, or already used")
            }
            // Same opaque message as bad credentials — never reveal whether the
            // email is known vs. the code is simply wrong.
            AccountError::BadRecoveryCode => {
                Status::unauthenticated("invalid email or recovery code")
            }
            AccountError::Internal => Status::internal("internal error"),
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

/// How an account's password is stored at rest. Exactly one form is authoritative.
#[derive(Clone)]
enum PwHash {
    /// Argon2id PHC string (`$argon2id$...`) — the current scheme (new + rotated).
    Argon2(String),
    /// LEGACY PBKDF2-HMAC-SHA256 salt+hash — verified on login, then transparently
    /// re-hashed to [`PwHash::Argon2`] and persisted (one-shot per account).
    Pbkdf2 {
        salt: [u8; SALT_LEN],
        hash: [u8; HASH_LEN],
    },
}

#[derive(Clone)]
struct Account {
    account_id: String,
    family_id: String,
    /// Password at rest (Argon2id, or legacy PBKDF2 awaiting on-login migration).
    pw: PwHash,
    /// Argon2id hash of the single-use recovery code, if one is set. `None` for a
    /// legacy account loaded from a pre-recovery snapshot (it simply has no
    /// self-service reset until the operator backstop or a future re-issue).
    recovery_phc: Option<String>,
    /// Argon2id hash of an outstanding EMAILED reset token, with its expiry. `None`
    /// when no email reset is in flight. Single-use: cleared the moment the token is
    /// consumed (a successful reset) or superseded (a fresh request overwrites it).
    /// Only the hash is stored — the plaintext is emailed once, never persisted.
    reset_token: Option<ResetToken>,
}

/// A pending emailed reset token at rest: its Argon2id hash + an absolute expiry.
#[derive(Clone)]
struct ResetToken {
    phc: String,
    expires_ms: i64,
}

#[derive(Clone)]
struct ChildRec {
    child_id: String,
    family_id: String,
    name: String,
    device_id: String,
    guardians: HashSet<String>,
    /// sha256 hex of the per-device token minted at pairing (the raw token is
    /// returned to the device exactly once, never stored). EMPTY for children
    /// enrolled before device tokens existed (or via AddChild, where no device
    /// is present to receive one) — those verify under a legacy grace until a
    /// device-removal/re-pair flow ships (re-pairing an enrolled device_id
    /// currently returns DeviceInUse — follow-up).
    /// See [`AccountStore::verify_device_token`].
    device_token_sha256: String,
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

/// A pending pairing code: who minted it + the child it will create on redeem.
/// Short-lived, single-use, NEVER persisted (like sessions).
#[derive(Clone)]
struct PairCodeRec {
    account_id: String,
    family_id: String,
    child_name: String,
    issued_ms: i64,
}

#[derive(Default)]
struct Inner {
    /// email (lowercased) → account.
    by_email: HashMap<String, Account>,
    /// account_id → email (reverse lookup).
    email_by_id: HashMap<String, String>,
    /// sha256(session token) hex → (account_id, issued time). Keyed by DIGEST so
    /// the raw bearer token never sits in a map or on disk — every lookup hashes
    /// the presented token. Expired tokens are rejected (see [`session_live`]).
    sessions: HashMap<String, SessionEntry>,
    /// email (lowercased) → failed-sign-in rate limit (repeated-wrong-password
    /// pause). Cleared on a successful sign-in; not persisted.
    login_fails: HashMap<String, LoginThrottle>,
    /// email (lowercased) → failed password-RESET throttle. Same shape + window as
    /// `login_fails` but a SEPARATE counter so reset attempts can't be used to lock
    /// a victim out of normal login (and vice-versa). Cleared on a successful
    /// reset; not persisted (an in-memory lockout clears on restart).
    reset_fails: HashMap<String, LoginThrottle>,
    /// email (lowercased) → emailed-reset-REQUEST throttle. Counts how often an
    /// email reset code has been requested for one address so a single inbox can't
    /// be flooded with reset mail. Separate from `reset_fails` (wrong-code guesses)
    /// and `login_fails`. Not persisted (clears on restart).
    request_fails: HashMap<String, LoginThrottle>,
    /// child_id → child record.
    children: HashMap<String, ChildRec>,
    /// device_id → child_id (for routing alerts by device to a child).
    device_to_child: HashMap<String, String>,
    /// pairing code → pending child record. Short-lived, single-use, not persisted.
    pair_codes: HashMap<String, PairCodeRec>,
    /// Failed pair-code REDEEM throttle. Redemption is the one unauthenticated
    /// guessing surface with no account to key on, so a single GLOBAL key
    /// ([`REDEEM_THROTTLE_KEY`]) paces all wrong-code attempts (same
    /// window/params as login). Cleared by a successful redeem; not persisted.
    redeem_fails: HashMap<String, LoginThrottle>,
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
    /// write-throughs every account/child/guardian mutation. Sessions persist as
    /// sha256(token) digests only — a login survives a restart/redeploy, but a
    /// stolen accounts.json cannot impersonate a guardian (at-rest credential
    /// surface = KDF hash + token digest). A corrupt file starts empty (logged);
    /// only an unusable directory is fatal.
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

    /// Hash a new/rotated password with Argon2id → a PHC string. New accounts and
    /// every change/reset go through here; the legacy PBKDF2 path is verify-only.
    fn hash_password(&self, password: &str) -> Result<String, AccountError> {
        argon2_hash(&self.rng, password.as_bytes())
    }

    /// Generate a fresh single-use recovery code (plaintext) and its Argon2id hash.
    /// Returns `(plaintext_for_the_user, hash_for_storage)`. The plaintext is shown
    /// once and never recoverable; only the hash is persisted.
    fn new_recovery_code(&self) -> Result<(String, String), AccountError> {
        let mut buf = [0u8; RECOVERY_CODE_BYTES];
        self.rng
            .fill(&mut buf)
            .map_err(|_| AccountError::Internal)?;
        // Crockford-ish base32 (no padding) split into readable groups. We hash the
        // canonical (uppercased, dash-stripped) form so user-entered spacing/case
        // doesn't matter on reset.
        let raw = data_encoding::BASE32_NOPAD.encode(&buf);
        let display = group_recovery_code(&raw);
        let hash = argon2_hash(&self.rng, normalize_recovery_code(&display).as_bytes())?;
        Ok((display, hash))
    }

    /// Create a parent account. Returns `(account_id, created, recovery_code)`:
    /// `created=true` + a one-time recovery code on success, or the existing id with
    /// `created=false` and an EMPTY recovery code if the email is taken (a duplicate
    /// call must NOT mint a code — that would let anyone harvest a reset credential
    /// for a registered email). The recovery code's plaintext is returned ONCE; only
    /// its Argon2id hash is stored.
    pub fn create_account(
        &self,
        email: &str,
        password: &str,
        _display_name: &str,
    ) -> Result<(String, bool, String), AccountError> {
        let email_key = normalize_email(email);
        if email_key.is_empty() {
            return Err(AccountError::Validation("email is required"));
        }
        if password.len() < 8 {
            return Err(AccountError::Validation(
                "password must be at least 8 characters",
            ));
        }
        // Hash OUTSIDE the lock (Argon2id is deliberately slow + memory-hard — never
        // hold the global account mutex across it).
        let phc = self.hash_password(password)?;
        let (recovery_code, recovery_phc) = self.new_recovery_code()?;
        let mut inner = self.inner.lock().expect("account mutex poisoned");
        if let Some(existing) = inner.by_email.get(&email_key) {
            // Email taken: no-op, and crucially DO NOT leak a recovery code.
            return Ok((existing.account_id.clone(), false, String::new()));
        }
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
                pw: PwHash::Argon2(phc),
                recovery_phc: Some(recovery_phc),
                reset_token: None,
            },
        );
        self.persist_locked(&inner);
        Ok((account_id, true, recovery_code))
    }

    /// Verify credentials and mint a session token on success. Accepts EITHER the
    /// current Argon2id PHC OR a legacy PBKDF2 hash; on a successful legacy verify
    /// the password is transparently re-hashed to Argon2id and persisted (the
    /// account self-upgrades on next login, zero user action).
    pub fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(String, String, i64), AccountError> {
        let email_key = normalize_email(email);
        let now = Self::now_ms();
        let (max_fails, window_ms) = login_throttle_params();

        // Snapshot the throttle + stored hash under the lock, then RELEASE it before
        // the (deliberately slow) KDF verify — never hold the global mutex across
        // Argon2id, or one slow login serializes all others.
        let pw = {
            let inner = self.inner.lock().expect("account mutex poisoned");
            if inner
                .login_fails
                .get(&email_key)
                .is_some_and(|t| throttle_locked(t, now, window_ms, max_fails))
            {
                return Err(AccountError::TooManyAttempts);
            }
            inner
                .by_email
                .get(&email_key)
                .map(|a| (a.pw.clone(), a.account_id.clone()))
        };

        // An unknown email and a wrong password are indistinguishable (both
        // `BadCredentials`) and both count toward the lockout.
        let (verified, needs_rehash, account_id) = match &pw {
            Some((PwHash::Argon2(phc), aid)) => {
                (argon2_verify(phc, password.as_bytes()), false, aid.clone())
            }
            Some((PwHash::Pbkdf2 { salt, hash }, aid)) => {
                let ok = pbkdf2::verify(
                    PBKDF2_ALG,
                    NonZeroU32::new(PBKDF2_ITERS).unwrap(),
                    salt,
                    password.as_bytes(),
                    hash,
                )
                .is_ok();
                // A correct legacy password earns a one-shot upgrade to Argon2id.
                (ok, ok, aid.clone())
            }
            None => (false, false, String::new()),
        };

        // Re-hash legacy → Argon2id OUTSIDE the lock (slow), before re-acquiring.
        let upgraded_phc = if verified && needs_rehash {
            self.hash_password(password).ok()
        } else {
            None
        };

        let mut inner = self.inner.lock().expect("account mutex poisoned");
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

        // Success: clear the failure counter, apply any legacy→Argon2id upgrade,
        // and mint a session.
        inner.login_fails.remove(&email_key);
        if let Some(phc) = upgraded_phc {
            if let Some(acct) = inner.by_email.get_mut(&email_key) {
                acct.pw = PwHash::Argon2(phc);
            }
        }
        let token = self.rand_hex(TOKEN_BYTES);
        let issued_ms = now;
        // Stored/persisted by DIGEST only — the raw token goes to the caller and
        // is never written anywhere server-side.
        inner.sessions.insert(
            token_hash(&token),
            SessionEntry {
                account_id: account_id.clone(),
                issued_ms,
            },
        );
        // Persist the new session (and any rehash) so a redeploy/restart doesn't
        // invalidate the login (the testing-phase continuous deploy restarts often).
        self.persist_locked(&inner);
        Ok((token, account_id, issued_ms))
    }

    /// Authenticated password change: the caller proves the OLD password, sets a
    /// new Argon2id one. On success ALL of the account's sessions EXCEPT the
    /// caller's are invalidated (a leaked old session can't outlive the rotation).
    /// Passwords are never logged.
    pub fn change_password(
        &self,
        token: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<String, AccountError> {
        if new_password.len() < 8 {
            return Err(AccountError::Validation(
                "password must be at least 8 characters",
            ));
        }
        // Resolve the session → account, and snapshot the stored hash, under the
        // lock; then verify + re-hash OUTSIDE it (slow KDF).
        let (account_id, pw) = {
            let inner = self.inner.lock().expect("account mutex poisoned");
            let account_id = Self::account_for_token(&inner, token)?;
            let pw = inner
                .by_email
                .values()
                .find(|a| a.account_id == account_id)
                .map(|a| a.pw.clone())
                .ok_or(AccountError::Unauthorized)?;
            (account_id, pw)
        };

        let old_ok = match &pw {
            PwHash::Argon2(phc) => argon2_verify(phc, old_password.as_bytes()),
            PwHash::Pbkdf2 { salt, hash } => pbkdf2::verify(
                PBKDF2_ALG,
                NonZeroU32::new(PBKDF2_ITERS).unwrap(),
                salt,
                old_password.as_bytes(),
                hash,
            )
            .is_ok(),
        };
        if !old_ok {
            return Err(AccountError::BadCredentials);
        }
        let new_phc = self.hash_password(new_password)?;
        let keep = token_hash(token);

        let mut inner = self.inner.lock().expect("account mutex poisoned");
        // Find the account by email key (mutable) and set the new hash.
        let email_key = inner
            .email_by_id
            .get(&account_id)
            .cloned()
            .ok_or(AccountError::Unauthorized)?;
        match inner.by_email.get_mut(&email_key) {
            Some(acct) => acct.pw = PwHash::Argon2(new_phc),
            None => return Err(AccountError::Unauthorized),
        }
        // Invalidate every OTHER session for this account; the caller's stays live.
        inner
            .sessions
            .retain(|digest, e| e.account_id != account_id || *digest == keep);
        self.persist_locked(&inner);
        Ok(account_id)
    }

    /// Self-service password reset via the one-time recovery code — no operator
    /// loop. Verifies the recovery-code hash for `email`, sets the new Argon2id
    /// password, INVALIDATES the used code, issues + returns a FRESH one, and (like
    /// change_password) drops all of the account's existing sessions. Reset
    /// attempts are throttled per email exactly like login. Returns the new
    /// recovery code (shown once).
    pub fn reset_password(
        &self,
        email: &str,
        recovery_code: &str,
        new_password: &str,
    ) -> Result<String, AccountError> {
        let email_key = normalize_email(email);
        let now = Self::now_ms();
        let (max_fails, window_ms) = login_throttle_params();
        if new_password.len() < 8 {
            return Err(AccountError::Validation(
                "password must be at least 8 characters",
            ));
        }

        // Throttle + snapshot BOTH the stored recovery hash and any outstanding
        // emailed reset token under the lock; verify the (slow) Argon2id OUTSIDE it.
        // `recovery_code` in the request may be EITHER credential — we try the
        // recovery code first, then the emailed token.
        let (recovery_phc, reset_token) = {
            let inner = self.inner.lock().expect("account mutex poisoned");
            if inner
                .reset_fails
                .get(&email_key)
                .is_some_and(|t| throttle_locked(t, now, window_ms, max_fails))
            {
                return Err(AccountError::TooManyAttempts);
            }
            // Unknown email and "no credential set" are indistinguishable from a
            // wrong code (all → BadRecoveryCode) so we never confirm an email exists.
            match inner.by_email.get(&email_key) {
                Some(a) => (a.recovery_phc.clone(), a.reset_token.clone()),
                None => (None, None),
            }
        };

        // 1) Recovery code (rotates on success). 2) Emailed token (expires on
        // success, and only if it hasn't already timed out).
        let recovery_ok = match &recovery_phc {
            Some(phc) => argon2_verify(phc, normalize_recovery_code(recovery_code).as_bytes()),
            None => false,
        };
        let token_ok = !recovery_ok
            && match &reset_token {
                Some(t) => {
                    t.expires_ms > now
                        && argon2_verify(&t.phc, normalize_recovery_code(recovery_code).as_bytes())
                }
                None => false,
            };

        if !recovery_ok && !token_ok {
            let mut inner = self.inner.lock().expect("account mutex poisoned");
            let t = inner
                .reset_fails
                .entry(email_key.clone())
                .or_insert(LoginThrottle {
                    fails: 0,
                    window_start_ms: now,
                });
            record_failure(t, now, window_ms);
            return Err(AccountError::BadRecoveryCode);
        }

        // Valid credential: mint the new password hash + a fresh recovery code
        // (slow, outside the lock), then commit.
        let new_phc = self.hash_password(new_password)?;
        let (new_recovery_code, new_recovery_phc) = self.new_recovery_code()?;

        let mut inner = self.inner.lock().expect("account mutex poisoned");
        inner.reset_fails.remove(&email_key);
        let account_id = match inner.by_email.get_mut(&email_key) {
            Some(acct) => {
                acct.pw = PwHash::Argon2(new_phc);
                acct.recovery_phc = Some(new_recovery_phc); // single-use: old code is dead
                                                            // Any outstanding emailed token is consumed by ANY successful reset
                                                            // (whichever credential proved it) so a leaked code can't be replayed.
                acct.reset_token = None;
                acct.account_id.clone()
            }
            // The account vanished between snapshot and commit (extremely unlikely).
            None => return Err(AccountError::BadRecoveryCode),
        };
        // Drop every session for this account — a reset means "I lost control of
        // this account"; force a fresh login everywhere.
        inner.sessions.retain(|_, e| e.account_id != account_id);
        self.persist_locked(&inner);
        Ok(new_recovery_code)
    }

    /// Request an EMAILED reset code — the alternative to the saved recovery code.
    /// ANTI-ENUMERATION: this is intentionally side-effect-quiet. It returns
    /// `Ok(Some((recipient_email, plaintext_code)))` ONLY when the email is a real
    /// account AND the per-email request rate limit hasn't been hit; otherwise
    /// `Ok(None)`. The CALLER (the async service) maps BOTH outcomes onto the SAME
    /// generic ack, so an observer can't tell a known email from an unknown one. On
    /// the `Some` path the account stores only the Argon2id HASH of the code + an
    /// expiry; the returned plaintext is for the one outgoing email and is never
    /// persisted. A fresh request overwrites any previous outstanding token.
    pub fn request_password_reset(
        &self,
        email: &str,
    ) -> Result<Option<(String, String)>, AccountError> {
        let email_key = normalize_email(email);
        let now = Self::now_ms();
        let (max_fails, window_ms) = login_throttle_params();

        // Rate-limit the REQUEST per email (separate from wrong-code guesses) so a
        // single inbox can't be flooded. A throttled request returns `None` — which
        // the caller renders identically to an unknown email (anti-enumeration).
        {
            let mut inner = self.inner.lock().expect("account mutex poisoned");
            let known = inner.by_email.contains_key(&email_key);
            if inner
                .request_fails
                .get(&email_key)
                .is_some_and(|t| throttle_locked(t, now, window_ms, max_fails))
            {
                return Ok(None);
            }
            // Count this request toward the per-email cap whether or not the email
            // exists (so probing an inbox is bounded regardless of account state).
            let t = inner
                .request_fails
                .entry(email_key.clone())
                .or_insert(LoginThrottle {
                    fails: 0,
                    window_start_ms: now,
                });
            record_failure(t, now, window_ms);
            if !known {
                // No such account — no email, but the caller still acks generically.
                return Ok(None);
            }
        }

        // Mint a token (slow hash, outside the lock), then store its hash + expiry.
        let (code, code_phc) = self.new_reset_token()?;
        let expires_ms = now.saturating_add(reset_token_ttl_ms());

        let mut inner = self.inner.lock().expect("account mutex poisoned");
        match inner.by_email.get_mut(&email_key) {
            Some(acct) => {
                acct.reset_token = Some(ResetToken {
                    phc: code_phc,
                    expires_ms,
                });
            }
            // The account vanished between the checks (extremely unlikely) — ack
            // generically without sending.
            None => return Ok(None),
        }
        self.persist_locked(&inner);
        Ok(Some((email_key, code)))
    }

    /// STAFF SUPPORT: clear a guardian's in-memory failed-attempt lockouts (login,
    /// reset-guess, and reset-request throttles) so a locked-out guardian can try
    /// again at once. Touches NO password, session, recovery code, or content.
    /// Returns whether an account with that email exists (for an honest ack). The
    /// caller (StaffAdmin) audits the action.
    pub fn staff_clear_lockout(&self, email: &str) -> bool {
        let key = normalize_email(email);
        let mut inner = self.inner.lock().expect("account mutex poisoned");
        inner.login_fails.remove(&key);
        inner.reset_fails.remove(&key);
        inner.request_fails.remove(&key);
        let existed = inner.by_email.contains_key(&key);
        self.persist_locked(&inner);
        existed
    }

    /// STAFF SUPPORT: content-free metadata for one guardian account (existence,
    /// lockout state, recovery/reset flags, child + device COUNTS). Never returns
    /// names, ids, tokens, the email, addresses, or any message/alert content.
    pub fn staff_guardian_meta(&self, email: &str) -> GuardianMetaData {
        let key = normalize_email(email);
        let now = Self::now_ms();
        let (max_fails, window_ms) = login_throttle_params();
        let inner = self.inner.lock().expect("account mutex poisoned");
        let acct = match inner.by_email.get(&key) {
            Some(a) => a,
            None => return GuardianMetaData::default(), // exists = false, all zero
        };
        let account_id = acct.account_id.clone();
        let locked = inner
            .login_fails
            .get(&key)
            .is_some_and(|t| throttle_locked(t, now, window_ms, max_fails));
        let has_recovery_code = acct.recovery_phc.is_some();
        let reset_pending = acct.reset_token.is_some();
        let mut child_count = 0u32;
        let mut device_count = 0u32;
        for c in inner.children.values() {
            if c.guardians.contains(&account_id) {
                child_count = child_count.saturating_add(1);
                if !c.device_id.trim().is_empty() {
                    device_count = device_count.saturating_add(1);
                }
            }
        }
        GuardianMetaData {
            exists: true,
            locked,
            has_recovery_code,
            reset_pending,
            child_count,
            device_count,
        }
    }

    /// Generate a fresh emailed reset token (plaintext) + its Argon2id hash. Same
    /// readable base32 grouping as the recovery code so a guardian can type it back.
    fn new_reset_token(&self) -> Result<(String, String), AccountError> {
        let mut buf = [0u8; RESET_TOKEN_BYTES];
        self.rng
            .fill(&mut buf)
            .map_err(|_| AccountError::Internal)?;
        let raw = data_encoding::BASE32_NOPAD.encode(&buf);
        let display = group_recovery_code(&raw);
        let hash = argon2_hash(&self.rng, normalize_recovery_code(&display).as_bytes())?;
        Ok((display, hash))
    }

    /// Resolve a session token to its account_id, or `Unauthorized` (unknown OR
    /// expired — a token past its TTL is treated as if it were never issued).
    fn account_for_token(inner: &Inner, token: &str) -> Result<String, AccountError> {
        let entry = inner
            .sessions
            .get(&token_hash(token))
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
            // AddChild is the manual (guardian-typed) enrollment path — no
            // device is present to receive a token, so this record verifies
            // under the legacy grace until the device pairs properly.
            device_token_sha256: String::new(),
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

    /// Mint a short-lived, single-use pairing code bound to the caller's family.
    /// The child record is created later, when the device redeems the code.
    pub fn create_pair_code(
        &self,
        token: &str,
        child_name: &str,
    ) -> Result<(String, i64), AccountError> {
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
        let issued_ms = Self::now_ms();
        let code = self.gen_pair_code();
        inner.pair_codes.insert(
            code.clone(),
            PairCodeRec {
                account_id,
                family_id,
                child_name: child_name.trim().to_string(),
                issued_ms,
            },
        );
        Ok((code, issued_ms + PAIR_CODE_TTL_SECS * 1000))
    }

    /// Redeem a pairing code from a child device: creates the child (with this
    /// `device_id`) under the code's family, assigns the minting parent as the
    /// first guardian, consumes the code, and mints the PER-DEVICE TOKEN the
    /// device authenticates with from then on (Heartbeat / config reads).
    /// Returns `(child_id, family_id, device_token)` — the raw token goes to
    /// the device exactly once; only its sha256 digest is stored.
    /// Unauthenticated — the code IS the credential, so the not-yet-enrolled
    /// child can call it; wrong-code guesses are paced by a global throttle
    /// (this is the one unauthenticated guessing surface here).
    pub fn redeem_pair_code(
        &self,
        code: &str,
        device_id: &str,
    ) -> Result<(String, String, String), AccountError> {
        let now = Self::now_ms();
        let (max_fails, window_ms) = login_throttle_params();
        let mut inner = self.inner.lock().expect("account mutex poisoned");
        // Throttle FIRST: while locked, even a correct code is refused (same
        // discipline as login). Unlike login there is no slow KDF on this path
        // — sha256 + the RNG are fast — so the whole redeem stays under the
        // one lock instead of the snapshot/release/re-acquire dance.
        if inner
            .redeem_fails
            .get(REDEEM_THROTTLE_KEY)
            .is_some_and(|t| throttle_locked(t, now, window_ms, max_fails))
        {
            return Err(AccountError::TooManyAttempts);
        }
        let key = code.trim().to_uppercase();
        let device_id = device_id.trim();
        if device_id.is_empty() {
            return Err(AccountError::Validation("device_id is required"));
        }
        // Unknown or expired code = a guess → count it toward the throttle.
        // (Validation/DeviceInUse are NOT guesses and don't count.)
        let rec = match inner.pair_codes.get(&key).cloned() {
            Some(rec) if session_live(rec.issued_ms, now, PAIR_CODE_TTL_SECS * 1000) => rec,
            other => {
                if other.is_some() {
                    inner.pair_codes.remove(&key); // expired → drop it
                }
                let t = inner
                    .redeem_fails
                    .entry(REDEEM_THROTTLE_KEY.to_string())
                    .or_insert(LoginThrottle {
                        fails: 0,
                        window_start_ms: now,
                    });
                record_failure(t, now, window_ms);
                return Err(AccountError::PairCodeInvalid);
            }
        };
        if inner.device_to_child.contains_key(device_id) {
            return Err(AccountError::DeviceInUse);
        }
        let child_id = self.rand_hex(ID_BYTES);
        // The per-device secret: 32 bytes of CSPRNG entropy, hex — the same
        // strength as a session token. Stored as a sha256 digest ONLY
        // (mirrors sessions: a copied accounts.json is never enough to act as
        // the device); the raw value goes back to the device exactly once.
        let device_token = self.rand_hex(TOKEN_BYTES);
        let mut guardians = HashSet::new();
        guardians.insert(rec.account_id.clone());
        let child_rec = ChildRec {
            child_id: child_id.clone(),
            family_id: rec.family_id.clone(),
            name: rec.child_name.clone(),
            device_id: device_id.to_string(),
            guardians,
            device_token_sha256: token_hash(&device_token),
        };
        inner
            .device_to_child
            .insert(device_id.to_string(), child_id.clone());
        inner.children.insert(child_id.clone(), child_rec);
        inner.pair_codes.remove(&key); // single-use
        inner.redeem_fails.remove(REDEEM_THROTTLE_KEY); // success clears the pacing
        self.persist_locked(&inner);
        Ok((child_id, rec.family_id, device_token))
    }

    /// Generate a short, human-typeable, unambiguous pairing code.
    fn gen_pair_code(&self) -> String {
        let mut buf = vec![0u8; PAIR_CODE_LEN];
        self.rng.fill(&mut buf).expect("rng fill");
        buf.iter()
            .map(|b| PAIR_CODE_ALPHABET[(*b as usize) % PAIR_CODE_ALPHABET.len()] as char)
            .collect()
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
        let entry = inner.sessions.get(&token_hash(token))?;
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

    /// Resolve a session token to its account id (the guardian who owns it), or
    /// `None` for an unknown OR expired token. Used to stamp `updated_by` audit
    /// fields on guardian-authored mutations (e.g. ChildControl.SetChildConfig).
    pub fn account_for_session(&self, token: &str) -> Option<String> {
        let inner = self.inner.lock().expect("account mutex poisoned");
        let entry = inner.sessions.get(&token_hash(token))?;
        if !session_live(entry.issued_ms, Self::now_ms(), session_ttl_ms()) {
            return None;
        }
        Some(entry.account_id.clone())
    }

    /// Resolve an ENROLLED device to its child's `(child_id, family_id,
    /// child_name)` — the coarse, content-free context a CHILD_SOS alert
    /// carries (who + which family; never location or content). `None` for an
    /// unknown device.
    pub fn child_for_device(&self, device_id: &str) -> Option<(String, String, String)> {
        let inner = self.inner.lock().expect("account mutex poisoned");
        let child_id = inner.device_to_child.get(device_id.trim())?;
        let c = inner.children.get(child_id)?;
        Some((c.child_id.clone(), c.family_id.clone(), c.name.clone()))
    }

    /// Account ids of the guardians assigned to `child_id` (empty for an unknown
    /// child). Used to SCOPE guardian push fan-out so a redacted alert reaches
    /// ONLY the guardians of the child it concerns — never another family.
    pub fn guardians_for_child(&self, child_id: &str) -> Vec<String> {
        let inner = self.inner.lock().expect("account mutex poisoned");
        inner
            .children
            .get(child_id.trim())
            .map(|c| c.guardians.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Account ids of the guardians assigned to the child owning the enrolled
    /// `device_id` (empty for an unknown device). The device-keyed counterpart to
    /// [`Self::guardians_for_child`] for alerts that carry only the child device.
    pub fn guardians_for_device(&self, device_id: &str) -> Vec<String> {
        let inner = self.inner.lock().expect("account mutex poisoned");
        inner
            .device_to_child
            .get(device_id.trim())
            .and_then(|cid| inner.children.get(cid))
            .map(|c| c.guardians.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Verify a per-device credential (minted at [`Self::redeem_pair_code`],
    /// presented on Heartbeat / child-config reads): `true` iff `device_id` is
    /// an enrolled child device AND sha256(token) matches the stored digest
    /// (digests compared, never raw secrets — the same digest-only pattern as
    /// the session HashMap lookup; the raw token is never stored).
    ///
    /// LEGACY GRACE: a record whose stored digest is EMPTY (device enrolled
    /// before per-device tokens existed, or added via AddChild with no device
    /// present) is accepted and logged — an honest acknowledgement that
    /// already-enrolled devices have no token to present. The grace tightens
    /// to a hard requirement once a device-removal/re-pair flow ships
    /// (re-pairing an enrolled device_id currently returns DeviceInUse —
    /// follow-up).
    pub fn verify_device_token(&self, device_id: &str, token: &str) -> bool {
        let device_id = device_id.trim();
        // Snapshot the stored digest under the lock; compare after releasing.
        let stored = {
            let inner = self.inner.lock().expect("account mutex poisoned");
            let Some(child_id) = inner.device_to_child.get(device_id) else {
                return false; // unknown device — nothing to verify against
            };
            match inner.children.get(child_id) {
                Some(c) => c.device_token_sha256.clone(),
                None => return false,
            }
        };
        if stored.is_empty() {
            // debug (not info): legacy devices hit this on every heartbeat +
            // config poll (~2x/min) — info would be production log noise.
            tracing::debug!(
                device = %device_id,
                "device enrolled before per-device tokens; accepted under legacy grace"
            );
            return true;
        }
        // Compare DIGESTS, not secrets: the presented token is hashed first,
        // so byte-wise equality here can't leak anything useful — knowing
        // digest bytes doesn't help construct a matching token (preimage
        // resistance). Same reasoning as the session lookup keyed by digest.
        token_hash(token) == stored
    }
}

/// Lowercase + trim an email for use as the account key.
pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Split a base32 recovery string into dash-separated groups for legibility
/// (e.g. `K7MQ29XF4T...` → `K7MQ2-9XF4T-...`). Cosmetic only — the stored hash is
/// over the [`normalize_recovery_code`] form, so grouping never affects verify.
fn group_recovery_code(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    chars
        .chunks(RECOVERY_GROUP_LEN)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// Canonicalize a user-entered recovery code for hashing/verify: strip dashes and
/// whitespace, uppercase. So `k7mq2-9xf4t` and `K7MQ2 9XF4T` verify identically.
fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Lowercase-hex encode (no deps).
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

/// sha256 of a presented session token, lowercase hex. Sessions are keyed and
/// persisted by this digest ONLY, so a copied accounts.json (or a memory dump of
/// the map) cannot stand in for a guardian. Unsalted SHA-256 is sufficient here:
/// tokens carry 256 bits of CSPRNG entropy ([`TOKEN_BYTES`]), so dictionary /
/// rainbow-table precomputation does not apply (unlike passwords, which use a KDF).
pub(crate) fn token_hash(token: &str) -> String {
    to_hex(ring::digest::digest(&ring::digest::SHA256, token.trim().as_bytes()).as_ref())
}

/// Decode an exactly-`N`-byte lowercase-hex string into `[u8; N]`. `None` on a
/// wrong-length or non-hex string (a corrupt snapshot row is skipped, not fatal).
pub(crate) fn from_hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
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
// Durable snapshot (serde JSON). Content-free: the Argon2id PHC string (or a
// legacy PBKDF2 salt+hash awaiting migration) + the recovery-code hash — NEVER
// the password or the recovery-code plaintext, ids, hosts. Sessions are persisted
// as sha256(token) digests — the raw bearer token never touches disk.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct AccountSnapshot {
    accounts: Vec<AccountRow>,
    children: Vec<ChildRow>,
    /// Persisted so a logged-in guardian survives a server restart/redeploy
    /// (sessions still expire via TTL). `#[serde(default)]` keeps old files loadable.
    #[serde(default)]
    sessions: Vec<SessionRow>,
}

#[derive(Serialize, Deserialize)]
struct SessionRow {
    /// sha256(token) hex — the only form that ever touches disk.
    #[serde(default)]
    token_sha256: String,
    /// LEGACY (pre-hashing snapshots): the raw token. Read for migration only —
    /// hashed on load, never serialized again (`skip_serializing_if`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    token: String,
    account_id: String,
    issued_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct AccountRow {
    email_key: String,
    account_id: String,
    family_id: String,
    /// Current scheme: Argon2id PHC string (`$argon2id$...`). `#[serde(default)]`
    /// keeps old salt_hex/hash_hex-only files loadable; empty = legacy account.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    phc: String,
    /// LEGACY PBKDF2 salt — present only for not-yet-migrated accounts. Skipped on
    /// write once an account upgrades to `phc` (so the at-rest form is Argon2id only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    salt_hex: String,
    /// LEGACY PBKDF2 hash — see `salt_hex`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    hash_hex: String,
    /// Argon2id hash of the single-use recovery code (`#[serde(default)]` → old
    /// files without it load as "no recovery code set").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    recovery_phc: String,
    /// Argon2id hash of an outstanding EMAILED reset token (`#[serde(default)]` →
    /// old files load as "no email reset in flight"). Empty when none. Only the hash
    /// is persisted; the plaintext lives only in the one outgoing email.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    reset_token_phc: String,
    /// Absolute expiry (unix ms) of `reset_token_phc`. Expired tokens are pruned on
    /// load (like sessions), so a stale code can't linger at rest. 0 when none.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    reset_token_expires_ms: i64,
}

/// serde helper: drop a zero expiry from the snapshot (keeps old files byte-clean).
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[derive(Serialize, Deserialize)]
struct ChildRow {
    child_id: String,
    family_id: String,
    name: String,
    device_id: String,
    guardians: Vec<String>,
    /// sha256 hex of the per-device pairing token (`#[serde(default)]` → rows
    /// written before device tokens load as "no token set" = legacy grace).
    /// Digest only — the raw token never touches disk.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    device_token_sha256: String,
}

impl Inner {
    /// Build a stable (sorted) serde snapshot. Sessions ARE persisted so a
    /// logged-in guardian survives a restart/redeploy (they still TTL-expire).
    fn snapshot(&self) -> AccountSnapshot {
        let mut accounts: Vec<AccountRow> = self
            .by_email
            .iter()
            .map(|(email_key, a)| {
                let (phc, salt_hex, hash_hex) = match &a.pw {
                    PwHash::Argon2(s) => (s.clone(), String::new(), String::new()),
                    PwHash::Pbkdf2 { salt, hash } => (String::new(), to_hex(salt), to_hex(hash)),
                };
                // Persist an outstanding emailed reset token (hash + expiry) so it
                // survives a restart; a token already past its expiry is written as
                // "none" (it is dead anyway and is pruned on load regardless).
                let (reset_token_phc, reset_token_expires_ms) = match &a.reset_token {
                    Some(t) => (t.phc.clone(), t.expires_ms),
                    None => (String::new(), 0),
                };
                AccountRow {
                    email_key: email_key.clone(),
                    account_id: a.account_id.clone(),
                    family_id: a.family_id.clone(),
                    phc,
                    salt_hex,
                    hash_hex,
                    recovery_phc: a.recovery_phc.clone().unwrap_or_default(),
                    reset_token_phc,
                    reset_token_expires_ms,
                }
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
                    device_token_sha256: c.device_token_sha256.clone(),
                }
            })
            .collect();
        children.sort_by(|a, b| a.child_id.cmp(&b.child_id));

        let mut sessions: Vec<SessionRow> = self
            .sessions
            .iter()
            .map(|(token_sha256, e)| SessionRow {
                token_sha256: token_sha256.clone(),
                token: String::new(),
                account_id: e.account_id.clone(),
                issued_ms: e.issued_ms,
            })
            .collect();
        sessions.sort_by(|a, b| a.token_sha256.cmp(&b.token_sha256));

        AccountSnapshot {
            accounts,
            children,
            sessions,
        }
    }

    /// Rebuild from a snapshot, deriving the reverse maps. Session rows are keyed
    /// by their sha256 digest; LEGACY rows that still carry a raw token are hashed
    /// on load (one-shot migration — the next persist writes digests only). Rows
    /// with malformed salt/hash are skipped.
    fn from_snapshot(snap: AccountSnapshot) -> Inner {
        let mut inner = Inner::default();
        for row in snap.accounts {
            // Prefer the Argon2id PHC; fall back to the legacy PBKDF2 salt+hash for
            // pre-upgrade snapshots. A row with neither (or a malformed legacy pair)
            // is unusable → skipped, never fatal.
            let pw = if !row.phc.is_empty() {
                PwHash::Argon2(row.phc)
            } else {
                match (
                    from_hex_array::<SALT_LEN>(&row.salt_hex),
                    from_hex_array::<HASH_LEN>(&row.hash_hex),
                ) {
                    (Some(salt), Some(hash)) => PwHash::Pbkdf2 { salt, hash },
                    _ => {
                        tracing::warn!(account = %row.account_id, "skipping account with no usable password hash");
                        continue;
                    }
                }
            };
            inner
                .email_by_id
                .insert(row.account_id.clone(), row.email_key.clone());
            // Restore an outstanding emailed reset token only if it is present AND
            // not already expired — prune stale tokens on load, like sessions.
            let reset_token = if !row.reset_token_phc.is_empty()
                && row.reset_token_expires_ms > AccountStore::now_ms()
            {
                Some(ResetToken {
                    phc: row.reset_token_phc,
                    expires_ms: row.reset_token_expires_ms,
                })
            } else {
                None
            };
            inner.by_email.insert(
                row.email_key,
                Account {
                    account_id: row.account_id,
                    family_id: row.family_id,
                    pw,
                    recovery_phc: (!row.recovery_phc.is_empty()).then_some(row.recovery_phc),
                    reset_token,
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
                    device_token_sha256: row.device_token_sha256,
                },
            );
        }
        for row in snap.sessions {
            // Prune expired sessions on load (correctness never depended on it —
            // lookups reject expired — but the file must not grow forever and
            // stale digests shouldn't linger at rest).
            if !session_live(row.issued_ms, AccountStore::now_ms(), session_ttl_ms()) {
                continue;
            }
            // Prefer the digest; hash a legacy raw token on load (migration).
            let key = if !row.token_sha256.is_empty() {
                row.token_sha256
            } else if !row.token.is_empty() {
                token_hash(&row.token)
            } else {
                continue;
            };
            inner.sessions.insert(
                key,
                SessionEntry {
                    account_id: row.account_id,
                    issued_ms: row.issued_ms,
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

/// Implements `bulwark_proto::v1::accounts_server::Accounts` over an [`AccountStore`].
#[derive(Clone)]
pub struct AccountsService {
    store: AccountStore,
    /// Optional EMAIL-based reset path: when `Some`, RequestPasswordReset emails a
    /// short-lived code; when `None` (no SMTP configured) the recovery code stays
    /// the only self-service reset, and the endpoint still acks generically.
    mailer: Option<crate::reset_mailer::ResetMailer>,
}

impl AccountsService {
    /// Recovery-code-only service (no email reset). Unchanged callers/tests use this.
    pub fn new(store: AccountStore) -> Self {
        Self {
            store,
            mailer: None,
        }
    }

    /// Service with an attached email-reset mailer (the email path is enabled).
    pub fn with_mailer(store: AccountStore, mailer: crate::reset_mailer::ResetMailer) -> Self {
        Self {
            store,
            mailer: Some(mailer),
        }
    }

    /// Build the service, enabling the email-reset path automatically when SMTP is
    /// configured in the environment (`BULWARK_SMTP_HOST` + a `From:`). Without SMTP
    /// the recovery-code path is the self-service fallback and we log one warning so
    /// operators know email reset is unavailable.
    pub fn from_env(store: AccountStore) -> Self {
        match crate::reset_mailer::ResetMailer::from_env() {
            Some(mailer) => {
                tracing::info!("email password-reset ENABLED (SMTP configured)");
                Self::with_mailer(store, mailer)
            }
            None => {
                tracing::warn!(
                    "email password-reset unavailable (no SMTP configured); \
                     guardians self-reset with their saved recovery code"
                );
                Self::new(store)
            }
        }
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
        let (account_id, created, recovery_code) =
            self.store
                .create_account(&r.email, &r.password, &r.display_name)?;
        Ok(Response::new(AccountAck {
            account_id,
            created,
            detail: if created {
                "account created — SAVE the recovery code; it is shown only once".to_string()
            } else {
                "email already registered".to_string()
            },
            // One-time secret on a fresh account; empty on the duplicate-email no-op.
            recovery_code,
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

    async fn create_pair_code(
        &self,
        req: Request<CreatePairCodeRequest>,
    ) -> Result<Response<PairCode>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        let (code, expires_ts) = self.store.create_pair_code(&token, &r.child_name)?;
        Ok(Response::new(PairCode { code, expires_ts }))
    }

    async fn redeem_pair_code(
        &self,
        req: Request<RedeemPairCodeRequest>,
    ) -> Result<Response<PairResult>, Status> {
        // Unauthenticated by design — the pairing code is the credential.
        let r = req.into_inner();
        let (child_id, family_id, device_token) =
            self.store.redeem_pair_code(&r.code, &r.device_id)?;
        Ok(Response::new(PairResult {
            child_id,
            family_id,
            // Returned exactly once: the device's authentication credential
            // from here on. Server-side only its sha256 digest exists.
            device_token,
        }))
    }

    async fn change_password(
        &self,
        req: Request<ChangePasswordRequest>,
    ) -> Result<Response<AccountAck>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        // Passwords are NEVER logged — only the resulting account id is observable.
        let account_id = self
            .store
            .change_password(&token, &r.old_password, &r.new_password)?;
        Ok(Response::new(AccountAck {
            account_id,
            created: false,
            detail: "password changed; other sessions signed out".to_string(),
            recovery_code: String::new(), // change does not rotate the recovery code
        }))
    }

    async fn reset_password(
        &self,
        req: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResetPasswordAck>, Status> {
        // Unauthenticated by design — the recovery code is the credential.
        let r = req.into_inner();
        let new_recovery_code =
            self.store
                .reset_password(&r.email, &r.recovery_code, &r.new_password)?;
        Ok(Response::new(ResetPasswordAck {
            ok: true,
            detail: "password reset — SAVE the new recovery code; the old one is now void"
                .to_string(),
            new_recovery_code,
        }))
    }

    async fn request_password_reset(
        &self,
        req: Request<RequestPasswordResetRequest>,
    ) -> Result<Response<RequestPasswordResetAck>, Status> {
        // Unauthenticated by design — the guardian is proving nothing yet; they
        // just ask for a code to be emailed to the account address.
        let r = req.into_inner();

        // The store mints + stores a token ONLY for a real, un-throttled account;
        // it returns the recipient + plaintext to email. An unknown email, a
        // throttled request, or a mint error all yield `None`/`Err` here, and we
        // ack the SAME generic message either way (anti-enumeration: never reveal
        // whether the email exists, and never surface an account-state error).
        if let Ok(Some((recipient, code))) = self.store.request_password_reset(&r.email) {
            match &self.mailer {
                Some(mailer) => {
                    let ttl_minutes = reset_token_ttl_ms() / 60_000;
                    // The reset code is NEVER logged. A send failure is logged
                    // content-free and does not change the generic ack.
                    if let Err(e) = mailer.send_reset_code(&recipient, &code, ttl_minutes).await {
                        tracing::warn!(error = %e, "guardian password-reset email could not be sent");
                    }
                }
                None => {
                    // SMTP not configured: a token was minted but cannot be emailed.
                    // Still ack generically; warn once so operators can enable SMTP.
                    tracing::warn!(
                        "password-reset email requested but email reset is unavailable \
                         (no SMTP configured); the guardian should use their recovery code"
                    );
                }
            }
        }

        Ok(Response::new(RequestPasswordResetAck {
            ok: true,
            detail: "If that email has an account, a reset code has been sent.".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_code_round_trip_creates_and_links_child() {
        let store = AccountStore::new();
        store
            .create_account("parent@example.com", "password123", "Parent")
            .unwrap();
        let (token, _aid, _) = store.login("parent@example.com", "password123").unwrap();

        let (code, _expires) = store.create_pair_code(&token, "Kiddo").unwrap();
        let (child_id, _family, _device_token) =
            store.redeem_pair_code(&code, "device-xyz").unwrap();

        // The parent now sees the linked child, routed by its device id.
        let kids = store.list_children(&token).unwrap();
        assert!(kids
            .iter()
            .any(|c| c.child_id == child_id && c.device_id == "device-xyz"));

        // Single-use: a second redeem of the same code fails.
        assert!(store.redeem_pair_code(&code, "device-2").is_err());
        // Unknown code fails.
        assert!(store.redeem_pair_code("NOTACODE", "device-3").is_err());
    }

    #[test]
    fn redeem_mints_device_token_and_stores_only_its_digest() {
        let dir = tmp_dir("device-token");
        let store = AccountStore::with_state_dir(&dir).unwrap();
        store
            .create_account("parent@example.com", "password123", "Parent")
            .unwrap();
        let (token, _aid, _) = store.login("parent@example.com", "password123").unwrap();
        let (code, _expires) = store.create_pair_code(&token, "Kiddo").unwrap();
        let (child_id, _family, device_token) =
            store.redeem_pair_code(&code, "device-tok").unwrap();

        // A real secret: 32 bytes of entropy, hex-encoded.
        assert_eq!(device_token.len(), TOKEN_BYTES * 2);
        // In memory AND at rest only the sha256 digest exists — never the raw.
        {
            let inner = store.inner.lock().unwrap();
            let rec = inner.children.get(&child_id).unwrap();
            assert_eq!(rec.device_token_sha256, token_hash(&device_token));
        }
        let on_disk = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
        assert!(
            !on_disk.contains(&device_token),
            "raw device token must never touch disk"
        );
        assert!(on_disk.contains(&token_hash(&device_token)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_token_verifies_and_rejects_wrong_or_unknown() {
        let store = AccountStore::new();
        store
            .create_account("parent@example.com", "password123", "Parent")
            .unwrap();
        let (token, _aid, _) = store.login("parent@example.com", "password123").unwrap();
        let (code, _) = store.create_pair_code(&token, "Kiddo").unwrap();
        let (_child, _family, device_token) = store.redeem_pair_code(&code, "device-tok").unwrap();

        assert!(store.verify_device_token("device-tok", &device_token));
        assert!(!store.verify_device_token("device-tok", "wrong-token"));
        assert!(!store.verify_device_token("device-tok", ""));
        assert!(!store.verify_device_token("no-such-device", &device_token));
    }

    #[test]
    fn legacy_device_with_no_stored_token_digest_passes_grace() {
        // AddChild-enrolled (or pre-token) devices have an empty stored digest:
        // accepted — with any or no token — until a device-removal/re-pair
        // flow ships (logged grace; re-pairing an enrolled device_id
        // currently returns DeviceInUse — follow-up).
        let store = AccountStore::new();
        store
            .create_account("parent@example.com", "password123", "Parent")
            .unwrap();
        let (token, _aid, _) = store.login("parent@example.com", "password123").unwrap();
        store.add_child(&token, "Kid", "legacy-device").unwrap();
        assert!(store.verify_device_token("legacy-device", ""));
        assert!(store.verify_device_token("legacy-device", "anything"));
    }

    #[test]
    fn redeem_is_throttled_after_repeated_wrong_codes() {
        let store = AccountStore::new();
        store
            .create_account("parent@example.com", "password123", "Parent")
            .unwrap();
        let (token, _aid, _) = store.login("parent@example.com", "password123").unwrap();
        let (code, _) = store.create_pair_code(&token, "Kiddo").unwrap();

        // Burn the budget on wrong codes (the global redeem counter).
        // "WRONGCOD" contains 'O', which the code alphabet excludes — it can
        // never collide with a minted code.
        for _ in 0..DEFAULT_LOGIN_MAX_FAILS {
            assert_eq!(
                store.redeem_pair_code("WRONGCOD", "device-x"),
                Err(AccountError::PairCodeInvalid)
            );
        }
        // Locked: even the CORRECT code is refused until the window passes.
        assert_eq!(
            store.redeem_pair_code(&code, "device-x"),
            Err(AccountError::TooManyAttempts)
        );
    }

    #[test]
    fn successful_redeem_clears_the_redeem_throttle() {
        let store = AccountStore::new();
        store
            .create_account("parent@example.com", "password123", "Parent")
            .unwrap();
        let (token, _aid, _) = store.login("parent@example.com", "password123").unwrap();

        // max-1 failures, then a success → counter cleared…
        for _ in 0..(DEFAULT_LOGIN_MAX_FAILS - 1) {
            assert_eq!(
                store.redeem_pair_code("WRONGCOD", "device-x"),
                Err(AccountError::PairCodeInvalid)
            );
        }
        let (code, _) = store.create_pair_code(&token, "Kid A").unwrap();
        assert!(store.redeem_pair_code(&code, "device-a").is_ok());
        // …so max-1 more failures still don't lock, and a fresh redeem works.
        for _ in 0..(DEFAULT_LOGIN_MAX_FAILS - 1) {
            assert_eq!(
                store.redeem_pair_code("WRONGCOD", "device-x"),
                Err(AccountError::PairCodeInvalid)
            );
        }
        let (code_b, _) = store.create_pair_code(&token, "Kid B").unwrap();
        assert!(store.redeem_pair_code(&code_b, "device-b").is_ok());
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bulwark-accounts-{tag}-{}-{}",
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
        let (alice, created, _rc) = s1.create_account("a@x.com", "passwordone", "A").unwrap();
        assert!(created);
        let (a_tok, _, _) = s1.login("a@x.com", "passwordone").unwrap();
        let child = s1.add_child(&a_tok, "Kid", "kids-tablet").unwrap();
        let (bob, _, _) = s1.create_account("b@x.com", "passwordtwo", "B").unwrap();
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
        // Sessions ARE persisted now: the OLD token survives a restart (login survives a
        // redeploy); it still TTL-expires.
        assert!(s2.guardian_scope(&a_tok).is_some());
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
    fn session_tokens_persist_hashed_never_raw() {
        let dir = tmp_dir("hashed-sessions");
        let s = AccountStore::with_state_dir(&dir).unwrap();
        s.create_account("h@x.com", "passwordeight", "H").unwrap();
        let (tok, acct, _) = s.login("h@x.com", "passwordeight").unwrap();
        let on_disk = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
        assert!(
            !on_disk.contains(&tok),
            "raw bearer token must never touch disk"
        );
        assert!(on_disk.contains(&token_hash(&tok)));
        // Restart: the same raw token still authenticates (lookup hashes it).
        drop(s);
        let s2 = AccountStore::with_state_dir(&dir).unwrap();
        assert_eq!(s2.account_for_session(&tok).as_deref(), Some(acct.as_str()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_plaintext_session_rows_migrate_to_hashes_on_load() {
        let dir = tmp_dir("legacy-sessions");
        // A pre-hashing snapshot: the session row carries the RAW token.
        let now = AccountStore::now_ms();
        let legacy = format!(
            r#"{{"accounts":[],"children":[],"sessions":[{{"token":"rawtoken123","account_id":"acct-1","issued_ms":{now}}}]}}"#
        );
        std::fs::write(dir.join("accounts.json"), legacy).unwrap();
        let s = AccountStore::with_state_dir(&dir).unwrap();
        // The old raw token still authenticates (hashed on load)…
        assert_eq!(
            s.account_for_session("rawtoken123").as_deref(),
            Some("acct-1")
        );
        // …and the next persisted snapshot is scrubbed: digest only.
        s.create_account("m@x.com", "passwordnine", "M").unwrap();
        let on_disk = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
        assert!(!on_disk.contains("rawtoken123"));
        assert!(on_disk.contains(&token_hash("rawtoken123")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_hash_is_stable_and_trims() {
        assert_eq!(token_hash("abc"), token_hash(" abc "));
        assert_eq!(token_hash("abc").len(), 64); // sha256 hex
        assert_ne!(token_hash("abc"), token_hash("abd"));
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
            inner.sessions.get_mut(&token_hash(&tok)).unwrap().issued_ms -= session_ttl_ms() + 1000;
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
        let (id, created, recovery) = store
            .create_account("Parent@Example.com", "hunter2hunter", "P")
            .unwrap();
        assert!(created);
        assert!(!id.is_empty());
        assert!(
            !recovery.is_empty(),
            "a fresh account is issued a recovery code"
        );

        // Duplicate email → created = false, same id, and NO recovery code leaked.
        let (id2, created2, recovery2) = store
            .create_account("parent@example.com", "different-pass", "P")
            .unwrap();
        assert!(!created2);
        assert_eq!(id, id2, "email is case-insensitive and unique");
        assert!(
            recovery2.is_empty(),
            "a duplicate-email no-op must not mint a recovery credential"
        );

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
        let (_alice_id, _, _) = store
            .create_account("alice@x.com", "alicepass1", "A")
            .unwrap();
        let (alice_tok, _, _) = store.login("alice@x.com", "alicepass1").unwrap();
        let (bob_id, _, _) = store
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
        let (_a, _, _) = store.create_account("a@x.com", "passwordone", "A").unwrap();
        let (a_tok, _, _) = store.login("a@x.com", "passwordone").unwrap();
        let (_b, _, _) = store.create_account("b@x.com", "passwordtwo", "B").unwrap();
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
        let (_a, _, _) = store.create_account("a@x.com", "passwordone", "A").unwrap();
        let (tok, _, _) = store.login("a@x.com", "passwordone").unwrap();
        assert_eq!(
            store.add_child(&tok, "Kid", "   "),
            Err(AccountError::Validation("device_id is required"))
        );
    }

    // -----------------------------------------------------------------------
    // Argon2id + recovery-code (self-service reset) hardening
    // -----------------------------------------------------------------------

    #[test]
    fn argon2_hash_round_trips_and_is_phc() {
        let rng = SystemRandom::new();
        let phc = argon2_hash(&rng, b"correct horse battery").unwrap();
        // PHC string, argon2id variant, with an embedded salt (different per call).
        assert!(phc.starts_with("$argon2id$"), "PHC: {phc}");
        assert!(argon2_verify(&phc, b"correct horse battery"));
        assert!(!argon2_verify(&phc, b"wrong"));
        // A garbage PHC string never panics — just fails to verify.
        assert!(!argon2_verify("not-a-phc-string", b"anything"));
        // Fresh salt each hash → two hashes of the same input differ.
        let phc2 = argon2_hash(&rng, b"correct horse battery").unwrap();
        assert_ne!(phc, phc2);
    }

    #[test]
    fn new_account_stores_argon2_not_pbkdf2() {
        let store = AccountStore::new();
        let (_id, _created, rc) = store
            .create_account("ar@x.com", "passwordone", "A")
            .unwrap();
        assert!(!rc.is_empty());
        let inner = store.inner.lock().unwrap();
        let acct = inner.by_email.get("ar@x.com").unwrap();
        assert!(
            matches!(acct.pw, PwHash::Argon2(_)),
            "new accounts must hash with Argon2id, never legacy PBKDF2"
        );
        assert!(acct.recovery_phc.is_some());
    }

    /// Insert a LEGACY (PBKDF2-only) account directly, the way an old accounts.json
    /// would have loaded it — no Argon2id PHC, no recovery code.
    fn insert_legacy_pbkdf2(store: &AccountStore, email: &str, password: &str) -> String {
        let mut salt = [0u8; SALT_LEN];
        store.rng.fill(&mut salt).unwrap();
        let mut hash = [0u8; HASH_LEN];
        pbkdf2::derive(
            PBKDF2_ALG,
            NonZeroU32::new(PBKDF2_ITERS).unwrap(),
            &salt,
            password.as_bytes(),
            &mut hash,
        );
        let account_id = store.rand_hex(ID_BYTES);
        let email_key = normalize_email(email);
        let mut inner = store.inner.lock().unwrap();
        inner
            .email_by_id
            .insert(account_id.clone(), email_key.clone());
        inner.by_email.insert(
            email_key,
            Account {
                account_id: account_id.clone(),
                family_id: store.rand_hex(ID_BYTES),
                pw: PwHash::Pbkdf2 { salt, hash },
                recovery_phc: None,
                reset_token: None,
            },
        );
        account_id
    }

    #[test]
    fn legacy_pbkdf2_login_verifies_and_rehashes_to_argon2() {
        let store = AccountStore::new();
        let aid = insert_legacy_pbkdf2(&store, "legacy@x.com", "passwordlegacy");
        // It really is legacy at rest before any login.
        assert!(matches!(
            store
                .inner
                .lock()
                .unwrap()
                .by_email
                .get("legacy@x.com")
                .unwrap()
                .pw,
            PwHash::Pbkdf2 { .. }
        ));
        // Wrong password is still rejected via the legacy path.
        assert_eq!(
            store.login("legacy@x.com", "nope"),
            Err(AccountError::BadCredentials)
        );
        // Correct password logs in AND transparently upgrades to Argon2id.
        let (_tok, got_aid, _) = store.login("legacy@x.com", "passwordlegacy").unwrap();
        assert_eq!(got_aid, aid);
        assert!(
            matches!(
                store
                    .inner
                    .lock()
                    .unwrap()
                    .by_email
                    .get("legacy@x.com")
                    .unwrap()
                    .pw,
                PwHash::Argon2(_)
            ),
            "a correct legacy login must re-hash to Argon2id in place"
        );
        // The upgraded account still logs in with the same password.
        assert!(store.login("legacy@x.com", "passwordlegacy").is_ok());
    }

    #[test]
    fn legacy_only_snapshot_loads_logs_in_and_next_persist_has_phc() {
        // An OLD accounts.json: salt_hex/hash_hex only, no phc, no recovery_phc.
        let dir = tmp_dir("legacy-snapshot");
        // Build a real PBKDF2 salt+hash for "passwordlegacy".
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).unwrap();
        let mut hash = [0u8; HASH_LEN];
        pbkdf2::derive(
            PBKDF2_ALG,
            NonZeroU32::new(PBKDF2_ITERS).unwrap(),
            &salt,
            b"passwordlegacy",
            &mut hash,
        );
        let legacy = format!(
            r#"{{"accounts":[{{"email_key":"old@x.com","account_id":"acct-old","family_id":"fam-old","salt_hex":"{}","hash_hex":"{}"}}],"children":[],"sessions":[]}}"#,
            to_hex(&salt),
            to_hex(&hash),
        );
        std::fs::write(dir.join("accounts.json"), legacy).unwrap();

        let store = AccountStore::with_state_dir(&dir).unwrap();
        // The old account logs in (legacy verify) — back-compat holds.
        let (_tok, aid, _) = store.login("old@x.com", "passwordlegacy").unwrap();
        assert_eq!(aid, "acct-old");
        // The login re-hashed + persisted: the on-disk row is now Argon2id PHC, and
        // the legacy salt/hash are gone (skip_serializing_if when phc is set).
        let on_disk = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
        assert!(
            on_disk.contains("$argon2id$"),
            "next persist carries a PHC string"
        );
        assert!(
            !on_disk.contains(&to_hex(&hash)),
            "the legacy hash must be dropped once migrated"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_reset_happy_path_rotates_code_and_password() {
        let store = AccountStore::new();
        let (_id, _c, code) = store.create_account("r@x.com", "oldpassword", "R").unwrap();
        // Old password works before the reset.
        assert!(store.login("r@x.com", "oldpassword").is_ok());

        // Reset with the saved code → new password set, fresh code returned.
        let new_code = store
            .reset_password("r@x.com", &code, "brandnewpass")
            .unwrap();
        assert!(!new_code.is_empty());
        assert_ne!(new_code, code, "reset must issue a NEW recovery code");

        // New password works; old password no longer does.
        assert!(store.login("r@x.com", "brandnewpass").is_ok());
        assert_eq!(
            store.login("r@x.com", "oldpassword"),
            Err(AccountError::BadCredentials)
        );
        // The OLD code is single-use → now dead; the NEW one works.
        assert_eq!(
            store.reset_password("r@x.com", &code, "anotherpass"),
            Err(AccountError::BadRecoveryCode)
        );
        assert!(store
            .reset_password("r@x.com", &new_code, "anotherpass")
            .is_ok());
    }

    #[test]
    fn recovery_reset_accepts_user_typed_spacing_and_case() {
        let store = AccountStore::new();
        let (_id, _c, code) = store
            .create_account("sp@x.com", "oldpassword", "S")
            .unwrap();
        // User retypes it lowercased, with spaces instead of dashes — still valid.
        let mangled = code.replace('-', " ").to_ascii_lowercase();
        assert!(store
            .reset_password("sp@x.com", &mangled, "newpass12")
            .is_ok());
    }

    #[test]
    fn recovery_reset_wrong_code_is_denied() {
        let store = AccountStore::new();
        store.create_account("w@x.com", "oldpassword", "W").unwrap();
        assert_eq!(
            store.reset_password("w@x.com", "WRONG-CODE-9999", "newpass12"),
            Err(AccountError::BadRecoveryCode)
        );
        // Unknown email is indistinguishable (no oracle confirming the email exists).
        assert_eq!(
            store.reset_password("nobody@x.com", "WRONG-CODE-9999", "newpass12"),
            Err(AccountError::BadRecoveryCode)
        );
        // The real password is untouched by a failed reset.
        assert!(store.login("w@x.com", "oldpassword").is_ok());
    }

    #[test]
    fn recovery_reset_is_throttled_per_email() {
        let store = AccountStore::new();
        store.create_account("t@x.com", "oldpassword", "T").unwrap();
        // Burn the failure budget on wrong codes.
        for _ in 0..DEFAULT_LOGIN_MAX_FAILS {
            assert_eq!(
                store.reset_password("t@x.com", "BADCODE", "newpass12"),
                Err(AccountError::BadRecoveryCode)
            );
        }
        // Now locked out — even a correct reset is refused until the window passes.
        assert_eq!(
            store.reset_password("t@x.com", "WHATEVER", "newpass12"),
            Err(AccountError::TooManyAttempts)
        );
    }

    #[test]
    fn reset_throttle_is_separate_from_login_throttle() {
        // Failing resets must NOT lock the victim out of normal login, and v.v.
        let store = AccountStore::new();
        store
            .create_account("sep@x.com", "oldpassword", "S")
            .unwrap();
        for _ in 0..DEFAULT_LOGIN_MAX_FAILS {
            let _ = store.reset_password("sep@x.com", "BADCODE", "newpass12");
        }
        // Reset is locked…
        assert_eq!(
            store.reset_password("sep@x.com", "X", "newpass12"),
            Err(AccountError::TooManyAttempts)
        );
        // …but login still works (the counters are independent).
        assert!(store.login("sep@x.com", "oldpassword").is_ok());
    }

    #[test]
    fn change_password_requires_correct_old_and_invalidates_other_sessions() {
        let store = AccountStore::new();
        store.create_account("c@x.com", "oldpassword", "C").unwrap();
        // Two live sessions for the same account.
        let (tok_keep, _aid, _) = store.login("c@x.com", "oldpassword").unwrap();
        let (tok_other, _aid, _) = store.login("c@x.com", "oldpassword").unwrap();
        assert!(store.account_for_session(&tok_other).is_some());

        // Wrong old password is denied.
        assert_eq!(
            store.change_password(&tok_keep, "wrongold", "newpassword"),
            Err(AccountError::BadCredentials)
        );
        // Correct old password rotates it.
        store
            .change_password(&tok_keep, "oldpassword", "newpassword")
            .unwrap();
        // New password logs in; old one is dead.
        assert!(store.login("c@x.com", "newpassword").is_ok());
        assert_eq!(
            store.login("c@x.com", "oldpassword"),
            Err(AccountError::BadCredentials)
        );
        // The caller's session survives; the OTHER session is invalidated.
        assert!(store.account_for_session(&tok_keep).is_some());
        assert!(
            store.account_for_session(&tok_other).is_none(),
            "change-password must sign out the account's other sessions"
        );
    }

    #[test]
    fn change_password_rejects_short_new_password_and_bad_token() {
        let store = AccountStore::new();
        store
            .create_account("c2@x.com", "oldpassword", "C")
            .unwrap();
        let (tok, _aid, _) = store.login("c2@x.com", "oldpassword").unwrap();
        assert_eq!(
            store.change_password(&tok, "oldpassword", "short"),
            Err(AccountError::Validation(
                "password must be at least 8 characters"
            ))
        );
        assert_eq!(
            store.change_password("not-a-token", "oldpassword", "newpassword"),
            Err(AccountError::Unauthorized)
        );
    }

    #[test]
    fn recovery_code_hash_is_never_the_plaintext_at_rest() {
        let dir = tmp_dir("recovery-at-rest");
        let store = AccountStore::with_state_dir(&dir).unwrap();
        let (_id, _c, code) = store
            .create_account("rest@x.com", "oldpassword", "R")
            .unwrap();
        let on_disk = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
        // The plaintext code (and its normalized form) NEVER touch disk.
        assert!(!on_disk.contains(&code));
        assert!(!on_disk.contains(&normalize_recovery_code(&code)));
        // Only its Argon2id hash is persisted.
        assert!(on_disk.contains("recovery_phc"));
        assert!(on_disk.contains("$argon2id$"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Emailed reset token (the email-based path ALONGSIDE the recovery code)
    // -----------------------------------------------------------------------

    #[test]
    fn request_reset_returns_token_for_known_email_only() {
        // Anti-enumeration at the store level: a real account yields a (recipient,
        // code) to email; an unknown email yields None (the caller acks identically).
        let store = AccountStore::new();
        store
            .create_account("known@x.com", "oldpassword", "K")
            .unwrap();

        let issued = store.request_password_reset("known@x.com").unwrap();
        let (recipient, code) = issued.expect("a known account mints a reset token");
        assert_eq!(recipient, "known@x.com");
        assert!(!code.is_empty());

        // Unknown email → None (no token, nothing to email).
        assert!(store
            .request_password_reset("nobody@x.com")
            .unwrap()
            .is_none());
    }

    #[test]
    fn emailed_token_resets_password_and_is_single_use() {
        let store = AccountStore::new();
        let (_id, _c, recovery) = store.create_account("e@x.com", "oldpassword", "E").unwrap();
        let (_recipient, code) = store
            .request_password_reset("e@x.com")
            .unwrap()
            .expect("token minted");

        // The EMAILED code resets the password (passed in the recovery_code field).
        let new_recovery = store
            .reset_password("e@x.com", &code, "brandnewpass")
            .unwrap();
        assert!(!new_recovery.is_empty());
        assert_ne!(
            new_recovery, recovery,
            "a reset still rotates the recovery code"
        );

        // New password works; old one is dead.
        assert!(store.login("e@x.com", "brandnewpass").is_ok());
        assert_eq!(
            store.login("e@x.com", "oldpassword"),
            Err(AccountError::BadCredentials)
        );

        // The emailed token is single-use → replaying it is denied.
        assert_eq!(
            store.reset_password("e@x.com", &code, "anotherpass1"),
            Err(AccountError::BadRecoveryCode)
        );
    }

    #[test]
    fn recovery_code_still_works_after_an_email_token_is_outstanding() {
        // Issuing an email token must NOT break the saved-recovery-code path.
        let store = AccountStore::new();
        let (_id, _c, recovery) = store
            .create_account("both@x.com", "oldpassword", "B")
            .unwrap();
        let _ = store.request_password_reset("both@x.com").unwrap().unwrap();

        // The original recovery code still resets the password.
        assert!(store
            .reset_password("both@x.com", &recovery, "newpassword1")
            .is_ok());
        assert!(store.login("both@x.com", "newpassword1").is_ok());
    }

    #[test]
    fn expired_emailed_token_is_denied() {
        let store = AccountStore::new();
        store.create_account("x@x.com", "oldpassword", "X").unwrap();
        let (_recipient, code) = store
            .request_password_reset("x@x.com")
            .unwrap()
            .expect("token minted");

        // Age the stored token past its expiry (in-module access to the field).
        {
            let mut inner = store.inner.lock().unwrap();
            let acct = inner.by_email.get_mut("x@x.com").unwrap();
            acct.reset_token.as_mut().unwrap().expires_ms = AccountStore::now_ms() - 1;
        }
        // An expired token is rejected, indistinguishable from a wrong code.
        assert_eq!(
            store.reset_password("x@x.com", &code, "newpassword1"),
            Err(AccountError::BadRecoveryCode)
        );
        // The real password is untouched.
        assert!(store.login("x@x.com", "oldpassword").is_ok());
    }

    #[test]
    fn email_reset_requests_are_rate_limited_per_email() {
        // A single inbox can't be flooded: after the per-email cap, further requests
        // mint nothing (return None) until the window passes.
        let store = AccountStore::new();
        store
            .create_account("flood@x.com", "oldpassword", "F")
            .unwrap();

        // The cap equals the shared login/reset max-fails budget.
        let mut minted = 0;
        for _ in 0..DEFAULT_LOGIN_MAX_FAILS {
            if store
                .request_password_reset("flood@x.com")
                .unwrap()
                .is_some()
            {
                minted += 1;
            }
        }
        assert_eq!(minted, DEFAULT_LOGIN_MAX_FAILS as i32);
        // Next request is over the cap → None (no email), anti-enumeration-safe.
        assert!(store
            .request_password_reset("flood@x.com")
            .unwrap()
            .is_none());
    }

    #[test]
    fn emailed_token_hash_is_never_plaintext_at_rest_and_prunes_when_expired() {
        let dir = tmp_dir("reset-token-at-rest");
        let store = AccountStore::with_state_dir(&dir).unwrap();
        store
            .create_account("rt@x.com", "oldpassword", "R")
            .unwrap();
        let (_recipient, code) = store
            .request_password_reset("rt@x.com")
            .unwrap()
            .expect("token minted");

        // Plaintext (and its normalized form) NEVER touch disk — only the Argon2id hash.
        let on_disk = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
        assert!(!on_disk.contains(&code));
        assert!(!on_disk.contains(&normalize_recovery_code(&code)));
        assert!(on_disk.contains("reset_token_phc"));

        // A live token survives a restart and still resets.
        drop(store);
        let store2 = AccountStore::with_state_dir(&dir).unwrap();
        assert!(store2
            .reset_password("rt@x.com", &code, "newpassword1")
            .is_ok());

        // Now mint another, force it expired on disk, and confirm it's pruned on load.
        let (_r2, code2) = store2
            .request_password_reset("rt@x.com")
            .unwrap()
            .expect("token minted");
        {
            let mut inner = store2.inner.lock().unwrap();
            inner
                .by_email
                .get_mut("rt@x.com")
                .unwrap()
                .reset_token
                .as_mut()
                .unwrap()
                .expires_ms = AccountStore::now_ms() - 1;
            // Persist the expired token, then reload.
            store2.persist_locked(&inner);
        }
        drop(store2);
        let store3 = AccountStore::with_state_dir(&dir).unwrap();
        // The expired token was pruned on load → it no longer resets.
        assert_eq!(
            store3.reset_password("rt@x.com", &code2, "newpassword2"),
            Err(AccountError::BadRecoveryCode)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_code_format_groups_and_normalizes() {
        assert_eq!(normalize_recovery_code("k7mq2-9xf4t"), "K7MQ29XF4T");
        assert_eq!(normalize_recovery_code("K7MQ2 9XF4T"), "K7MQ29XF4T");
        assert_eq!(group_recovery_code("ABCDEFGHIJ"), "ABCDE-FGHIJ");
        // A minted code is grouped + base32 (uppercase, dash-separated).
        let store = AccountStore::new();
        let (code, _hash) = store.new_recovery_code().unwrap();
        assert!(code.contains('-'));
        assert!(code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn staff_guardian_meta_is_content_free_and_counts_only() {
        let store = AccountStore::new();
        // Unknown email → exists=false, everything zero (anti-enumeration shape).
        let m0 = store.staff_guardian_meta("nobody@x.com");
        assert_eq!(m0, GuardianMetaData::default());
        assert!(!m0.exists);

        let (_id, created, recovery) = store.create_account("g@x.com", "oldpassword", "G").unwrap();
        assert!(created);
        assert!(!recovery.is_empty());
        let m1 = store.staff_guardian_meta("G@x.com"); // case-insensitive (normalized)
        assert!(m1.exists);
        assert!(
            m1.has_recovery_code,
            "a freshly created account has a recovery code"
        );
        assert!(!m1.locked);
        assert!(!m1.reset_pending);
        assert_eq!(m1.child_count, 0);
        assert_eq!(m1.device_count, 0);
    }

    #[test]
    fn staff_clear_lockout_reports_existence_and_is_safe_on_unknown() {
        let store = AccountStore::new();
        store.create_account("g@x.com", "oldpassword", "G").unwrap();
        // Existing account → true; unknown email → false (no panic, idempotent).
        assert!(store.staff_clear_lockout("g@x.com"));
        assert!(store.staff_clear_lockout("g@x.com")); // idempotent
        assert!(!store.staff_clear_lockout("nobody@x.com"));
    }

    #[test]
    fn staff_meta_reflects_a_pending_emailed_reset() {
        let store = AccountStore::new();
        store.create_account("g@x.com", "oldpassword", "G").unwrap();
        // request_password_reset mints + stores a reset token for a real account.
        let dispatched = store.request_password_reset("g@x.com").unwrap();
        assert!(dispatched.is_some(), "a real account mints a reset token");
        assert!(store.staff_guardian_meta("g@x.com").reset_pending);
    }
}
