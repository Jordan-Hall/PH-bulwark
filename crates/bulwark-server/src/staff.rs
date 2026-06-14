//! Staff accounts + the `StaffAdmin` service — the INTERNAL operators console
//! for Predator Hunters staff (support / safety-officer / operator / admin).
//!
//! NOT guardian-facing: staff accounts live in a SEPARATE store with a separate
//! token namespace, so a guardian session can never authorize a staff RPC and a
//! staff session can never read a family's alerts (`Review`/`ChildControl`
//! resolve tokens against [`crate::accounts::AccountStore`], which knows nothing
//! about staff tokens — isolation by construction, not by role flag).
//!
//! CONTENT-FREE BY SHAPE: every message this service serves carries ids,
//! counts, versions, timestamps, and hashes ONLY — no message text, no media,
//! no alert snippets, no child names, no peer identities. See
//! docs/design/staff-management-system.md ("What staff must never access").
//!
//! AuthN mirrors [`crate::accounts`]: Argon2id PHC at rest, per-email sign-in
//! throttle, sessions keyed + persisted as sha256 digests only — PLUS mandatory
//! TOTP (RFC 6238: HMAC-SHA1, 30s step, 6 digits, +/-1-step skew) on every
//! staff login. The TOTP secret is necessarily stored retrievable (the server
//! must compute the same code); it lives only in the 0600 staff.json under the
//! 0700 state dir and is returned to the new staff member exactly once at
//! creation. Replay within the skew window is refused (last accepted counter
//! remembered).
//!
//! BOOTSTRAP: the FIRST staff account can only be created by presenting the
//! operator-set `BULWARK_STAFF_BOOTSTRAP_CODE` (compared by sha256 digest) and
//! is forced ADMIN; the moment one staff account exists the bootstrap path is
//! dead forever (CreateStaff then requires a live ADMIN session).
//!
//! AUDIT: every staff action (logins, creations, reads) appends to a
//! tamper-evident sha256 HASH CHAIN — the same construction as
//! `bulwark-store::hashchain` (re-implemented here because bulwark-store /
//! rusqlite must stay out of this dep tree; it does not build on the Windows
//! host): editing, deleting, or reordering an entry breaks every later link.
//!
//! State is in-memory (`Arc<Mutex<…>>`) with optional write-through JSON
//! persistence under `BULWARK_STATE_DIR` — the SAME [`JsonFile`] pattern as
//! [`AccountStore`](crate::accounts::AccountStore).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::accounts::{
    argon2_hash, argon2_verify, bearer_token, from_hex_array, login_throttle_params,
    normalize_email, record_failure, session_live, throttle_locked, to_hex, token_hash,
    LoginThrottle,
};
use crate::persist::JsonFile;
use crate::safety_cases::{SafetyCaseError, SafetyCaseStore};
use bulwark_proto::v1::staff_admin_server::StaffAdmin;
use bulwark_proto::v1::{
    CreateStaffRequest, FleetHealth, FleetHealthRequest, GetSafetyCaseRequest, GuardianMeta,
    GuardianMetaRequest, ListSafetyCasesRequest, OpenSafetyCaseAck, OpenSafetyCaseRequest,
    RegionInfo, Regions, RegionsRequest, SafetyCase, SafetyCaseState, SafetyCases, StaffAck,
    StaffAuditEntry, StaffAuditPage, StaffAuditQuery, StaffLoginRequest, StaffRole, StaffSession,
    TransitionSafetyCaseAck, TransitionSafetyCaseRequest, TriggerGuardianResetAck,
    TriggerGuardianResetRequest, UnlockGuardianAck, UnlockGuardianRequest,
};
use ring::rand::{SecureRandom, SystemRandom};
use tonic::{Request, Response, Status};

/// Staff session/id token entropy (same strength as guardian tokens).
const STAFF_TOKEN_BYTES: usize = 32;
const STAFF_ID_BYTES: usize = 16;
/// TOTP shared secret: 20 bytes (160 bits), the RFC 4226/6238 recommendation.
const TOTP_SECRET_BYTES: usize = 20;
const TOTP_STEP_SECS: i64 = 30;
/// 6-digit codes (modulus), the universal authenticator-app default.
const TOTP_DIGITS_MOD: u32 = 1_000_000;
/// Accept the previous/next step too (clock skew between phone and server).
const TOTP_SKEW_STEPS: i64 = 1;
/// Staff passwords are operator credentials — held to a longer minimum than
/// the guardian 8-char floor.
const STAFF_PASSWORD_MIN: usize = 12;
/// Staff sessions are SHORT by default (vs the guardians' 12h): override with
/// `BULWARK_STAFF_SESSION_TTL_SECS` (positive integer seconds).
const DEFAULT_STAFF_SESSION_TTL_SECS: i64 = 2 * 3600;

/// This region's TLS-cert expiry (unix ms) from `BULWARK_TLS_CERT_EXPIRY_TS`,
/// surfaced on the LOCAL region's `RegionInfo`. No x509 dependency: the deploy
/// sets it (e.g. from `openssl x509 -enddate`) so the staff dashboard can warn
/// before a cert lapses. `0` (unset / unparseable) = unknown.
fn tls_cert_expiry_ts_from_env() -> i64 {
    std::env::var("BULWARK_TLS_CERT_EXPIRY_TS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(0)
}

/// The configured staff-session TTL in milliseconds (env override, else default).
fn staff_session_ttl_ms() -> i64 {
    std::env::var("BULWARK_STAFF_SESSION_TTL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_STAFF_SESSION_TTL_SECS)
        .saturating_mul(1000)
}

/// Every staff role — for read-only, content-free RPCs any signed-in staff
/// member may call (region list / fleet health).
pub const ALL_STAFF_ROLES: [StaffRole; 4] = [
    StaffRole::Support,
    StaffRole::SafetyOfficer,
    StaffRole::Operator,
    StaffRole::Admin,
];

/// Guardian-support RPCs (reset / unlock / metadata) are SUPPORT or ADMIN only —
/// OPERATOR is fleet-only and SAFETY_OFFICER is case-only (least privilege).
pub const SUPPORT_ROLES: [StaffRole; 2] = [StaffRole::Support, StaffRole::Admin];

/// Safety-report queue (NCMEC workflow) RPCs are SAFETY_OFFICER or ADMIN only —
/// SUPPORT is guardian-only and OPERATOR is fleet-only (least privilege).
pub const SAFETY_ROLES: [StaffRole; 2] = [StaffRole::SafetyOfficer, StaffRole::Admin];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Domain errors the gRPC layer maps onto a tonic [`Status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaffError {
    /// A staff account with this email already exists.
    EmailExists,
    /// Email/password/TOTP didn't verify — deliberately indistinguishable.
    BadCredentials,
    /// The staff session token is missing, unknown, or expired.
    Unauthorized,
    /// The session is valid but the role does not allow this action.
    Forbidden,
    /// Too many failed sign-ins for this email within the window.
    TooManyAttempts,
    /// Bootstrap was attempted but no bootstrap code is configured on this node.
    BootstrapLocked,
    /// A required field was empty or malformed.
    Validation(&'static str),
    /// RNG / KDF failure — never a credential leak.
    Internal,
}

impl From<StaffError> for Status {
    fn from(e: StaffError) -> Self {
        match e {
            StaffError::EmailExists => {
                Status::already_exists("a staff account with that email exists")
            }
            // One opaque message for wrong email, password, OR code.
            StaffError::BadCredentials => {
                Status::unauthenticated("invalid email, password, or code")
            }
            StaffError::Unauthorized => {
                Status::unauthenticated("invalid or missing staff session token")
            }
            StaffError::Forbidden => {
                Status::permission_denied("staff role does not allow this action")
            }
            StaffError::TooManyAttempts => {
                Status::resource_exhausted("too many attempts; try again later")
            }
            StaffError::BootstrapLocked => {
                Status::failed_precondition("staff bootstrap is not enabled on this node")
            }
            StaffError::Validation(m) => Status::invalid_argument(m),
            StaffError::Internal => Status::internal("internal error"),
        }
    }
}

impl From<SafetyCaseError> for Status {
    fn from(e: SafetyCaseError) -> Self {
        match e {
            SafetyCaseError::Validation(m) => Status::invalid_argument(m),
            SafetyCaseError::NotFound => Status::not_found("no such safety case"),
            SafetyCaseError::InvalidTransition => {
                Status::failed_precondition("invalid safety-case workflow transition")
            }
            SafetyCaseError::Internal => Status::internal("internal error"),
        }
    }
}

/// A resolved, authorized staff caller (stamped into audit entries).
#[derive(Debug, Clone)]
pub struct StaffIdentity {
    pub staff_id: String,
    pub role: i32,
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238) — ring::hmac + data-encoding, no new dependency.
// ---------------------------------------------------------------------------

/// The 6-digit TOTP code for `secret` at time-step `counter`. HMAC-SHA1 per
/// RFC 6238's default (what authenticator apps implement); SHA-1's collision
/// weakness is irrelevant to HMAC-based OTPs — hence ring's "legacy use" key.
fn totp_code_at(secret: &[u8], counter: i64) -> u32 {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = ring::hmac::sign(&key, &(counter as u64).to_be_bytes());
    let b = tag.as_ref();
    // RFC 4226 dynamic truncation.
    let off = (b[b.len() - 1] & 0x0f) as usize;
    let bin = ((b[off] as u32 & 0x7f) << 24)
        | ((b[off + 1] as u32) << 16)
        | ((b[off + 2] as u32) << 8)
        | (b[off + 3] as u32);
    bin % TOTP_DIGITS_MOD
}

/// Verify a presented code against `secret_b32` at `unix_secs` with +/-1-step
/// skew. Returns the ACCEPTED counter iff the code matches a window AND that
/// counter is strictly newer than `last_counter` (replay refusal). `None`
/// otherwise (including a malformed secret/code — never a panic).
fn verify_totp(secret_b32: &str, code: &str, unix_secs: i64, last_counter: i64) -> Option<i64> {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_b32.as_bytes())
        .ok()?;
    let presented: u32 = code.trim().parse().ok()?;
    let step = unix_secs / TOTP_STEP_SECS;
    for offset in -TOTP_SKEW_STEPS..=TOTP_SKEW_STEPS {
        let counter = step + offset;
        if counter < 0 || counter <= last_counter {
            continue; // replay (or pre-epoch) — refuse
        }
        if totp_code_at(&secret, counter) == presented {
            return Some(counter);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Audit hash chain — same construction as bulwark-store::hashchain.
// ---------------------------------------------------------------------------

/// Domain-separated genesis hash seeding entry 0 (cannot collide with a real
/// entry hash by construction).
fn audit_genesis() -> [u8; 32] {
    let d = ring::digest::digest(
        &ring::digest::SHA256,
        b"bulwark-server/staff-audit/genesis/v1",
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Length-prefix a string field so field boundaries can't be shifted without
/// changing the hash (mirrors bulwark-store's canonical_bytes discipline).
fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Canonical (content-free) bytes of one audit entry, EXCLUDING entry_hash.
fn audit_canonical(
    seq: u64,
    ts: i64,
    staff_id: &str,
    role: i32,
    action: &str,
    target: &str,
    detail: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&ts.to_be_bytes());
    push_field(&mut buf, staff_id.as_bytes());
    buf.extend_from_slice(&role.to_be_bytes());
    push_field(&mut buf, action.as_bytes());
    push_field(&mut buf, target.as_bytes());
    push_field(&mut buf, detail.as_bytes());
    buf
}

/// `entry_hash[i] = sha256(entry_hash[i-1] || canonical(entry[i]))`.
fn audit_link(prev: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(prev);
    ctx.update(canonical);
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StaffRec {
    staff_id: String,
    display_name: String,
    role: i32,
    /// Argon2id PHC string — the password is never stored plaintext.
    phc: String,
    /// TOTP shared secret (base32). Necessarily retrievable (the server must
    /// compute the same code); guarded by the 0600 state file. Returned to the
    /// staff member exactly once, at creation.
    totp_secret_b32: String,
    /// Last ACCEPTED TOTP counter — a code can never be replayed.
    last_totp_counter: i64,
}

#[derive(Clone)]
struct StaffSessionEntry {
    staff_id: String,
    issued_ms: i64,
}

#[derive(Default)]
struct Inner {
    /// email (lowercased) → staff record.
    by_email: HashMap<String, StaffRec>,
    /// staff_id → email (reverse lookup).
    email_by_id: HashMap<String, String>,
    /// sha256(session token) hex → session. Digest-keyed like guardian sessions.
    sessions: HashMap<String, StaffSessionEntry>,
    /// email (lowercased) → failed-sign-in throttle (same params as guardians).
    login_fails: HashMap<String, LoginThrottle>,
}

/// One persisted audit entry (also the in-memory form).
#[derive(Clone, Serialize, Deserialize)]
struct AuditRec {
    seq: u64,
    ts: i64,
    staff_id: String,
    role: i32,
    action: String,
    target: String,
    detail: String,
    /// sha256 hex chain link: H(prev || canonical(self)).
    entry_hash: String,
}

#[derive(Default)]
struct AuditInner {
    entries: Vec<AuditRec>,
}

#[derive(Serialize, Deserialize, Default)]
struct AuditSnapshot {
    entries: Vec<AuditRec>,
}

/// Cloneable handle to the staff state. Every clone shares the same maps.
#[derive(Clone)]
pub struct StaffStore {
    inner: Arc<Mutex<Inner>>,
    audit: Arc<Mutex<AuditInner>>,
    rng: Arc<SystemRandom>,
    /// `Some` → write-through staff.json persistence; `None` → in-memory.
    persist: Option<JsonFile>,
    /// `Some` → write-through staff_audit.json persistence.
    audit_persist: Option<JsonFile>,
    /// sha256 hex of the one-time bootstrap code. `None` = bootstrap locked.
    /// Only consulted while ZERO staff accounts exist.
    bootstrap_sha256: Option<String>,
}

impl Default for StaffStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StaffStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            audit: Arc::new(Mutex::new(AuditInner::default())),
            rng: Arc::new(SystemRandom::new()),
            persist: None,
            audit_persist: None,
            bootstrap_sha256: None,
        }
    }

    /// Durable store rooted at `dir`: loads `staff.json` + `staff_audit.json`
    /// on startup and write-throughs every mutation. A corrupt file starts
    /// empty (logged); only an unusable directory is fatal — same contract as
    /// [`AccountStore::with_state_dir`](crate::accounts::AccountStore::with_state_dir).
    /// The audit chain is verified on load; a broken chain is loudly logged and
    /// the entries are KEPT (they are evidence — never silently discarded).
    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let file = JsonFile::new(dir, "staff.json")?;
        let audit_file = JsonFile::new(dir, "staff_audit.json")?;
        let snap: StaffSnapshot = file.load_or_default();
        let audit_snap: AuditSnapshot = audit_file.load_or_default();
        if !Self::verify_entries(&audit_snap.entries) {
            tracing::error!(
                "staff audit chain FAILED verification on load — entries kept as evidence; investigate"
            );
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner::from_snapshot(snap))),
            audit: Arc::new(Mutex::new(AuditInner {
                entries: audit_snap.entries,
            })),
            rng: Arc::new(SystemRandom::new()),
            persist: Some(file),
            audit_persist: Some(audit_file),
            bootstrap_sha256: None,
        })
    }

    /// Arm the one-time bootstrap path with an explicit code (tests / callers).
    /// Only its sha256 digest is kept.
    pub fn with_bootstrap_code(mut self, code: &str) -> Self {
        if !code.trim().is_empty() {
            self.bootstrap_sha256 = Some(token_hash(code));
        }
        self
    }

    /// Arm the bootstrap path from `BULWARK_STAFF_BOOTSTRAP_CODE` (unset/empty
    /// = bootstrap locked; with zero staff accounts the node then refuses
    /// CreateStaff until the operator sets it).
    pub fn with_bootstrap_from_env(self) -> Self {
        match std::env::var("BULWARK_STAFF_BOOTSTRAP_CODE") {
            Ok(code) if !code.trim().is_empty() => self.with_bootstrap_code(code.trim()),
            _ => self,
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

    /// Persist staff.json AFTER a mutation, under the held lock (consistent).
    /// A write failure is logged, never fatal — in-memory stays authoritative.
    fn persist_locked(&self, inner: &Inner) {
        if let Some(file) = &self.persist {
            if let Err(e) = file.store(&inner.snapshot()) {
                tracing::warn!(error = %e, "failed to persist staff store; continuing in-memory");
            }
        }
    }

    /// Resolve a staff session token → (staff_id, role), or `Unauthorized`
    /// (unknown OR expired — staff TTL is SHORT, default 2h).
    fn identity_for_token(inner: &Inner, token: &str) -> Result<(String, i32), StaffError> {
        let entry = inner
            .sessions
            .get(&token_hash(token))
            .ok_or(StaffError::Unauthorized)?;
        if !session_live(entry.issued_ms, Self::now_ms(), staff_session_ttl_ms()) {
            return Err(StaffError::Unauthorized);
        }
        let email = inner
            .email_by_id
            .get(&entry.staff_id)
            .ok_or(StaffError::Unauthorized)?;
        let rec = inner.by_email.get(email).ok_or(StaffError::Unauthorized)?;
        Ok((rec.staff_id.clone(), rec.role))
    }

    /// Resolve + role-gate a staff token. `Unauthorized` for a bad/expired
    /// token (including any GUARDIAN token — those live in a different store
    /// and simply don't exist here); `Forbidden` for a live session whose role
    /// is not in `allowed`.
    pub fn authorize(
        &self,
        token: &str,
        allowed: &[StaffRole],
    ) -> Result<StaffIdentity, StaffError> {
        let inner = self.inner.lock().expect("staff mutex poisoned");
        let (staff_id, role) = Self::identity_for_token(&inner, token)?;
        if allowed.iter().any(|r| *r as i32 == role) {
            Ok(StaffIdentity { staff_id, role })
        } else {
            Err(StaffError::Forbidden)
        }
    }

    /// Create a staff account.
    ///
    /// * ZERO staff accounts + armed bootstrap: `bootstrap_code` must digest-match
    ///   `BULWARK_STAFF_BOOTSTRAP_CODE`; the account is FORCED to ADMIN. Without
    ///   an armed code the node refuses (`BootstrapLocked`).
    /// * Otherwise: `admin_token` must be a live ADMIN staff session.
    ///
    /// Returns `(staff_id, totp_secret_base32, otpauth_uri)` — the TOTP
    /// enrollment material exists in a response exactly once, here.
    pub fn create_staff(
        &self,
        admin_token: &str,
        bootstrap_code: &str,
        email: &str,
        password: &str,
        role: i32,
        display_name: &str,
    ) -> Result<(String, String, String), StaffError> {
        let email_key = normalize_email(email);
        if email_key.is_empty() {
            return Err(StaffError::Validation("email is required"));
        }
        if password.len() < STAFF_PASSWORD_MIN {
            return Err(StaffError::Validation(
                "staff password must be at least 12 characters",
            ));
        }
        // Hash OUTSIDE the lock (Argon2id is deliberately slow — same
        // discipline as AccountStore::create_account).
        let phc = argon2_hash(&self.rng, password.as_bytes()).map_err(|_| StaffError::Internal)?;

        // TOTP secret: 160 bits of CSPRNG entropy, base32 for authenticator apps.
        let mut secret = [0u8; TOTP_SECRET_BYTES];
        self.rng
            .fill(&mut secret)
            .map_err(|_| StaffError::Internal)?;
        let secret_b32 = data_encoding::BASE32_NOPAD.encode(&secret);

        let mut inner = self.inner.lock().expect("staff mutex poisoned");

        // Authorization: bootstrap path ONLY while the store is empty.
        let (actor_id, actor_role, effective_role) = if inner.by_email.is_empty() {
            let expected = self
                .bootstrap_sha256
                .as_ref()
                .ok_or(StaffError::BootstrapLocked)?;
            // Digest-compared (like every other secret lookup here) — the raw
            // bootstrap code is never stored and a digest equality can't leak it.
            if token_hash(bootstrap_code) != *expected {
                return Err(StaffError::Unauthorized);
            }
            // The first account is always ADMIN (someone must be able to add the rest).
            (
                "bootstrap".to_string(),
                StaffRole::Admin as i32,
                StaffRole::Admin as i32,
            )
        } else {
            let (admin_id, admin_role) = Self::identity_for_token(&inner, admin_token)?;
            if admin_role != StaffRole::Admin as i32 {
                return Err(StaffError::Forbidden);
            }
            if !(StaffRole::Support as i32..=StaffRole::Admin as i32).contains(&role) {
                return Err(StaffError::Validation("role is required"));
            }
            (admin_id, admin_role, role)
        };

        if inner.by_email.contains_key(&email_key) {
            return Err(StaffError::EmailExists);
        }

        let staff_id = self.rand_hex(STAFF_ID_BYTES);
        inner
            .email_by_id
            .insert(staff_id.clone(), email_key.clone());
        inner.by_email.insert(
            email_key.clone(),
            StaffRec {
                staff_id: staff_id.clone(),
                display_name: display_name.trim().to_string(),
                role: effective_role,
                phc,
                totp_secret_b32: secret_b32.clone(),
                last_totp_counter: -1,
            },
        );
        self.persist_locked(&inner);
        drop(inner); // lock order: inner before audit, never nested

        self.audit_append(
            &actor_id,
            actor_role,
            "staff.create",
            &staff_id,
            &format!("role={effective_role}"),
        );

        // otpauth:// provisioning URI ('@' percent-encoded for the label).
        let label = email_key.replace('@', "%40");
        let otpauth_uri = format!(
            "otpauth://totp/PH%20Bulwark%20Staff:{label}?secret={secret_b32}&issuer=PH%20Bulwark%20Staff&algorithm=SHA1&digits=6&period=30"
        );
        Ok((staff_id, secret_b32, otpauth_uri))
    }

    /// Staff sign-in: password AND a live TOTP code. Throttled per email with
    /// the same window/params as guardian login; wrong email, wrong password,
    /// and wrong code are indistinguishable (`BadCredentials`) and all count
    /// toward the lockout. Returns `(token, staff_id, role, issued_ms)`.
    pub fn login(
        &self,
        email: &str,
        password: &str,
        totp_code: &str,
    ) -> Result<(String, String, i32, i64), StaffError> {
        let email_key = normalize_email(email);
        let now = Self::now_ms();
        let (max_fails, window_ms) = login_throttle_params();

        // Snapshot under the lock; verify the slow KDF outside it (the same
        // snapshot/release/verify/re-acquire dance as AccountStore::login).
        let snapshot = {
            let inner = self.inner.lock().expect("staff mutex poisoned");
            if inner
                .login_fails
                .get(&email_key)
                .is_some_and(|t| throttle_locked(t, now, window_ms, max_fails))
            {
                return Err(StaffError::TooManyAttempts);
            }
            inner.by_email.get(&email_key).map(|r| {
                (
                    r.phc.clone(),
                    r.totp_secret_b32.clone(),
                    r.last_totp_counter,
                )
            })
        };

        let mut accepted_counter: Option<i64> = None;
        let verified = match &snapshot {
            Some((phc, secret_b32, last_counter)) => {
                let pw_ok = argon2_verify(phc, password.as_bytes());
                // TOTP only evaluated after a correct password, so a wrong
                // password can't be used to probe code validity.
                pw_ok
                    && match verify_totp(secret_b32, totp_code, now / 1000, *last_counter) {
                        Some(counter) => {
                            accepted_counter = Some(counter);
                            true
                        }
                        None => false,
                    }
            }
            None => false,
        };

        let mut inner = self.inner.lock().expect("staff mutex poisoned");
        if !verified {
            let t = inner
                .login_fails
                .entry(email_key.clone())
                .or_insert(LoginThrottle {
                    fails: 0,
                    window_start_ms: now,
                });
            record_failure(t, now, window_ms);
            return Err(StaffError::BadCredentials);
        }

        inner.login_fails.remove(&email_key);
        let (staff_id, role) = match inner.by_email.get_mut(&email_key) {
            Some(rec) => {
                // Remember the accepted counter so the same code can never be
                // replayed (monotonic — an older counter is never written back).
                if let Some(c) = accepted_counter {
                    if c > rec.last_totp_counter {
                        rec.last_totp_counter = c;
                    }
                }
                (rec.staff_id.clone(), rec.role)
            }
            None => return Err(StaffError::BadCredentials),
        };
        let token = self.rand_hex(STAFF_TOKEN_BYTES);
        // Stored/persisted by DIGEST only — the raw token goes to the caller.
        inner.sessions.insert(
            token_hash(&token),
            StaffSessionEntry {
                staff_id: staff_id.clone(),
                issued_ms: now,
            },
        );
        self.persist_locked(&inner);
        drop(inner);

        self.audit_append(&staff_id, role, "staff.login", "", "sign-in ok");
        Ok((token, staff_id, role, now))
    }

    /// Append one entry to the tamper-evident audit chain (and persist it).
    /// Content-free by signature: ids + an action name + a short note only.
    pub fn audit_append(
        &self,
        staff_id: &str,
        role: i32,
        action: &str,
        target: &str,
        detail: &str,
    ) {
        let mut audit = self.audit.lock().expect("staff audit mutex poisoned");
        // Chain from the last entry's hash (a corrupt last hash falls back to
        // genesis — verify_entries flags the break regardless, so tampering
        // can't hide behind the fallback).
        let prev = audit
            .entries
            .last()
            .and_then(|e| from_hex_array::<32>(&e.entry_hash))
            .unwrap_or_else(audit_genesis);
        let seq = audit.entries.last().map(|e| e.seq + 1).unwrap_or(0);
        let ts = Self::now_ms();
        let hash = audit_link(
            &prev,
            &audit_canonical(seq, ts, staff_id, role, action, target, detail),
        );
        audit.entries.push(AuditRec {
            seq,
            ts,
            staff_id: staff_id.to_string(),
            role,
            action: action.to_string(),
            target: target.to_string(),
            detail: detail.to_string(),
            entry_hash: to_hex(&hash),
        });
        if let Some(file) = &self.audit_persist {
            if let Err(e) = file.store(&AuditSnapshot {
                entries: audit.entries.clone(),
            }) {
                tracing::warn!(error = %e, "failed to persist staff audit; continuing in-memory");
            }
        }
    }

    /// Re-derive the chain over `entries` and compare each stored hash. Any
    /// edit/delete/reorder breaks the first affected link and every later one.
    fn verify_entries(entries: &[AuditRec]) -> bool {
        let mut prev = audit_genesis();
        for e in entries {
            let derived = audit_link(
                &prev,
                &audit_canonical(
                    e.seq,
                    e.ts,
                    &e.staff_id,
                    e.role,
                    &e.action,
                    &e.target,
                    &e.detail,
                ),
            );
            if to_hex(&derived) != e.entry_hash {
                return false;
            }
            prev = derived;
        }
        true
    }

    /// Verify the full in-memory chain (exposed for the console + tests).
    pub fn verify_audit_chain(&self) -> bool {
        let audit = self.audit.lock().expect("staff audit mutex poisoned");
        Self::verify_entries(&audit.entries)
    }

    /// Page through the audit chain: entries with `seq >= after_seq`, up to
    /// `limit` (0 = 100, capped at 1000). Returns `(entries, next_seq, chain_ok)`
    /// — the chain is re-verified on EVERY read so at-rest tampering surfaces
    /// in the console immediately.
    pub fn query_audit(&self, after_seq: u64, limit: u32) -> (Vec<StaffAuditEntry>, u64, bool) {
        let audit = self.audit.lock().expect("staff audit mutex poisoned");
        let chain_ok = Self::verify_entries(&audit.entries);
        let limit = if limit == 0 { 100 } else { limit.min(1000) } as usize;
        let entries: Vec<StaffAuditEntry> = audit
            .entries
            .iter()
            .filter(|e| e.seq >= after_seq)
            .take(limit)
            .map(|e| StaffAuditEntry {
                seq: e.seq,
                ts: e.ts,
                staff_id: e.staff_id.clone(),
                role: e.role,
                action: e.action.clone(),
                target: e.target.clone(),
                detail: e.detail.clone(),
                entry_hash: e.entry_hash.clone(),
            })
            .collect();
        let next_seq = entries.last().map(|e| e.seq + 1).unwrap_or(after_seq);
        (entries, next_seq, chain_ok)
    }
}

// ---------------------------------------------------------------------------
// Durable snapshot (serde JSON). At-rest credential surface mirrors accounts:
// Argon2id PHC + sha256 session digests. The TOTP secret is the ONE documented
// exception (the server must compute the same code) — guarded by the 0600 file.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct StaffSnapshot {
    staff: Vec<StaffRow>,
    sessions: Vec<StaffSessionRow>,
}

#[derive(Serialize, Deserialize)]
struct StaffRow {
    email_key: String,
    staff_id: String,
    display_name: String,
    role: i32,
    phc: String,
    totp_secret_base32: String,
    #[serde(default)]
    last_totp_counter: i64,
}

#[derive(Serialize, Deserialize)]
struct StaffSessionRow {
    /// sha256(token) hex — the only form that ever touches disk.
    token_sha256: String,
    staff_id: String,
    issued_ms: i64,
}

impl Inner {
    /// Build a stable (sorted) serde snapshot.
    fn snapshot(&self) -> StaffSnapshot {
        let mut staff: Vec<StaffRow> = self
            .by_email
            .iter()
            .map(|(email_key, r)| StaffRow {
                email_key: email_key.clone(),
                staff_id: r.staff_id.clone(),
                display_name: r.display_name.clone(),
                role: r.role,
                phc: r.phc.clone(),
                totp_secret_base32: r.totp_secret_b32.clone(),
                last_totp_counter: r.last_totp_counter,
            })
            .collect();
        staff.sort_by(|a, b| a.email_key.cmp(&b.email_key));

        let mut sessions: Vec<StaffSessionRow> = self
            .sessions
            .iter()
            .map(|(token_sha256, e)| StaffSessionRow {
                token_sha256: token_sha256.clone(),
                staff_id: e.staff_id.clone(),
                issued_ms: e.issued_ms,
            })
            .collect();
        sessions.sort_by(|a, b| a.token_sha256.cmp(&b.token_sha256));

        StaffSnapshot { staff, sessions }
    }

    /// Rebuild from a snapshot; expired sessions are pruned on load (the SHORT
    /// staff TTL applies at rest too).
    fn from_snapshot(snap: StaffSnapshot) -> Inner {
        let mut inner = Inner::default();
        for row in snap.staff {
            if row.phc.is_empty() || row.totp_secret_base32.is_empty() {
                tracing::warn!(staff = %row.staff_id, "skipping staff row with no usable credentials");
                continue;
            }
            inner
                .email_by_id
                .insert(row.staff_id.clone(), row.email_key.clone());
            inner.by_email.insert(
                row.email_key,
                StaffRec {
                    staff_id: row.staff_id,
                    display_name: row.display_name,
                    role: row.role,
                    phc: row.phc,
                    totp_secret_b32: row.totp_secret_base32,
                    last_totp_counter: row.last_totp_counter,
                },
            );
        }
        for row in snap.sessions {
            if !session_live(row.issued_ms, StaffStore::now_ms(), staff_session_ttl_ms()) {
                continue;
            }
            if row.token_sha256.is_empty() {
                continue;
            }
            inner.sessions.insert(
                row.token_sha256,
                StaffSessionEntry {
                    staff_id: row.staff_id,
                    issued_ms: row.issued_ms,
                },
            );
        }
        inner
    }
}

// ---------------------------------------------------------------------------
// gRPC service
// ---------------------------------------------------------------------------

/// One staff-visible region (static config in increment 1; live probing joins
/// in increment 4). Content-free: a name + the public endpoint.
#[derive(Clone, Debug)]
pub struct StaticRegion {
    pub region: String,
    pub endpoint: String,
}

/// Parse `BULWARK_STAFF_REGIONS` ("uk=lon.host:8443,us=nyc.host:8443").
fn parse_regions(s: &str) -> Vec<StaticRegion> {
    s.split(',')
        .filter_map(|p| {
            let (name, ep) = p.split_once('=')?;
            let (name, ep) = (name.trim(), ep.trim());
            (!name.is_empty() && !ep.is_empty()).then(|| StaticRegion {
                region: name.to_string(),
                endpoint: ep.to_string(),
            })
        })
        .collect()
}

/// Implements `bulwark_proto::v1::staff_admin_server::StaffAdmin` over a
/// [`StaffStore`]. EVERY RPC appends to the audit chain — reads included.
#[derive(Clone)]
pub struct StaffAdminService {
    store: StaffStore,
    regions: Vec<StaticRegion>,
    /// Guardian account store — present enables the increment-2 support RPCs
    /// (reset / unlock / metadata). `None` → those RPCs return FAILED_PRECONDITION.
    accounts: Option<crate::accounts::AccountStore>,
    /// Reset-code mailer — present lets `TriggerGuardianReset` actually email the
    /// guardian. `None` → a reset is minted but `dispatched` is false (SMTP off).
    reset_mailer: Option<crate::reset_mailer::ResetMailer>,
    /// Safety-report queue (NCMEC workflow). Always present — defaults to an
    /// in-memory store so the SAFETY_OFFICER RPCs work even without a state dir;
    /// service.rs swaps in the persistent one when `BULWARK_STATE_DIR` is set.
    safety_cases: SafetyCaseStore,
    /// Live fleet-data sources for THIS node's region (increment 4). `None`
    /// handles leave the corresponding gauge at its honest default so a
    /// region with no live source reports `probed = false`.
    fleet: FleetSources,
}

/// Optional live data sources backing the fleet dashboard (increment 4). The
/// local `Cluster` knows only its OWN cluster's members — there is no cross-
/// region gossip on the single-box deployment — so live data populates ONLY
/// the region whose name matches `local_region`; every other configured region
/// stays `probed = false` (honest: we have no live snapshot for it).
#[derive(Clone, Default)]
struct FleetSources {
    /// This node's cluster handle (queue depth / latency / load via `health`).
    cluster: Option<Arc<bulwark_cluster::Cluster>>,
    /// This node's WireGuard peer store (enrolled-peer COUNT only).
    wg_peers: Option<crate::wg_provision::WgPeerStore>,
    /// The region name this node serves (`BULWARK_REGION`); live data attaches
    /// to the `RegionInfo` whose `region` equals this. Empty = match nothing.
    local_region: String,
    /// This region's TLS-cert expiry (unix ms; 0 = unknown).
    tls_cert_expiry_ts: i64,
}

impl StaffAdminService {
    pub fn new(store: StaffStore, regions: Vec<StaticRegion>) -> Self {
        Self {
            store,
            regions,
            accounts: None,
            reset_mailer: None,
            safety_cases: SafetyCaseStore::new(),
            fleet: FleetSources::default(),
        }
    }

    /// Attach the guardian [`AccountStore`](crate::accounts::AccountStore) so the
    /// guardian-support RPCs can act on guardian accounts (by email, content-free).
    pub fn with_accounts(mut self, accounts: crate::accounts::AccountStore) -> Self {
        self.accounts = Some(accounts);
        self
    }

    /// Attach the [`ResetMailer`](crate::reset_mailer::ResetMailer) so a staff
    /// guardian reset actually emails the code (which staff never see).
    pub fn with_reset_mailer(mut self, mailer: crate::reset_mailer::ResetMailer) -> Self {
        self.reset_mailer = Some(mailer);
        self
    }

    /// Swap in a specific [`SafetyCaseStore`] (e.g. the persistent one rooted at
    /// `BULWARK_STATE_DIR`). Defaults to an in-memory store otherwise.
    pub fn with_safety_cases(mut self, cases: SafetyCaseStore) -> Self {
        self.safety_cases = cases;
        self
    }

    /// Attach this node's [`Cluster`](bulwark_cluster::Cluster) so the LOCAL
    /// region's `RegionInfo`/`FleetHealth` reports a LIVE `HealthStatus`
    /// (queue depth / latency / load — already content-free) and `probed = true`.
    pub fn with_cluster(mut self, cluster: Arc<bulwark_cluster::Cluster>) -> Self {
        self.fleet.cluster = Some(cluster);
        self
    }

    /// Attach this node's [`WgPeerStore`](crate::wg_provision::WgPeerStore) so the
    /// LOCAL region reports the enrolled WireGuard peer COUNT (never identities).
    pub fn with_wg_peers(mut self, wg_peers: crate::wg_provision::WgPeerStore) -> Self {
        self.fleet.wg_peers = Some(wg_peers);
        self
    }

    /// Name the region THIS node serves (live fleet data attaches to the
    /// `RegionInfo` whose `region` equals this) and set its TLS-cert expiry.
    pub fn with_local_region(mut self, region: &str, tls_cert_expiry_ts: i64) -> Self {
        self.fleet.local_region = region.to_string();
        self.fleet.tls_cert_expiry_ts = tls_cert_expiry_ts;
        self
    }

    /// Regions from `BULWARK_STAFF_REGIONS`, else this node itself
    /// (`BULWARK_REGION`, default "self", at `BULWARK_BIND`). The local region
    /// name + TLS-cert expiry are read from the environment so live fleet data
    /// (increment 4) attaches to the right `RegionInfo`.
    pub fn from_env(store: StaffStore) -> Self {
        let local_region = std::env::var("BULWARK_REGION").unwrap_or_else(|_| "self".into());
        let regions = std::env::var("BULWARK_STAFF_REGIONS")
            .ok()
            .map(|s| parse_regions(&s))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                vec![StaticRegion {
                    region: local_region.clone(),
                    endpoint: std::env::var("BULWARK_BIND").unwrap_or_default(),
                }]
            });
        let mut svc = Self::new(store, regions);
        svc.fleet.local_region = local_region;
        svc.fleet.tls_cert_expiry_ts = tls_cert_expiry_ts_from_env();
        svc
    }

    /// Effective token: the explicit field first, then `authorization: Bearer`.
    fn token_or_meta<T>(req: &Request<T>, field: &str) -> String {
        if !field.trim().is_empty() {
            return field.trim().to_string();
        }
        bearer_token(req).unwrap_or_default()
    }

    /// Content-free `RegionInfo` for a NON-local region (or any region when no
    /// live source is attached): `probed = false`, honest zero gauges. We have
    /// no live snapshot for a region other than the one this node serves.
    fn static_region_info(r: &StaticRegion, now: i64) -> RegionInfo {
        RegionInfo {
            region: r.region.clone(),
            endpoint: r.endpoint.clone(),
            probed: false,
            healthy: false,
            deploy_version: env!("CARGO_PKG_VERSION").to_string(),
            tls_cert_expiry_ts: 0,
            wg_peer_count: 0,
            enrolled_device_count: 0,
            ts: now,
        }
    }

    /// This node's LIVE `HealthStatus` via [`bulwark_cluster::Cluster`], or
    /// `None` when no cluster handle is attached. Content-free (queue depth /
    /// in-flight / load / latency gauges).
    async fn local_node_health(&self) -> Option<bulwark_proto::v1::HealthStatus> {
        use bulwark_cluster::ClusterMember;
        let cluster = self.fleet.cluster.as_ref()?;
        cluster
            .health(bulwark_proto::v1::HealthRequest::default())
            .await
            .ok()
    }

    /// Is `r` the region THIS node serves (so live data attaches to it)?
    fn is_local_region(&self, r: &StaticRegion) -> bool {
        !self.fleet.local_region.is_empty() && r.region == self.fleet.local_region
    }

    /// Content-free `RegionInfo` for `r`, joining LIVE data when `r` is the
    /// region THIS node serves: `probed = true`, `healthy` from the node's
    /// `accepting_work`, plus WG peer + enrolled-device COUNTS, the deploy
    /// version, and this region's TLS-cert expiry. A non-local region falls back
    /// to [`Self::static_region_info`]. `health` is the LOCAL node's snapshot
    /// (the caller fetches it once via [`Self::local_node_health`] so a single
    /// RPC serves both this summary and `FleetHealth.nodes`).
    fn region_info_with_health(
        &self,
        r: &StaticRegion,
        now: i64,
        health: Option<&bulwark_proto::v1::HealthStatus>,
    ) -> RegionInfo {
        if !self.is_local_region(r) {
            return Self::static_region_info(r, now);
        }
        // A live cluster snapshot makes the node `probed` + sets `healthy` from
        // `accepting_work`; without one we still surface the COUNTS + cert expiry
        // we DO have but stay honest that the node itself wasn't probed.
        RegionInfo {
            region: r.region.clone(),
            endpoint: r.endpoint.clone(),
            probed: health.is_some(),
            healthy: health.is_some_and(|h| h.accepting_work),
            deploy_version: env!("CARGO_PKG_VERSION").to_string(),
            tls_cert_expiry_ts: self.fleet.tls_cert_expiry_ts,
            wg_peer_count: self.fleet.wg_peers.as_ref().map_or(0, |s| s.peer_count()),
            enrolled_device_count: self
                .accounts
                .as_ref()
                .map_or(0, |a| a.staff_enrolled_device_count()),
            ts: now,
        }
    }

    /// Content-free `RegionInfo` for `r`, fetching the local node's live health
    /// when `r` is the region this node serves (else the static fallback).
    async fn live_region_info(&self, r: &StaticRegion, now: i64) -> RegionInfo {
        // Only probe the cluster for the local region (no cross-region snapshot).
        let health = if self.is_local_region(r) {
            self.local_node_health().await
        } else {
            None
        };
        self.region_info_with_health(r, now, health.as_ref())
    }
}

#[tonic::async_trait]
impl StaffAdmin for StaffAdminService {
    async fn create_staff(
        &self,
        req: Request<CreateStaffRequest>,
    ) -> Result<Response<StaffAck>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        let (staff_id, totp_secret_base32, otpauth_uri) = self.store.create_staff(
            &token,
            &r.bootstrap_code,
            &r.email,
            &r.password,
            r.role,
            &r.display_name,
        )?;
        Ok(Response::new(StaffAck {
            staff_id,
            created: true,
            detail: "staff account created — enroll the TOTP secret NOW; it is shown only once"
                .to_string(),
            totp_secret_base32,
            otpauth_uri,
        }))
    }

    async fn staff_login(
        &self,
        req: Request<StaffLoginRequest>,
    ) -> Result<Response<StaffSession>, Status> {
        let r = req.into_inner();
        let (token, staff_id, role, issued_ts) =
            self.store.login(&r.email, &r.password, &r.totp_code)?;
        Ok(Response::new(StaffSession {
            token,
            staff_id,
            role,
            issued_ts,
        }))
    }

    async fn list_regions(
        &self,
        req: Request<RegionsRequest>,
    ) -> Result<Response<Regions>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let ident = self.store.authorize(&token, &ALL_STAFF_ROLES)?;
        self.store
            .audit_append(&ident.staff_id, ident.role, "fleet.list_regions", "", "");
        let now = StaffStore::now_ms();
        let mut regions = Vec::with_capacity(self.regions.len());
        for r in &self.regions {
            regions.push(self.live_region_info(r, now).await);
        }
        Ok(Response::new(Regions { regions }))
    }

    async fn get_fleet_health(
        &self,
        req: Request<FleetHealthRequest>,
    ) -> Result<Response<FleetHealth>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let ident = self.store.authorize(&token, &ALL_STAFF_ROLES)?;
        let r = req.into_inner();
        let region = r.region.trim();
        if region.is_empty() {
            return Err(Status::invalid_argument("region is required"));
        }
        self.store
            .audit_append(&ident.staff_id, ident.role, "fleet.get_health", region, "");
        let cfg = self
            .regions
            .iter()
            .find(|x| x.region == region)
            .ok_or_else(|| Status::not_found("no such region"))?
            .clone();
        // Fetch the local node's live snapshot ONCE (only for the local region),
        // serving both the RegionInfo summary and the per-node `nodes` list.
        let health = if self.is_local_region(&cfg) {
            self.local_node_health().await
        } else {
            None
        };
        let info = self.region_info_with_health(&cfg, StaffStore::now_ms(), health.as_ref());
        // Per-node ClusterControl `HealthStatus` snapshots for the LOCAL region
        // (queue depth / latency / load — already content-free). A non-local
        // region has no live snapshot here, so `nodes` stays empty.
        let nodes = health.into_iter().collect();
        Ok(Response::new(FleetHealth {
            region: cfg.region.clone(),
            info: Some(info),
            nodes,
        }))
    }

    async fn query_staff_audit(
        &self,
        req: Request<StaffAuditQuery>,
    ) -> Result<Response<StaffAuditPage>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        // ADMIN only — and the query is itself audited.
        let ident = self.store.authorize(&token, &[StaffRole::Admin])?;
        let r = req.into_inner();
        self.store.audit_append(
            &ident.staff_id,
            ident.role,
            "audit.query",
            "",
            &format!("after_seq={}", r.after_seq),
        );
        let (entries, next_seq, chain_ok) = self.store.query_audit(r.after_seq, r.limit);
        Ok(Response::new(StaffAuditPage {
            entries,
            next_seq,
            chain_ok,
        }))
    }

    async fn trigger_guardian_reset(
        &self,
        req: Request<TriggerGuardianResetRequest>,
    ) -> Result<Response<TriggerGuardianResetAck>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        let ident = self.store.authorize(&token, &SUPPORT_ROLES)?;
        let accounts = self.accounts.as_ref().ok_or_else(|| {
            Status::failed_precondition("guardian support unavailable (accounts not configured)")
        })?;
        // Mint + email the reset via the SAME path as self-service; staff NEVER see
        // the code. dispatched=false covers unknown email / throttled / SMTP-off
        // alike (anti-enumeration — staff can't probe which emails exist).
        let dispatched = match accounts.request_password_reset(&r.guardian_email) {
            Ok(Some((recipient, code))) => match &self.reset_mailer {
                Some(mailer) => mailer
                    .send_reset_code(
                        &recipient,
                        &code,
                        crate::accounts::reset_token_ttl_minutes(),
                    )
                    .await
                    .is_ok(),
                None => false,
            },
            _ => false,
        };
        // Content-free audit: never the guardian email/id; only the outcome.
        self.store.audit_append(
            &ident.staff_id,
            ident.role,
            "guardian.reset",
            "",
            if dispatched { "dispatched" } else { "no-op" },
        );
        Ok(Response::new(TriggerGuardianResetAck {
            dispatched,
            detail: "if the account exists, a reset code was emailed to the guardian".to_string(),
        }))
    }

    async fn unlock_guardian_account(
        &self,
        req: Request<UnlockGuardianRequest>,
    ) -> Result<Response<UnlockGuardianAck>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        let ident = self.store.authorize(&token, &SUPPORT_ROLES)?;
        let accounts = self.accounts.as_ref().ok_or_else(|| {
            Status::failed_precondition("guardian support unavailable (accounts not configured)")
        })?;
        let existed = accounts.staff_clear_lockout(&r.guardian_email);
        self.store.audit_append(
            &ident.staff_id,
            ident.role,
            "guardian.unlock",
            "",
            if existed { "cleared" } else { "no-account" },
        );
        Ok(Response::new(UnlockGuardianAck {
            existed,
            detail: if existed {
                "sign-in lockout cleared".to_string()
            } else {
                "no account with that email".to_string()
            },
        }))
    }

    async fn get_guardian_meta(
        &self,
        req: Request<GuardianMetaRequest>,
    ) -> Result<Response<GuardianMeta>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let r = req.into_inner();
        let ident = self.store.authorize(&token, &SUPPORT_ROLES)?;
        let accounts = self.accounts.as_ref().ok_or_else(|| {
            Status::failed_precondition("guardian support unavailable (accounts not configured)")
        })?;
        let m = accounts.staff_guardian_meta(&r.guardian_email);
        self.store.audit_append(
            &ident.staff_id,
            ident.role,
            "guardian.meta",
            "",
            if m.exists { "hit" } else { "miss" },
        );
        Ok(Response::new(GuardianMeta {
            exists: m.exists,
            locked: m.locked,
            has_recovery_code: m.has_recovery_code,
            reset_pending: m.reset_pending,
            child_count: m.child_count,
            device_count: m.device_count,
        }))
    }

    async fn open_safety_case(
        &self,
        req: Request<OpenSafetyCaseRequest>,
    ) -> Result<Response<OpenSafetyCaseAck>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let ident = self.store.authorize(&token, &SAFETY_ROLES)?;
        let r = req.into_inner();
        let case = self.safety_cases.open_case(
            &r.sha256,
            &r.perceptual_hash,
            r.category,
            &r.jurisdiction,
        )?;
        // Content-free audit: the case id + opening state only — never a hash,
        // an email, or any content.
        let state_name = SafetyCaseState::try_from(case.state)
            .map(|s| s.as_str_name())
            .unwrap_or("UNKNOWN");
        self.store.audit_append(
            &ident.staff_id,
            ident.role,
            "safety_case.open",
            &case.case_id,
            &format!("state={state_name}"),
        );
        Ok(Response::new(OpenSafetyCaseAck {
            safety_case: Some(case),
        }))
    }

    async fn list_safety_cases(
        &self,
        req: Request<ListSafetyCasesRequest>,
    ) -> Result<Response<SafetyCases>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let ident = self.store.authorize(&token, &SAFETY_ROLES)?;
        let r = req.into_inner();
        let cases = self.safety_cases.list_cases(r.state_filter);
        self.store.audit_append(
            &ident.staff_id,
            ident.role,
            "safety_case.list",
            "",
            &format!("count={}", cases.len()),
        );
        Ok(Response::new(SafetyCases { cases }))
    }

    async fn transition_safety_case(
        &self,
        req: Request<TransitionSafetyCaseRequest>,
    ) -> Result<Response<TransitionSafetyCaseAck>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let ident = self.store.authorize(&token, &SAFETY_ROLES)?;
        let r = req.into_inner();
        let case = self
            .safety_cases
            .transition(&r.case_id, r.new_state, &r.ncmec_reference)?;
        // Audit the new state by its stable enum name — content-free.
        let state_name = SafetyCaseState::try_from(case.state)
            .map(|s| s.as_str_name())
            .unwrap_or("UNKNOWN");
        self.store.audit_append(
            &ident.staff_id,
            ident.role,
            "safety_case.transition",
            &case.case_id,
            &format!("state={state_name}"),
        );
        Ok(Response::new(TransitionSafetyCaseAck {
            safety_case: Some(case),
        }))
    }

    async fn get_safety_case(
        &self,
        req: Request<GetSafetyCaseRequest>,
    ) -> Result<Response<SafetyCase>, Status> {
        let token = Self::token_or_meta(&req, &req.get_ref().token);
        let ident = self.store.authorize(&token, &SAFETY_ROLES)?;
        let r = req.into_inner();
        let case = self.safety_cases.get_case(&r.case_id)?;
        self.store.audit_append(
            &ident.staff_id,
            ident.role,
            "safety_case.get",
            &case.case_id,
            "",
        );
        Ok(Response::new(case))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::AccountStore;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bulwark-staff-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The CURRENT 6-digit code for a base32 secret (what an authenticator
    /// app would show right now). +/-1-step server skew absorbs a boundary roll.
    fn current_code(secret_b32: &str) -> String {
        let secret = data_encoding::BASE32_NOPAD
            .decode(secret_b32.as_bytes())
            .unwrap();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        format!("{:06}", totp_code_at(&secret, now_secs / TOTP_STEP_SECS))
    }

    /// Bootstrapped store with a signed-in ADMIN. Returns (store, admin_token, admin_id).
    fn bootstrap_store() -> (StaffStore, String, String) {
        let store = StaffStore::new().with_bootstrap_code("bootstrap-code-1");
        let (admin_id, secret, _uri) = store
            .create_staff(
                "",
                "bootstrap-code-1",
                "admin@ph.example",
                "adminpassword123",
                StaffRole::Admin as i32,
                "Admin",
            )
            .unwrap();
        let (token, _, _, _) = store
            .login(
                "admin@ph.example",
                "adminpassword123",
                &current_code(&secret),
            )
            .unwrap();
        (store, token, admin_id)
    }

    #[test]
    fn totp_matches_rfc6238_sha1_test_vector() {
        // RFC 6238 Appendix B: secret "12345678901234567890", T=59s → step 1,
        // 8-digit code 94287082 → 6-digit truncation 287082.
        assert_eq!(totp_code_at(b"12345678901234567890", 1), 287_082);
    }

    #[test]
    fn bootstrap_gates_the_first_account_then_dies() {
        // No bootstrap code armed → refused outright.
        let locked = StaffStore::new();
        assert_eq!(
            locked
                .create_staff("", "anything", "a@ph.example", "adminpassword123", 4, "A")
                .unwrap_err(),
            StaffError::BootstrapLocked
        );

        // Armed: wrong code refused; right code creates the FIRST account (ADMIN).
        let store = StaffStore::new().with_bootstrap_code("right-code");
        assert_eq!(
            store
                .create_staff("", "wrong-code", "a@ph.example", "adminpassword123", 4, "A")
                .unwrap_err(),
            StaffError::Unauthorized
        );
        let (_, secret, uri) = store
            .create_staff(
                "",
                "right-code",
                "a@ph.example",
                "adminpassword123",
                StaffRole::Support as i32, // ignored on bootstrap…
                "A",
            )
            .unwrap();
        assert!(!secret.is_empty());
        assert!(uri.starts_with("otpauth://totp/"));

        // …the account is ADMIN, and the bootstrap path is now dead forever.
        let (_, _, role, _) = store
            .login("a@ph.example", "adminpassword123", &current_code(&secret))
            .unwrap();
        assert_eq!(role, StaffRole::Admin as i32);
        assert_eq!(
            store
                .create_staff("", "right-code", "b@ph.example", "adminpassword123", 1, "B")
                .unwrap_err(),
            StaffError::Unauthorized,
            "bootstrap must not work once any staff account exists"
        );
    }

    #[test]
    fn admin_creates_staff_and_rbac_gates_actions() {
        let (store, admin_token, _) = bootstrap_store();
        let (_, support_secret, _) = store
            .create_staff(
                &admin_token,
                "",
                "support@ph.example",
                "supportpassword1",
                StaffRole::Support as i32,
                "Sup",
            )
            .unwrap();
        let (support_token, _, role, _) = store
            .login(
                "support@ph.example",
                "supportpassword1",
                &current_code(&support_secret),
            )
            .unwrap();
        assert_eq!(role, StaffRole::Support as i32);

        // SUPPORT may pass an any-role gate but not an ADMIN gate…
        assert!(store.authorize(&support_token, &ALL_STAFF_ROLES).is_ok());
        assert_eq!(
            store
                .authorize(&support_token, &[StaffRole::Admin])
                .unwrap_err(),
            StaffError::Forbidden
        );
        // …and cannot create staff.
        assert_eq!(
            store
                .create_staff(
                    &support_token,
                    "",
                    "x@ph.example",
                    "anotherpassword1",
                    1,
                    "X"
                )
                .unwrap_err(),
            StaffError::Forbidden
        );
        // Duplicate email is refused.
        assert_eq!(
            store
                .create_staff(
                    &admin_token,
                    "",
                    "support@ph.example",
                    "anotherpassword1",
                    1,
                    "S2"
                )
                .unwrap_err(),
            StaffError::EmailExists
        );
    }

    #[test]
    fn login_requires_password_and_live_totp() {
        let store = StaffStore::new().with_bootstrap_code("boot");
        let (_, secret, _) = store
            .create_staff("", "boot", "a@ph.example", "adminpassword123", 4, "A")
            .unwrap();
        // Wrong password (even with the right code) → opaque failure.
        assert_eq!(
            store
                .login("a@ph.example", "wrong-password!", &current_code(&secret))
                .unwrap_err(),
            StaffError::BadCredentials
        );
        // Right password, wrong code → same opaque failure.
        assert_eq!(
            store
                .login("a@ph.example", "adminpassword123", "000000")
                .unwrap_err(),
            StaffError::BadCredentials
        );
        // Both right → session.
        assert!(store
            .login("a@ph.example", "adminpassword123", &current_code(&secret))
            .is_ok());
    }

    #[test]
    fn totp_replay_is_rejected() {
        let store = StaffStore::new().with_bootstrap_code("boot");
        let (_, secret, _) = store
            .create_staff("", "boot", "a@ph.example", "adminpassword123", 4, "A")
            .unwrap();
        let code = current_code(&secret);
        assert!(store
            .login("a@ph.example", "adminpassword123", &code)
            .is_ok());
        // The SAME code again is a replay — refused even with the right password.
        assert_eq!(
            store
                .login("a@ph.example", "adminpassword123", &code)
                .unwrap_err(),
            StaffError::BadCredentials
        );
    }

    #[test]
    fn repeated_wrong_sign_ins_are_rate_limited() {
        let store = StaffStore::new().with_bootstrap_code("boot");
        let (_, secret, _) = store
            .create_staff("", "boot", "a@ph.example", "adminpassword123", 4, "A")
            .unwrap();
        let (max_fails, _) = login_throttle_params();
        for _ in 0..max_fails {
            assert_eq!(
                store
                    .login("a@ph.example", "wrong-password!", "000000")
                    .unwrap_err(),
                StaffError::BadCredentials
            );
        }
        // Locked: even correct credentials are refused until the window passes.
        assert_eq!(
            store
                .login("a@ph.example", "adminpassword123", &current_code(&secret))
                .unwrap_err(),
            StaffError::TooManyAttempts
        );
    }

    #[test]
    fn guardian_and_staff_token_namespaces_are_isolated() {
        // A live GUARDIAN session must authorize ZERO staff RPCs…
        let accounts = AccountStore::new();
        accounts
            .create_account("parent@example.com", "password123", "P")
            .unwrap();
        let (guardian_token, _, _) = accounts.login("parent@example.com", "password123").unwrap();
        let (staff_store, staff_token, _) = bootstrap_store();
        assert_eq!(
            staff_store
                .authorize(&guardian_token, &ALL_STAFF_ROLES)
                .unwrap_err(),
            StaffError::Unauthorized
        );
        // …and a live STAFF session resolves to no guardian account.
        assert!(accounts.account_for_session(&staff_token).is_none());
        assert!(accounts.guardian_scope(&staff_token).is_none());
    }

    #[test]
    fn staff_persist_and_reload_across_restart() {
        let dir = tmp_dir("reload");
        let s1 = StaffStore::with_state_dir(&dir)
            .unwrap()
            .with_bootstrap_code("boot");
        let (_, secret, _) = s1
            .create_staff("", "boot", "a@ph.example", "adminpassword123", 4, "A")
            .unwrap();
        let (token, _, _, _) = s1
            .login("a@ph.example", "adminpassword123", &current_code(&secret))
            .unwrap();

        // At rest: Argon2id PHC + token DIGEST only (the raw bearer token never
        // touches disk). The TOTP secret is present by necessity — documented.
        let on_disk = std::fs::read_to_string(dir.join("staff.json")).unwrap();
        assert!(
            !on_disk.contains(&token),
            "raw staff token must never touch disk"
        );
        assert!(on_disk.contains(&token_hash(&token)));
        assert!(on_disk.contains("$argon2id$"));
        assert!(!on_disk.contains("adminpassword123"));

        drop(s1); // simulate a restart
        let s2 = StaffStore::with_state_dir(&dir).unwrap();
        // The session survives (until its short TTL)…
        assert!(s2.authorize(&token, &[StaffRole::Admin]).is_ok());
        // …and a WRONG code still fails opaquely (credentials reloaded).
        assert_eq!(
            s2.login("a@ph.example", "adminpassword123", "000000")
                .unwrap_err(),
            StaffError::BadCredentials
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_chain_appends_and_detects_tamper() {
        let (store, _token, admin_id) = bootstrap_store();
        // bootstrap_store produced staff.create + staff.login entries.
        assert!(store.verify_audit_chain());
        let (entries, _, chain_ok) = store.query_audit(0, 0);
        assert!(chain_ok);
        assert!(entries.iter().any(|e| e.action == "staff.create"));
        assert!(entries
            .iter()
            .any(|e| e.action == "staff.login" && e.staff_id == admin_id));

        // Tamper with an early entry → the chain breaks from that point on.
        {
            let mut audit = store.audit.lock().unwrap();
            audit.entries[0].action = "edited".to_string();
        }
        assert!(!store.verify_audit_chain());
        let (_, _, chain_ok) = store.query_audit(0, 0);
        assert!(!chain_ok, "tampering must surface on every read");
    }

    #[test]
    fn audit_query_paginates_by_seq() {
        let (store, _token, _) = bootstrap_store();
        for i in 0..5 {
            store.audit_append("staff-x", 4, "test.action", &format!("t{i}"), "");
        }
        let (page1, next, ok) = store.query_audit(0, 3);
        assert!(ok);
        assert_eq!(page1.len(), 3);
        let (page2, _, _) = store.query_audit(next, 100);
        assert_eq!(page2.first().map(|e| e.seq), Some(next));
        // seq is dense and strictly increasing across the chain.
        assert!(page1.windows(2).all(|w| w[1].seq == w[0].seq + 1));
    }

    #[tokio::test]
    async fn rpc_bootstrap_login_regions_and_audit_gate() {
        let store = StaffStore::new().with_bootstrap_code("boot");
        let svc = StaffAdminService::new(
            store.clone(),
            vec![StaticRegion {
                region: "uk".into(),
                endpoint: "lon.example:8443".into(),
            }],
        );

        // Bootstrap-create over the RPC surface.
        let ack = svc
            .create_staff(Request::new(CreateStaffRequest {
                token: String::new(),
                bootstrap_code: "boot".into(),
                email: "root@ph.example".into(),
                password: "adminpassword123".into(),
                display_name: "Root".into(),
                role: StaffRole::Admin as i32,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(ack.created);
        assert!(!ack.totp_secret_base32.is_empty());

        // Login with password + TOTP.
        let sess = svc
            .staff_login(Request::new(StaffLoginRequest {
                email: "root@ph.example".into(),
                password: "adminpassword123".into(),
                totp_code: current_code(&ack.totp_secret_base32),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(sess.role, StaffRole::Admin as i32);

        // Content-free region read (any role).
        let regions = svc
            .list_regions(Request::new(RegionsRequest {
                token: sess.token.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(regions.regions.len(), 1);
        assert_eq!(regions.regions[0].region, "uk");
        // No live source attached → honest static default (increment-4 probing off).
        assert!(!regions.regions[0].probed);

        // Unknown region → NOT_FOUND.
        let err = svc
            .get_fleet_health(Request::new(FleetHealthRequest {
                token: sess.token.clone(),
                region: "nope".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Audit query: works for ADMIN, chain intact, actions recorded.
        let page = svc
            .query_staff_audit(Request::new(StaffAuditQuery {
                token: sess.token.clone(),
                after_seq: 0,
                limit: 0,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(page.chain_ok);
        assert!(page.entries.iter().any(|e| e.action == "staff.create"));
        assert!(page
            .entries
            .iter()
            .any(|e| e.action == "fleet.list_regions"));

        // A garbage token is unauthenticated everywhere.
        let err = svc
            .list_regions(Request::new(RegionsRequest {
                token: "not-a-token".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn parse_regions_handles_good_and_garbage() {
        let v = parse_regions("uk=lon:8443, us = nyc:8443 ,bad,=x,y=");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].region, "uk");
        assert_eq!(v[1].endpoint, "nyc:8443");
    }

    #[tokio::test]
    async fn fleet_health_joins_live_data_for_the_local_region_only() {
        use crate::wg_provision::WgPeerStore;

        let (store, _token, _) = bootstrap_store();
        // A guardian account with one paired (enrolled) device → device count 1.
        let accounts = AccountStore::new();
        accounts
            .create_account("p@x.com", "password123", "P")
            .unwrap();
        let (gtoken, _, _) = accounts.login("p@x.com", "password123").unwrap();
        let (code, _) = accounts.create_pair_code(&gtoken, "Kid").unwrap();
        accounts.redeem_pair_code(&code, "dev-1").unwrap();
        // A WG peer store with one enrolled peer → peer count 1. A canonical
        // 44-char base64 of 32 bytes (data_encoding's decoder is strict).
        let wg = WgPeerStore::new();
        wg.register_peer("dev-1", &data_encoding::BASE64.encode(&[1u8; 32]))
            .unwrap();
        // This node's cluster (live HealthStatus source).
        let cluster = std::sync::Arc::new(bulwark_cluster::Cluster::new(
            bulwark_cluster::ClusterConfig::default(),
        ));

        let svc = StaffAdminService::new(
            store.clone(),
            vec![
                StaticRegion {
                    region: "uk".into(),
                    endpoint: "lon.example:8443".into(),
                },
                StaticRegion {
                    region: "us".into(),
                    endpoint: "nyc.example:8443".into(),
                },
            ],
        )
        .with_accounts(accounts.clone())
        .with_wg_peers(wg)
        .with_cluster(cluster)
        .with_local_region("uk", 1_900_000_000_000);

        let token = login_role(&store, &_token, "op@ph.example", StaffRole::Operator);

        // The LOCAL region ("uk") is probed live: healthy, counts, cert expiry.
        let regions = svc
            .list_regions(Request::new(RegionsRequest {
                token: token.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        let uk = regions.regions.iter().find(|r| r.region == "uk").unwrap();
        assert!(uk.probed, "local region must be probed live");
        assert!(uk.healthy, "a fresh cluster accepts work");
        assert_eq!(uk.wg_peer_count, 1);
        assert_eq!(uk.enrolled_device_count, 1);
        assert_eq!(uk.tls_cert_expiry_ts, 1_900_000_000_000);
        assert!(!uk.deploy_version.is_empty());

        // A NON-local region ("us") has no live snapshot → honest static default.
        let us = regions.regions.iter().find(|r| r.region == "us").unwrap();
        assert!(!us.probed);
        assert_eq!(us.wg_peer_count, 0);
        assert_eq!(us.enrolled_device_count, 0);
        assert_eq!(us.tls_cert_expiry_ts, 0);

        // GetFleetHealth on the local region carries the live per-node HealthStatus.
        let fh = svc
            .get_fleet_health(Request::new(FleetHealthRequest {
                token: token.clone(),
                region: "uk".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(fh.info.unwrap().probed);
        assert_eq!(fh.nodes.len(), 1, "local node HealthStatus joined");
        assert!(fh.nodes[0].accepting_work);

        // A non-local region's health has no node snapshots.
        let fh_us = svc
            .get_fleet_health(Request::new(FleetHealthRequest {
                token,
                region: "us".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!fh_us.info.unwrap().probed);
        assert!(fh_us.nodes.is_empty());
    }

    /// Sign in a fresh staff account of `role` (created by an ADMIN) over the
    /// store, returning its session token.
    fn login_role(store: &StaffStore, admin_token: &str, email: &str, role: StaffRole) -> String {
        let (_, secret, _) = store
            .create_staff(admin_token, "", email, "rolepassword123", role as i32, "R")
            .unwrap();
        let (token, _, _, _) = store
            .login(email, "rolepassword123", &current_code(&secret))
            .unwrap();
        token
    }

    #[tokio::test]
    async fn rpc_safety_case_workflow_rbac_and_audit() {
        use bulwark_proto::v1::Category;
        let (store, admin_token, _) = bootstrap_store();
        // A SAFETY_OFFICER (allowed) plus SUPPORT + OPERATOR (both refused).
        let safety_token = login_role(
            &store,
            &admin_token,
            "officer@ph.example",
            StaffRole::SafetyOfficer,
        );
        let support_token = login_role(
            &store,
            &admin_token,
            "support@ph.example",
            StaffRole::Support,
        );
        let operator_token = login_role(
            &store,
            &admin_token,
            "operator@ph.example",
            StaffRole::Operator,
        );
        let svc = StaffAdminService::new(store.clone(), vec![]);

        // Neither SUPPORT nor OPERATOR may open a case (least privilege — only
        // SAFETY_OFFICER + ADMIN are in SAFETY_ROLES).
        for refused in [&support_token, &operator_token] {
            let err = svc
                .open_safety_case(Request::new(OpenSafetyCaseRequest {
                    token: refused.clone(),
                    sha256: vec![1, 2, 3],
                    perceptual_hash: vec![],
                    category: Category::CsamSuspected as i32,
                    jurisdiction: "uk".into(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);
        }

        // SAFETY_OFFICER opens a case (state = OPENED, case_id assigned).
        let opened = svc
            .open_safety_case(Request::new(OpenSafetyCaseRequest {
                token: safety_token.clone(),
                sha256: vec![0xab, 0xcd],
                perceptual_hash: vec![0x01],
                category: Category::CsamSuspected as i32,
                jurisdiction: "uk".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        let case = opened.safety_case.unwrap();
        assert_eq!(case.state, SafetyCaseState::Opened as i32);
        let case_id = case.case_id.clone();
        assert!(!case_id.is_empty());

        // An invalid skip (OPENED → REPORTED_NCMEC) is FAILED_PRECONDITION.
        let err = svc
            .transition_safety_case(Request::new(TransitionSafetyCaseRequest {
                token: safety_token.clone(),
                case_id: case_id.clone(),
                new_state: SafetyCaseState::ReportedNcmec as i32,
                ncmec_reference: "x".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        // Valid step OPENED → UNDER_REVIEW.
        let moved = svc
            .transition_safety_case(Request::new(TransitionSafetyCaseRequest {
                token: safety_token.clone(),
                case_id: case_id.clone(),
                new_state: SafetyCaseState::UnderReview as i32,
                ncmec_reference: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            moved.safety_case.unwrap().state,
            SafetyCaseState::UnderReview as i32
        );

        // List (no filter) sees the case; GetSafetyCase returns it by id.
        let listed = svc
            .list_safety_cases(Request::new(ListSafetyCasesRequest {
                token: safety_token.clone(),
                state_filter: SafetyCaseState::Unspecified as i32,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.cases.len(), 1);
        let got = svc
            .get_safety_case(Request::new(GetSafetyCaseRequest {
                token: safety_token.clone(),
                case_id: case_id.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.case_id, case_id);

        // An unknown case id is NOT_FOUND.
        let err = svc
            .get_safety_case(Request::new(GetSafetyCaseRequest {
                token: safety_token.clone(),
                case_id: "nope".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Every safety action is audited (content-free) on the staff chain.
        let (entries, _, chain_ok) = store.query_audit(0, 0);
        assert!(chain_ok);
        assert!(entries.iter().any(|e| e.action == "safety_case.open"));
        assert!(entries
            .iter()
            .any(|e| e.action == "safety_case.transition" && e.target == case_id));
        // The audit detail carries the state NAME, never a hash or content.
        assert!(entries.iter().any(
            |e| e.action == "safety_case.open" && e.detail == "state=SAFETY_CASE_STATE_OPENED"
        ));
    }

    #[tokio::test]
    async fn support_only_guardian_rpcs_deny_operator_and_safety_officer() {
        // The guardian-support RPCs are SUPPORT/ADMIN only. authorize(SUPPORT_ROLES)
        // runs BEFORE the accounts.as_ref() precondition, so a service with NO
        // AccountStore still returns PermissionDenied for the wrong role (rather
        // than FailedPrecondition) — proving the role gate, not the wiring.
        let (store, admin_token, _) = bootstrap_store();
        let operator = login_role(&store, &admin_token, "op@ph.example", StaffRole::Operator);
        let officer = login_role(
            &store,
            &admin_token,
            "officer@ph.example",
            StaffRole::SafetyOfficer,
        );
        let svc = StaffAdminService::new(store.clone(), vec![]);

        for refused in [&operator, &officer] {
            let err = svc
                .trigger_guardian_reset(Request::new(TriggerGuardianResetRequest {
                    token: refused.clone(),
                    guardian_email: "p@x.com".into(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);

            let err = svc
                .unlock_guardian_account(Request::new(UnlockGuardianRequest {
                    token: refused.clone(),
                    guardian_email: "p@x.com".into(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);

            let err = svc
                .get_guardian_meta(Request::new(GuardianMetaRequest {
                    token: refused.clone(),
                    guardian_email: "p@x.com".into(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);
        }

        // SUPPORT itself passes the SUPPORT_ROLES gate (then hits the honest
        // FailedPrecondition because no AccountStore is wired) — confirming the
        // deny above is the ROLE gate, not a blanket refusal.
        let support = login_role(
            &store,
            &admin_token,
            "support@ph.example",
            StaffRole::Support,
        );
        let err = svc
            .get_guardian_meta(Request::new(GuardianMetaRequest {
                token: support,
                guardian_email: "p@x.com".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn safety_only_rpcs_deny_support_and_operator() {
        // The SafetyCase RPCs are SAFETY_OFFICER/ADMIN only. Cover list / get /
        // transition (open is already covered) — SUPPORT and OPERATOR are refused.
        let (store, admin_token, _) = bootstrap_store();
        let support = login_role(
            &store,
            &admin_token,
            "support@ph.example",
            StaffRole::Support,
        );
        let operator = login_role(&store, &admin_token, "op@ph.example", StaffRole::Operator);
        let svc = StaffAdminService::new(store.clone(), vec![]);

        for refused in [&support, &operator] {
            let err = svc
                .list_safety_cases(Request::new(ListSafetyCasesRequest {
                    token: refused.clone(),
                    state_filter: SafetyCaseState::Unspecified as i32,
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);

            let err = svc
                .get_safety_case(Request::new(GetSafetyCaseRequest {
                    token: refused.clone(),
                    case_id: "any".into(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);

            let err = svc
                .transition_safety_case(Request::new(TransitionSafetyCaseRequest {
                    token: refused.clone(),
                    case_id: "any".into(),
                    new_state: SafetyCaseState::UnderReview as i32,
                    ncmec_reference: String::new(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);
        }
    }

    #[tokio::test]
    async fn audit_chain_is_content_free() {
        use bulwark_proto::v1::Category;
        // Distinctive sentinels: if any PII/content reached the audit chain it
        // would appear verbatim. The audit must carry only ids/outcomes/state.
        const SENTINEL_EMAIL: &str = "leak-probe@example.com";
        const SENTINEL_NAME: &str = "LeakProbeName";

        let (store, admin_token, _) = bootstrap_store();
        // A guardian to act on. The guardian display-name is never stored by
        // AccountStore, so the guardian-email + content-hash are the real PII
        // vectors here; the staff display-name below is the real NAME vector.
        let accounts = AccountStore::new();
        accounts
            .create_account(SENTINEL_EMAIL, "password123", "Guardian")
            .unwrap();
        // A staff account whose DISPLAY NAME is the sentinel — create_staff DOES
        // persist it (StaffRec.display_name), yet must never write it to the
        // audit chain (staff.create records the staff_id + role only).
        store
            .create_staff(
                &admin_token,
                "",
                "named@ph.example",
                "rolepassword123",
                StaffRole::Support as i32,
                SENTINEL_NAME,
            )
            .unwrap();
        let support = login_role(
            &store,
            &admin_token,
            "support@ph.example",
            StaffRole::Support,
        );
        let officer = login_role(
            &store,
            &admin_token,
            "officer@ph.example",
            StaffRole::SafetyOfficer,
        );
        let svc = StaffAdminService::new(store.clone(), vec![]).with_accounts(accounts);

        // Run all three guardian-support RPCs against the sentinel email.
        svc.trigger_guardian_reset(Request::new(TriggerGuardianResetRequest {
            token: support.clone(),
            guardian_email: SENTINEL_EMAIL.into(),
        }))
        .await
        .unwrap();
        svc.unlock_guardian_account(Request::new(UnlockGuardianRequest {
            token: support.clone(),
            guardian_email: SENTINEL_EMAIL.into(),
        }))
        .await
        .unwrap();
        svc.get_guardian_meta(Request::new(GuardianMetaRequest {
            token: support,
            guardian_email: SENTINEL_EMAIL.into(),
        }))
        .await
        .unwrap();

        // Open a safety case with a recognizable hash — its hex must never land
        // in an audit detail either (the audit records the case id + state only).
        let sha = vec![0xde, 0xad, 0xbe, 0xef];
        let sha_hex = to_hex(&sha);
        svc.open_safety_case(Request::new(OpenSafetyCaseRequest {
            token: officer,
            sha256: sha,
            perceptual_hash: vec![],
            category: Category::CsamSuspected as i32,
            jurisdiction: "uk".into(),
        }))
        .await
        .unwrap();

        let (entries, _, chain_ok) = store.query_audit(0, 0);
        assert!(chain_ok);
        // Every audit field that could carry a free string is checked: no email,
        // no staff display name, no content hash anywhere on the chain.
        for e in &entries {
            for field in [&e.target, &e.detail, &e.staff_id, &e.action] {
                assert!(
                    !field.contains(SENTINEL_EMAIL),
                    "audit leaked guardian email in {field:?}"
                );
                assert!(
                    !field.contains(SENTINEL_NAME),
                    "audit leaked staff display name in {field:?}"
                );
                assert!(
                    !field.contains(&sha_hex),
                    "audit leaked content hash in {field:?}"
                );
            }
        }
        // And the audited actions DID run — their content-free outcomes are present.
        assert!(entries.iter().any(|e| e.action == "guardian.reset"));
        assert!(entries.iter().any(|e| e.action == "guardian.unlock"));
        assert!(entries.iter().any(|e| e.action == "guardian.meta"));
        assert!(entries.iter().any(|e| e.action == "safety_case.open"));
    }
}
