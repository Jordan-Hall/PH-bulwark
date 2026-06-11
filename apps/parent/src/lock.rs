//! App-lock: the "stay logged in, unlock fast" layer that sits IN FRONT of the
//! saved guardian session.
//!
//! The guardian session token already persists per-server (see
//! `servers::guardian_token`). That alone would mean anyone who opens the app on
//! this machine reaches the console. The app-lock fixes that: when a session is
//! saved, re-opening the app shows a LOCK screen, and the guardian unlocks with a
//! biometric (preferred) or a 4–6 digit PIN — NOT a full email/password re-login.
//!
//! Two honest layers:
//!
//! * **PIN — the real, implemented mechanism.** We store a salted PBKDF2-HMAC-
//!   SHA256 hash of the PIN under the app config dir (never the PIN itself).
//!   Verification is constant-time (ring's `pbkdf2::verify`). This is exactly the
//!   approach the server uses for guardian passwords (`bulwark-server/accounts`),
//!   so there is no new crypto here — `ring` is already in the build (tonic's
//!   `tls-ring`), we just declare it as a direct dependency.
//!
//! * **Biometric — a documented platform SEAM, not yet wired.** `biometric_*`
//!   below describe where Windows Hello (`UserConsentVerifier`, via `windows-rs`)
//!   and later Android `BiometricPrompt` plug in. Today they report "unavailable"
//!   so the UI ALWAYS falls back to the working PIN. The lock can never depend on
//!   biometric succeeding.
//!
//! Scope: the lock is per-INSTALL (one PIN for this Manager install), independent
//! of which server/region is selected, because it gates the whole app shell. The
//! per-server session tokens are unchanged.

use std::num::NonZeroU32;

use ring::{pbkdf2, rand::SecureRandom};

use crate::config::app_config_dir;

/// PBKDF2 parameters — mirror the server's guardian-password hashing
/// (`bulwark-server`): SHA-256, 100k iterations, 32-byte output, 16-byte salt.
/// A PIN has far less entropy than a password, so a strong KDF here is what makes
/// a local 4–6 digit PIN meaningfully resistant to an offline file grab.
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const PBKDF2_ITERS: u32 = 100_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

/// On-disk record version, so a future format change can be detected/migrated.
const RECORD_VERSION: &str = "pbkdf2-sha256-v1";

/// Where the PIN record lives: `<app_config_dir>/app_lock.txt`. One line:
/// `pbkdf2-sha256-v1:<iters>:<salt_hex>:<hash_hex>`. No PIN, ever.
pub fn lock_record_path() -> std::path::PathBuf {
    app_config_dir().join("app_lock.txt")
}

/// Is a PIN configured for this install? Drives whether re-opening the app shows
/// the Lock screen (PIN set) or goes straight in (no PIN — first run / skipped).
pub fn pin_is_set() -> bool {
    parse_record().is_some()
}

/// Minimum/maximum PIN length the UI enforces and we re-check here.
pub const PIN_MIN: usize = 4;
pub const PIN_MAX: usize = 6;

/// Validate PIN shape: 4–6 ASCII digits. Returned as `Result` so the UI can show
/// a precise inline message.
pub fn validate_pin_shape(pin: &str) -> Result<(), String> {
    let len = pin.chars().count();
    if !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN must be digits only.".to_string());
    }
    if len < PIN_MIN || len > PIN_MAX {
        return Err(format!("PIN must be {PIN_MIN} to {PIN_MAX} digits."));
    }
    Ok(())
}

/// Hash and store a new PIN (overwrites any existing one). Returns an error on a
/// bad PIN shape or a filesystem/RNG failure. The PIN is never written anywhere.
pub fn set_pin(pin: &str) -> Result<(), String> {
    validate_pin_shape(pin)?;

    let rng = ring::rand::SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| "couldn't generate a secure salt".to_string())?;

    let mut hash = [0u8; HASH_LEN];
    pbkdf2::derive(
        PBKDF2_ALG,
        NonZeroU32::new(PBKDF2_ITERS).expect("iters > 0"),
        &salt,
        pin.as_bytes(),
        &mut hash,
    );

    let record = format!(
        "{RECORD_VERSION}:{PBKDF2_ITERS}:{}:{}",
        to_hex(&salt),
        to_hex(&hash)
    );

    let path = lock_record_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("couldn't create config dir: {e}"))?;
    }
    std::fs::write(&path, record).map_err(|e| format!("couldn't save PIN record: {e}"))?;
    Ok(())
}

/// Constant-time verify of `pin` against the stored record. `false` if no PIN is
/// set or the record is malformed (fail-closed: a corrupt record never unlocks).
pub fn verify_pin(pin: &str) -> bool {
    let Some(rec) = parse_record() else {
        return false;
    };
    pbkdf2::verify(
        PBKDF2_ALG,
        NonZeroU32::new(rec.iters).unwrap_or(NonZeroU32::new(PBKDF2_ITERS).unwrap()),
        &rec.salt,
        pin.as_bytes(),
        &rec.hash,
    )
    .is_ok()
}

/// Remove the PIN record (used by "Forget PIN" / full sign-out). Idempotent.
pub fn clear_pin() -> std::io::Result<()> {
    match std::fs::remove_file(lock_record_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Biometric — platform SEAM. PIN is the real mechanism; this is where the OS
// prompt plugs in. Today it reports unavailable so the UI always offers the PIN.
// ---------------------------------------------------------------------------

/// Result of a biometric unlock attempt. `Unavailable` is the honest default on
/// every platform until the native call is wired — the UI treats it as "use the
/// PIN", never as a failure to surface scarily.
///
/// `Verified`/`Declined` are only *constructed* once the platform call is wired
/// (the Lock screen already matches on them); until then they're the documented
/// seam shape, so we allow them to be unconstructed without a warning.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BiometricOutcome {
    /// The platform verified the guardian (Windows Hello / Android BiometricPrompt).
    Verified,
    /// The guardian cancelled or the platform declined — fall back to PIN.
    Declined,
    /// No biometric hardware/enrolment, or the seam isn't wired on this build.
    Unavailable,
}

/// Whether to even SHOW the "Use biometric" affordance. While the platform call
/// is a stub this is `false`, so the lock screen leads with the PIN (the thing
/// that actually works) and doesn't promise a button that can't deliver.
///
/// SEAM: on desktop this becomes
/// `windows::Security::Credentials::UI::UserConsentVerifier::CheckAvailabilityAsync`
/// `== Available`; on Android, `BiometricManager.canAuthenticate(...) == SUCCESS`.
pub fn biometric_available() -> bool {
    // Honest default: not wired yet. Keep the PIN as the sole working unlock.
    false
}

/// Attempt a biometric unlock. SEAM — not yet wired, so it always returns
/// `Unavailable` and the caller falls back to the PIN.
///
/// SEAM (Windows Hello, desktop): call
/// `UserConsentVerifier::RequestVerificationAsync("Unlock PH Bulwark Manager")`
/// and map `UserConsentVerificationResult::Verified` -> `Verified`, anything else
/// -> `Declined`. (`windows` is already a Windows-target dependency of this app;
/// the `Security_Credentials_UI` feature is what would be enabled to call it.)
///
/// SEAM (Android, later/mobile build): drive `BiometricPrompt` across the JNI
/// bridge and map its callback to this enum.
pub fn biometric_unlock() -> BiometricOutcome {
    BiometricOutcome::Unavailable
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

struct Record {
    iters: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

/// Parse the on-disk record, or `None` if absent/malformed.
fn parse_record() -> Option<Record> {
    let raw = std::fs::read_to_string(lock_record_path()).ok()?;
    let raw = raw.trim();
    let mut parts = raw.splitn(4, ':');
    let version = parts.next()?;
    if version != RECORD_VERSION {
        return None;
    }
    let iters: u32 = parts.next()?.parse().ok()?;
    let salt = from_hex(parts.next()?)?;
    let hash = from_hex(parts.next()?)?;
    if salt.len() != SALT_LEN || hash.len() != HASH_LEN || iters == 0 {
        return None;
    }
    Some(Record { iters, salt, hash })
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Point app_config_dir at a unique temp dir for a hermetic test (it reads
    // LOCALAPPDATA / XDG_CONFIG_HOME / HOME — set LOCALAPPDATA so Windows CI and
    // the dev host both land in temp). Serialized via a mutex since they all
    // share the same process-wide env var.
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_config<T>(f: impl FnOnce() -> T) -> T {
        // Tolerate a poisoned lock: if a prior test panicked mid-body we still
        // want the env restore to run, not cascade a second failure.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("bulwark-lock-test-{}", nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let prev_local = std::env::var_os("LOCALAPPDATA");
        let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("LOCALAPPDATA", &dir);
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
        let out = f();
        match prev_local {
            Some(v) => std::env::set_var("LOCALAPPDATA", v),
            None => std::env::remove_var("LOCALAPPDATA"),
        }
        if let Some(v) = prev_xdg {
            std::env::set_var("XDG_CONFIG_HOME", v);
        }
        if let Some(v) = prev_home {
            std::env::set_var("HOME", v);
        }
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    fn nonce() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    #[test]
    fn pin_shape_rules() {
        assert!(validate_pin_shape("1234").is_ok());
        assert!(validate_pin_shape("123456").is_ok());
        assert!(validate_pin_shape("123").is_err()); // too short
        assert!(validate_pin_shape("1234567").is_err()); // too long
        assert!(validate_pin_shape("12a4").is_err()); // non-digit
        assert!(validate_pin_shape("").is_err());
    }

    #[test]
    fn set_then_verify_roundtrip_and_reject_wrong() {
        with_temp_config(|| {
            assert!(!pin_is_set());
            set_pin("4271").expect("set pin");
            assert!(pin_is_set());
            assert!(verify_pin("4271"));
            assert!(!verify_pin("0000"));
            assert!(!verify_pin("42710")); // different length
            clear_pin().expect("clear");
            assert!(!pin_is_set());
            assert!(!verify_pin("4271")); // no record -> false
        });
    }

    #[test]
    fn corrupt_record_fails_closed() {
        with_temp_config(|| {
            let path = lock_record_path();
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).unwrap();
            }
            std::fs::write(&path, "garbage:not:a:record").unwrap();
            assert!(!pin_is_set());
            assert!(!verify_pin("4271"));
        });
    }

    #[test]
    fn biometric_seam_is_honest_default() {
        assert!(!biometric_available());
        assert_eq!(biometric_unlock(), BiometricOutcome::Unavailable);
    }
}
