//! Windows DPAPI-backed [`CaKeyStore`] — wraps the crown-jewel CA private key
//! with `CryptProtectData` / `CryptUnprotectData` so it is **never written as
//! plaintext** (threat-model Asset 1, STRIDE-I).
//!
//! ## FFI ISOLATION NOTICE
//! This is one of only two modules in the crate that contain `unsafe` (the other
//! is the wintun TUN backend). The crate root sets `#![forbid(unsafe_code)]`;
//! this module locally lifts that with `#![allow(unsafe_code)]` and **every
//! `unsafe` block is annotated with why it is sound** (`// SAFETY:`). All FFI is
//! contained here — no `unsafe` leaks into the proxy / interceptor logic.
//!
//! ## What DPAPI gives us (and the honest limitation)
//! `CryptProtectData` encrypts a blob with a key derived from the
//! machine + user credentials; only the same user on the same machine can
//! `CryptUnprotectData` it. We store the resulting ciphertext blob on disk; the
//! raw PKCS#8 key only exists in memory transiently while we mint leaf certs.
//!
//! DPAPI is **at-rest protection**, not a hardware signer: a local attacker
//! running *as the same user* (A3) can call `CryptUnprotectData` too. The
//! stronger tier (raw key never in-process, signing inside a TPM via CNG
//! `Microsoft Platform Crypto Provider` / `NCryptSignHash`, key flagged
//! non-exportable) is documented in [`super::keystore`] as the upgrade target.
//! We pass `CRYPTPROTECT_LOCAL_MACHINE`-free (user-scoped) + an extra entropy
//! value so another app on the box can't unwrap it without the entropy.
#![allow(unsafe_code)] // FFI to DPAPI is unavoidable; isolated + documented here.

use std::path::PathBuf;

use crate::ca::keystore::{CaKeyStore, KeyStoreTier};
use crate::Result;

#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_FLAGS, CRYPT_INTEGER_BLOB,
};
#[cfg(windows)]
use windows::Win32::System::Memory::LocalFree;

/// DPAPI flags. `0` = user scope (the default we want): only the same user on
/// the same machine can unprotect. We deliberately do NOT pass
/// `CRYPTPROTECT_LOCAL_MACHINE` (that would widen decryptability to any process
/// on the box). No UI flag — this is non-interactive.
#[cfg(windows)]
const DPAPI_FLAGS: CRYPTPROTECT_FLAGS = CRYPTPROTECT_FLAGS(0);

/// Extra entropy mixed into DPAPI so that another process running as the same
/// user cannot unwrap our blob without also knowing this value. Compiled in; it
/// is NOT the secret (the user+machine key is) — it is a per-application salt.
const DPAPI_ENTROPY: &[u8] = b"aegis-net::per-install-ca::v1";

/// Filename of the wrapped (DPAPI ciphertext) CA key under the store dir.
const WRAPPED_KEY_FILE: &str = "ca-key.dpapi";

/// Filename of the public root cert (DER) under the store dir. Public — stored
/// in the clear (only the key is secret).
const PUBLIC_CERT_FILE: &str = "ca-cert.der";

/// DPAPI-backed keystore for the per-install root CA private key (Windows).
pub struct DpapiKeyStore {
    /// Directory holding the wrapped key ciphertext. The directory should be
    /// per-user (e.g. `%LOCALAPPDATA%\Aegis`) so DPAPI's user scope matches.
    dir: PathBuf,
}

impl DpapiKeyStore {
    /// Create a DPAPI keystore writing its ciphertext blob under `dir`.
    pub fn new(dir: PathBuf) -> Self {
        DpapiKeyStore { dir }
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join(WRAPPED_KEY_FILE)
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join(PUBLIC_CERT_FILE)
    }
}

impl CaKeyStore for DpapiKeyStore {
    fn tier(&self) -> KeyStoreTier {
        // At-rest wrapping by DPAPI; not an in-hardware signer.
        KeyStoreTier::OsWrappedAtRest
    }

    fn exists(&self) -> bool {
        self.key_path().exists()
    }

    fn store_key(&self, key_der: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let wrapped = protect(key_der)?;
        // Write ciphertext only. (A future hardening pass can additionally ACL
        // the file to the current user; DPAPI already binds decryptability.)
        std::fs::write(self.key_path(), wrapped)?;
        Ok(())
    }

    fn load_key(&self) -> Result<Vec<u8>> {
        let path = self.key_path();
        if !path.exists() {
            // Fail-CLOSED upstream: no key → caller must block + alert.
            return Err(crate::NetError::keystore(format!(
                "no wrapped CA key at {}",
                path.display()
            )));
        }
        let wrapped = std::fs::read(&path)?;
        unprotect(&wrapped)
    }

    fn delete_key(&self) -> Result<()> {
        let path = self.key_path();
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let cert = self.cert_path();
        if cert.exists() {
            std::fs::remove_file(&cert)?;
        }
        Ok(())
    }

    fn store_public_cert(&self, cert_der: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.cert_path(), cert_der)?;
        Ok(())
    }

    fn load_public_cert(&self) -> Result<Option<Vec<u8>>> {
        let path = self.cert_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(std::fs::read(&path)?))
    }
}

// ---------------------------------------------------------------------------
// The thin FFI core. Everything `unsafe` is here, each block justified.
// ---------------------------------------------------------------------------

/// DPAPI-encrypt `plaintext` (user scope + entropy). Windows only.
#[cfg(windows)]
fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    // CRYPT_INTEGER_BLOB points at borrowed slices we keep alive for the call.
    // The pbData field is `*mut u8` in the bindings even for input; DPAPI does
    // not mutate the input buffer, so casting our read-only slices is sound.
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: DPAPI_ENTROPY.len() as u32,
        pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `CryptProtectData` reads `in_blob`/`entropy_blob` (whose pointers
    // reference `plaintext` and `DPAPI_ENTROPY`, both alive — owned locals /
    // 'static const — for the duration of this call) and writes the allocated
    // ciphertext into `out_blob`. The input pointers are passed as `*const` per
    // the binding signature; DPAPI treats them as read-only. We pass a valid
    // zeroed out-blob; on success Windows fills it with a LocalAlloc'd buffer we
    // copy out and free below. The three blobs are distinct (no aliasing).
    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            None,                       // no description
            Some(&entropy_blob),        // additional entropy
            None,                       // reserved
            None,                       // no prompt struct (non-interactive)
            DPAPI_FLAGS,                // user scope, no UI
            &mut out_blob,
        )
    };
    ok.map_err(|e| crate::NetError::keystore(format!("CryptProtectData failed: {e}")))?;

    // SAFETY: on success `out_blob.pbData` is a valid pointer to `cbData` bytes
    // allocated by DPAPI. We copy them into an owned Vec before freeing.
    let ciphertext = unsafe {
        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
    };
    free_dpapi_blob(&out_blob);
    Ok(ciphertext)
}

/// DPAPI-decrypt `wrapped` back to the raw key bytes. Windows only.
#[cfg(windows)]
fn unprotect(wrapped: &[u8]) -> Result<Vec<u8>> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: wrapped.len() as u32,
        pbData: wrapped.as_ptr() as *mut u8,
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: DPAPI_ENTROPY.len() as u32,
        pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();

    // SAFETY: mirror of `protect`. `CryptUnprotectData` reads the borrowed
    // `in_blob`/`entropy_blob` (alive for the call) and writes a LocalAlloc'd
    // plaintext buffer into `out_blob`, which we copy and free. The entropy must
    // match the value used at protect time (it does — same 'static const). Input
    // pointers are read-only to DPAPI; the out-blob is distinct.
    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            None,                  // ppszDataDescr out (unused)
            Some(&entropy_blob),
            None,
            None,
            DPAPI_FLAGS,
            &mut out_blob,
        )
    };
    ok.map_err(|e| crate::NetError::keystore(format!("CryptUnprotectData failed: {e}")))?;

    // SAFETY: see `protect` — valid pointer/len on success; copied then freed.
    let plaintext = unsafe {
        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
    };
    free_dpapi_blob(&out_blob);
    Ok(plaintext)
}

/// Free a DPAPI output blob's `LocalAlloc`'d buffer. Windows only.
#[cfg(windows)]
fn free_dpapi_blob(blob: &CRYPT_INTEGER_BLOB) {
    if !blob.pbData.is_null() {
        // SAFETY: `pbData` was allocated by DPAPI via LocalAlloc (documented
        // contract of CryptProtectData/CryptUnprotectData); freeing it with
        // LocalFree is the matching deallocation. We only reach here once per
        // successful call and never use the pointer afterwards.
        unsafe {
            let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                blob.pbData as *mut core::ffi::c_void,
            )));
        }
    }
}

// --- Non-Windows: the type exists for doc/reference but is inert. ---

/// On non-Windows targets DPAPI is unavailable; this errors clearly. The real
/// platform keystores (Keychain / Android Keystore / TPM) are separate impls.
#[cfg(not(windows))]
fn protect(_plaintext: &[u8]) -> Result<Vec<u8>> {
    Err(crate::NetError::keystore(
        "DPAPI is Windows-only; use the platform keystore for this OS",
    ))
}

#[cfg(not(windows))]
fn unprotect(_wrapped: &[u8]) -> Result<Vec<u8>> {
    Err(crate::NetError::keystore(
        "DPAPI is Windows-only; use the platform keystore for this OS",
    ))
}
