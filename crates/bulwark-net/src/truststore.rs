//! OS trust-store install / **uninstall** for the per-install root CA.
//!
//! Decrypting HTTPS requires our root to be trusted by the device. This module
//! installs the root into the **Windows Trusted Root Certification Authorities**
//! store and — critically — removes it again on uninstall.
//!
//! ## Why uninstall is a release-blocker (threat-model Asset 1)
//! An orphaned root left in the trust store after uninstall is a **latent MITM
//! backdoor**: anyone holding the (now-deleted) key, or who later recovers it,
//! could impersonate any site to this device. The threat model marks "uninstall
//! removes the root" as a release-blocker test case. [`uninstall_root`] therefore
//! exists and is wired into the [`Interceptor::shutdown`](crate::Interceptor)
//! teardown path's documentation.
//!
//! ## Two backends
//!   * **`windows` crate cert-store API** (`CertOpenStore` /
//!     `CertAddEncodedCertificateToStore` / `CertDeleteCertificateFromStore`) —
//!     the in-process path, isolated FFI below.
//!   * **`certutil` fallback** (`certutil -addstore Root` / `-delstore`) — shells
//!     out; no FFI, used when the in-process API is unavailable or for parity
//!     with how Bark/Net Nanny install (platform-feasibility §1). Documented; the
//!     in-process API is preferred so we control the exact store + scope.
//!
//! Installing into the *machine* store needs admin (one UAC prompt at install,
//! expected — platform-feasibility §1). The *current-user* store does not, and
//! is the safer default for a per-user install.
#![allow(unsafe_code)] // FFI to the Windows cert-store API; isolated + documented.

use crate::{NetError, Result};

/// Which trust store to target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreScope {
    /// Current user's Trusted Root store (`HKCU`). No admin needed; per-user.
    CurrentUser,
    /// Local machine's Trusted Root store (`HKLM`). Needs admin (UAC prompt).
    LocalMachine,
}

/// Install the per-install root CA (DER) into the Trusted Root store.
///
/// Idempotent at the store-query level: if the exact DER certificate is already
/// present, returns without invoking the Windows add path, avoiding repeated
/// consent prompts on every app restart. Logs the install so it is auditable
/// (threat-model Asset 6).
#[cfg(windows)]
pub fn install_root(cert_der: &[u8], scope: StoreScope) -> Result<()> {
    win::add_to_store(cert_der, scope)
}

/// Remove the per-install root CA (matched by DER) from the Trusted Root store.
/// MUST be called on uninstall — see module docs (release-blocker).
#[cfg(windows)]
pub fn uninstall_root(cert_der: &[u8], scope: StoreScope) -> Result<()> {
    win::remove_from_store(cert_der, scope)
}

// --- Non-Windows: documented stubs. Real impls are per-OS trust stores. ---

/// Linux/macOS/Android trust-store install is not implemented here yet.
/// * Linux: write the PEM into `/usr/local/share/ca-certificates` + run
///   `update-ca-certificates` (system) or NSS (`certutil -d sql:~/.pki/nssdb`)
///   for Chromium/Firefox.
/// * macOS: `security add-trusted-cert` into the System/login keychain.
/// * Android: user-CA install intent (and the documented Android-7+ limitation —
///   most apps ignore user CAs; platform-feasibility §3).
#[cfg(not(windows))]
pub fn install_root(_cert_der: &[u8], _scope: StoreScope) -> Result<()> {
    Err(NetError::unsupported(
        "trust-store install not implemented for this OS (see module docs for the per-OS path)",
    ))
}

/// See [`install_root`] for the per-OS uninstall commands. Uninstall MUST be
/// implemented before shipping on each platform (orphaned-root release-blocker).
#[cfg(not(windows))]
pub fn uninstall_root(_cert_der: &[u8], _scope: StoreScope) -> Result<()> {
    Err(NetError::unsupported(
        "trust-store uninstall not implemented for this OS — MUST exist before shipping",
    ))
}

/// `certutil`-based install fallback (documented alternative; shells out, no FFI).
/// Writes the cert to a temp file and runs `certutil -addstore Root <file>`
/// (machine) or `-user -addstore Root` (current user). Returns the command's
/// status. Kept available for parity / recovery; the in-process API is preferred.
pub fn install_root_via_certutil(cert_pem: &str, scope: StoreScope) -> Result<()> {
    let tmp = std::env::temp_dir().join("bulwark-root-ca.pem");
    std::fs::write(&tmp, cert_pem)?;
    let mut cmd = std::process::Command::new("certutil");
    if scope == StoreScope::CurrentUser {
        cmd.arg("-user");
    }
    cmd.args(["-addstore", "Root"]).arg(&tmp);
    run_certutil(cmd)?;
    let _ = std::fs::remove_file(&tmp);
    Ok(())
}

/// `certutil`-based uninstall fallback: `certutil -delstore Root <name|serial>`.
/// `identifier` is the cert CN or serial certutil matches on.
pub fn uninstall_root_via_certutil(identifier: &str, scope: StoreScope) -> Result<()> {
    let mut cmd = std::process::Command::new("certutil");
    if scope == StoreScope::CurrentUser {
        cmd.arg("-user");
    }
    cmd.args(["-delstore", "Root", identifier]);
    run_certutil(cmd)
}

fn run_certutil(mut cmd: std::process::Command) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| NetError::trust_store(format!("spawning certutil: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(NetError::trust_store(format!(
            "certutil exited with status {status}"
        )))
    }
}

// ---------------------------------------------------------------------------
// Windows cert-store FFI. All `unsafe` is contained here, each block justified.
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod win {
    use super::{NetError, Result, StoreScope};
    use windows::core::w;
    use windows::Win32::Security::Cryptography::HCERTSTORE;
    use windows::Win32::Security::Cryptography::{
        CertAddEncodedCertificateToStore, CertCloseStore, CertDeleteCertificateFromStore,
        CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertOpenStore,
        CERT_QUERY_ENCODING_TYPE, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W,
        CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, X509_ASN_ENCODING,
    };

    const PKCS_7_ASN_ENCODING: u32 = 0x0001_0000;

    fn open_root_store(scope: StoreScope) -> Result<HCERTSTORE> {
        let flags = match scope {
            StoreScope::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            StoreScope::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        };
        // SAFETY: `CertOpenStore` with `CERT_STORE_PROV_SYSTEM_W` takes a wide
        // store name (`w!("ROOT")`, a valid static NUL-terminated UTF-16 literal)
        // and the scope flags. We pass `None`/0 for the unused crypto-provider
        // and para args, which is the documented way to open a system store. The
        // returned handle is closed via `CertCloseStore` in every path below.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                windows::Win32::Security::Cryptography::CERT_OPEN_STORE_FLAGS(flags),
                Some(w!("ROOT").as_ptr() as *const core::ffi::c_void),
            )
        }
        .map_err(|e| NetError::trust_store(format!("CertOpenStore(ROOT) failed: {e}")))?;
        Ok(store)
    }

    fn close_store(store: HCERTSTORE) {
        // SAFETY: `store` is a handle returned by `CertOpenStore` and not yet
        // closed; closing it once is the matching teardown. We never use it after.
        unsafe {
            let _ = CertCloseStore(Some(store), 0);
        }
    }

    pub(super) fn add_to_store(cert_der: &[u8], scope: StoreScope) -> Result<()> {
        let store = open_root_store(scope)?;
        if contains_cert_der(store, cert_der) {
            close_store(store);
            tracing::info!("per-install root CA already present in Windows Trusted Root store");
            return Ok(());
        }
        // SAFETY: `cert_der` is a valid byte slice we keep alive for the call.
        // `CertAddEncodedCertificateToStore` copies the encoded cert into the
        // store; `CERT_STORE_ADD_REPLACE_EXISTING` makes it idempotent. We pass
        // `None` for the optional out-context (we don't need the added context).
        let res = unsafe {
            CertAddEncodedCertificateToStore(
                Some(store),
                CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING),
                cert_der,
                CERT_STORE_ADD_REPLACE_EXISTING,
                None,
            )
        };
        let result =
            res.map_err(|e| NetError::trust_store(format!("add cert to ROOT failed: {e}")));
        close_store(store);
        result?;
        tracing::info!("installed per-install root CA into Windows Trusted Root store");
        Ok(())
    }

    fn contains_cert_der(store: HCERTSTORE, cert_der: &[u8]) -> bool {
        let mut ctx: *mut windows::Win32::Security::Cryptography::CERT_CONTEXT =
            core::ptr::null_mut();
        loop {
            // SAFETY: `store` is valid and `ctx` is either null for the first call
            // or the prior context returned by the same enumerator. The API owns
            // and advances/free-tracks the prior context as documented.
            ctx = unsafe { CertEnumCertificatesInStore(store, Some(ctx as *const _)) };
            if ctx.is_null() {
                return false;
            }
            // SAFETY: a non-null `ctx` points to a live CERT_CONTEXT for this
            // iteration. We only borrow the encoded cert bytes for comparison.
            let this_der = unsafe {
                let c = &*ctx;
                std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize)
            };
            if this_der == cert_der {
                return true;
            }
        }
    }

    pub(super) fn remove_from_store(cert_der: &[u8], scope: StoreScope) -> Result<()> {
        let store = open_root_store(scope)?;
        let mut removed = false;
        // Enumerate certs, find the one whose encoded bytes match ours, delete it.
        let mut ctx: *mut windows::Win32::Security::Cryptography::CERT_CONTEXT =
            core::ptr::null_mut();
        loop {
            // SAFETY: `CertEnumCertificatesInStore` walks the store, returning the
            // next context each call (or null at the end / on error). It takes the
            // previous context and frees it internally as it advances, so we must
            // NOT free `ctx` ourselves between iterations. The handle `store` is
            // valid for the whole loop.
            ctx = unsafe { CertEnumCertificatesInStore(store, Some(ctx as *const _)) };
            if ctx.is_null() {
                break;
            }
            // SAFETY: a non-null `ctx` points to a valid CERT_CONTEXT owned by the
            // enumerator. We read its encoded cert blob (pbCertEncoded/cbCertEncoded)
            // for the lifetime of this iteration only.
            let this_der = unsafe {
                let c = &*ctx;
                std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize)
            };
            if this_der == cert_der {
                // `CertDeleteCertificateFromStore` FREES the context it is given.
                // The enumerator still owns `ctx`, so per MSDN we DUPLICATE it and
                // hand the duplicate to delete; the enumerator's own context is
                // then left intact and we stop enumerating (break).
                // SAFETY: `ctx` is a valid enumerator-owned context; duplicating
                // it yields an independently-owned context whose ownership we pass
                // to `CertDeleteCertificateFromStore`, which frees exactly that
                // duplicate. We do not reuse the duplicate afterwards.
                let dup = unsafe { CertDuplicateCertificateContext(Some(ctx)) };
                let del = unsafe { CertDeleteCertificateFromStore(dup as *const _) };
                removed = del.is_ok();
                if let Err(e) = del {
                    close_store(store);
                    return Err(NetError::trust_store(format!(
                        "deleting root from store failed: {e}"
                    )));
                }
                break;
            }
        }
        close_store(store);
        if removed {
            tracing::info!("removed per-install root CA from Windows Trusted Root store");
            Ok(())
        } else {
            // Not finding it is not fatal on uninstall (already gone), but we log
            // so a truly-orphaned root is investigated.
            tracing::warn!(
                "root CA not found in Trusted Root store during uninstall (already removed?)"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_distinct() {
        assert_ne!(StoreScope::CurrentUser, StoreScope::LocalMachine);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_install_is_unsupported_not_silent() {
        // Honesty: we error rather than pretend to install on an unsupported OS.
        let err = install_root(b"der", StoreScope::CurrentUser).unwrap_err();
        assert!(matches!(err, NetError::Unsupported(_)));
        let err = uninstall_root(b"der", StoreScope::CurrentUser).unwrap_err();
        assert!(matches!(err, NetError::Unsupported(_)));
    }
}
