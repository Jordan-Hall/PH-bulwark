//! OS trust-store install / **uninstall** for the per-install root CA.
//!
//! Decrypting HTTPS requires our root to be trusted by the device. This module
//! installs the root into the OS trust store and — critically — removes it again
//! on uninstall.
//!
//! ## Per-OS backends
//!   * **Windows** — the **Trusted Root Certification Authorities** store via the
//!     `windows` crate cert-store API (isolated FFI below), with a `certutil`
//!     fallback.
//!   * **Linux** — the **system CA store**: write the PEM into
//!     `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
//!     (uninstall removes the file and runs `update-ca-certificates --fresh` to
//!     prune the orphaned `/etc/ssl/certs` symlink — a clean reversal). Browser
//!     (NSS) trust is the documented `certutil -d sql:$HOME/.pki/nssdb` path; its
//!     argv is built + unit-tested but executed per-user-profile out of band.
//!   * **macOS** — the **system/login keychain** via
//!     `security add-trusted-cert -d -r trustRoot -k <keychain>` / the matching
//!     `security remove-trusted-cert -d`.
//!
//! Runtime execution of the Linux/macOS paths is **device-validated later** (CI +
//! the dev host here are Windows/Linux build-only); the command construction is
//! unit-tested on every host so the argv cannot silently drift.
//!
//! ## Why uninstall is a release-blocker (threat-model Asset 1)
//! An orphaned root left in the trust store after uninstall is a **latent TLS inspection
//! backdoor**: anyone holding the (now-deleted) key, or who later recovers it,
//! could impersonate any site to this device. The threat model marks "uninstall
//! removes the root" as a release-blocker test case. [`uninstall_root`] therefore
//! exists and is wired into the [`Interceptor::shutdown`](crate::Interceptor)
//! teardown path's documentation.
//!
//! ## Windows backends (detail)
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

// --- Linux: system CA store via update-ca-certificates ----------------------
//
// SYSTEM scope copies the PEM into `/usr/local/share/ca-certificates/<file>.crt`
// and runs `update-ca-certificates`, which (re)builds the bundle in
// `/etc/ssl/certs` and the per-cert symlinks. Uninstall removes the file and runs
// `update-ca-certificates --fresh`, which rebuilds from scratch and so prunes the
// now-orphaned symlink — a clean reversal (release-blocker; see module docs).
//
// Browser trust (Chromium/Firefox use their own NSS DB, not the system bundle) is
// the documented NSS path: `certutil -d sql:$HOME/.pki/nssdb -A -n <name> -t C,,
// -i <pem>` to add and `-D -n <name>` to remove. We build + unit-test that argv
// via [`linux_nss_add_argv`]/[`linux_nss_remove_argv`] but do not execute it here
// (per-user browser profiles are out of scope for the system-scope installer).
//
// `LINUX_CA_DIR` / the cert filename are stable so install + uninstall agree.
#[cfg(any(target_os = "linux", test))]
const LINUX_CA_DIR: &str = "/usr/local/share/ca-certificates";
/// Filename (under [`LINUX_CA_DIR`]) for our root. `.crt` is required —
/// `update-ca-certificates` only picks up `*.crt` files.
#[cfg(any(target_os = "linux", test))]
const LINUX_CA_FILE: &str = "bulwark-root-ca.crt";
/// Nickname used for the NSS DB entry (documented browser-trust path).
/// Test-only: the NSS argv is built + unit-tested but not executed by the
/// system-scope installer, so it has no non-test caller on the Linux lib build.
#[cfg(test)]
const NSS_NICKNAME: &str = "PH Bulwark Root CA";

/// Path the Linux system-scope installer writes the PEM to.
#[cfg(any(target_os = "linux", test))]
fn linux_ca_path() -> std::path::PathBuf {
    std::path::Path::new(LINUX_CA_DIR).join(LINUX_CA_FILE)
}

/// argv for the system-store refresh after writing/removing the PEM.
/// `fresh = true` (used on uninstall) rebuilds from scratch so a removed cert's
/// symlink in `/etc/ssl/certs` is pruned — without it the old trust can linger.
#[cfg(any(target_os = "linux", test))]
fn linux_update_ca_argv(fresh: bool) -> Vec<String> {
    let mut v = vec!["update-ca-certificates".to_string()];
    if fresh {
        v.push("--fresh".to_string());
    }
    v
}

/// argv to add our root to the per-user NSS DB (Chromium/Firefox browser trust).
/// Documented path — built + tested but not executed by the system installer, so
/// it is `cfg(test)` only (no non-test caller → would be dead_code on the lib build).
#[cfg(test)]
fn linux_nss_add_argv(nssdb: &str, pem_path: &str) -> Vec<String> {
    vec![
        "certutil".to_string(),
        "-d".to_string(),
        format!("sql:{nssdb}"),
        "-A".to_string(),
        "-n".to_string(),
        NSS_NICKNAME.to_string(),
        "-t".to_string(),
        "C,,".to_string(),
        "-i".to_string(),
        pem_path.to_string(),
    ]
}

/// argv to remove our root from the per-user NSS DB (reverses [`linux_nss_add_argv`]).
/// `cfg(test)` only — see [`linux_nss_add_argv`].
#[cfg(test)]
fn linux_nss_remove_argv(nssdb: &str) -> Vec<String> {
    vec![
        "certutil".to_string(),
        "-d".to_string(),
        format!("sql:{nssdb}"),
        "-D".to_string(),
        "-n".to_string(),
        NSS_NICKNAME.to_string(),
    ]
}

#[cfg(target_os = "linux")]
pub fn install_root(cert_der: &[u8], scope: StoreScope) -> Result<()> {
    if scope != StoreScope::LocalMachine {
        // The system CA store is machine-wide; there is no per-user system store
        // on Linux (browser trust is the NSS path, documented above).
        return Err(NetError::unsupported(
            "Linux trust-store install supports LocalMachine (system) scope only; \
             per-user browser trust is the documented NSS path",
        ));
    }
    let pem = der_to_pem(cert_der);
    let path = linux_ca_path();
    std::fs::write(&path, pem)
        .map_err(|e| NetError::trust_store(format!("writing {}: {e}", path.display())))?;
    let argv = linux_update_ca_argv(false);
    run_trust_cmd(&argv)?;
    tracing::info!(
        path = %path.display(),
        "installed per-install root CA into the Linux system trust store (update-ca-certificates)"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall_root(_cert_der: &[u8], scope: StoreScope) -> Result<()> {
    if scope != StoreScope::LocalMachine {
        return Err(NetError::unsupported(
            "Linux trust-store uninstall supports LocalMachine (system) scope only",
        ));
    }
    let path = linux_ca_path();
    // Removing the file is not fatal if it is already gone (idempotent teardown).
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(path = %path.display(), "root CA file already absent on uninstall");
        }
        Err(e) => {
            return Err(NetError::trust_store(format!(
                "removing {}: {e}",
                path.display()
            )))
        }
    }
    // `--fresh` rebuilds the bundle + symlinks from scratch, pruning the orphaned
    // symlink left in /etc/ssl/certs (a plain run would not). Clean reversal.
    let argv = linux_update_ca_argv(true);
    run_trust_cmd(&argv)?;
    tracing::info!("removed per-install root CA from the Linux system trust store");
    Ok(())
}

// --- macOS: system/login keychain via the `security` tool -------------------
//
// Scope decides BOTH the trust domain (`-d` = admin/system domain, needs sudo;
// omitted = the per-user domain, no sudo) AND the keychain (`-k`):
//   * LocalMachine → `add-trusted-cert -d  -r trustRoot -k System.keychain` (admin).
//   * CurrentUser  → `add-trusted-cert     -r trustRoot -k login.keychain-db` (no admin;
//     mirrors Windows `CurrentUser` = HKCU = no UAC).
// `-r trustRoot` marks our root a trusted anchor. Uninstall reverses symmetrically:
// `remove-trusted-cert [-d] <pem>` with the SAME domain flag, so a per-user install
// is removed from the per-user domain (not left orphaned in the admin domain). The
// cert file is required for removal too, so we re-write the PEM to disk for teardown.
//
// Orphaned-root note: `remove-trusted-cert` removes the *trust setting*, which is
// what closes the latent TLS-inspection path (the root can no longer validate a
// forged leaf) — that satisfies the release-blocker. A copy of the cert may remain
// in the keychain as an UNtrusted entry; removing that artifact entirely (e.g.
// `security delete-certificate`) is a documented follow-up, not a trust risk.
#[cfg(any(target_os = "macos", test))]
const MACOS_SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
/// Filename for the PEM we write to a temp dir for the `security` calls.
#[cfg(target_os = "macos")]
const MACOS_CA_FILE: &str = "bulwark-root-ca.pem";

/// Keychain path for the given scope (login keychain resolved at runtime).
#[cfg(target_os = "macos")]
fn macos_keychain(scope: StoreScope) -> String {
    match scope {
        StoreScope::LocalMachine => MACOS_SYSTEM_KEYCHAIN.to_string(),
        // The user's login keychain. `security` resolves the bare name against the
        // current user's search list; the conventional path also works.
        StoreScope::CurrentUser => match std::env::var("HOME") {
            Ok(home) => format!("{home}/Library/Keychains/login.keychain-db"),
            Err(_) => "login.keychain".to_string(),
        },
    }
}

/// argv to add our root as a trusted root. `LocalMachine` adds `-d` (admin/system
/// trust domain, needs sudo); `CurrentUser` omits it (per-user domain, no sudo —
/// mirroring the Windows `CurrentUser` = HKCU, no-UAC contract).
#[cfg(any(target_os = "macos", test))]
fn macos_add_argv(scope: StoreScope, keychain: &str, pem_path: &str) -> Vec<String> {
    let mut v = vec!["security".to_string(), "add-trusted-cert".to_string()];
    if scope == StoreScope::LocalMachine {
        v.push("-d".to_string());
    }
    v.extend([
        "-r".to_string(),
        "trustRoot".to_string(),
        "-k".to_string(),
        keychain.to_string(),
        pem_path.to_string(),
    ]);
    v
}

/// argv to remove our trusted root (reverses [`macos_add_argv`]). Uses the SAME
/// trust-domain flag as install for the scope, so a per-user install is removed
/// from the per-user domain and an admin install from the admin domain — never
/// left orphaned in the wrong domain. The cert file identifies which cert to remove.
#[cfg(any(target_os = "macos", test))]
fn macos_remove_argv(scope: StoreScope, pem_path: &str) -> Vec<String> {
    let mut v = vec!["security".to_string(), "remove-trusted-cert".to_string()];
    if scope == StoreScope::LocalMachine {
        v.push("-d".to_string());
    }
    v.push(pem_path.to_string());
    v
}

#[cfg(target_os = "macos")]
pub fn install_root(cert_der: &[u8], scope: StoreScope) -> Result<()> {
    let pem = der_to_pem(cert_der);
    let path = std::env::temp_dir().join(MACOS_CA_FILE);
    std::fs::write(&path, pem)
        .map_err(|e| NetError::trust_store(format!("writing {}: {e}", path.display())))?;
    let keychain = macos_keychain(scope);
    let pem_path = path.to_string_lossy().into_owned();
    let argv = macos_add_argv(scope, &keychain, &pem_path);
    let res = run_trust_cmd(&argv);
    let _ = std::fs::remove_file(&path);
    res?;
    tracing::info!(
        keychain = %keychain,
        "installed per-install root CA into the macOS keychain (security add-trusted-cert)"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall_root(cert_der: &[u8], scope: StoreScope) -> Result<()> {
    // `security remove-trusted-cert` needs the cert file, so re-materialise the PEM.
    let pem = der_to_pem(cert_der);
    let path = std::env::temp_dir().join(MACOS_CA_FILE);
    std::fs::write(&path, pem)
        .map_err(|e| NetError::trust_store(format!("writing {}: {e}", path.display())))?;
    let pem_path = path.to_string_lossy().into_owned();
    let argv = macos_remove_argv(scope, &pem_path);
    let res = run_trust_cmd(&argv);
    let _ = std::fs::remove_file(&path);
    res?;
    tracing::info!(
        "removed per-install root CA from the macOS keychain (security remove-trusted-cert)"
    );
    Ok(())
}

// --- Other (non-Windows, non-Linux, non-macOS): documented stub -------------

/// Android trusts the inspection CA via Device Owner provisioning, not this
/// module; other targets have no desktop trust store. We error rather than
/// silently pretend to install (orphaned-root honesty).
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn install_root(_cert_der: &[u8], _scope: StoreScope) -> Result<()> {
    Err(NetError::unsupported(
        "trust-store install not implemented for this OS (Android uses Device-Owner CA provisioning)",
    ))
}

/// See [`install_root`] for the per-OS uninstall commands.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn uninstall_root(_cert_der: &[u8], _scope: StoreScope) -> Result<()> {
    Err(NetError::unsupported(
        "trust-store uninstall not implemented for this OS",
    ))
}

/// Standard base64 alphabet (RFC 4648) for PEM armor. Local + tiny so we add no
/// new crate dependency just to wrap a cert.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Minimal standard-base64 encoder (with `=` padding). Used only to PEM-armor a
/// DER certificate; not performance-critical.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = *chunk.get(1).unwrap_or(&0) as usize;
        let b2 = *chunk.get(2).unwrap_or(&0) as usize;
        out.push(B64_ALPHABET[b0 >> 2] as char);
        out.push(B64_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Wrap a DER-encoded certificate in PEM armor (`-----BEGIN CERTIFICATE-----`).
/// Linux/macOS trust tools take PEM on disk; we generate it from the DER we hold.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn der_to_pem(cert_der: &[u8]) -> String {
    let b64 = base64_encode(cert_der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    // PEM wraps base64 at 64 columns.
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Run a trust-store command (argv[0] = program). Shared by the Linux + macOS
/// install/uninstall paths so failures are uniform. Captures stderr/stdout into
/// the error message. Never `unsafe`; pure `std::process::Command`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_trust_cmd(argv: &[String]) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| NetError::trust_store("empty command".to_string()))?;
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| NetError::trust_store(format!("spawning `{program}`: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(NetError::trust_store(format!(
            "`{}` failed ({}): {}",
            argv.join(" "),
            output.status,
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            }
        )))
    }
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

    // Only the genuinely-unimplemented targets (not Windows/Linux/macOS, e.g. the
    // `not(any(...))` stub) must still report Unsupported. Gating this `not(any(...))`
    // is critical: on a Linux/macOS CI runner the stub is gone, so calling
    // `install_root` there would shell out instead of returning Unsupported and the
    // assertion would (wrongly) break the build.
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    #[test]
    fn unimplemented_os_install_is_unsupported_not_silent() {
        // Honesty: we error rather than pretend to install on an unsupported OS.
        let err = install_root(b"der", StoreScope::CurrentUser).unwrap_err();
        assert!(matches!(err, NetError::Unsupported(_)));
        let err = uninstall_root(b"der", StoreScope::CurrentUser).unwrap_err();
        assert!(matches!(err, NetError::Unsupported(_)));
    }

    // --- Command-construction tests (host-agnostic; the argv builders are cfg'd
    // `any(... , test)` so they compile + run on this Windows host too). These lock
    // the exact argv/flags the OS trust tools require; runtime execution is
    // device-validated later. ---

    #[test]
    fn der_to_pem_round_trips_armor() {
        // Three bytes -> exactly four base64 chars, wrapped in PEM armor.
        let pem = der_to_pem(&[0x00, 0x01, 0x02]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
        assert!(pem.contains("AAEC")); // base64 of 00 01 02
    }

    #[test]
    fn base64_encode_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn linux_update_ca_argv_install_vs_uninstall() {
        // Install runs the plain refresh; uninstall MUST pass --fresh so the
        // orphaned /etc/ssl/certs symlink is pruned (clean reversal).
        assert_eq!(linux_update_ca_argv(false), vec!["update-ca-certificates"]);
        assert_eq!(
            linux_update_ca_argv(true),
            vec!["update-ca-certificates", "--fresh"]
        );
    }

    #[test]
    fn linux_ca_path_is_a_dot_crt_under_the_system_dir() {
        let p = linux_ca_path();
        assert!(p.starts_with(LINUX_CA_DIR));
        // update-ca-certificates only ingests *.crt files.
        assert_eq!(p.extension().and_then(|e| e.to_str()), Some("crt"));
    }

    #[test]
    fn linux_nss_argv_add_and_remove() {
        let add = linux_nss_add_argv("/home/kid/.pki/nssdb", "/tmp/root.pem");
        assert_eq!(
            add,
            vec![
                "certutil",
                "-d",
                "sql:/home/kid/.pki/nssdb",
                "-A",
                "-n",
                NSS_NICKNAME,
                "-t",
                "C,,",
                "-i",
                "/tmp/root.pem",
            ]
        );
        let rm = linux_nss_remove_argv("/home/kid/.pki/nssdb");
        assert_eq!(
            rm,
            vec![
                "certutil",
                "-d",
                "sql:/home/kid/.pki/nssdb",
                "-D",
                "-n",
                NSS_NICKNAME,
            ]
        );
    }

    #[test]
    fn macos_add_argv_local_machine_uses_admin_domain() {
        let argv = macos_add_argv(
            StoreScope::LocalMachine,
            MACOS_SYSTEM_KEYCHAIN,
            "/tmp/root.pem",
        );
        assert_eq!(
            argv,
            vec![
                "security",
                "add-trusted-cert",
                "-d", // admin/system trust domain
                "-r",
                "trustRoot",
                "-k",
                MACOS_SYSTEM_KEYCHAIN,
                "/tmp/root.pem",
            ]
        );
    }

    #[test]
    fn macos_add_argv_current_user_omits_admin_domain() {
        // CurrentUser must NOT pass -d (that would require sudo), mirroring the
        // Windows CurrentUser = HKCU, no-UAC contract.
        let argv = macos_add_argv(
            StoreScope::CurrentUser,
            "login.keychain-db",
            "/tmp/root.pem",
        );
        assert_eq!(
            argv,
            vec![
                "security",
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-k",
                "login.keychain-db",
                "/tmp/root.pem",
            ]
        );
        assert!(!argv.iter().any(|a| a == "-d"));
    }

    #[test]
    fn macos_remove_argv_reverses_install_in_the_same_domain() {
        // Each scope's removal carries the SAME domain flag as its install, so a
        // per-user install is removed from the per-user domain and an admin install
        // from the admin domain — never orphaned in the wrong domain.
        assert_eq!(
            macos_remove_argv(StoreScope::LocalMachine, "/tmp/root.pem"),
            vec!["security", "remove-trusted-cert", "-d", "/tmp/root.pem"]
        );
        assert_eq!(
            macos_remove_argv(StoreScope::CurrentUser, "/tmp/root.pem"),
            vec!["security", "remove-trusted-cert", "/tmp/root.pem"]
        );
    }
}
