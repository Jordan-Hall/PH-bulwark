//! Linux **TPM 2.0** CA-key sealing — scaffold + the real call sequence,
//! `device-validated-later`.
//!
//! ## Status (honest)
//! This module is a **documented scaffold**, NOT a host-verified code path. The
//! shipping/tested Linux fallback is [`super::enc_file::EncryptedFileKeyStore`]
//! (AES-256-GCM at rest). [`select_linux_keystore`] returns that fallback today;
//! the TPM path here describes exactly what the hardware-backed impl does and is
//! validated on a TPM-equipped device in a later increment (issue #141 is
//! explicitly multi-week + needs device testing).
//!
//! ## Why scaffold, not a live `tss-esapi` dep
//! The mature Rust TPM 2.0 binding is `tss-esapi`, which links the **system C
//! library `tpm2-tss`** at build time. That:
//!   * is a build-time *system* dependency (won't compile on this Windows CI
//!     host, and would need `libtss2-*` on the Linux image), and
//!   * is `tss-esapi` itself (BSD-3-Clause, permissive — acceptable) but wraps a
//!     `tpm2-tss` C lib (BSD-2/3-Clause — also permissive), so the LICENSE is
//!     fine; the blocker is purely the **system-lib build dep + non-host-
//!     verifiability**, not copyleft.
//!
//! When we add it, gate it behind a non-default `tpm` feature so the default
//! build (and non-Linux targets) never pull the system-lib dep.
//!
//! ## The real sealing sequence (what the live impl will do)
//! With a TPM the CA key is **sealed to the TPM** so the wrapping secret is held
//! by hardware and is NEVER on disk — that is the genuine
//! [`KeyStoreTier::HardwareNonExportable`] / `OsWrappedAtRest` upgrade the
//! encrypted-file fallback explicitly is not.
//!
//! `store_key(key_der)` (via the `tss-esapi` `Context`):
//!   1. `Context::new(TctiNameConf::from_environment_variable()?)` — connect to
//!      the system TPM (`/dev/tpmrm0` resource manager).
//!   2. Create / load a primary key in the **Owner** hierarchy (a restricted
//!      decrypt parent) — persisted at a stable handle so restarts reuse it.
//!   3. `create` a **keyedhash sealed data object** whose sensitive `data` is the
//!      CA PKCS#8 DER, under that parent, with an auth policy (optionally bound
//!      to PCRs so the key only unseals in a known-good boot state).
//!   4. Persist the returned `(public, private)` blobs to disk — these are
//!      TPM-wrapped; the unsealing secret never leaves the chip.
//!
//! `load_key()`:
//!   1. Reconnect + reload the primary parent.
//!   2. `load` the sealed object from the stored `(public, private)` blobs.
//!   3. `unseal` it (satisfying the auth policy / PCRs) → CA PKCS#8 DER for the
//!      transient in-process signer.
//!
//! `delete_key()` evicts the persistent parent handle + removes the on-disk
//! TPM-wrapped blobs.
//!
//! NOTE on the strongest tier: the *ideal* posture signs INSIDE the TPM (the raw
//! key never re-enters our address space). `rcgen` needs an in-process signer, so
//! even the TPM tier unseals transiently to mint leaves until a TPM/PKCS#11
//! signer is wired into leaf minting — same honest limitation documented in
//! [`super::keystore`].

use std::path::PathBuf;
use std::sync::Arc;

use super::enc_file::EncryptedFileKeyStore;
use super::keystore::CaKeyStore;

/// Select the Linux production CA keystore.
///
/// Today: the AES-256-GCM [`EncryptedFileKeyStore`] (no-TPM fallback) — a real,
/// host-tested code path. When the `tpm` feature + device validation land, this
/// returns a `Tpm2KeyStore` if a TPM is present and falls back to the encrypted
/// file otherwise. Returning an `Arc<dyn CaKeyStore>` keeps that future swap a
/// one-line change with no call-site churn.
pub fn select_linux_keystore(dir: PathBuf) -> Arc<dyn CaKeyStore> {
    // device-validated-later: probe for /dev/tpmrm0 + seal under the TPM here.
    Arc::new(EncryptedFileKeyStore::new(dir))
}
