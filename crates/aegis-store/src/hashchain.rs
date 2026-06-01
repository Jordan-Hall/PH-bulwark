//! Tamper-evident audit log via a SHA-256 **hash chain**.
//!
//! Each `audit_log` row stores a `row_hash` computed from the previous row's
//! hash and the row's own canonical (content-free) bytes:
//!
//! ```text
//! row_hash[0] = H( GENESIS  || canonical(row[0]) )
//! row_hash[i] = H( row_hash[i-1] || canonical(row[i]) )
//! ```
//!
//! Editing any field of a row, deleting a row, or reordering rows breaks the
//! chain at that point and every row after it: re-deriving the chain and
//! comparing against the stored `row_hash` column detects the tampering. This is
//! integrity (detection), not confidentiality — the table is *also* encrypted at
//! rest (SQLCipher / Postgres at-rest), but encryption alone would not reveal
//! an authorized-but-malicious in-place edit; the chain does.
//!
//! No secret key is required for the basic chain (it detects edits/deletes by an
//! actor who cannot also recompute the whole tail consistently *and* update
//! every dependent hash). For a stronger guarantee against an actor with write
//! access to the whole table, [`keyed_link`] supports an HMAC-style keyed chain
//! whose key lives in the OS keystore (C2) — see [`crate::crypto`].
//!
//! Uses `ring::digest` (SHA-256) — no `unsafe`, no AI/ML.

use ring::digest::{Context, SHA256};
use ring::hmac;

use crate::model::{hex_encode, AuditRow};

/// The well-known genesis hash that seeds row 0. Any fixed value works; we use
/// the SHA-256 of a domain-separation tag so it cannot collide with a real row
/// hash by construction.
pub fn genesis() -> [u8; 32] {
    let mut ctx = Context::new(&SHA256);
    ctx.update(b"aegis-store/audit-log/genesis/v1");
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Compute the `row_hash` for a row given the previous row's hash.
/// `prev_hash` is the 32-byte hash of row `i-1` (or [`genesis`] for row 0).
pub fn link(prev_hash: &[u8; 32], row: &AuditRow) -> [u8; 32] {
    let mut ctx = Context::new(&SHA256);
    ctx.update(prev_hash);
    ctx.update(&row.canonical_bytes());
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Keyed variant: HMAC-SHA256 over `prev_hash || canonical(row)`. Use when the
/// audit key (C2, OS keystore) should make the chain unforgeable even by an
/// actor with full table write access. The key never touches the data store.
pub fn keyed_link(key: &hmac::Key, prev_hash: &[u8; 32], row: &AuditRow) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 128);
    buf.extend_from_slice(prev_hash);
    buf.extend_from_slice(&row.canonical_bytes());
    let tag = hmac::sign(key, &buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Convenience: the hex string form of a row hash, as stored in the DB column.
pub fn hash_hex(hash: &[u8; 32]) -> String {
    hex_encode(hash)
}

/// Result of verifying a chain.
#[derive(Debug, Clone, PartialEq)]
pub enum Verify {
    /// The chain is intact: every stored hash matches the re-derived hash.
    Ok,
    /// Tampering detected. `index` is the first row whose stored hash did not
    /// match (an edit), or where the chain link broke (a deletion/reorder).
    Tampered {
        /// Zero-based position of the first bad row in the supplied slice.
        index: usize,
    },
}

/// Re-derive the chain over `rows` (in id order) and compare each row's
/// re-derived hash to its `stored_hashes` entry. Returns [`Verify::Tampered`] at
/// the first mismatch, else [`Verify::Ok`].
///
/// `rows[i]` must correspond to `stored_hashes[i]`; both must be in ascending
/// `id` order. A deleted row shifts the chain, so the first surviving row after
/// the gap mismatches — that is exactly the detection we want.
pub fn verify(rows: &[AuditRow], stored_hashes: &[[u8; 32]]) -> Verify {
    if rows.len() != stored_hashes.len() {
        // Length disagreement is itself evidence of a missing/extra row.
        return Verify::Tampered {
            index: rows.len().min(stored_hashes.len()),
        };
    }
    let mut prev = genesis();
    for (i, row) in rows.iter().enumerate() {
        let derived = link(&prev, row);
        if derived != stored_hashes[i] {
            return Verify::Tampered { index: i };
        }
        prev = derived;
    }
    Verify::Ok
}

/// Keyed counterpart of [`verify`].
pub fn verify_keyed(key: &hmac::Key, rows: &[AuditRow], stored_hashes: &[[u8; 32]]) -> Verify {
    if rows.len() != stored_hashes.len() {
        return Verify::Tampered {
            index: rows.len().min(stored_hashes.len()),
        };
    }
    let mut prev = genesis();
    for (i, row) in rows.iter().enumerate() {
        let derived = keyed_link(key, &prev, row);
        if derived != stored_hashes[i] {
            return Verify::Tampered { index: i };
        }
        prev = derived;
    }
    Verify::Ok
}

/// Parse a hex `row_hash` column back into 32 bytes; `None` if malformed.
pub fn hash_from_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = crate::model::hex_decode(s);
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::v1::{Action, Category, Severity};

    fn row(id: i64, score: f32, codes: &[&str]) -> AuditRow {
        AuditRow {
            id,
            ts: 1_700_000_000_000 + id,
            device_id: "dev-1".into(),
            category: Category::Grooming as i32,
            action: Action::Block as i32,
            severity: Severity::High as i32,
            score,
            reason_codes: codes.iter().map(|s| s.to_string()).collect(),
            model_id: "rules-v1".into(),
            app: "messenger".into(),
            alert_kind: None,
            content_sha256: String::new(),
        }
    }

    /// Build a valid chain over a set of rows.
    fn build_chain(rows: &[AuditRow]) -> Vec<[u8; 32]> {
        let mut hashes = Vec::with_capacity(rows.len());
        let mut prev = genesis();
        for r in rows {
            let h = link(&prev, r);
            hashes.push(h);
            prev = h;
        }
        hashes
    }

    #[test]
    fn intact_chain_verifies() {
        let rows = vec![row(0, 0.4, &["secrecy"]), row(1, 0.8, &["image_request"])];
        let hashes = build_chain(&rows);
        assert_eq!(verify(&rows, &hashes), Verify::Ok);
    }

    #[test]
    fn editing_a_row_is_detected() {
        let rows = vec![row(0, 0.4, &["secrecy"]), row(1, 0.8, &["image_request"])];
        let hashes = build_chain(&rows);

        // Tamper: lower the score on row 0 to hide a high-severity event.
        let mut tampered = rows.clone();
        tampered[0].score = 0.01;

        // Stored hashes still reflect the original rows; re-derivation mismatches
        // at the edited row.
        assert_eq!(verify(&tampered, &hashes), Verify::Tampered { index: 0 });
    }

    #[test]
    fn deleting_a_row_is_detected() {
        let rows = vec![
            row(0, 0.4, &["secrecy"]),
            row(1, 0.8, &["image_request"]),
            row(2, 0.9, &["sexualization"]),
        ];
        let hashes = build_chain(&rows);

        // Attacker deletes the middle (incriminating) row but leaves its stored
        // hash list as-is would be caught by length; even if they also drop the
        // hash, the surviving row 2 now chains from row 0's hash → mismatch.
        let surviving_rows = vec![rows[0].clone(), rows[2].clone()];
        let surviving_hashes = vec![hashes[0], hashes[2]];
        assert_eq!(
            verify(&surviving_rows, &surviving_hashes),
            Verify::Tampered { index: 1 }
        );
    }

    #[test]
    fn reordering_rows_is_detected() {
        let rows = vec![row(0, 0.4, &["secrecy"]), row(1, 0.8, &["image_request"])];
        let hashes = build_chain(&rows);
        let swapped = vec![rows[1].clone(), rows[0].clone()];
        assert_eq!(verify(&swapped, &hashes), Verify::Tampered { index: 0 });
    }

    #[test]
    fn keyed_chain_verifies_and_detects() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"audit-key-from-keystore");
        let rows = vec![row(0, 0.4, &["secrecy"]), row(1, 0.8, &["image_request"])];
        let mut hashes = Vec::new();
        let mut prev = genesis();
        for r in &rows {
            let h = keyed_link(&key, &prev, r);
            hashes.push(h);
            prev = h;
        }
        assert_eq!(verify_keyed(&key, &rows, &hashes), Verify::Ok);

        let mut tampered = rows.clone();
        tampered[1].score = 0.0;
        assert_eq!(
            verify_keyed(&key, &tampered, &hashes),
            Verify::Tampered { index: 1 }
        );
    }

    #[test]
    fn hash_hex_round_trips() {
        let h = link(&genesis(), &row(0, 0.5, &["secrecy"]));
        let hex = hash_hex(&h);
        assert_eq!(hash_from_hex(&hex), Some(h));
        assert_eq!(hash_from_hex("nope"), None);
    }
}
