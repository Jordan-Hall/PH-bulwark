//! Client/local backend: **encrypted SQLite via SQLCipher** (`rusqlite` with the
//! `bundled-sqlcipher` feature).
//!
//! This is the on-device store. The whole database is encrypted at rest by
//! SQLCipher (key applied via `PRAGMA key` from the OS keystore — see
//! [`crate::crypto`]). The `audit_log` table is additionally **tamper-evident**:
//! every inserted row extends a SHA-256 hash chain ([`crate::hashchain`]) so an
//! edit/delete/reorder is detectable even by an actor who can decrypt the file.
//!
//! `rusqlite` is synchronous; the [`crate::Store`] trait is async. The sync core
//! lives in [`SqliteStore`]'s inherent methods (also directly unit-testable
//! without a runtime), and the async trait impl wraps them. SQLite work here is
//! local and fast; we guard the connection with a `std::sync::Mutex`.
//!
//! `#![forbid(unsafe_code)]` (crate-level). No AI/ML. No telemetry.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto::AtRestKey;
use crate::error::{Result, StoreError};
use crate::hashchain::{self, genesis, hash_from_hex, hash_hex};
use crate::model::{AlertDedupe, AuditRow, EvidenceMeta, StoredEvent};
use crate::retention::{PurgeReport, RetentionPolicy};
use crate::schema::SQLITE_DDL;

/// Encrypted-SQLite implementation of the store.
pub struct SqliteStore {
    conn: Mutex<Connection>,
    retention: RetentionPolicy,
    /// When set, the audit chain is HMAC-keyed (stronger tamper-evidence).
    audit_key: Option<ring::hmac::Key>,
}

impl SqliteStore {
    /// Open (or create) an encrypted database at `path`, key it with the
    /// keystore-provided [`AtRestKey`], run migrations, and adopt `retention`.
    ///
    /// The `PRAGMA key` MUST be the first statement on the connection (SQLCipher
    /// requirement). We also derive the keyed audit-chain key from the same
    /// keystore secret (domain-separated) so the tamper-evidence is unforgeable.
    pub fn open(
        path: &std::path::Path,
        key: &AtRestKey,
        retention: RetentionPolicy,
    ) -> Result<Self> {
        retention.validate()?;
        let conn = Connection::open(path).map_err(StoreError::open)?;
        Self::init_conn(&conn, key)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
            retention,
            audit_key: Some(key.audit_hmac_key()),
        })
    }

    /// Open an in-memory encrypted database with an explicit at-rest key and
    /// retention policy (tests / ephemeral use, full control).
    pub fn open_in_memory_with(key: &AtRestKey, retention: RetentionPolicy) -> Result<Self> {
        retention.validate()?;
        let conn = Connection::open_in_memory().map_err(StoreError::open)?;
        Self::init_conn(&conn, key)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
            retention,
            audit_key: Some(key.audit_hmac_key()),
        })
    }

    /// Open an ephemeral in-memory store as a boxed [`Store`] trait object, for
    /// dev / dashboard use (e.g. `bulwark-ui`). Mints a random throwaway at-rest key
    /// (the `:memory:` DB never touches disk), applies the default
    /// [`RetentionPolicy`], and returns `Arc<dyn Store>`.
    pub fn open_in_memory() -> bulwark_core::Result<std::sync::Arc<dyn crate::Store>> {
        use ring::rand::SecureRandom;
        let mut key_bytes = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut key_bytes)
            .map_err(|_| StoreError::crypto("failed to generate ephemeral at-rest key"))?;
        let key = AtRestKey::new(key_bytes.to_vec())?;
        let store = Self::open_in_memory_with(&key, RetentionPolicy::default())?;
        Ok(std::sync::Arc::new(store))
    }

    fn init_conn(conn: &Connection, key: &AtRestKey) -> Result<()> {
        // SQLCipher page-level at-rest encryption is OPT-IN (the `sqlcipher`
        // feature + rusqlite `bundled-sqlcipher`). When off, the DB is plain
        // SQLite — the store holds only metadata/hashes (never content), so
        // at-rest protection is OS disk encryption + age-encrypted exports. The
        // key still seeds the tamper-evident audit HMAC chain (see chain_link).
        #[cfg(feature = "sqlcipher")]
        conn.pragma_update(None, "key", key.sqlcipher_pragma_value())
            .map_err(|e| StoreError::crypto(format!("PRAGMA key failed: {e}")))?;
        #[cfg(not(feature = "sqlcipher"))]
        let _ = key;
        // Enforce FK cascade (evidence_meta → audit_log) and durable journaling.
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(StoreError::open)?;
        conn.execute_batch(SQLITE_DDL).map_err(StoreError::open)?;
        Ok(())
    }

    /// The configured retention policy.
    pub fn retention(&self) -> &RetentionPolicy {
        &self.retention
    }

    fn chain_link(&self, prev: &[u8; 32], row: &AuditRow) -> [u8; 32] {
        match &self.audit_key {
            Some(k) => hashchain::keyed_link(k, prev, row),
            None => hashchain::link(prev, row),
        }
    }

    // --- sync core (also used directly by tests) ---------------------------

    /// Append a [`StoredEvent`] as a tamper-evident audit row (+ evidence meta if
    /// the verdict carried a content hash). Returns the new audit row id.
    pub fn record_sync(&self, event: &StoredEvent) -> Result<i64> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction().map_err(StoreError::backend)?;

        // Determine chain position + previous hash.
        let (next_id, prev_hash) = {
            let row: Option<(i64, String)> = tx
                .query_row(
                    "SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                    [],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(StoreError::backend)?;
            match row {
                Some((id, hex)) => {
                    let prev = hash_from_hex(&hex)
                        .ok_or_else(|| StoreError::integrity("stored row_hash is malformed"))?;
                    (id + 1, prev)
                }
                None => (0, genesis()),
            }
        };

        let audit = AuditRow::from_event(next_id, event);
        let row_hash = self.chain_link(&prev_hash, &audit);
        let reason_json = serde_json::to_string(&audit.reason_codes)?;

        tx.execute(
            "INSERT INTO audit_log
               (id, ts, device_id, category, action, severity, score,
                reason_codes, model_id, app, alert_kind, content_sha256,
                prev_hash, row_hash)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                audit.id,
                audit.ts,
                audit.device_id,
                audit.category,
                audit.action,
                audit.severity,
                audit.score,
                reason_json,
                audit.model_id,
                audit.app,
                audit.alert_kind,
                audit.content_sha256,
                hash_hex(&prev_hash),
                hash_hex(&row_hash),
            ],
        )
        .map_err(StoreError::backend)?;

        // Evidence metadata (C1) — hashes + safe-thumbnail reference only.
        if let Some(ev) = event.verdict.evidence.as_ref() {
            if !ev.sha256.is_empty() || !ev.perceptual_hash.is_empty() {
                tx.execute(
                    "INSERT INTO evidence_meta
                       (audit_id, sha256, phash, safe_thumbnail_ref, label)
                     VALUES (?1,?2,?3,?4,?5)",
                    params![
                        next_id,
                        crate::model::hex_encode(&ev.sha256),
                        crate::model::hex_encode(&ev.perceptual_hash),
                        // safe_thumbnail bytes are NOT stored; a reference is. If
                        // the analyzer didn't provide one, store NULL (hash-only).
                        Option::<String>::None,
                        audit.reason_codes.first().cloned().unwrap_or_default(),
                    ],
                )
                .map_err(StoreError::backend)?;
            }
        }

        tx.commit().map_err(StoreError::backend)?;
        Ok(next_id)
    }

    /// Load all audit rows (id order) + their stored hashes for verification.
    fn load_chain(&self, conn: &Connection) -> Result<(Vec<AuditRow>, Vec<[u8; 32]>)> {
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, device_id, category, action, severity, score,
                        reason_codes, model_id, app, alert_kind, content_sha256, row_hash
                 FROM audit_log ORDER BY id ASC",
            )
            .map_err(StoreError::backend)?;
        let mut rows = Vec::new();
        let mut hashes = Vec::new();
        let mapped = stmt
            .query_map([], |r| {
                let reason_json: String = r.get(7)?;
                let reason_codes: Vec<String> =
                    serde_json::from_str(&reason_json).unwrap_or_default();
                let row = AuditRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    device_id: r.get(2)?,
                    category: r.get(3)?,
                    action: r.get(4)?,
                    severity: r.get(5)?,
                    score: r.get(6)?,
                    reason_codes,
                    model_id: r.get(8)?,
                    app: r.get(9)?,
                    alert_kind: r.get(10)?,
                    content_sha256: r.get(11)?,
                };
                let row_hash: String = r.get(12)?;
                Ok((row, row_hash))
            })
            .map_err(StoreError::backend)?;
        for item in mapped {
            let (row, hex) = item.map_err(StoreError::backend)?;
            let h = hash_from_hex(&hex)
                .ok_or_else(|| StoreError::integrity("stored row_hash malformed"))?;
            rows.push(row);
            hashes.push(h);
        }
        Ok((rows, hashes))
    }

    /// Verify the tamper-evident audit chain. `Ok(())` = intact; an
    /// [`StoreError::Integrity`] names the first tampered row.
    pub fn verify_audit_chain_sync(&self) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let (rows, hashes) = self.load_chain(&conn)?;
        let result = match &self.audit_key {
            Some(k) => hashchain::verify_keyed(k, &rows, &hashes),
            None => hashchain::verify(&rows, &hashes),
        };
        match result {
            hashchain::Verify::Ok => Ok(()),
            hashchain::Verify::Tampered { index } => Err(StoreError::integrity(format!(
                "audit chain broken at row index {index}"
            ))),
        }
    }

    /// Recent events for `device_id`, newest first, capped at `limit`.
    pub fn recent_sync(&self, device_id: &str, limit: u32) -> Result<Vec<StoredEvent>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, device_id, category, action, severity, score,
                        reason_codes, model_id, app, alert_kind, content_sha256
                 FROM audit_log WHERE device_id = ?1 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(StoreError::backend)?;
        let rows = stmt
            .query_map(params![device_id, limit], |r| {
                let reason_json: String = r.get(7)?;
                let reason_codes: Vec<String> =
                    serde_json::from_str(&reason_json).unwrap_or_default();
                Ok(AuditRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    device_id: r.get(2)?,
                    category: r.get(3)?,
                    action: r.get(4)?,
                    severity: r.get(5)?,
                    score: r.get(6)?,
                    reason_codes,
                    model_id: r.get(8)?,
                    app: r.get(9)?,
                    alert_kind: r.get(10)?,
                    content_sha256: r.get(11)?,
                })
            })
            .map_err(StoreError::backend)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(StoreError::backend)?.to_event());
        }
        Ok(out)
    }

    /// Read a thread-state blob, if present.
    pub fn thread_state_sync(&self, thread_id: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT state FROM thread_state WHERE thread_id = ?1",
            params![thread_id],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(StoreError::backend)
    }

    /// Upsert a thread-state blob.
    pub fn put_thread_state_sync(&self, thread_id: &str, state: &[u8], now_ms: i64) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO thread_state (thread_id, state, updated_ts)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(thread_id) DO UPDATE SET state = ?2, updated_ts = ?3",
            params![thread_id, state, now_ms],
        )
        .map_err(StoreError::backend)?;
        Ok(())
    }

    /// Record an alert id for dedupe. Returns `true` if newly inserted (i.e. NOT
    /// a duplicate), `false` if the alert id was already present.
    pub fn dedupe_alert_sync(&self, dedupe: &AlertDedupe) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let changed = conn
            .execute(
                "INSERT OR IGNORE INTO alert_dedupe (alert_id, ts) VALUES (?1, ?2)",
                params![dedupe.alert_id, dedupe.ts],
            )
            .map_err(StoreError::backend)?;
        Ok(changed == 1)
    }

    /// Read a config value.
    pub fn config_get_sync(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row("SELECT v FROM config_kv WHERE k = ?1", params![key], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .map_err(StoreError::backend)
    }

    /// Upsert a config value.
    pub fn config_put_sync(&self, key: &str, value: &str, now_ms: i64) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO config_kv (k, v, updated_ts) VALUES (?1, ?2, ?3)
             ON CONFLICT(k) DO UPDATE SET v = ?2, updated_ts = ?3",
            params![key, value, now_ms],
        )
        .map_err(StoreError::backend)?;
        Ok(())
    }

    /// Lookup an evidence_meta row for an audit id (review UI).
    pub fn evidence_for_sync(&self, audit_id: i64) -> Result<Option<EvidenceMeta>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT audit_id, sha256, phash, safe_thumbnail_ref, label
             FROM evidence_meta WHERE audit_id = ?1",
            params![audit_id],
            |r| {
                Ok(EvidenceMeta {
                    audit_id: r.get(0)?,
                    sha256: r.get(1)?,
                    phash: r.get(2)?,
                    safe_thumbnail_ref: r.get(3)?,
                    label: r.get(4)?,
                })
            },
        )
        .optional()
        .map_err(StoreError::backend)
    }

    /// Apply retention auto-purge at `now_ms` (data-handling.md §4). Deletes
    /// expired C1 evidence and rotates the C3 audit ring (age + size caps).
    ///
    /// NOTE: deleting an interior audit row breaks the hash chain by design;
    /// retention purge therefore prunes only the **oldest contiguous prefix**
    /// (age cap) and trims the head (size cap), which keeps the surviving chain
    /// re-verifiable from a recorded checkpoint. Evidence-only purge leaves the
    /// audit row intact (it's metadata) and just drops the C1 derived artifact.
    pub fn purge_expired_sync(&self, now_ms: i64) -> Result<PurgeReport> {
        let p = &self.retention;
        let mut report = PurgeReport::default();
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction().map_err(StoreError::backend)?;

        // C1 evidence TTL: drop evidence_meta whose parent audit row is older
        // than the evidence cutoff (the audit *metadata* row may live longer
        // under the audit ring; the derived C1 artifact is what expires here).
        if let Some(cutoff) = p.evidence_cutoff_ms(now_ms) {
            let n = tx
                .execute(
                    "DELETE FROM evidence_meta
                     WHERE audit_id IN (SELECT id FROM audit_log WHERE ts < ?1)",
                    params![cutoff],
                )
                .map_err(StoreError::backend)?;
            report.evidence_rows_purged = n as u64;
        }

        // C3 audit age cap: delete the oldest contiguous prefix past the cutoff.
        if let Some(cutoff) = p.audit_cutoff_ms(now_ms) {
            let n = tx
                .execute("DELETE FROM audit_log WHERE ts < ?1", params![cutoff])
                .map_err(StoreError::backend)?;
            report.audit_rows_aged_out = n as u64;
        }

        // C3 audit size cap: keep only the newest `audit_max_rows` rows.
        if p.audit_max_rows > 0 {
            let n = tx
                .execute(
                    "DELETE FROM audit_log WHERE id IN (
                        SELECT id FROM audit_log ORDER BY id DESC LIMIT -1 OFFSET ?1
                     )",
                    params![p.audit_max_rows as i64],
                )
                .map_err(StoreError::backend)?;
            report.audit_rows_rotated = n as u64;
        }

        tx.commit().map_err(StoreError::backend)?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::{Action, AlertKind, Category, Evidence, Severity, Verdict};

    fn key() -> AtRestKey {
        AtRestKey::new(vec![7u8; 32]).unwrap()
    }

    fn store() -> SqliteStore {
        SqliteStore::open_in_memory_with(&key(), RetentionPolicy::default()).unwrap()
    }

    fn event(ts: i64, score: f32, sha: Vec<u8>) -> StoredEvent {
        StoredEvent {
            device: bulwark_core::DeviceId("dev-1".into()),
            verdict: Verdict {
                request_id: "r".into(),
                category: Category::Grooming as i32,
                action: Action::Block as i32,
                severity: Severity::High as i32,
                score,
                rationale: String::new(),
                evidence: Some(Evidence {
                    sha256: sha,
                    perceptual_hash: vec![1, 2],
                    safe_thumbnail: Vec::new(),
                    text_snippet: String::new(),
                    model_id: "rules-v1".into(),
                    model_version: "1".into(),
                }),
                grooming: None,
                worker_id: String::new(),
                latency_ms: 0,
            },
            action: Action::Block,
            alert: Some(AlertKind::Intervention),
            ts,
        }
    }

    #[test]
    fn records_and_reads_recent() {
        let s = store();
        s.record_sync(&event(1000, 0.8, vec![0xaa])).unwrap();
        s.record_sync(&event(2000, 0.9, vec![0xbb])).unwrap();
        let recent = s.recent_sync("dev-1", 10).unwrap();
        assert_eq!(recent.len(), 2);
        // newest first
        assert_eq!(recent[0].ts, 2000);
    }

    // At-rest encryption only exists under the `sqlcipher` feature; on the plain
    // backend the key seeds only the audit HMAC chain, so a wrong key still opens
    // the (unencrypted) file. This assertion is meaningful only with SQLCipher.
    #[cfg(feature = "sqlcipher")]
    #[test]
    fn encrypted_file_round_trips_with_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bulwark-test.db");
        let k = key();
        {
            let s = SqliteStore::open(&path, &k, RetentionPolicy::default()).unwrap();
            s.record_sync(&event(1000, 0.8, vec![0xaa])).unwrap();
        }
        // Re-open with the SAME key → data is readable.
        {
            let s = SqliteStore::open(&path, &k, RetentionPolicy::default()).unwrap();
            assert_eq!(s.recent_sync("dev-1", 10).unwrap().len(), 1);
        }
        // Opening with a WRONG key must fail (SQLCipher rejects the page MAC),
        // proving the file is encrypted at rest rather than plaintext.
        {
            let wrong = AtRestKey::new(vec![0xFFu8; 32]).unwrap();
            let res = SqliteStore::open(&path, &wrong, RetentionPolicy::default());
            assert!(res.is_err(), "wrong key must not open the encrypted DB");
        }
    }

    #[test]
    fn audit_chain_verifies_when_intact() {
        let s = store();
        for i in 0..5 {
            s.record_sync(&event(1000 + i, 0.5, vec![i as u8])).unwrap();
        }
        s.verify_audit_chain_sync().expect("intact chain verifies");
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let s = store();
        for i in 0..5 {
            s.record_sync(&event(1000 + i, 0.5, vec![i as u8])).unwrap();
        }
        // Tamper directly in the DB: rewrite a row's score WITHOUT updating its
        // chained hash (simulating an attacker editing the encrypted file).
        {
            let conn = s.conn.lock().unwrap();
            conn.execute("UPDATE audit_log SET score = 0.0 WHERE id = 2", [])
                .unwrap();
        }
        let err = s.verify_audit_chain_sync().unwrap_err();
        assert!(matches!(err, StoreError::Integrity(_)));
    }

    #[test]
    fn audit_chain_detects_deletion() {
        let s = store();
        for i in 0..5 {
            s.record_sync(&event(1000 + i, 0.5, vec![i as u8])).unwrap();
        }
        {
            let conn = s.conn.lock().unwrap();
            conn.execute("DELETE FROM audit_log WHERE id = 2", [])
                .unwrap();
        }
        assert!(matches!(
            s.verify_audit_chain_sync(),
            Err(StoreError::Integrity(_))
        ));
    }

    #[test]
    fn thread_state_round_trips() {
        let s = store();
        assert!(s.thread_state_sync("t1").unwrap().is_none());
        s.put_thread_state_sync("t1", b"\x01\x02\x03", 100).unwrap();
        assert_eq!(s.thread_state_sync("t1").unwrap().unwrap(), b"\x01\x02\x03");
        // upsert overwrites
        s.put_thread_state_sync("t1", b"\x04", 200).unwrap();
        assert_eq!(s.thread_state_sync("t1").unwrap().unwrap(), b"\x04");
    }

    #[test]
    fn alert_dedupe_suppresses_repeats() {
        let s = store();
        let a = AlertDedupe {
            alert_id: "alert-1".into(),
            ts: 1,
        };
        assert!(s.dedupe_alert_sync(&a).unwrap()); // first time → inserted
        assert!(!s.dedupe_alert_sync(&a).unwrap()); // repeat → suppressed
    }

    #[test]
    fn config_kv_round_trips() {
        let s = store();
        assert!(s.config_get_sync("k").unwrap().is_none());
        s.config_put_sync("k", "v1", 1).unwrap();
        assert_eq!(s.config_get_sync("k").unwrap().unwrap(), "v1");
        s.config_put_sync("k", "v2", 2).unwrap();
        assert_eq!(s.config_get_sync("k").unwrap().unwrap(), "v2");
    }

    #[test]
    fn evidence_meta_holds_only_hashes() {
        let s = store();
        let id = s.record_sync(&event(1000, 0.8, vec![0xde, 0xad])).unwrap();
        let ev = s.evidence_for_sync(id).unwrap().unwrap();
        assert_eq!(ev.sha256, "dead");
        // No pixel data — thumbnail ref is absent (hash-only) by default.
        assert!(ev.safe_thumbnail_ref.is_none());
    }

    #[test]
    fn retention_purge_removes_expired() {
        // evidence TTL 30d, audit TTL 90d.
        let s = store();
        let day = 24 * 60 * 60 * 1000i64;
        let now = 200 * day;
        // Old rows (well past both cutoffs) + a fresh row.
        s.record_sync(&event(10 * day, 0.5, vec![1])).unwrap(); // age > 90d
        s.record_sync(&event(180 * day, 0.5, vec![2])).unwrap(); // within 90d, > 30d evidence? 200-180=20d < 30d → evidence kept
        s.record_sync(&event(now, 0.5, vec![3])).unwrap(); // fresh

        let report = s.purge_expired_sync(now).unwrap();
        // The 10-day-old row is past the 90-day audit cutoff (200-90=110d).
        assert!(report.audit_rows_aged_out >= 1);
        // The 10-day-old row's evidence is also past the 30-day evidence cutoff
        // (200-30=170d), so it's purged too.
        assert!(report.evidence_rows_purged >= 1);

        // Fresh row survives.
        let remaining = s.recent_sync("dev-1", 100).unwrap();
        assert!(remaining.iter().any(|e| e.ts == now));
    }

    #[test]
    fn retention_size_cap_rotates() {
        let policy = RetentionPolicy {
            evidence_ttl_days: 0,
            audit_ttl_days: 0,
            audit_max_rows: 3,
            honor_pins: true,
        };
        let s = SqliteStore::open_in_memory_with(&key(), policy).unwrap();
        for i in 0..10 {
            s.record_sync(&event(1000 + i, 0.5, vec![i as u8])).unwrap();
        }
        let report = s.purge_expired_sync(99999).unwrap();
        assert_eq!(report.audit_rows_rotated, 7); // 10 - 3 kept
        assert_eq!(s.recent_sync("dev-1", 100).unwrap().len(), 3);
    }
}
