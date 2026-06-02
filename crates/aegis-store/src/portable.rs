//! Portable, **pure-Rust** backend — no native/C dependency, builds on *any*
//! host.
//!
//! This is the dependency-free fallback for environments where the bundled
//! SQLite C compile can't run — most notably **Windows under Smart App Control**,
//! which blocks the freshly-built, unsigned `sqlite3.c` artifact (`os error
//! 4551`). It is the default backend so `cargo build` works out-of-the-box
//! everywhere; production/CI opt into the `sqlite` (or `sqlcipher`) backend for
//! durable, encrypted on-disk storage.
//!
//! It honours the **same [`crate::Store`] contract** as the SQLite/Postgres
//! adapters, including the tamper-evident audit **hash chain** (reusing
//! [`crate::hashchain`]) and the [`crate::retention`] auto-purge. State is held
//! in memory behind a `Mutex`; [`PortableStore::open`] adds best-effort JSON-file
//! persistence so an on-device deployment survives a restart.
//!
//! ## The no-content invariant still holds
//! It persists the very same row types as the other backends ([`AuditRow`],
//! [`EvidenceMeta`]) — which are *structurally* incapable of holding message
//! text or media bytes (see [`crate::model`]). There is no content here either.
//!
//! `#![forbid(unsafe_code)]` (crate-level). No AI/ML. No telemetry.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::crypto::AtRestKey;
use crate::error::{Result, StoreError};
use crate::hashchain::{self, genesis, hash_from_hex, hash_hex};
use crate::model::{AlertDedupe, AuditRow, EvidenceMeta, StoredEvent};
use crate::retention::{PurgeReport, RetentionPolicy};

/// An audit row plus its chained hash (hex), mirroring the `row_hash` column the
/// SQLite backend stores. Kept together so the chain re-verifies after reload.
#[derive(Clone, Serialize, Deserialize)]
struct StoredAudit {
    row: AuditRow,
    /// Hex-encoded SHA-256 chain hash for this row.
    row_hash: String,
}

/// The full persisted state. Serializable so [`PortableStore::open`] can snapshot
/// it to a JSON file. Holds only C1/C3 derived rows — never content.
#[derive(Default, Serialize, Deserialize)]
struct Inner {
    /// The tamper-evident audit log, in chain (insertion) order.
    audit: Vec<StoredAudit>,
    /// C1 evidence metadata (hashes + safe-thumbnail references only).
    evidence: Vec<EvidenceMeta>,
    /// Thread-state blobs for the grooming state machine (content-free by the
    /// `aegis-text` producer contract).
    thread_state: HashMap<String, Vec<u8>>,
    /// Small config key/value store.
    config: HashMap<String, String>,
    /// Seen alert ids, for idempotent dedupe.
    dedupe: HashSet<String>,
}

/// Pure-Rust implementation of the [`crate::Store`] contract.
pub struct PortableStore {
    inner: Mutex<Inner>,
    retention: RetentionPolicy,
    /// When set, the audit chain is HMAC-keyed (stronger tamper-evidence). Always
    /// set by the constructors below (derived from the at-rest key).
    audit_key: Option<ring::hmac::Key>,
    /// When set, mutations are snapshotted to this JSON file (best-effort).
    path: Option<PathBuf>,
}

impl PortableStore {
    /// Open an in-memory store with an explicit at-rest key (used to seed the
    /// tamper-evident audit HMAC chain) and retention policy.
    pub fn open_in_memory_with(key: &AtRestKey, retention: RetentionPolicy) -> Result<Self> {
        retention.validate()?;
        Ok(PortableStore {
            inner: Mutex::new(Inner::default()),
            retention,
            audit_key: Some(key.audit_hmac_key()),
            path: None,
        })
    }

    /// Open an ephemeral in-memory store as a boxed [`crate::Store`] trait object
    /// (dev / dashboard use). Mints a random throwaway key for the audit HMAC and
    /// applies the default [`RetentionPolicy`].
    pub fn open_in_memory() -> aegis_core::Result<std::sync::Arc<dyn crate::Store>> {
        use ring::rand::SecureRandom;
        let mut key_bytes = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut key_bytes)
            .map_err(|_| StoreError::crypto("failed to generate ephemeral at-rest key"))?;
        let key = AtRestKey::new(key_bytes.to_vec())?;
        let store = Self::open_in_memory_with(&key, RetentionPolicy::default())?;
        Ok(std::sync::Arc::new(store))
    }

    /// Open a file-backed store at `path` (JSON snapshot). Loads existing state if
    /// the file is present, and persists on every mutation. The `key` seeds the
    /// audit HMAC chain; the JSON itself is *not* encrypted (the no-content
    /// invariant means it holds only hashes/codes/metadata — at-rest protection is
    /// OS disk encryption + age-encrypted exports, per data-handling.md §3).
    pub fn open(path: &Path, key: &AtRestKey, retention: RetentionPolicy) -> Result<Self> {
        retention.validate()?;
        let inner = if path.exists() {
            let bytes = std::fs::read(path).map_err(StoreError::open)?;
            serde_json::from_slice::<Inner>(&bytes)?
        } else {
            Inner::default()
        };
        Ok(PortableStore {
            inner: Mutex::new(inner),
            retention,
            audit_key: Some(key.audit_hmac_key()),
            path: Some(path.to_path_buf()),
        })
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

    /// Snapshot to disk if file-backed. Best-effort but surfaced as an error so a
    /// failed write doesn't silently drop the audit row.
    fn persist(&self, inner: &Inner) -> Result<()> {
        if let Some(path) = &self.path {
            let bytes = serde_json::to_vec(inner)?;
            std::fs::write(path, bytes).map_err(StoreError::open)?;
        }
        Ok(())
    }

    // --- sync core (also used directly by tests) ---------------------------

    /// Append a [`StoredEvent`] as a tamper-evident audit row (+ evidence meta if
    /// the verdict carried a content hash). Returns the new audit row id.
    pub fn record_sync(&self, event: &StoredEvent) -> Result<i64> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");

        let (next_id, prev_hash) = match inner.audit.last() {
            Some(last) => {
                let prev = hash_from_hex(&last.row_hash)
                    .ok_or_else(|| StoreError::integrity("stored row_hash is malformed"))?;
                (last.row.id + 1, prev)
            }
            None => (0, genesis()),
        };

        let audit = AuditRow::from_event(next_id, event);
        let row_hash = self.chain_link(&prev_hash, &audit);

        // Evidence metadata (C1) — hashes + safe-thumbnail reference only.
        if let Some(ev) = event.verdict.evidence.as_ref() {
            if !ev.sha256.is_empty() || !ev.perceptual_hash.is_empty() {
                inner.evidence.push(EvidenceMeta {
                    audit_id: next_id,
                    sha256: crate::model::hex_encode(&ev.sha256),
                    phash: crate::model::hex_encode(&ev.perceptual_hash),
                    // safe_thumbnail bytes are NOT stored; a reference would be.
                    safe_thumbnail_ref: None,
                    label: audit.reason_codes.first().cloned().unwrap_or_default(),
                });
            }
        }

        inner.audit.push(StoredAudit {
            row: audit,
            row_hash: hash_hex(&row_hash),
        });
        self.persist(&inner)?;
        Ok(next_id)
    }

    /// Verify the tamper-evident audit chain. `Ok(())` = intact; an
    /// [`StoreError::Integrity`] names the first tampered row.
    pub fn verify_audit_chain_sync(&self) -> Result<()> {
        let inner = self.inner.lock().expect("store mutex poisoned");
        let rows: Vec<AuditRow> = inner.audit.iter().map(|a| a.row.clone()).collect();
        let mut hashes = Vec::with_capacity(inner.audit.len());
        for a in &inner.audit {
            hashes.push(
                hash_from_hex(&a.row_hash)
                    .ok_or_else(|| StoreError::integrity("stored row_hash malformed"))?,
            );
        }
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
        let inner = self.inner.lock().expect("store mutex poisoned");
        let out = inner
            .audit
            .iter()
            .rev() // chain order is ascending id → reverse for newest-first
            .filter(|a| a.row.device_id == device_id)
            .take(limit as usize)
            .map(|a| a.row.to_event())
            .collect();
        Ok(out)
    }

    /// Read a thread-state blob, if present.
    pub fn thread_state_sync(&self, thread_id: &str) -> Result<Option<Vec<u8>>> {
        let inner = self.inner.lock().expect("store mutex poisoned");
        Ok(inner.thread_state.get(thread_id).cloned())
    }

    /// Upsert a thread-state blob.
    pub fn put_thread_state_sync(&self, thread_id: &str, state: &[u8], _now_ms: i64) -> Result<()> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        inner
            .thread_state
            .insert(thread_id.to_string(), state.to_vec());
        self.persist(&inner)?;
        Ok(())
    }

    /// Record an alert id for dedupe. Returns `true` if newly inserted (NOT a
    /// duplicate), `false` if it was already present.
    pub fn dedupe_alert_sync(&self, dedupe: &AlertDedupe) -> Result<bool> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        let inserted = inner.dedupe.insert(dedupe.alert_id.clone());
        if inserted {
            self.persist(&inner)?;
        }
        Ok(inserted)
    }

    /// Read a config value.
    pub fn config_get_sync(&self, key: &str) -> Result<Option<String>> {
        let inner = self.inner.lock().expect("store mutex poisoned");
        Ok(inner.config.get(key).cloned())
    }

    /// Upsert a config value.
    pub fn config_put_sync(&self, key: &str, value: &str, _now_ms: i64) -> Result<()> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        inner.config.insert(key.to_string(), value.to_string());
        self.persist(&inner)?;
        Ok(())
    }

    /// Lookup an evidence_meta row for an audit id (review UI).
    pub fn evidence_for_sync(&self, audit_id: i64) -> Result<Option<EvidenceMeta>> {
        let inner = self.inner.lock().expect("store mutex poisoned");
        Ok(inner
            .evidence
            .iter()
            .find(|e| e.audit_id == audit_id)
            .cloned())
    }

    /// Apply retention auto-purge at `now_ms` (data-handling.md §4). Same policy
    /// semantics as the SQLite backend: evidence TTL, audit age cap (oldest
    /// contiguous prefix), and audit size cap (ring rotation).
    pub fn purge_expired_sync(&self, now_ms: i64) -> Result<PurgeReport> {
        let p = &self.retention;
        let mut report = PurgeReport::default();
        let mut inner = self.inner.lock().expect("store mutex poisoned");

        // C1 evidence TTL: drop evidence whose parent audit row is older than the
        // evidence cutoff (the audit metadata row may outlive it under the ring).
        if let Some(cutoff) = p.evidence_cutoff_ms(now_ms) {
            let expired: HashSet<i64> = inner
                .audit
                .iter()
                .filter(|a| a.row.ts < cutoff)
                .map(|a| a.row.id)
                .collect();
            let before = inner.evidence.len();
            inner.evidence.retain(|e| !expired.contains(&e.audit_id));
            report.evidence_rows_purged = (before - inner.evidence.len()) as u64;
        }

        // C3 audit age cap: delete rows older than the cutoff.
        if let Some(cutoff) = p.audit_cutoff_ms(now_ms) {
            let before = inner.audit.len();
            inner.audit.retain(|a| a.row.ts >= cutoff);
            report.audit_rows_aged_out = (before - inner.audit.len()) as u64;
        }

        // C3 audit size cap: keep only the newest `audit_max_rows` rows.
        if p.audit_max_rows > 0 && inner.audit.len() > p.audit_max_rows as usize {
            let remove = inner.audit.len() - p.audit_max_rows as usize;
            report.audit_rows_rotated = remove as u64;
            inner.audit.drain(0..remove);
        }

        self.persist(&inner)?;
        Ok(report)
    }
}

#[async_trait::async_trait]
impl crate::Store for PortableStore {
    async fn record(&self, event: StoredEvent) -> aegis_core::Result<()> {
        self.record_sync(&event)?;
        Ok(())
    }

    async fn recent(
        &self,
        device: &aegis_core::DeviceId,
        limit: u32,
    ) -> aegis_core::Result<Vec<StoredEvent>> {
        Ok(self.recent_sync(device.0.as_str(), limit)?)
    }

    async fn thread_state(&self, thread_id: &str) -> aegis_core::Result<Option<Vec<u8>>> {
        Ok(self.thread_state_sync(thread_id)?)
    }

    async fn put_thread_state(&self, thread_id: &str, state: &[u8]) -> aegis_core::Result<()> {
        self.put_thread_state_sync(thread_id, state, crate::now_ms())?;
        Ok(())
    }

    async fn verify_audit_chain(&self) -> aegis_core::Result<()> {
        self.verify_audit_chain_sync()?;
        Ok(())
    }

    async fn purge_expired(&self, now_ms: i64) -> aegis_core::Result<PurgeReport> {
        Ok(self.purge_expired_sync(now_ms)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::v1::{Action, AlertKind, Category, Evidence, Severity, Verdict};

    fn key() -> AtRestKey {
        AtRestKey::new(vec![7u8; 32]).unwrap()
    }

    fn store() -> PortableStore {
        PortableStore::open_in_memory_with(&key(), RetentionPolicy::default()).unwrap()
    }

    fn event(ts: i64, score: f32, sha: Vec<u8>) -> StoredEvent {
        StoredEvent {
            device: aegis_core::DeviceId("dev-1".into()),
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
    fn records_and_reads_recent_newest_first() {
        let s = store();
        s.record_sync(&event(1000, 0.8, vec![0xaa])).unwrap();
        s.record_sync(&event(2000, 0.9, vec![0xbb])).unwrap();
        let recent = s.recent_sync("dev-1", 10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].ts, 2000);
        // device filter
        assert!(s.recent_sync("other", 10).unwrap().is_empty());
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
        // Tamper directly: rewrite a row's score WITHOUT updating its chained hash.
        {
            let mut inner = s.inner.lock().unwrap();
            inner.audit[2].row.score = 0.0;
        }
        assert!(matches!(
            s.verify_audit_chain_sync(),
            Err(StoreError::Integrity(_))
        ));
    }

    #[test]
    fn audit_chain_detects_deletion() {
        let s = store();
        for i in 0..5 {
            s.record_sync(&event(1000 + i, 0.5, vec![i as u8])).unwrap();
        }
        {
            let mut inner = s.inner.lock().unwrap();
            inner.audit.remove(2);
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
        assert!(s.dedupe_alert_sync(&a).unwrap());
        assert!(!s.dedupe_alert_sync(&a).unwrap());
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
        assert!(ev.safe_thumbnail_ref.is_none());
    }

    #[test]
    fn retention_size_cap_rotates() {
        let policy = RetentionPolicy {
            evidence_ttl_days: 0,
            audit_ttl_days: 0,
            audit_max_rows: 3,
            honor_pins: true,
        };
        let s = PortableStore::open_in_memory_with(&key(), policy).unwrap();
        for i in 0..10 {
            s.record_sync(&event(1000 + i, 0.5, vec![i as u8])).unwrap();
        }
        let report = s.purge_expired_sync(99999).unwrap();
        assert_eq!(report.audit_rows_rotated, 7); // 10 - 3 kept
        assert_eq!(s.recent_sync("dev-1", 100).unwrap().len(), 3);
    }

    #[test]
    fn retention_purge_removes_expired() {
        let s = store();
        let day = 24 * 60 * 60 * 1000i64;
        let now = 200 * day;
        s.record_sync(&event(10 * day, 0.5, vec![1])).unwrap(); // age > 90d audit + >30d evidence
        s.record_sync(&event(180 * day, 0.5, vec![2])).unwrap(); // within both
        s.record_sync(&event(now, 0.5, vec![3])).unwrap(); // fresh

        let report = s.purge_expired_sync(now).unwrap();
        assert!(report.audit_rows_aged_out >= 1);
        assert!(report.evidence_rows_purged >= 1);
        assert!(s.recent_sync("dev-1", 100).unwrap().iter().any(|e| e.ts == now));
    }

    #[test]
    fn file_backed_round_trips_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("portable.json");
        let k = key();
        {
            let s = PortableStore::open(&path, &k, RetentionPolicy::default()).unwrap();
            s.record_sync(&event(1000, 0.8, vec![0xaa])).unwrap();
            s.put_thread_state_sync("t1", b"\x09", 1).unwrap();
        }
        // Reopen with the same key → data + intact chain survive.
        {
            let s = PortableStore::open(&path, &k, RetentionPolicy::default()).unwrap();
            assert_eq!(s.recent_sync("dev-1", 10).unwrap().len(), 1);
            assert_eq!(s.thread_state_sync("t1").unwrap().unwrap(), b"\x09");
            s.verify_audit_chain_sync().expect("chain re-verifies after reload");
        }
    }
}
