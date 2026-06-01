//! Server/cluster backend: **Postgres via `sqlx`** for shared cluster state.
//!
//! The cluster's analysis workers are stateless; durable shared state (audit
//! log, evidence metadata, thread state, dedupe, config) lives in Postgres,
//! which is also the quorum source-of-truth elsewhere (PLAN §1). At-rest
//! encryption is provided by the Postgres deployment (TDE / encrypted volume)
//! and access is restricted by mTLS — `docs/security/data-handling.md` §3.
//!
//! The same **no-content invariant** and the same **tamper-evident audit hash
//! chain** as the client backend apply here (shared [`crate::schema`] +
//! [`crate::hashchain`] / [`crate::model::AuditRow`]). The chain is computed in
//! Rust, so it is backend-independent: an audit row exported from Postgres
//! verifies with the exact same logic as one from SQLite.
//!
//! `sqlx` is natively async, so these methods need no blocking wrapper.
//!
//! `#![forbid(unsafe_code)]` (crate-level). No AI/ML. No telemetry.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

use crate::error::{Result, StoreError};
use crate::hashchain::{self, genesis, hash_from_hex, hash_hex};
use crate::model::{AlertDedupe, AuditRow, EvidenceMeta, StoredEvent};
use crate::retention::{PurgeReport, RetentionPolicy};
use crate::schema::POSTGRES_DDL;

/// Postgres-backed implementation of the store (server/cluster).
pub struct PostgresStore {
    pool: PgPool,
    retention: RetentionPolicy,
    audit_key: Option<ring::hmac::Key>,
}

impl PostgresStore {
    /// Connect to Postgres at `database_url`, run migrations, adopt `retention`.
    /// The audit chain is HMAC-keyed when an `audit_key` is supplied (the key is
    /// a C2 secret sourced from the deployment's secret store, never the DB).
    pub async fn connect(
        database_url: &str,
        retention: RetentionPolicy,
        audit_key: Option<ring::hmac::Key>,
    ) -> Result<Self> {
        retention.validate()?;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await
            .map_err(StoreError::open)?;
        sqlx::raw_sql(POSTGRES_DDL)
            .execute(&pool)
            .await
            .map_err(StoreError::open)?;
        Ok(PostgresStore {
            pool,
            retention,
            audit_key,
        })
    }

    /// Build from an existing pool (lets the server share one pool with the
    /// cluster crate). Runs migrations.
    pub async fn from_pool(
        pool: PgPool,
        retention: RetentionPolicy,
        audit_key: Option<ring::hmac::Key>,
    ) -> Result<Self> {
        retention.validate()?;
        sqlx::raw_sql(POSTGRES_DDL)
            .execute(&pool)
            .await
            .map_err(StoreError::open)?;
        Ok(PostgresStore {
            pool,
            retention,
            audit_key,
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

    /// Append a [`StoredEvent`] as a tamper-evident audit row (+ evidence meta).
    /// Returns the new audit row id. Uses a serializable transaction so the
    /// chain head read + insert are atomic against concurrent workers.
    pub async fn record(&self, event: &StoredEvent) -> Result<i64> {
        let mut tx = self.pool.begin().await.map_err(StoreError::backend)?;

        let head: Option<(i64, String)> = sqlx::query(
            "SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::backend)?
        .map(|r| (r.get::<i64, _>("id"), r.get::<String, _>("row_hash")));

        let (next_id, prev_hash) = match head {
            Some((id, hex)) => {
                let prev = hash_from_hex(&hex)
                    .ok_or_else(|| StoreError::integrity("stored row_hash malformed"))?;
                (id + 1, prev)
            }
            None => (0, genesis()),
        };

        let audit = AuditRow::from_event(next_id, event);
        let row_hash = self.chain_link(&prev_hash, &audit);
        let reason_json = serde_json::to_string(&audit.reason_codes)?;

        sqlx::query(
            "INSERT INTO audit_log
               (id, ts, device_id, category, action, severity, score,
                reason_codes, model_id, app, alert_kind, content_sha256,
                prev_hash, row_hash)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(audit.id)
        .bind(audit.ts)
        .bind(&audit.device_id)
        .bind(audit.category)
        .bind(audit.action)
        .bind(audit.severity)
        .bind(audit.score)
        .bind(&reason_json)
        .bind(&audit.model_id)
        .bind(&audit.app)
        .bind(audit.alert_kind)
        .bind(&audit.content_sha256)
        .bind(hash_hex(&prev_hash))
        .bind(hash_hex(&row_hash))
        .execute(&mut *tx)
        .await
        .map_err(StoreError::backend)?;

        if let Some(ev) = event.verdict.evidence.as_ref() {
            if !ev.sha256.is_empty() || !ev.perceptual_hash.is_empty() {
                sqlx::query(
                    "INSERT INTO evidence_meta
                       (audit_id, sha256, phash, safe_thumbnail_ref, label)
                     VALUES ($1,$2,$3,$4,$5)",
                )
                .bind(next_id)
                .bind(crate::model::hex_encode(&ev.sha256))
                .bind(crate::model::hex_encode(&ev.perceptual_hash))
                .bind(Option::<String>::None) // safe-thumbnail REFERENCE only; never pixels
                .bind(audit.reason_codes.first().cloned().unwrap_or_default())
                .execute(&mut *tx)
                .await
                .map_err(StoreError::backend)?;
            }
        }

        tx.commit().await.map_err(StoreError::backend)?;
        Ok(next_id)
    }

    /// Recent events for a device, newest first.
    pub async fn recent(&self, device_id: &str, limit: u32) -> Result<Vec<StoredEvent>> {
        let rows = sqlx::query(
            "SELECT id, ts, device_id, category, action, severity, score,
                    reason_codes, model_id, app, alert_kind, content_sha256
             FROM audit_log WHERE device_id = $1 ORDER BY id DESC LIMIT $2",
        )
        .bind(device_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::backend)?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(row_to_audit(&r)?.to_event());
        }
        Ok(out)
    }

    /// Verify the tamper-evident audit chain over the whole table.
    pub async fn verify_audit_chain(&self) -> Result<()> {
        let rows = sqlx::query(
            "SELECT id, ts, device_id, category, action, severity, score,
                    reason_codes, model_id, app, alert_kind, content_sha256, row_hash
             FROM audit_log ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::backend)?;

        let mut audit_rows = Vec::with_capacity(rows.len());
        let mut hashes = Vec::with_capacity(rows.len());
        for r in &rows {
            audit_rows.push(row_to_audit(r)?);
            let hex: String = r.get("row_hash");
            hashes.push(
                hash_from_hex(&hex)
                    .ok_or_else(|| StoreError::integrity("stored row_hash malformed"))?,
            );
        }
        let result = match &self.audit_key {
            Some(k) => hashchain::verify_keyed(k, &audit_rows, &hashes),
            None => hashchain::verify(&audit_rows, &hashes),
        };
        match result {
            hashchain::Verify::Ok => Ok(()),
            hashchain::Verify::Tampered { index } => Err(StoreError::integrity(format!(
                "audit chain broken at row index {index}"
            ))),
        }
    }

    /// Read a thread-state blob.
    pub async fn thread_state(&self, thread_id: &str) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query("SELECT state FROM thread_state WHERE thread_id = $1")
            .bind(thread_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::backend)?;
        Ok(row.map(|r| r.get::<Vec<u8>, _>("state")))
    }

    /// Upsert a thread-state blob.
    pub async fn put_thread_state(&self, thread_id: &str, state: &[u8], now_ms: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO thread_state (thread_id, state, updated_ts)
             VALUES ($1, $2, $3)
             ON CONFLICT (thread_id) DO UPDATE SET state = $2, updated_ts = $3",
        )
        .bind(thread_id)
        .bind(state)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(StoreError::backend)?;
        Ok(())
    }

    /// Record an alert id for dedupe; `true` if newly inserted.
    pub async fn dedupe_alert(&self, dedupe: &AlertDedupe) -> Result<bool> {
        let res = sqlx::query(
            "INSERT INTO alert_dedupe (alert_id, ts) VALUES ($1, $2)
             ON CONFLICT (alert_id) DO NOTHING",
        )
        .bind(&dedupe.alert_id)
        .bind(dedupe.ts)
        .execute(&self.pool)
        .await
        .map_err(StoreError::backend)?;
        Ok(res.rows_affected() == 1)
    }

    /// Read a config value.
    pub async fn config_get(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT v FROM config_kv WHERE k = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::backend)?;
        Ok(row.map(|r| r.get::<String, _>("v")))
    }

    /// Upsert a config value.
    pub async fn config_put(&self, key: &str, value: &str, now_ms: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO config_kv (k, v, updated_ts) VALUES ($1, $2, $3)
             ON CONFLICT (k) DO UPDATE SET v = $2, updated_ts = $3",
        )
        .bind(key)
        .bind(value)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(StoreError::backend)?;
        Ok(())
    }

    /// Lookup evidence metadata for an audit id.
    pub async fn evidence_for(&self, audit_id: i64) -> Result<Option<EvidenceMeta>> {
        let row = sqlx::query(
            "SELECT audit_id, sha256, phash, safe_thumbnail_ref, label
             FROM evidence_meta WHERE audit_id = $1",
        )
        .bind(audit_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::backend)?;
        Ok(row.map(|r| EvidenceMeta {
            audit_id: r.get("audit_id"),
            sha256: r.get("sha256"),
            phash: r.get("phash"),
            safe_thumbnail_ref: r.get("safe_thumbnail_ref"),
            label: r.get("label"),
        }))
    }

    /// Apply retention auto-purge at `now_ms` (same policy semantics as the
    /// SQLite backend; see [`crate::sqlite::SqliteStore::purge_expired_sync`]).
    pub async fn purge_expired(&self, now_ms: i64) -> Result<PurgeReport> {
        let p = &self.retention;
        let mut report = PurgeReport::default();
        let mut tx = self.pool.begin().await.map_err(StoreError::backend)?;

        if let Some(cutoff) = p.evidence_cutoff_ms(now_ms) {
            let n = sqlx::query(
                "DELETE FROM evidence_meta
                 WHERE audit_id IN (SELECT id FROM audit_log WHERE ts < $1)",
            )
            .bind(cutoff)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::backend)?;
            report.evidence_rows_purged = n.rows_affected();
        }

        if let Some(cutoff) = p.audit_cutoff_ms(now_ms) {
            let n = sqlx::query("DELETE FROM audit_log WHERE ts < $1")
                .bind(cutoff)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::backend)?;
            report.audit_rows_aged_out = n.rows_affected();
        }

        if p.audit_max_rows > 0 {
            let n = sqlx::query(
                "DELETE FROM audit_log WHERE id IN (
                    SELECT id FROM audit_log ORDER BY id DESC OFFSET $1
                 )",
            )
            .bind(p.audit_max_rows as i64)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::backend)?;
            report.audit_rows_rotated = n.rows_affected();
        }

        tx.commit().await.map_err(StoreError::backend)?;
        Ok(report)
    }
}

/// Map a Postgres `audit_log` row to an [`AuditRow`].
fn row_to_audit(r: &sqlx::postgres::PgRow) -> Result<AuditRow> {
    let reason_json: String = r.get("reason_codes");
    let reason_codes: Vec<String> = serde_json::from_str(&reason_json).unwrap_or_default();
    Ok(AuditRow {
        id: r.get("id"),
        ts: r.get("ts"),
        device_id: r.get("device_id"),
        category: r.get("category"),
        action: r.get("action"),
        severity: r.get("severity"),
        score: r.get("score"),
        reason_codes,
        model_id: r.get("model_id"),
        app: r.get("app"),
        alert_kind: r.get("alert_kind"),
        content_sha256: r.get("content_sha256"),
    })
}
