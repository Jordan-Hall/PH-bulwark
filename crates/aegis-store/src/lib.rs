//! # aegis-store — redacted event/verdict persistence (the [`Store`] contract).
//!
//! Implements the [`Store`] trait from `docs/design/interfaces.md` with **two
//! adapters behind one trait**:
//!
//! * [`SqliteStore`] — **client/local**: encrypted SQLite via **SQLCipher**
//!   (`rusqlite` `bundled-sqlcipher`). The whole DB is encrypted at rest; the
//!   key comes from the OS keystore (see [`crypto`]).
//! * [`PostgresStore`] — **server/cluster**: shared state via **Postgres**
//!   (`sqlx`); at-rest encryption from the deployment, access over mTLS.
//!
//! ## The no-content invariant (data-handling.md §1–2)
//!
//! This crate persists **C1/C3 data only** — verdict + reason codes + severity +
//! score + content **hashes** + a safe-thumbnail **reference** + metadata.
//! **It never persists C0**: message text, explicit media bytes, raw decrypted
//! bodies, or raw OCR plaintext. That is enforced *structurally* by the table
//! shapes in [`schema`] (no column is typed to hold a message body or media
//! bytes) and asserted by [`schema`]'s `no_content_columns` test. The
//! `Verdict.evidence` handed in is already redacted by the `Analyzer` contract;
//! [`model::AuditRow::from_event`] strips it further to derived fields only.
//!
//! ## Tamper-evident audit log
//!
//! Every `audit_log` row extends a SHA-256 (optionally HMAC-keyed) **hash chain**
//! (`prev_hash + canonical(row) → row_hash`, see [`hashchain`]). Editing,
//! deleting, or reordering a row breaks the chain and is detected by
//! `verify_audit_chain`. Encryption-at-rest hides the data; the chain proves it
//! was not altered.
//!
//! ## Retention / auto-purge (data-handling.md §4)
//!
//! [`retention::RetentionPolicy`] (default: C1 evidence 30 days, C3 audit ring
//! 90 days + size cap) drives `purge_expired`, which a scheduler runs on the
//! retention clock.
//!
//! ## Constraints
//! `#![forbid(unsafe_code)]`. **No AI/ML. No telemetry.** The only persistence is
//! local (SQLite) or the owner's own cluster (Postgres).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod error;
pub mod hashchain;
pub mod model;
pub mod retention;
pub mod schema;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "portable")]
pub mod portable;

// --- Public API re-exports -------------------------------------------------

pub use crypto::{AgeExporter, AtRestKey};
pub use error::{Result as StoreResult, StoreError};
pub use hashchain::Verify;
pub use model::{AlertDedupe, AuditRow, EvidenceMeta, StoredEvent};
pub use retention::{PurgeReport, RetentionPolicy};
pub use schema::{Column, ColType, Table, ALL_TABLES};

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;

#[cfg(feature = "postgres")]
pub use postgres::PostgresStore;

#[cfg(feature = "portable")]
pub use portable::PortableStore;

use aegis_core::DeviceId;

/// Open an ephemeral in-memory [`Store`] using the best available backend:
/// encrypted SQLite when the `sqlite` feature is enabled, otherwise the
/// dependency-free [`PortableStore`] (which builds on any host — including
/// locked-down Windows where the bundled-SQLite C compile is blocked). Binaries
/// should call this backend-agnostic entry point rather than a concrete type.
pub fn open_in_memory() -> aegis_core::Result<std::sync::Arc<dyn Store>> {
    #[cfg(feature = "sqlite")]
    {
        return SqliteStore::open_in_memory();
    }
    #[cfg(all(not(feature = "sqlite"), feature = "portable"))]
    {
        portable::PortableStore::open_in_memory()
    }
    #[cfg(all(not(feature = "sqlite"), not(feature = "portable")))]
    {
        return Err(aegis_core::Error::Other(anyhow::anyhow!(
            "aegis-store: no in-memory store backend enabled (enable `portable` or `sqlite`)"
        )));
    }
}

/// Persists redacted events/verdicts (interfaces.md `Store`). One trait, two
/// adapters ([`SqliteStore`] client, [`PostgresStore`] server).
///
/// **Never stores explicit media** — only the redacted/derived fields of a
/// [`StoredEvent`] (the `Verdict.evidence` is already redacted by the `Analyzer`
/// contract, and this crate strips it further to hashes/codes/metadata).
///
/// The trait surface is exactly the contract from interfaces.md; the
/// integrity/retention extras (audit-chain verification, purge) are exposed as
/// additional methods with safe defaults so the contract callers are unaffected.
#[async_trait::async_trait]
pub trait Store: Send + Sync {
    /// Record one redacted event (audit row + optional evidence metadata). The
    /// audit row extends the tamper-evident hash chain.
    async fn record(&self, event: StoredEvent) -> aegis_core::Result<()>;

    /// Recent events for the dashboard / coverage matrix (newest first, paged).
    async fn recent(&self, device: &DeviceId, limit: u32)
        -> aegis_core::Result<Vec<StoredEvent>>;

    /// Conversation state blob for the grooming state machine (thread-scoped).
    /// The blob is content-free by the `aegis-text` producer contract.
    async fn thread_state(&self, thread_id: &str) -> aegis_core::Result<Option<Vec<u8>>>;

    /// Upsert a conversation-state blob.
    async fn put_thread_state(&self, thread_id: &str, state: &[u8]) -> aegis_core::Result<()>;

    /// Verify the tamper-evident audit hash chain. `Ok(())` = intact; an error
    /// (`aegis_core::Error` wrapping [`StoreError::Integrity`]) names the first
    /// tampered row. Default impl: assume integrity is backend-checked elsewhere.
    async fn verify_audit_chain(&self) -> aegis_core::Result<()> {
        Ok(())
    }

    /// Run the retention auto-purge at `now_ms`. Default impl: no-op (a backend
    /// without retention overrides this).
    async fn purge_expired(&self, _now_ms: i64) -> aegis_core::Result<PurgeReport> {
        Ok(PurgeReport::default())
    }
}

/// Current unix epoch millis (used as the default `now` for timestamps/purge).
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "portable"))]
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(feature = "sqlite")]
#[async_trait::async_trait]
impl Store for SqliteStore {
    async fn record(&self, event: StoredEvent) -> aegis_core::Result<()> {
        self.record_sync(&event)?;
        Ok(())
    }

    async fn recent(
        &self,
        device: &DeviceId,
        limit: u32,
    ) -> aegis_core::Result<Vec<StoredEvent>> {
        Ok(self.recent_sync(device.0.as_str(), limit)?)
    }

    async fn thread_state(&self, thread_id: &str) -> aegis_core::Result<Option<Vec<u8>>> {
        Ok(self.thread_state_sync(thread_id)?)
    }

    async fn put_thread_state(&self, thread_id: &str, state: &[u8]) -> aegis_core::Result<()> {
        self.put_thread_state_sync(thread_id, state, now_ms())?;
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

#[cfg(feature = "postgres")]
#[async_trait::async_trait]
impl Store for PostgresStore {
    async fn record(&self, event: StoredEvent) -> aegis_core::Result<()> {
        PostgresStore::record(self, &event).await?;
        Ok(())
    }

    async fn recent(
        &self,
        device: &DeviceId,
        limit: u32,
    ) -> aegis_core::Result<Vec<StoredEvent>> {
        Ok(PostgresStore::recent(self, device.0.as_str(), limit).await?)
    }

    async fn thread_state(&self, thread_id: &str) -> aegis_core::Result<Option<Vec<u8>>> {
        Ok(PostgresStore::thread_state(self, thread_id).await?)
    }

    async fn put_thread_state(&self, thread_id: &str, state: &[u8]) -> aegis_core::Result<()> {
        PostgresStore::put_thread_state(self, thread_id, state, now_ms()).await?;
        Ok(())
    }

    async fn verify_audit_chain(&self) -> aegis_core::Result<()> {
        PostgresStore::verify_audit_chain(self).await?;
        Ok(())
    }

    async fn purge_expired(&self, now_ms: i64) -> aegis_core::Result<PurgeReport> {
        Ok(PostgresStore::purge_expired(self, now_ms).await?)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod store_trait_tests {
    use super::*;
    use aegis_proto::v1::{Action, Category, Severity, Verdict};

    fn store() -> SqliteStore {
        let key = AtRestKey::new(vec![3u8; 32]).unwrap();
        SqliteStore::open_in_memory_with(&key, RetentionPolicy::default()).unwrap()
    }

    fn event(ts: i64) -> StoredEvent {
        StoredEvent {
            device: DeviceId("dev-1".into()),
            verdict: Verdict {
                request_id: "r".into(),
                category: Category::AdultText as i32,
                action: Action::Warn as i32,
                severity: Severity::Medium as i32,
                score: 0.6,
                rationale: String::new(),
                evidence: None,
                grooming: None,
                worker_id: String::new(),
                latency_ms: 0,
            },
            action: Action::Warn,
            alert: None,
            ts,
        }
    }

    #[tokio::test]
    async fn trait_record_recent_and_verify() {
        let s = store();
        Store::record(&s, event(1)).await.unwrap();
        Store::record(&s, event(2)).await.unwrap();

        let recent = Store::recent(&s, &DeviceId("dev-1".into()), 10)
            .await
            .unwrap();
        assert_eq!(recent.len(), 2);

        // Tamper-evidence is reachable through the trait.
        Store::verify_audit_chain(&s).await.unwrap();
    }

    #[tokio::test]
    async fn trait_thread_state_and_purge() {
        let s = store();
        Store::put_thread_state(&s, "t1", b"\x09\x09")
            .await
            .unwrap();
        let got = Store::thread_state(&s, "t1").await.unwrap();
        assert_eq!(got.unwrap(), b"\x09\x09");

        let report = Store::purge_expired(&s, i64::MAX / 2).await.unwrap();
        // Default retention: everything is far past the cutoff at this `now`.
        let _ = report.total();
    }
}
