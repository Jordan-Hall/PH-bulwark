//! SQL schema (DDL) shared by both backends, plus the **no-content invariant**
//! enforced structurally and asserted by test.
//!
//! `docs/security/data-handling.md` §2 hard rule: **C0 data (message text /
//! explicit media bytes / raw decrypted bodies) may not be written anywhere
//! persistent.** We enforce that by *shape*: the tables below have **no column
//! capable of holding message text or media bytes**.
//!
//! What that means concretely, table by table:
//!
//! * `audit_log` — discriminants (category/action/severity), a float score, a
//!   JSON array of **reason codes** (stable rule names, NOT text), provenance
//!   strings (`model_id`, `app`), a **hex content hash**, and the hash-chain
//!   columns. No `message`, `body`, `transcript`, `text`, or `blob` column.
//! * `evidence_meta` — `sha256` + `phash` (hex strings), a thumbnail
//!   **reference** string, a label. No pixel/blob column.
//! * `thread_state` — a serialized grooming `ThreadState` blob. By the
//!   `aegis-text` contract (see `state.rs`) that blob is category names +
//!   timestamps + counts only — never message text. Stored as a bounded blob;
//!   its content-freeness is the producer's typed invariant.
//! * `alert_dedupe` — alert id + timestamp. No content.
//! * `config_kv` — operational config (C3/C4) key/value. Not a content channel.
//!
//! The two backends differ only in dialect (`INTEGER`/`BLOB` vs.
//! `BIGINT`/`BYTEA`, `?` vs. `$n` placeholders); the column *set* is identical
//! and the invariant test runs against the shared column lists in
//! [`ALL_TABLES`].

/// A column description used both to render DDL and to assert the no-content
/// invariant in tests.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Column {
    /// Column name.
    pub name: &'static str,
    /// Logical type (backend-agnostic; mapped to dialect in the adapters).
    pub ty: ColType,
}

/// Backend-agnostic column types. Crucially there is **no** `Text` or `Bytes`
/// type that is allowed to hold *content*; the only blob is the explicitly
/// content-free [`ColType::StateBlob`] (serialized `ThreadState`) and the only
/// strings are bounded codes/refs/hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColType {
    /// 64-bit integer (id, timestamp, enum discriminant).
    Int,
    /// 32-bit float (normalized score).
    Float,
    /// A short, bounded identifier / code / reference string (device id, app,
    /// model id, reason-code JSON array, hex hash, thumbnail ref, config value).
    /// Audited to never carry message text — see [`tests::no_content_columns`].
    Code,
    /// The serialized grooming `ThreadState` blob (category names + timestamps +
    /// counts; content-free by the `aegis-text` producer contract).
    StateBlob,
}

/// Column set for one table (used by the invariant test).
#[derive(Debug, Clone, Copy)]
pub struct Table {
    /// Table name.
    pub name: &'static str,
    /// Columns in declaration order.
    pub columns: &'static [Column],
}

// A `const fn` (NOT a fn-pointer `const`): calling a function pointer in a
// `const` context — as the column arrays below do — is not permitted, whereas a
// `const fn` call is. `#[allow(non_snake_case)]` keeps the terse `C(...)` name.
#[allow(non_snake_case)]
const fn C(name: &'static str, ty: ColType) -> Column {
    Column { name, ty }
}

/// `audit_log` columns (class C3, tamper-evident).
pub const AUDIT_LOG_COLUMNS: &[Column] = &[
    C("id", ColType::Int),
    C("ts", ColType::Int),
    C("device_id", ColType::Code),
    C("category", ColType::Int),
    C("action", ColType::Int),
    C("severity", ColType::Int),
    C("score", ColType::Float),
    C("reason_codes", ColType::Code), // JSON array of stable codes — NOT text
    C("model_id", ColType::Code),
    C("app", ColType::Code),
    C("alert_kind", ColType::Int),
    C("content_sha256", ColType::Code), // hex hash, never the media
    C("prev_hash", ColType::Code),      // hex, hash-chain
    C("row_hash", ColType::Code),       // hex, hash-chain
];

/// `evidence_meta` columns (class C1).
pub const EVIDENCE_META_COLUMNS: &[Column] = &[
    C("audit_id", ColType::Int),
    C("sha256", ColType::Code),
    C("phash", ColType::Code),
    C("safe_thumbnail_ref", ColType::Code), // reference, NOT pixels
    C("label", ColType::Code),
];

/// `thread_state` columns.
pub const THREAD_STATE_COLUMNS: &[Column] = &[
    C("thread_id", ColType::Code),
    C("state", ColType::StateBlob), // serialized ThreadState (content-free)
    C("updated_ts", ColType::Int),
];

/// `alert_dedupe` columns (class C3).
pub const ALERT_DEDUPE_COLUMNS: &[Column] = &[C("alert_id", ColType::Code), C("ts", ColType::Int)];

/// `config_kv` columns (class C3/C4).
pub const CONFIG_KV_COLUMNS: &[Column] = &[
    C("k", ColType::Code),
    C("v", ColType::Code),
    C("updated_ts", ColType::Int),
];

/// Every table's shape — the single list the no-content invariant test walks.
pub const ALL_TABLES: &[Table] = &[
    Table {
        name: "audit_log",
        columns: AUDIT_LOG_COLUMNS,
    },
    Table {
        name: "evidence_meta",
        columns: EVIDENCE_META_COLUMNS,
    },
    Table {
        name: "thread_state",
        columns: THREAD_STATE_COLUMNS,
    },
    Table {
        name: "alert_dedupe",
        columns: ALERT_DEDUPE_COLUMNS,
    },
    Table {
        name: "config_kv",
        columns: CONFIG_KV_COLUMNS,
    },
];

// --- SQLite DDL ------------------------------------------------------------

/// SQLite DDL run once at open (idempotent). Applies to the SQLCipher-encrypted
/// client database. No column can hold message text or media bytes.
#[cfg(feature = "sqlite")]
pub const SQLITE_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY,        -- chain position (monotonic)
    ts              INTEGER NOT NULL,
    device_id       TEXT    NOT NULL,
    category        INTEGER NOT NULL,
    action          INTEGER NOT NULL,
    severity        INTEGER NOT NULL,
    score           REAL    NOT NULL,
    reason_codes    TEXT    NOT NULL DEFAULT '[]',  -- JSON array of CODES, not text
    model_id        TEXT    NOT NULL DEFAULT '',
    app             TEXT    NOT NULL DEFAULT '',
    alert_kind      INTEGER,
    content_sha256  TEXT    NOT NULL DEFAULT '',    -- hex hash, never the media
    prev_hash       TEXT    NOT NULL,               -- hex, tamper-evident chain
    row_hash        TEXT    NOT NULL                -- hex, tamper-evident chain
);
CREATE INDEX IF NOT EXISTS idx_audit_device_ts ON audit_log(device_id, ts);

CREATE TABLE IF NOT EXISTS evidence_meta (
    audit_id            INTEGER NOT NULL REFERENCES audit_log(id) ON DELETE CASCADE,
    sha256              TEXT    NOT NULL,
    phash               TEXT    NOT NULL DEFAULT '',
    safe_thumbnail_ref  TEXT,                       -- reference only, NOT pixels
    label               TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_evidence_audit ON evidence_meta(audit_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha ON evidence_meta(sha256);

CREATE TABLE IF NOT EXISTS thread_state (
    thread_id   TEXT    PRIMARY KEY,
    state       BLOB    NOT NULL,                   -- serialized ThreadState (content-free)
    updated_ts  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_dedupe (
    alert_id    TEXT    PRIMARY KEY,
    ts          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS config_kv (
    k           TEXT    PRIMARY KEY,
    v           TEXT    NOT NULL,
    updated_ts  INTEGER NOT NULL
);
"#;

// --- Postgres DDL ----------------------------------------------------------

/// Postgres DDL for the shared cluster state. Same column set; Postgres dialect.
/// At-rest encryption is provided by the database/volume (data-handling.md §3).
#[cfg(feature = "postgres")]
pub const POSTGRES_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGINT  PRIMARY KEY,
    ts              BIGINT  NOT NULL,
    device_id       TEXT    NOT NULL,
    category        INTEGER NOT NULL,
    action          INTEGER NOT NULL,
    severity        INTEGER NOT NULL,
    score           REAL    NOT NULL,
    reason_codes    TEXT    NOT NULL DEFAULT '[]',
    model_id        TEXT    NOT NULL DEFAULT '',
    app             TEXT    NOT NULL DEFAULT '',
    alert_kind      INTEGER,
    content_sha256  TEXT    NOT NULL DEFAULT '',
    prev_hash       TEXT    NOT NULL,
    row_hash        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_device_ts ON audit_log(device_id, ts);

CREATE TABLE IF NOT EXISTS evidence_meta (
    audit_id            BIGINT  NOT NULL REFERENCES audit_log(id) ON DELETE CASCADE,
    sha256              TEXT    NOT NULL,
    phash               TEXT    NOT NULL DEFAULT '',
    safe_thumbnail_ref  TEXT,
    label               TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_evidence_audit ON evidence_meta(audit_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha ON evidence_meta(sha256);

CREATE TABLE IF NOT EXISTS thread_state (
    thread_id   TEXT    PRIMARY KEY,
    state       BYTEA   NOT NULL,
    updated_ts  BIGINT  NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_dedupe (
    alert_id    TEXT    PRIMARY KEY,
    ts          BIGINT  NOT NULL
);

CREATE TABLE IF NOT EXISTS config_kv (
    k           TEXT    PRIMARY KEY,
    v           TEXT    NOT NULL,
    updated_ts  BIGINT  NOT NULL
);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// CRITICAL invariant (data-handling.md §2 hard rule): the audit + evidence
    /// schema must have **no column that could hold message text or media bytes**.
    ///
    /// We assert this two ways:
    /// 1. No column may use a free-content type. The only blob in the schema is
    ///    the explicitly content-free `ThreadState` state blob; nothing is typed
    ///    to hold media bytes or a message body.
    /// 2. No column name may match a content-bearing name (message/body/text/
    ///    transcript/media/image/payload/blob/content/snippet/caption/raw…) in
    ///    the audit or evidence tables.
    #[test]
    fn no_content_columns() {
        // Names that would indicate a content channel and must NOT appear in the
        // audit or evidence tables.
        const FORBIDDEN_SUBSTRINGS: &[&str] = &[
            "message",
            "body",
            "transcript",
            "media",
            "image",
            "frame",
            "audio",
            "video",
            "payload",
            "blob",
            "content_text",
            "snippet",
            "caption",
            "raw",
            "plaintext",
            "thumbnail_data",
            "pixels",
            "bytes",
        ];

        for table in ALL_TABLES {
            // Only `thread_state.state` may be a StateBlob, and nothing anywhere
            // may be a content blob/text type beyond that.
            for col in table.columns {
                if col.ty == ColType::StateBlob {
                    assert_eq!(
                        (table.name, col.name),
                        ("thread_state", "state"),
                        "the ONLY content-free state blob is thread_state.state; \
                         {}.{} must not be a StateBlob",
                        table.name,
                        col.name
                    );
                }
            }

            // The audit + evidence tables are the C0-adjacent ones: assert no
            // content-bearing column NAME slips in.
            if table.name == "audit_log" || table.name == "evidence_meta" {
                for col in table.columns {
                    let lname = col.name.to_ascii_lowercase();
                    for bad in FORBIDDEN_SUBSTRINGS {
                        assert!(
                            !lname.contains(bad),
                            "{}.{} looks like a content column (matches {:?}) — \
                             data-handling.md forbids persisting C0 content",
                            table.name,
                            col.name,
                            bad
                        );
                    }
                    // And no raw byte/text *content* type in these two tables —
                    // only Int / Float / bounded Code are permitted.
                    assert!(
                        matches!(col.ty, ColType::Int | ColType::Float | ColType::Code),
                        "{}.{} has a non-metadata type; audit/evidence rows are \
                         metadata-only",
                        table.name,
                        col.name
                    );
                }
            }
        }
    }

    /// The rendered SQLite DDL must likewise not introduce a content column that
    /// the typed table list above doesn't know about (guards against the DDL and
    /// the [`ALL_TABLES`] shape drifting apart).
    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_ddl_has_no_content_keywords() {
        let ddl = SQLITE_DDL.to_ascii_lowercase();
        for bad in [
            "message ",
            "body ",
            "transcript ",
            " media ",
            "payload ",
            "plaintext ",
        ] {
            assert!(
                !ddl.contains(bad),
                "SQLITE_DDL contains a content-like column token: {bad:?}"
            );
        }
        // Exactly one BLOB column is allowed (thread_state.state).
        assert_eq!(
            ddl.matches("blob").count(),
            1,
            "expected exactly one BLOB column (thread_state.state)"
        );
    }

    #[test]
    fn audit_table_has_chain_columns() {
        let names: Vec<&str> = AUDIT_LOG_COLUMNS.iter().map(|c| c.name).collect();
        assert!(names.contains(&"prev_hash"));
        assert!(names.contains(&"row_hash"));
    }
}
