//! Domain row types for the store, shaped to make the **no-content invariant**
//! structural (`docs/security/data-handling.md` §1–2).
//!
//! Every persisted row here carries **C1/C3** data only — verdict, reason
//! codes, severity, score, hashes, a safe-thumbnail *reference*, and metadata.
//! There is deliberately **no field** typed to hold message text or media bytes:
//!
//! * No `String` field is the message body. `text_snippet` does **not** live
//!   here — a redacted snippet belongs to alerting (`AlertEvent.redacted_context`),
//!   not the audit/evidence store. The audit row keeps only *reason codes*.
//! * No `Vec<u8>` field is media. The only byte fields are fixed-shape **hashes**
//!   (`sha256`, `phash`) and a thumbnail **reference string** (a content-address /
//!   keystore handle), never inline pixels.
//!
//! These types are the single source of truth for "what a row may contain"; the
//! SQL DDL in [`crate::schema`] mirrors them and a unit test
//! ([`crate::schema::tests`]) asserts neither shape exposes a content column.

use serde::{Deserialize, Serialize};

use aegis_proto::v1::{Action, AlertKind, Verdict};

/// The high-level event handed to [`crate::Store::record`] (mirrors
/// `StoredEvent` in interfaces.md). The verdict's `Evidence` is already redacted
/// by contract — this crate strips it further into [`AuditRow`] + [`EvidenceMeta`]
/// so no content can ride along even by accident.
#[derive(Clone, Debug)]
pub struct StoredEvent {
    /// Supervised device (mTLS client-cert subject).
    pub device: aegis_core::DeviceId,
    /// The verdict. `evidence` is redacted by the `Analyzer` contract; this crate
    /// persists only its derived fields (hashes / model id / reason).
    pub verdict: Verdict,
    /// Policy action that was taken.
    pub action: Action,
    /// Whether an alert fired (and its kind), if any.
    pub alert: Option<AlertKind>,
    /// Event timestamp, unix epoch millis.
    pub ts: i64,
}

/// A single tamper-evident audit-log row (table `audit_log`, class **C3**).
///
/// CONTENT INVARIANT: the only free-text-ish field is [`reason_codes`] — a list
/// of **stable reason / rule-category codes** (e.g. the eight grooming
/// indicators, `"nsfw_image"`, `"adult_text"`), NOT message text. There is no
/// column for a message body, transcript, or media.
///
/// [`reason_codes`]: AuditRow::reason_codes
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRow {
    /// Monotonic row id (chain position). Assigned by the store on insert.
    pub id: i64,
    /// Event timestamp, unix epoch millis.
    pub ts: i64,
    /// Supervised device id.
    pub device_id: String,
    /// Verdict category (enum discriminant; never free text).
    pub category: i32,
    /// Policy action taken (enum discriminant).
    pub action: i32,
    /// Severity band (enum discriminant).
    pub severity: i32,
    /// Normalized confidence score 0.0–1.0.
    pub score: f32,
    /// Stable reason / rule codes that fired (e.g. grooming indicators). NOT the
    /// message — codes only.
    pub reason_codes: Vec<String>,
    /// Which model/rule pack produced the verdict (auditable provenance).
    pub model_id: String,
    /// App / site involved (e.g. `"messenger"`, `"example.com"`).
    pub app: String,
    /// Alert kind raised for this event, if any (enum discriminant; None = no alert).
    pub alert_kind: Option<i32>,
    /// `sha256` of the analysed media, hex-encoded — identity/dedupe only, never
    /// the media itself. Empty for pure-text verdicts.
    pub content_sha256: String,
}

impl AuditRow {
    /// Build an audit row from a [`StoredEvent`], extracting **only** derived,
    /// content-free fields from the verdict + its evidence.
    pub fn from_event(id: i64, ev: &StoredEvent) -> Self {
        let v = &ev.verdict;
        let evidence = v.evidence.as_ref();
        let content_sha256 = evidence.map(|e| hex_encode(&e.sha256)).unwrap_or_default();
        let model_id = evidence.map(|e| e.model_id.clone()).unwrap_or_default();

        // Reason codes: the grooming indicator categories that fired, if present.
        // These are stable codes, never message text.
        let mut reason_codes: Vec<String> = Vec::new();
        if let Some(g) = v.grooming.as_ref() {
            reason_codes.extend(g.fired_categories.iter().cloned());
        }

        AuditRow {
            id,
            ts: ev.ts,
            device_id: ev.device.to_string(),
            category: v.category,
            action: ev.action as i32,
            severity: v.severity,
            score: v.score,
            reason_codes,
            model_id,
            app: derive_app(v),
            alert_kind: ev.alert.map(|k| k as i32),
            content_sha256,
        }
    }

    /// Reconstruct a (best-effort) [`StoredEvent`] view for the dashboard
    /// [`crate::Store::recent`] query. The original media is gone by design; the
    /// verdict is rebuilt from the derived fields only.
    pub fn to_event(&self) -> StoredEvent {
        use aegis_proto::v1::{Evidence, GroomingSignal};

        let evidence = Evidence {
            sha256: hex_decode(&self.content_sha256),
            perceptual_hash: Vec::new(),
            safe_thumbnail: Vec::new(),
            text_snippet: String::new(),
            model_id: self.model_id.clone(),
            model_version: String::new(),
        };
        let grooming = if self.reason_codes.is_empty() {
            None
        } else {
            Some(GroomingSignal {
                fired_categories: self.reason_codes.clone(),
                score: self.score,
                excerpt: String::new(),
                classifier_backed: false,
            })
        };
        let verdict = Verdict {
            request_id: String::new(),
            category: self.category,
            action: self.action,
            severity: self.severity,
            score: self.score,
            rationale: String::new(),
            evidence: Some(evidence),
            grooming,
            worker_id: String::new(),
            latency_ms: 0,
        };
        StoredEvent {
            device: aegis_core::DeviceId(self.device_id.clone()),
            verdict,
            action: action_from_i32(self.action),
            alert: self.alert_kind.and_then(alert_kind_from_i32),
            ts: self.ts,
        }
    }

    /// Canonical, stable byte encoding of the row's content-free fields for the
    /// tamper-evident hash chain. Deliberately excludes `id` (chain position is
    /// folded in by the chainer via `prev_hash`) and uses a fixed field order so
    /// the same logical row always hashes identically.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.ts.to_be_bytes());
        push_field(&mut buf, self.device_id.as_bytes());
        buf.extend_from_slice(&self.category.to_be_bytes());
        buf.extend_from_slice(&self.action.to_be_bytes());
        buf.extend_from_slice(&self.severity.to_be_bytes());
        buf.extend_from_slice(&self.score.to_be_bytes());
        // Reason codes are length-prefixed and joined so reordering changes the hash.
        buf.extend_from_slice(&(self.reason_codes.len() as u32).to_be_bytes());
        for code in &self.reason_codes {
            push_field(&mut buf, code.as_bytes());
        }
        push_field(&mut buf, self.model_id.as_bytes());
        push_field(&mut buf, self.app.as_bytes());
        buf.extend_from_slice(&self.alert_kind.unwrap_or(-1).to_be_bytes());
        push_field(&mut buf, self.content_sha256.as_bytes());
        buf
    }
}

/// Derived evidence metadata (table `evidence_meta`, class **C1**).
///
/// CONTENT INVARIANT: holds a crypto hash + perceptual hash + a *reference* to a
/// safe (blurred/cropped) thumbnail held elsewhere — **never** the thumbnail
/// pixels and never the original media. `data-handling.md` §"Redact / derive":
/// store hash + label; pixels, if any, are a separate SAFE artifact referenced
/// by handle.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceMeta {
    /// Foreign key back to the `audit_log` row this evidence belongs to.
    pub audit_id: i64,
    /// Content sha256, hex-encoded (identity / dedupe).
    pub sha256: String,
    /// Perceptual hash, hex-encoded (near-dup / known-hash matching).
    pub phash: String,
    /// Opaque reference to a SAFE thumbnail held in a content-addressed store /
    /// keystore (e.g. `"thumb://<sha256>"`). NOT the pixels. `None` = hash-only.
    pub safe_thumbnail_ref: Option<String>,
    /// Stable label for the evidence (e.g. category code), for the review UI.
    pub label: String,
}

/// A row in the `alert_dedupe` table (class **C3**): just an alert id + when it
/// was seen, so retries are suppressed. No content.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlertDedupe {
    /// Idempotency key from `AlertEvent.alert_id`.
    pub alert_id: String,
    /// When the alert was first seen, unix epoch millis.
    pub ts: i64,
}

// --- helpers ---------------------------------------------------------------

/// Length-prefix a field into the canonical buffer so concatenation is
/// unambiguous (prevents `"ab"+"c"` colliding with `"a"+"bc"`).
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

/// `aegis-proto` does not give us the app string on the verdict directly; it
/// lives on the request. We keep an empty default and let the SQLite/Postgres
/// adapters override it from the request side when available.
fn derive_app(_v: &Verdict) -> String {
    String::new()
}

fn action_from_i32(v: i32) -> Action {
    Action::try_from(v).unwrap_or(Action::Unspecified)
}

fn alert_kind_from_i32(v: i32) -> Option<AlertKind> {
    AlertKind::try_from(v).ok()
}

/// Lowercase hex-encode bytes (no external dep; small fixed-shape inputs only).
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode a lowercase/uppercase hex string back to bytes (best-effort; invalid
/// input yields an empty vec rather than erroring — this is a read-back path).
pub fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in bytes.chunks_exact(2) {
        match (val(pair[0]), val(pair[1])) {
            (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
            _ => return Vec::new(),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::v1::{Category, Evidence, GroomingSignal, Severity};

    fn sample_event() -> StoredEvent {
        let verdict = Verdict {
            request_id: "r1".into(),
            category: Category::Grooming as i32,
            action: Action::Block as i32,
            severity: Severity::High as i32,
            score: 0.82,
            rationale: "secrecy + image request".into(),
            evidence: Some(Evidence {
                sha256: vec![0xde, 0xad, 0xbe, 0xef],
                perceptual_hash: vec![0x01, 0x02],
                safe_thumbnail: Vec::new(),
                text_snippet: String::new(),
                model_id: "grooming-rules-v1".into(),
                model_version: "1.0".into(),
            }),
            grooming: Some(GroomingSignal {
                fired_categories: vec!["secrecy".into(), "image_request".into()],
                score: 0.82,
                excerpt: String::new(),
                classifier_backed: false,
            }),
            worker_id: "w1".into(),
            latency_ms: 12,
        };
        StoredEvent {
            device: aegis_core::DeviceId("dev-1".into()),
            verdict,
            action: Action::Block,
            alert: Some(AlertKind::GroomingSuspected),
            ts: 1_700_000_000_000,
        }
    }

    #[test]
    fn audit_row_extracts_only_derived_fields() {
        let row = AuditRow::from_event(1, &sample_event());
        assert_eq!(row.content_sha256, "deadbeef");
        assert_eq!(row.model_id, "grooming-rules-v1");
        assert_eq!(row.reason_codes, vec!["secrecy", "image_request"]);
        assert_eq!(row.category, Category::Grooming as i32);
        assert_eq!(row.alert_kind, Some(AlertKind::GroomingSuspected as i32));
    }

    #[test]
    fn canonical_bytes_are_order_sensitive() {
        let mut a = AuditRow::from_event(1, &sample_event());
        let before = a.canonical_bytes();
        a.reason_codes.reverse();
        assert_ne!(before, a.canonical_bytes());
    }

    #[test]
    fn hex_round_trips() {
        let b = vec![0x00, 0x10, 0xff, 0xab];
        assert_eq!(hex_decode(&hex_encode(&b)), b);
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_decode("zz"), Vec::<u8>::new());
    }
}
