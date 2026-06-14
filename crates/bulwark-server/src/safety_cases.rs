//! Safety-report queue — the NCMEC escalation **workflow state machine** for
//! `CSAM_SUSPECTED` events (StaffAdmin increment 3, SAFETY_OFFICER + ADMIN).
//!
//! CONTENT-FREE BY SHAPE: a case carries a case id, the content sha256 +
//! perceptual hash, the category, a region-granularity jurisdiction, the
//! workflow state, an opaque NCMEC report reference, and timestamps — and
//! NOTHING ELSE. There is **no media to review** (report-never-store): this
//! queue manages *legal workflow state*, never content. By construction there
//! is no field that could carry media, names, message text, or per-child /
//! per-device identifiers. See docs/design/staff-management-system.md §1/§7.
//!
//! State is in-memory (`Arc<Mutex<…>>`) with optional write-through JSON
//! persistence under `BULWARK_STATE_DIR` — the SAME [`JsonFile`] pattern as
//! [`StaffStore`](crate::staff::StaffStore). The store is plain CRUD plus a
//! transition validator; the tamper-evident audit of every transition lives in
//! the staff hash chain ([`StaffStore::audit_append`](crate::staff::StaffStore::audit_append)),
//! appended by the service layer — exactly like the guardian-support RPCs.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::accounts::to_hex;
use crate::persist::JsonFile;
use bulwark_proto::v1::{SafetyCase, SafetyCaseState};
use ring::rand::{SecureRandom, SystemRandom};

/// Case-id entropy (16 bytes → 32 hex chars). Content-free random id.
const CASE_ID_BYTES: usize = 16;

/// Max stored `jurisdiction` length. Region codes are short ("uk", "us",
/// "eu-west-2"); capping here keeps the field REGION-granular by construction,
/// so a caller cannot smuggle a finer locality string into the content-free
/// case record (defence-in-depth — the caller is already an authorized officer).
const JURISDICTION_MAX_LEN: usize = 16;

/// Normalize a jurisdiction to the documented region granularity: trimmed,
/// lowercased, and length-capped (by `char`, so a multibyte input can never
/// panic on a byte boundary). NOT a content field — a coarse region code.
fn normalize_jurisdiction(jurisdiction: &str) -> String {
    jurisdiction
        .trim()
        .to_lowercase()
        .chars()
        .take(JURISDICTION_MAX_LEN)
        .collect()
}

/// Errors a safety-case operation can produce; the service maps them onto a
/// tonic `Status`. Deliberately small and content-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyCaseError {
    /// A required field was empty or malformed (e.g. an empty content hash).
    Validation(&'static str),
    /// No case exists with the supplied id.
    NotFound,
    /// The requested workflow transition is not a valid successor of the
    /// current state (a skip, a move out of a terminal state, or UNSPECIFIED).
    InvalidTransition,
    /// RNG failure — never a content leak.
    Internal,
}

/// Is `to` a valid one-step successor of `from` in the NCMEC workflow?
///
/// Forward path: OPENED → UNDER_REVIEW → REPORTED_NCMEC → LAW_ENFORCEMENT →
/// CLOSED. A REPORTED_NCMEC case may ALSO close directly (REPORTED_NCMEC →
/// CLOSED): many NCMEC reports are triaged + resolved without a separate law-
/// enforcement handoff, so forcing every reported case through LAW_ENFORCEMENT
/// would misrecord the legal workflow. REJECTED is reachable from OPENED or
/// UNDER_REVIEW (triaged as not a genuine case). CLOSED and REJECTED are
/// terminal — no edge leaves them. UNSPECIFIED is never a valid source/target.
fn is_valid_transition(from: SafetyCaseState, to: SafetyCaseState) -> bool {
    use SafetyCaseState::*;
    matches!(
        (from, to),
        (Opened, UnderReview)
            | (Opened, Rejected)
            | (UnderReview, ReportedNcmec)
            | (UnderReview, Rejected)
            | (ReportedNcmec, LawEnforcement)
            | (ReportedNcmec, Closed)
            | (LawEnforcement, Closed)
    )
}

/// One stored case (also the in-memory form). Mirrors the proto `SafetyCase`
/// field-for-field; hashes are kept as lowercase hex in JSON for readability
/// and converted to `bytes` at the proto boundary.
#[derive(Clone, Serialize, Deserialize)]
struct CaseRec {
    case_id: String,
    /// Content sha256, lowercase hex (empty only for a malformed legacy row).
    sha256_hex: String,
    /// Perceptual hash, lowercase hex (may be empty — pHash is optional).
    phash_hex: String,
    /// `Category` enum as i32 (reused from the shared proto enum).
    category: i32,
    /// Region granularity only ("uk" | "us" | ...). Never a finer locality.
    jurisdiction: String,
    /// `SafetyCaseState` enum as i32.
    state: i32,
    /// Opaque NCMEC report reference (set at the REPORTED_NCMEC transition).
    ncmec_reference: String,
    opened_ts: i64,
    updated_ts: i64,
}

impl CaseRec {
    /// Project to the content-free proto message.
    fn to_proto(&self) -> SafetyCase {
        SafetyCase {
            case_id: self.case_id.clone(),
            sha256: hex_to_bytes(&self.sha256_hex),
            perceptual_hash: hex_to_bytes(&self.phash_hex),
            category: self.category,
            jurisdiction: self.jurisdiction.clone(),
            state: self.state,
            ncmec_reference: self.ncmec_reference.clone(),
            opened_ts: self.opened_ts,
            updated_ts: self.updated_ts,
        }
    }
}

/// Decode lowercase hex → bytes; a non-hex / odd-length string yields empty
/// (never a panic — a corrupt at-rest hash must not crash a read).
fn hex_to_bytes(s: &str) -> Vec<u8> {
    if !s.len().is_multiple_of(2) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16);
        let lo = (b[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
            _ => return Vec::new(),
        }
        i += 2;
    }
    out
}

#[derive(Default)]
struct Inner {
    /// case_id → record.
    by_id: HashMap<String, CaseRec>,
}

#[derive(Serialize, Deserialize, Default)]
struct CaseSnapshot {
    cases: Vec<CaseRec>,
}

/// Cloneable handle to the safety-case state. Every clone shares the same map.
#[derive(Clone)]
pub struct SafetyCaseStore {
    inner: Arc<Mutex<Inner>>,
    rng: Arc<SystemRandom>,
    /// `Some` → write-through `safety_cases.json` persistence; `None` → in-memory.
    persist: Option<JsonFile>,
}

impl Default for SafetyCaseStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyCaseStore {
    /// In-memory store (no persistence). Used by tests and stateless nodes.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            rng: Arc::new(SystemRandom::new()),
            persist: None,
        }
    }

    /// Durable store rooted at `dir`: loads `safety_cases.json` on startup and
    /// write-throughs every mutation. A corrupt file starts empty (logged) —
    /// the same lenient contract as
    /// [`StaffStore::with_state_dir`](crate::staff::StaffStore::with_state_dir);
    /// only an unusable directory is fatal.
    pub fn with_state_dir(dir: &Path) -> std::io::Result<Self> {
        let file = JsonFile::new(dir, "safety_cases.json")?;
        let snap: CaseSnapshot = file.load_or_default();
        let mut inner = Inner::default();
        for row in snap.cases {
            inner.by_id.insert(row.case_id.clone(), row);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            rng: Arc::new(SystemRandom::new()),
            persist: Some(file),
        })
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Random lowercase-hex id of `bytes` entropy.
    fn rand_hex(&self, bytes: usize) -> Result<String, SafetyCaseError> {
        let mut buf = vec![0u8; bytes];
        self.rng
            .fill(&mut buf)
            .map_err(|_| SafetyCaseError::Internal)?;
        Ok(to_hex(&buf))
    }

    /// Persist the current state under the held lock (consistent). A write
    /// failure is logged, never fatal — in-memory stays authoritative (the
    /// same contract as the account/staff stores).
    fn persist_locked(&self, inner: &Inner) {
        if let Some(file) = &self.persist {
            let mut cases: Vec<CaseRec> = inner.by_id.values().cloned().collect();
            cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
            if let Err(e) = file.store(&CaseSnapshot { cases }) {
                tracing::warn!(error = %e, "failed to persist safety cases; continuing in-memory");
            }
        }
    }

    /// Open a new case from a `CSAM_SUSPECTED` event: assigns a content-free
    /// case id, stamps `opened_ts`/`updated_ts`, and forces state = OPENED.
    /// `sha256` is required; `perceptual_hash` is optional. Returns the case.
    pub fn open_case(
        &self,
        sha256: &[u8],
        perceptual_hash: &[u8],
        category: i32,
        jurisdiction: &str,
    ) -> Result<SafetyCase, SafetyCaseError> {
        if sha256.is_empty() {
            return Err(SafetyCaseError::Validation("content sha256 is required"));
        }
        let case_id = self.rand_hex(CASE_ID_BYTES)?;
        let now = Self::now_ms();
        let rec = CaseRec {
            case_id: case_id.clone(),
            sha256_hex: to_hex(sha256),
            phash_hex: to_hex(perceptual_hash),
            category,
            jurisdiction: normalize_jurisdiction(jurisdiction),
            state: SafetyCaseState::Opened as i32,
            ncmec_reference: String::new(),
            opened_ts: now,
            updated_ts: now,
        };
        let proto = rec.to_proto();
        let mut inner = self.inner.lock().expect("safety-case mutex poisoned");
        inner.by_id.insert(case_id, rec);
        self.persist_locked(&inner);
        Ok(proto)
    }

    /// All cases, newest-opened first, optionally filtered by workflow state
    /// (`state_filter == UNSPECIFIED`/0 returns every state).
    pub fn list_cases(&self, state_filter: i32) -> Vec<SafetyCase> {
        let inner = self.inner.lock().expect("safety-case mutex poisoned");
        let mut cases: Vec<&CaseRec> = inner
            .by_id
            .values()
            .filter(|c| {
                state_filter == SafetyCaseState::Unspecified as i32 || c.state == state_filter
            })
            .collect();
        // Newest opened first; case_id as a stable tie-break for equal ts.
        cases.sort_by(|a, b| {
            b.opened_ts
                .cmp(&a.opened_ts)
                .then_with(|| a.case_id.cmp(&b.case_id))
        });
        cases.iter().map(|c| c.to_proto()).collect()
    }

    /// Fetch one case by id.
    pub fn get_case(&self, case_id: &str) -> Result<SafetyCase, SafetyCaseError> {
        let inner = self.inner.lock().expect("safety-case mutex poisoned");
        inner
            .by_id
            .get(case_id.trim())
            .map(CaseRec::to_proto)
            .ok_or(SafetyCaseError::NotFound)
    }

    /// Drive one case through a single validated workflow transition. Invalid
    /// edges (a skip, a move out of a terminal state, or an UNSPECIFIED target)
    /// are refused with `InvalidTransition`. A `REPORTED_NCMEC` transition
    /// requires a non-empty `ncmec_reference` (recorded on the case); the
    /// reference is ignored for other transitions. Stamps `updated_ts`.
    pub fn transition(
        &self,
        case_id: &str,
        new_state: i32,
        ncmec_reference: &str,
    ) -> Result<SafetyCase, SafetyCaseError> {
        let to =
            SafetyCaseState::try_from(new_state).map_err(|_| SafetyCaseError::InvalidTransition)?;
        let mut inner = self.inner.lock().expect("safety-case mutex poisoned");
        let rec = inner
            .by_id
            .get_mut(case_id.trim())
            .ok_or(SafetyCaseError::NotFound)?;
        let from =
            SafetyCaseState::try_from(rec.state).map_err(|_| SafetyCaseError::InvalidTransition)?;
        if !is_valid_transition(from, to) {
            return Err(SafetyCaseError::InvalidTransition);
        }
        if to == SafetyCaseState::ReportedNcmec && ncmec_reference.trim().is_empty() {
            return Err(SafetyCaseError::Validation(
                "ncmec_reference is required to report a case to NCMEC",
            ));
        }
        rec.state = new_state;
        if to == SafetyCaseState::ReportedNcmec {
            rec.ncmec_reference = ncmec_reference.trim().to_string();
        }
        rec.updated_ts = Self::now_ms();
        let proto = rec.to_proto();
        self.persist_locked(&inner);
        Ok(proto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_proto::v1::Category;

    fn store() -> SafetyCaseStore {
        SafetyCaseStore::new()
    }

    #[test]
    fn open_requires_a_content_hash_and_stamps_opened() {
        let s = store();
        assert_eq!(
            s.open_case(&[], &[], Category::CsamSuspected as i32, "uk")
                .unwrap_err(),
            SafetyCaseError::Validation("content sha256 is required")
        );
        let c = s
            .open_case(&[1, 2, 3, 4], &[9, 9], Category::CsamSuspected as i32, "uk")
            .unwrap();
        assert!(!c.case_id.is_empty());
        assert_eq!(c.state, SafetyCaseState::Opened as i32);
        assert_eq!(c.sha256, vec![1, 2, 3, 4]);
        assert_eq!(c.perceptual_hash, vec![9, 9]);
        assert_eq!(c.jurisdiction, "uk");
        assert!(c.opened_ts > 0 && c.updated_ts == c.opened_ts);
        assert!(c.ncmec_reference.is_empty());
    }

    #[test]
    fn jurisdiction_is_normalized_to_region_granularity() {
        let s = store();
        // Lowercased + trimmed…
        let c = s
            .open_case(&[1], &[], Category::CsamSuspected as i32, "  UK  ")
            .unwrap();
        assert_eq!(c.jurisdiction, "uk");
        // …and capped so a finer locality string can't be smuggled in.
        let c = s
            .open_case(
                &[2],
                &[],
                Category::CsamSuspected as i32,
                "123 Acacia Avenue, Sometown",
            )
            .unwrap();
        assert!(c.jurisdiction.chars().count() <= JURISDICTION_MAX_LEN);
    }

    /// Every workflow state, including UNSPECIFIED (never a valid source/target).
    const ALL_STATES: [SafetyCaseState; 7] = [
        SafetyCaseState::Unspecified,
        SafetyCaseState::Opened,
        SafetyCaseState::UnderReview,
        SafetyCaseState::ReportedNcmec,
        SafetyCaseState::LawEnforcement,
        SafetyCaseState::Closed,
        SafetyCaseState::Rejected,
    ];

    /// The COMPLETE spec of valid one-step edges — the single source of truth the
    /// matrix below checks `is_valid_transition` against. Forward path plus the
    /// documented `REPORTED_NCMEC → CLOSED` shortcut and the two REJECTED edges;
    /// CLOSED/REJECTED are terminal and UNSPECIFIED is never a source/target, so
    /// every pair NOT in this list must be refused.
    const VALID_EDGES: [(SafetyCaseState, SafetyCaseState); 7] = [
        (SafetyCaseState::Opened, SafetyCaseState::UnderReview),
        (SafetyCaseState::Opened, SafetyCaseState::Rejected),
        (SafetyCaseState::UnderReview, SafetyCaseState::ReportedNcmec),
        (SafetyCaseState::UnderReview, SafetyCaseState::Rejected),
        (
            SafetyCaseState::ReportedNcmec,
            SafetyCaseState::LawEnforcement,
        ),
        (SafetyCaseState::ReportedNcmec, SafetyCaseState::Closed),
        (SafetyCaseState::LawEnforcement, SafetyCaseState::Closed),
    ];

    #[test]
    fn transition_matrix_accepts_only_the_documented_edges() {
        // Exhaustively check ALL 7×7 = 49 (from, to) pairs against the spec: a
        // pair is accepted by `is_valid_transition` IFF it is one of VALID_EDGES.
        // This subsumes the scattered edge tests and catches any future drift
        // (a new edge, a dropped terminal guard, an UNSPECIFIED leak).
        for &from in &ALL_STATES {
            for &to in &ALL_STATES {
                let expected = VALID_EDGES.contains(&(from, to));
                assert_eq!(
                    is_valid_transition(from, to),
                    expected,
                    "transition {from:?} -> {to:?} should be {}",
                    if expected { "accepted" } else { "refused" }
                );
            }
        }
        // Sanity: terminal states have NO outgoing edge, UNSPECIFIED has none
        // either way, and the spec's count matches the validator.
        for term in [SafetyCaseState::Closed, SafetyCaseState::Rejected] {
            assert!(
                ALL_STATES.iter().all(|&to| !is_valid_transition(term, to)),
                "{term:?} must be terminal (no outgoing edge)"
            );
        }
        assert!(
            ALL_STATES
                .iter()
                .all(|&s| !is_valid_transition(SafetyCaseState::Unspecified, s)
                    && !is_valid_transition(s, SafetyCaseState::Unspecified)),
            "UNSPECIFIED is never a valid source or target"
        );
    }

    #[test]
    fn under_review_may_be_rejected() {
        // The valid UNDER_REVIEW → REJECTED edge (triaged as not a genuine case
        // after review began) — exercised end-to-end through the store, which the
        // scattered edge tests did not cover.
        let s = store();
        let id = s
            .open_case(&[3], &[], Category::CsamSuspected as i32, "uk")
            .unwrap()
            .case_id;
        s.transition(&id, SafetyCaseState::UnderReview as i32, "")
            .unwrap();
        let c = s
            .transition(&id, SafetyCaseState::Rejected as i32, "")
            .unwrap();
        assert_eq!(c.state, SafetyCaseState::Rejected as i32);
        // …and REJECTED is terminal even when reached from UNDER_REVIEW.
        assert_eq!(
            s.transition(&id, SafetyCaseState::Closed as i32, "")
                .unwrap_err(),
            SafetyCaseError::InvalidTransition
        );
    }

    #[test]
    fn full_forward_path_is_valid() {
        let s = store();
        let c = s
            .open_case(&[0xab, 0xcd], &[], Category::CsamSuspected as i32, "uk")
            .unwrap();
        let id = c.case_id;
        let c = s
            .transition(&id, SafetyCaseState::UnderReview as i32, "")
            .unwrap();
        assert_eq!(c.state, SafetyCaseState::UnderReview as i32);
        let c = s
            .transition(&id, SafetyCaseState::ReportedNcmec as i32, "NCMEC-12345")
            .unwrap();
        assert_eq!(c.state, SafetyCaseState::ReportedNcmec as i32);
        assert_eq!(c.ncmec_reference, "NCMEC-12345");
        let c = s
            .transition(&id, SafetyCaseState::LawEnforcement as i32, "")
            .unwrap();
        assert_eq!(c.state, SafetyCaseState::LawEnforcement as i32);
        let c = s
            .transition(&id, SafetyCaseState::Closed as i32, "")
            .unwrap();
        assert_eq!(c.state, SafetyCaseState::Closed as i32);
    }

    #[test]
    fn reported_case_may_close_without_law_enforcement() {
        // A report resolved without a separate LE handoff: REPORTED_NCMEC → CLOSED.
        let s = store();
        let id = s
            .open_case(&[7], &[], Category::CsamSuspected as i32, "uk")
            .unwrap()
            .case_id;
        s.transition(&id, SafetyCaseState::UnderReview as i32, "")
            .unwrap();
        s.transition(&id, SafetyCaseState::ReportedNcmec as i32, "NCMEC-9")
            .unwrap();
        let c = s
            .transition(&id, SafetyCaseState::Closed as i32, "")
            .unwrap();
        assert_eq!(c.state, SafetyCaseState::Closed as i32);
    }

    #[test]
    fn invalid_skips_and_terminal_moves_are_refused() {
        let s = store();
        let id = s
            .open_case(&[1], &[], Category::CsamSuspected as i32, "uk")
            .unwrap()
            .case_id;
        // Skip OPENED → REPORTED_NCMEC (must pass UNDER_REVIEW first).
        assert_eq!(
            s.transition(&id, SafetyCaseState::ReportedNcmec as i32, "x")
                .unwrap_err(),
            SafetyCaseError::InvalidTransition
        );
        // UNSPECIFIED target is never valid.
        assert_eq!(
            s.transition(&id, SafetyCaseState::Unspecified as i32, "")
                .unwrap_err(),
            SafetyCaseError::InvalidTransition
        );
        // Reject is reachable from OPENED — and is terminal.
        let c = s
            .transition(&id, SafetyCaseState::Rejected as i32, "")
            .unwrap();
        assert_eq!(c.state, SafetyCaseState::Rejected as i32);
        assert_eq!(
            s.transition(&id, SafetyCaseState::UnderReview as i32, "")
                .unwrap_err(),
            SafetyCaseError::InvalidTransition,
            "no edge leaves a terminal state"
        );
    }

    #[test]
    fn report_to_ncmec_requires_a_reference() {
        let s = store();
        let id = s
            .open_case(&[1], &[], Category::CsamSuspected as i32, "uk")
            .unwrap()
            .case_id;
        s.transition(&id, SafetyCaseState::UnderReview as i32, "")
            .unwrap();
        assert_eq!(
            s.transition(&id, SafetyCaseState::ReportedNcmec as i32, "   ")
                .unwrap_err(),
            SafetyCaseError::Validation("ncmec_reference is required to report a case to NCMEC")
        );
    }

    #[test]
    fn get_and_list_filter_by_state() {
        let s = store();
        let a = s
            .open_case(&[1], &[], Category::CsamSuspected as i32, "uk")
            .unwrap()
            .case_id;
        let b = s
            .open_case(&[2], &[], Category::CsamSuspected as i32, "us")
            .unwrap()
            .case_id;
        s.transition(&b, SafetyCaseState::UnderReview as i32, "")
            .unwrap();

        assert_eq!(s.get_case(&a).unwrap().case_id, a);
        assert_eq!(s.get_case("nope").unwrap_err(), SafetyCaseError::NotFound);

        // No filter → both; OPENED filter → only a; UNDER_REVIEW → only b.
        assert_eq!(s.list_cases(SafetyCaseState::Unspecified as i32).len(), 2);
        let opened = s.list_cases(SafetyCaseState::Opened as i32);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].case_id, a);
        let review = s.list_cases(SafetyCaseState::UnderReview as i32);
        assert_eq!(review.len(), 1);
        assert_eq!(review[0].case_id, b);
    }

    #[test]
    fn persist_and_reload_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "bulwark-cases-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let s1 = SafetyCaseStore::with_state_dir(&dir).unwrap();
        let id = s1
            .open_case(&[0xde, 0xad], &[0xbe], Category::CsamSuspected as i32, "uk")
            .unwrap()
            .case_id;
        s1.transition(&id, SafetyCaseState::UnderReview as i32, "")
            .unwrap();
        drop(s1); // simulate a restart

        let s2 = SafetyCaseStore::with_state_dir(&dir).unwrap();
        let c = s2.get_case(&id).unwrap();
        assert_eq!(c.state, SafetyCaseState::UnderReview as i32);
        assert_eq!(c.sha256, vec![0xde, 0xad]);
        assert_eq!(c.perceptual_hash, vec![0xbe]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
