//! Per-device guardian-override allowlist + tamper-evident audit log.
//!
//! When a guardian reviews an alert (see `docs/design/parent-notifications.md`)
//! and chooses **APPROVE**, bulwark-policy records that the flagged item is
//! permitted for *that supervised device* so the same item is not re-blocked.
//! **DENY** confirms the block (and is audited too). The engine
//! ([`crate::Policy`]) consults the allowlist *before* it bands a verdict.
//!
//! Stores **only** a lowercased host and content **hashes** (hex of
//! `Evidence.sha256`) — never message text, media, or thumbnails.
//! **CSAM is never allowlistable** (PLAN §0c). Every override (applied or
//! refused) is appended to a SHA-256 hash-chained [`AuditLog`].

use std::collections::{BTreeMap, BTreeSet};

use bulwark_proto::v1::{Category, ReviewDecision, ReviewScope};
use bulwark_proto::DeviceId;

/// Allowed hosts + content hashes for one device. Tiny and content-free.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceAllowlist {
    hosts: BTreeSet<String>,
    hashes: BTreeSet<String>,
}

impl DeviceAllowlist {
    /// True if `host` (case-insensitive) was approved for this device.
    pub fn allows_host(&self, host: &str) -> bool {
        let h = host.trim().to_ascii_lowercase();
        !h.is_empty() && self.hosts.contains(&h)
    }
    /// True if the content hash (raw `sha256` bytes) was approved.
    pub fn allows_hash(&self, sha256: &[u8]) -> bool {
        !sha256.is_empty() && self.hashes.contains(&hex(sha256))
    }
    /// Approved hosts (lowercased).
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }
    /// Approved content hashes (hex).
    pub fn hashes(&self) -> impl Iterator<Item = &str> {
        self.hashes.iter().map(String::as_str)
    }
}

/// The resolved facts of a review decision. The caller resolves the original
/// `AlertEvent` to these fields before applying the decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewItem {
    pub device: DeviceId,
    pub alert_id: String,
    pub host: String,
    pub sha256: Vec<u8>,
    pub category: Category,
}

impl ReviewItem {
    pub fn new(
        device: DeviceId,
        alert_id: impl Into<String>,
        host: impl Into<String>,
        sha256: Vec<u8>,
        category: Category,
    ) -> Self {
        ReviewItem {
            device,
            alert_id: alert_id.into(),
            host: host.into(),
            sha256,
            category,
        }
    }
}

/// Outcome of applying a decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// APPROVE recorded; the item/host is now allowlisted for the device.
    Approved,
    /// DENY recorded; the block is confirmed.
    DenyConfirmed,
    /// Refused (e.g. APPROVE of CSAM, or nothing to key on) — content-free reason.
    Refused(String),
}

/// One appended audit record. Content-free; chained to the prior entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub device_id: String,
    pub alert_id: String,
    pub decision: ReviewDecision,
    pub scope: ReviewScope,
    pub host: String,
    pub sha256_hex: String,
    pub category: Category,
    pub outcome: ApplyOutcome,
    pub ts: i64,
    pub chain_hash: String,
}

/// Append-only, hash-chained audit log of every guardian override.
#[derive(Clone, Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    fn head(&self) -> String {
        self.entries
            .last()
            .map(|e| e.chain_hash.clone())
            .unwrap_or_else(|| "bulwark-audit-genesis".to_string())
    }
    /// Verify the hash chain end-to-end. Returns the index of the first tampered
    /// entry, else `Ok(())`.
    pub fn verify(&self) -> Result<(), usize> {
        let mut prev = "bulwark-audit-genesis".to_string();
        for (i, e) in self.entries.iter().enumerate() {
            if chain_hash(&prev, e) != e.chain_hash {
                return Err(i);
            }
            prev = e.chain_hash.clone();
        }
        Ok(())
    }
    fn append(&mut self, mut entry: AuditEntry) {
        let prev = self.head();
        entry.chain_hash = chain_hash(&prev, &entry);
        self.entries.push(entry);
    }
}

/// Per-device override store: an allowlist per device + the audit log. Pure
/// in-memory; no I/O, no AI, no telemetry.
#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    per_device: BTreeMap<String, DeviceAllowlist>,
    audit: AuditLog,
}

impl Allowlist {
    pub fn new() -> Self {
        Allowlist::default()
    }
    pub fn device(&self, device: &DeviceId) -> Option<&DeviceAllowlist> {
        self.per_device.get(&device.0)
    }
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }
    pub fn is_host_allowed(&self, device: &DeviceId, host: &str) -> bool {
        self.per_device
            .get(&device.0)
            .is_some_and(|d| d.allows_host(host))
    }
    pub fn is_hash_allowed(&self, device: &DeviceId, sha256: &[u8]) -> bool {
        self.per_device
            .get(&device.0)
            .is_some_and(|d| d.allows_hash(sha256))
    }

    /// Apply a guardian decision to a resolved [`ReviewItem`], recording it in
    /// the audit log. **CSAM is never allowlistable** — an APPROVE of a
    /// `CSAM_SUSPECTED` item is [`ApplyOutcome::Refused`] (still audited).
    pub fn apply(
        &mut self,
        item: &ReviewItem,
        decision: ReviewDecision,
        scope: ReviewScope,
        ts: i64,
    ) -> ApplyOutcome {
        let outcome = match decision {
            ReviewDecision::Approve => self.apply_approve(item, scope),
            ReviewDecision::Deny => ApplyOutcome::DenyConfirmed,
            ReviewDecision::Unspecified => {
                ApplyOutcome::Refused("decision unspecified".to_string())
            }
        };
        self.audit.append(AuditEntry {
            device_id: item.device.0.clone(),
            alert_id: item.alert_id.clone(),
            decision,
            scope,
            host: item.host.trim().to_ascii_lowercase(),
            sha256_hex: if item.sha256.is_empty() {
                String::new()
            } else {
                hex(&item.sha256)
            },
            category: item.category,
            outcome: outcome.clone(),
            ts,
            chain_hash: String::new(),
        });
        outcome
    }

    fn apply_approve(&mut self, item: &ReviewItem, scope: ReviewScope) -> ApplyOutcome {
        if item.category == Category::CsamSuspected {
            return ApplyOutcome::Refused(
                "CSAM_SUSPECTED items are never allowlistable (report-never-archive)".to_string(),
            );
        }
        let entry = self.per_device.entry(item.device.0.clone()).or_default();
        match scope {
            ReviewScope::ThisHost => {
                let host = item.host.trim().to_ascii_lowercase();
                if host.is_empty() {
                    return ApplyOutcome::Refused("THIS_HOST approve with no host".to_string());
                }
                entry.hosts.insert(host);
                ApplyOutcome::Approved
            }
            ReviewScope::ThisItem | ReviewScope::Unspecified => {
                if item.sha256.is_empty() {
                    return ApplyOutcome::Refused(
                        "THIS_ITEM approve with no content hash".to_string(),
                    );
                }
                entry.hashes.insert(hex(&item.sha256));
                ApplyOutcome::Approved
            }
        }
    }
}

/// Lowercase hex (no external dep).
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn chain_hash(prev: &str, e: &AuditEntry) -> String {
    let mut s = String::new();
    s.push_str(prev);
    s.push('|');
    s.push_str(&e.device_id);
    s.push('|');
    s.push_str(&e.alert_id);
    s.push('|');
    s.push_str(decision_name(e.decision));
    s.push('|');
    s.push_str(scope_name(e.scope));
    s.push('|');
    s.push_str(&e.host);
    s.push('|');
    s.push_str(&e.sha256_hex);
    s.push('|');
    s.push_str(&(e.category as i32).to_string());
    s.push('|');
    s.push_str(outcome_tag(&e.outcome));
    s.push('|');
    s.push_str(&e.ts.to_string());
    hex(&sha256(s.as_bytes()))
}

fn decision_name(d: ReviewDecision) -> &'static str {
    match d {
        ReviewDecision::Unspecified => "unspecified",
        ReviewDecision::Approve => "approve",
        ReviewDecision::Deny => "deny",
    }
}
fn scope_name(s: ReviewScope) -> &'static str {
    match s {
        ReviewScope::Unspecified => "unspecified",
        ReviewScope::ThisItem => "this_item",
        ReviewScope::ThisHost => "this_host",
    }
}
fn outcome_tag(o: &ApplyOutcome) -> &'static str {
    match o {
        ApplyOutcome::Approved => "approved",
        ApplyOutcome::DenyConfirmed => "deny_confirmed",
        ApplyOutcome::Refused(_) => "refused",
    }
}

/// Self-contained SHA-256 (keeps bulwark-policy dependency-free). Used only to
/// chain the audit log; not a performance path.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> DeviceId {
        DeviceId("kids-tablet".into())
    }
    fn item(host: &str, sha: Vec<u8>, category: Category) -> ReviewItem {
        ReviewItem::new(dev(), "alert-1", host, sha, category)
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn approve_host_then_hash_scopes() {
        let mut a = Allowlist::new();
        let out = a.apply(
            &item("example.com", vec![0xde, 0xad], Category::AdultImage),
            ReviewDecision::Approve,
            ReviewScope::ThisHost,
            1,
        );
        assert_eq!(out, ApplyOutcome::Approved);
        assert!(a.is_host_allowed(&dev(), "Example.com"));
        assert!(!a.is_hash_allowed(&dev(), &[0xde, 0xad]));
    }

    #[test]
    fn approve_csam_refused_and_audited() {
        let mut a = Allowlist::new();
        let out = a.apply(
            &item("bad.example", vec![0x09], Category::CsamSuspected),
            ReviewDecision::Approve,
            ReviewScope::ThisHost,
            1,
        );
        assert!(matches!(out, ApplyOutcome::Refused(_)));
        assert!(!a.is_host_allowed(&dev(), "bad.example"));
        assert_eq!(a.audit().len(), 1);
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let mut a = Allowlist::new();
        for i in 0..3 {
            a.apply(
                &item("example.com", vec![i], Category::AdultImage),
                ReviewDecision::Approve,
                ReviewScope::ThisItem,
                i as i64,
            );
        }
        assert!(a.audit().verify().is_ok());
        let mut tampered = a.audit().clone();
        tampered.entries[1].host = "evil.example".to_string();
        assert_eq!(tampered.verify(), Err(1));
    }
}
