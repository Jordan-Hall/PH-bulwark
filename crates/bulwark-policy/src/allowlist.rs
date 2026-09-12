//! Per-device guardian override allowlist with a content-free hash-chain audit.

use std::collections::{BTreeMap, BTreeSet};

use bulwark_proto::v1::{Category, ReviewDecision, ReviewScope};
use bulwark_proto::DeviceId;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceAllowlist {
    hosts: BTreeSet<String>,
    hashes: BTreeSet<String>,
}

impl DeviceAllowlist {
    pub fn allows_host(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        !host.is_empty() && self.hosts.contains(&host)
    }

    pub fn allows_hash(&self, sha256: &[u8]) -> bool {
        !sha256.is_empty() && self.hashes.contains(&hex(sha256))
    }

    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }

    pub fn hashes(&self) -> impl Iterator<Item = &str> {
        self.hashes.iter().map(String::as_str)
    }

    fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.hashes.is_empty()
    }
}

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
        Self {
            device,
            alert_id: alert_id.into(),
            host: host.into(),
            sha256,
            category,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Approved,
    DenyConfirmed,
    Refused(String),
}

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

    pub fn verify(&self) -> Result<(), usize> {
        let mut previous = "bulwark-audit-genesis".to_string();
        for (index, entry) in self.entries.iter().enumerate() {
            if chain_hash(&previous, entry) != entry.chain_hash {
                return Err(index);
            }
            previous = entry.chain_hash.clone();
        }
        Ok(())
    }

    fn append(&mut self, mut entry: AuditEntry) {
        let previous = self
            .entries
            .last()
            .map(|entry| entry.chain_hash.as_str())
            .unwrap_or("bulwark-audit-genesis");
        entry.chain_hash = chain_hash(previous, &entry);
        self.entries.push(entry);
    }
}

#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    per_device: BTreeMap<String, DeviceAllowlist>,
    audit: AuditLog,
}

impl Allowlist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn device(&self, device: &DeviceId) -> Option<&DeviceAllowlist> {
        self.per_device.get(&device.0)
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn is_host_allowed(&self, device: &DeviceId, host: &str) -> bool {
        self.device(device)
            .is_some_and(|entry| entry.allows_host(host))
    }

    pub fn is_hash_allowed(&self, device: &DeviceId, sha256: &[u8]) -> bool {
        self.device(device)
            .is_some_and(|entry| entry.allows_hash(sha256))
    }

    pub fn apply(
        &mut self,
        item: &ReviewItem,
        decision: ReviewDecision,
        scope: ReviewScope,
        ts: i64,
    ) -> ApplyOutcome {
        let outcome = match decision {
            ReviewDecision::Approve => self.apply_approve(item, scope),
            ReviewDecision::Deny => self.apply_deny(item, scope),
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
                "CSAM_SUSPECTED items are never allowlistable".to_string(),
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
            }
            ReviewScope::ThisItem | ReviewScope::Unspecified => {
                if item.sha256.is_empty() {
                    return ApplyOutcome::Refused(
                        "THIS_ITEM approve with no content hash".to_string(),
                    );
                }
                entry.hashes.insert(hex(&item.sha256));
            }
        }
        ApplyOutcome::Approved
    }

    fn apply_deny(&mut self, item: &ReviewItem, scope: ReviewScope) -> ApplyOutcome {
        let key = item.device.0.clone();
        let mut remove_device = false;
        if let Some(entry) = self.per_device.get_mut(&key) {
            let host = item.host.trim().to_ascii_lowercase();
            let hash = (!item.sha256.is_empty()).then(|| hex(&item.sha256));
            match scope {
                ReviewScope::ThisHost => {
                    if !host.is_empty() {
                        entry.hosts.remove(&host);
                    }
                }
                ReviewScope::ThisItem => {
                    if let Some(hash) = &hash {
                        entry.hashes.remove(hash);
                    }
                }
                ReviewScope::Unspecified => {
                    if !host.is_empty() {
                        entry.hosts.remove(&host);
                    }
                    if let Some(hash) = &hash {
                        entry.hashes.remove(hash);
                    }
                }
            }
            remove_device = entry.is_empty();
        }
        if remove_device {
            self.per_device.remove(&key);
        }
        ApplyOutcome::DenyConfirmed
    }
}

fn decision_name(value: ReviewDecision) -> &'static str {
    match value {
        ReviewDecision::Unspecified => "unspecified",
        ReviewDecision::Approve => "approve",
        ReviewDecision::Deny => "deny",
    }
}

fn scope_name(value: ReviewScope) -> &'static str {
    match value {
        ReviewScope::Unspecified => "unspecified",
        ReviewScope::ThisItem => "this_item",
        ReviewScope::ThisHost => "this_host",
    }
}

fn outcome_name(value: &ApplyOutcome) -> &'static str {
    match value {
        ApplyOutcome::Approved => "approved",
        ApplyOutcome::DenyConfirmed => "deny_confirmed",
        ApplyOutcome::Refused(_) => "refused",
    }
}

fn chain_hash(previous: &str, entry: &AuditEntry) -> String {
    hex(&sha256(
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            previous,
            entry.device_id,
            entry.alert_id,
            decision_name(entry.decision),
            scope_name(entry.scope),
            entry.host,
            entry.sha256_hex,
            entry.category as i32,
            outcome_name(&entry.outcome),
            entry.ts
        )
        .as_bytes(),
    ))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354,
        0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
        0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa,
        0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() & 63 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let (blocks, remainder) = message.as_chunks::<64>();
    debug_assert!(remainder.is_empty());
    for chunk in blocks {
        let mut w = [0u32; 64];
        let (words, remainder) = chunk.as_chunks::<4>();
        debug_assert!(remainder.is_empty());
        for (word, bytes) in w.iter_mut().take(16).zip(words) {
            *word = u32::from_be_bytes(*bytes);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7)
                ^ w[i - 15].rotate_right(18)
                ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17)
                ^ w[i - 2].rotate_right(19)
                ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in h
            .iter_mut()
            .zip([a, b, c, d, e, f, g, hh])
        {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut out = [0u8; 32];
    for (index, word) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceId {
        DeviceId("kids-tablet".into())
    }

    fn item(host: &str, sha256: Vec<u8>, category: Category) -> ReviewItem {
        ReviewItem::new(device(), "alert-1", host, sha256, category)
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
    fn unspecified_deny_revokes_matching_host_and_hash() {
        let mut allowlist = Allowlist::new();
        let review = item("example.com", vec![0xde, 0xad], Category::AdultImage);
        allowlist.apply(
            &review,
            ReviewDecision::Approve,
            ReviewScope::ThisHost,
            1,
        );
        allowlist.apply(
            &review,
            ReviewDecision::Approve,
            ReviewScope::ThisItem,
            2,
        );
        assert!(allowlist.is_host_allowed(&device(), "example.com"));
        assert!(allowlist.is_hash_allowed(&device(), &[0xde, 0xad]));
        allowlist.apply(
            &review,
            ReviewDecision::Deny,
            ReviewScope::Unspecified,
            3,
        );
        assert!(!allowlist.is_host_allowed(&device(), "example.com"));
        assert!(!allowlist.is_hash_allowed(&device(), &[0xde, 0xad]));
    }

    #[test]
    fn csam_approval_is_refused_and_audited() {
        let mut allowlist = Allowlist::new();
        let outcome = allowlist.apply(
            &item("bad.example", vec![9], Category::CsamSuspected),
            ReviewDecision::Approve,
            ReviewScope::ThisHost,
            1,
        );
        assert!(matches!(outcome, ApplyOutcome::Refused(_)));
        assert_eq!(allowlist.audit().len(), 1);
        assert!(allowlist.audit().verify().is_ok());
    }
}
