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
        let device_key = item.device.0.clone();
        let mut remove_device = false;
        if let Some(entry) = self.per_device.get_mut(&device_key) {
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
            self.per_device.remove(&device_key);
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
    let canonical = format!(
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
    );
    hex(ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes()).as_ref())
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
    fn unspecified_deny_revokes_matching_host_and_hash() {
        let mut allowlist = Allowlist::new();
        let review = item("example.com", vec![0xde, 0xad], Category::AdultImage);
        allowlist.apply(&review, ReviewDecision::Approve, ReviewScope::ThisHost, 1);
        allowlist.apply(&review, ReviewDecision::Approve, ReviewScope::ThisItem, 2);
        assert!(allowlist.is_host_allowed(&device(), "example.com"));
        assert!(allowlist.is_hash_allowed(&device(), &[0xde, 0xad]));
        allowlist.apply(&review, ReviewDecision::Deny, ReviewScope::Unspecified, 3);
        assert!(!allowlist.is_host_allowed(&device(), "example.com"));
        assert!(!allowlist.is_hash_allowed(&device(), &[0xde, 0xad]));
        assert!(allowlist.audit().verify().is_ok());
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
