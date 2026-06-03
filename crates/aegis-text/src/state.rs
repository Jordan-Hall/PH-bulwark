//! Conversation-level state for the grooming engine, keyed by
//! [`aegis_proto::TextSpan::thread_id`].
//!
//! Grooming rarely shows in a single message; the dangerous signals are
//! *cross-message* (secrecy followed by a move to another app, then an image
//! request — slow escalation over days). The engine therefore remembers, per
//! thread, **which categories have fired and when** so it can apply the context
//! multipliers from model-research.md §grooming:
//!
//!   * secrecy × platform-switch (even across messages)
//!   * sexualization × (gifts | emotional-isolation)
//!   * rapid escalation: ≥2 distinct categories within 7 days ⇒ ×1.5
//!   * any image-request seen in-thread ⇒ escalate to CRITICAL
//!
//! PRIVACY: state stores only category names + timestamps + counts — **never**
//! message text. It serializes to JSON via serde for the `Store` thread-state
//! API (`thread_state` / `put_thread_state` in interfaces.md); aegis-store
//! persists it encrypted.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use aegis_proto::GroomingRule;

/// Rapid-escalation window: distinct categories firing inside this span trigger
/// the ×1.5 escalation multiplier (model-research: "rapid escalation <7d ×1.5").
pub const ESCALATION_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Per-thread grooming memory. Cheap to clone; serde-serializable for the store.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ThreadState {
    /// Stable conversation id (echoes `TextSpan.thread_id`).
    pub thread_id: String,
    /// Last unix-millis timestamp at which each category fired in this thread.
    /// Keyed by the stable category name so it round-trips through JSON.
    last_seen_ms: BTreeMap<String, i64>,
    /// How many messages in this thread have fired at least one category.
    pub flagged_messages: u32,
    /// Sticky: once an image request is seen, the thread stays CRITICAL-eligible.
    pub image_request_seen: bool,
}

impl ThreadState {
    /// Fresh state for a thread id.
    pub fn new(thread_id: impl Into<String>) -> Self {
        ThreadState {
            thread_id: thread_id.into(),
            ..Default::default()
        }
    }

    /// True if `rule` has fired in this thread at or before `now_ms` (i.e. on a
    /// *prior* message — call this BEFORE [`record`] for the current message).
    pub fn has_seen(&self, rule: GroomingRule) -> bool {
        self.last_seen_ms.contains_key(rule.as_str())
    }

    /// True if `rule` fired within `window_ms` before `now_ms`.
    pub fn seen_within(&self, rule: GroomingRule, now_ms: i64, window_ms: i64) -> bool {
        self.last_seen_ms
            .get(rule.as_str())
            .map(|&t| now_ms.saturating_sub(t) <= window_ms)
            .unwrap_or(false)
    }

    /// Count of distinct categories seen within `window_ms` before `now_ms`
    /// (drives the rapid-escalation multiplier).
    pub fn distinct_within(&self, now_ms: i64, window_ms: i64) -> usize {
        self.last_seen_ms
            .values()
            .filter(|&&t| now_ms.saturating_sub(t) <= window_ms)
            .count()
    }

    /// Has any image request ever been seen in this thread?
    pub fn image_request_seen(&self) -> bool {
        self.image_request_seen
    }

    /// Record the categories that fired on the current message at `now_ms`.
    /// Call AFTER reading prior state so "across messages" multipliers see the
    /// pre-update view.
    pub fn record(&mut self, fired: &[GroomingRule], now_ms: i64) {
        if fired.is_empty() {
            return;
        }
        self.flagged_messages = self.flagged_messages.saturating_add(1);
        for &rule in fired {
            // Keep the most recent sighting.
            let entry = self
                .last_seen_ms
                .entry(rule.as_str().to_string())
                .or_insert(now_ms);
            if now_ms >= *entry {
                *entry = now_ms;
            }
            if rule == GroomingRule::ImageRequest {
                self.image_request_seen = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_recalls_categories() {
        let mut st = ThreadState::new("t1");
        assert!(!st.has_seen(GroomingRule::Secrecy));
        st.record(&[GroomingRule::Secrecy], 1_000);
        assert!(st.has_seen(GroomingRule::Secrecy));
        assert_eq!(st.flagged_messages, 1);
    }

    #[test]
    fn escalation_window_is_respected() {
        let mut st = ThreadState::new("t1");
        st.record(&[GroomingRule::Secrecy], 0);
        // Same category 6 days later → within window.
        let six_days = 6 * 24 * 60 * 60 * 1000;
        assert!(st.seen_within(GroomingRule::Secrecy, six_days, ESCALATION_WINDOW_MS));
        // 8 days later → outside window.
        let eight_days = 8 * 24 * 60 * 60 * 1000;
        assert!(!st.seen_within(GroomingRule::Secrecy, eight_days, ESCALATION_WINDOW_MS));
    }

    #[test]
    fn image_request_is_sticky() {
        let mut st = ThreadState::new("t1");
        st.record(&[GroomingRule::ImageRequest], 100);
        assert!(st.image_request_seen());
    }

    #[test]
    fn state_round_trips_through_json() {
        let mut st = ThreadState::new("t1");
        st.record(&[GroomingRule::Secrecy, GroomingRule::PlatformSwitching], 5);
        let bytes = serde_json::to_vec(&st).unwrap();
        let back: ThreadState = serde_json::from_slice(&bytes).unwrap();
        assert!(back.has_seen(GroomingRule::PlatformSwitching));
        assert_eq!(back.flagged_messages, 1);
    }
}
