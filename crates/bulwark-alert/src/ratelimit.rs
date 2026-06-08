//! Dedupe + burst coalescing.
//!
//! Two jobs, both driven by [`RateLimitConfig`]:
//!
//! 1. **Dedupe by `alert_id`.** The same alert id seen again inside the dedupe
//!    window is suppressed (the caller marks the ack `deduped = true`). This
//!    makes `raise` idempotent across retries.
//!
//! 2. **Burst coalescing.** Within a rolling burst window we send up to
//!    `max_immediate_per_window` alerts immediately; anything beyond that is
//!    buffered. The buffered events are later flushed as a single **digest**
//!    email via the batch path — turning a flood into one roll-up.
//!
//! The clock is injectable (`now`) so tests are deterministic and don't sleep.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bulwark_proto::v1::AlertEvent;

use crate::config::RateLimitConfig;

/// What the limiter decided to do with one incoming alert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Send this alert now as its own email.
    SendNow,
    /// Suppressed as a duplicate of a recently-seen `alert_id`.
    Deduped,
    /// Buffered; will go out in the next digest flush.
    Coalesced,
}

/// Per-recipient-set dedupe + burst state. Not internally synchronized; the
/// sink wraps it in a mutex so this stays a pure, testable state machine.
pub struct RateLimiter {
    cfg: RateLimitConfig,
    /// alert_id -> when first seen (for dedupe window expiry).
    seen: HashMap<String, Instant>,
    /// Timestamps of alerts sent immediately, for the rolling burst window.
    recent_sends: VecDeque<Instant>,
    /// Events buffered for the next digest.
    pending_digest: Vec<AlertEvent>,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            seen: HashMap::new(),
            recent_sends: VecDeque::new(),
            pending_digest: Vec::new(),
        }
    }

    /// Admit one alert at logical time `now`. Returns the [`Decision`]; on
    /// [`Decision::Coalesced`] the event has been pushed onto the pending
    /// digest buffer.
    pub fn admit(&mut self, event: &AlertEvent, now: Instant) -> Decision {
        self.expire(now);

        // 1) Dedupe by alert_id within the dedupe window.
        if !event.alert_id.is_empty() {
            if let Some(&first) = self.seen.get(&event.alert_id) {
                if now.duration_since(first) < self.cfg.dedupe_window {
                    return Decision::Deduped;
                }
            }
            self.seen.insert(event.alert_id.clone(), now);
        }

        // 2) Burst budget within the rolling window.
        if (self.recent_sends.len() as u32) < self.cfg.max_immediate_per_window {
            self.recent_sends.push_back(now);
            Decision::SendNow
        } else {
            if self.pending_digest.len() < self.cfg.digest_max_events {
                self.pending_digest.push(event.clone());
            }
            Decision::Coalesced
        }
    }

    /// True if there are buffered events waiting for a digest flush.
    pub fn has_pending_digest(&self) -> bool {
        !self.pending_digest.is_empty()
    }

    /// Number of buffered events.
    pub fn pending_len(&self) -> usize {
        self.pending_digest.len()
    }

    /// Take the buffered events for a digest send, clearing the buffer.
    pub fn drain_digest(&mut self) -> Vec<AlertEvent> {
        std::mem::take(&mut self.pending_digest)
    }

    /// Record that `count` digest events were just sent, charging them against
    /// the burst budget so the digest itself participates in rate-limiting.
    pub fn note_digest_sent(&mut self, now: Instant) {
        self.recent_sends.push_back(now);
    }

    /// Drop dedupe entries and burst timestamps that have aged out.
    fn expire(&mut self, now: Instant) {
        let dedupe = self.cfg.dedupe_window;
        self.seen
            .retain(|_, first| now.duration_since(*first) < dedupe);

        let burst = self.cfg.burst_window;
        while let Some(&front) = self.recent_sends.front() {
            if now.duration_since(front) >= burst {
                self.recent_sends.pop_front();
            } else {
                break;
            }
        }
    }

    /// Expose the burst window for the sink's flush scheduling.
    pub fn burst_window(&self) -> Duration {
        self.cfg.burst_window
    }
}
