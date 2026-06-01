//! The broadcast-delay ring buffer — what makes real-time filtering possible.
//!
//! A streaming-media segment (progressive `mp4` chunk, HLS `.ts`, DASH `.m4s`)
//! is **admitted** to this buffer, held for a configurable analysis-delay window
//! while the analyzer/offload layer returns a verdict, then either **released**
//! (forwarded, possibly rewritten) or **dropped** (BLOCK). The play-out stays at
//! least one analysis window behind live (architecture.md §3d/§4).
//!
//! Design (no AI/ML, no telemetry):
//!   * **Bounded capacity** by both segment count and total bytes → back-pressure.
//!     `admit` returns [`Admission::BackPressure`] when full so the producer
//!     (interceptor) slows the source rather than the buffer growing unbounded.
//!   * **Latency budget**: each segment carries a `deadline` (live) or a relaxed
//!     VOD budget. [`due_segments`] surfaces segments whose deadline elapsed
//!     with no verdict so the caller can **shed / fast-path** them under the
//!     fail-safe default (per policy: forward-with-warn or block).
//!   * **Verdict application**: [`apply`] maps an `Action` onto a held segment —
//!     `ALLOW`/`WARN`/`LOG` → release (forward), `BLOCK` → drop, `BLUR`/`MUTE`
//!     → release the (caller-)rewritten bytes. `hold` keeps it pending.
//!
//! The buffer is `async`-friendly but does its own bookkeeping synchronously
//! under a `Mutex`; it does not block on I/O.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;

use serde::{Deserialize, Serialize};

use aegis_proto::v1::Action;

use crate::error::FlowError;

/// Configuration for the delay ring buffer.
///
/// Serde-serializable (millis-valued durations) so the buffer can be tuned from
/// the same TOML config layer the rest of Aegis uses (`aegis_core::Config`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BufferConfig {
    /// Maximum number of segments held pending at once (count back-pressure).
    pub max_segments: usize,
    /// Maximum total bytes held pending at once (memory back-pressure).
    pub max_bytes: usize,
    /// The broadcast-delay window for **live** segments, in milliseconds —
    /// play-out stays this far behind live so a verdict can return before the
    /// deadline (architecture.md §4: a 2–5 s window).
    pub live_delay_ms: u32,
    /// The (relaxed) hold budget for **VOD** segments, in milliseconds. VOD has
    /// no hard live deadline; this only bounds how long the buffer waits before
    /// shedding.
    pub vod_budget_ms: u32,
}

impl Default for BufferConfig {
    fn default() -> Self {
        BufferConfig {
            max_segments: 64,
            // ~64 MiB of held media before back-pressure kicks in.
            max_bytes: 64 * 1024 * 1024,
            live_delay_ms: crate::classify::LIVE_DELAY_MS,
            vod_budget_ms: crate::classify::VOD_DELAY_MS,
        }
    }
}

impl BufferConfig {
    /// The live broadcast-delay window as a [`Duration`].
    pub fn live_delay(&self) -> Duration {
        Duration::from_millis(self.live_delay_ms as u64)
    }

    /// The VOD hold budget as a [`Duration`].
    pub fn vod_budget(&self) -> Duration {
        Duration::from_millis(self.vod_budget_ms as u64)
    }
}

/// The result of trying to admit a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Admitted; this is the segment's buffer ticket id.
    Admitted(u64),
    /// The buffer is at capacity (count or bytes). The producer must apply
    /// back-pressure to the source (or shed) before retrying.
    BackPressure,
}

/// Lifecycle state of a buffered segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SegState {
    /// Held, awaiting a verdict, deadline not yet elapsed.
    Pending,
    /// Held, but the deadline elapsed before a verdict (fail-safe candidate).
    Overdue,
    /// A `hold` verdict explicitly extended the wait (re-analysis in progress).
    Held,
}

/// One segment held in the buffer.
#[derive(Clone, Debug)]
struct Segment {
    id: u64,
    bytes: Bytes,
    live: bool,
    admitted_at: Instant,
    /// Wall-clock instant by which a verdict must arrive (admitted_at + budget).
    deadline: Instant,
    state: SegState,
}

/// What [`apply`](DelayBuffer::apply) decided to do with a segment after a verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Released {
    /// Forward these bytes downstream (original on ALLOW/WARN/LOG, or the
    /// rewritten bytes the caller supplied for BLUR/MUTE).
    Forward(Bytes),
    /// Drop the segment entirely (BLOCK) — it never reaches the device.
    Dropped,
    /// Keep holding (a `hold` decision / `Action::Unspecified`): no release yet.
    StillHeld,
}

/// A segment whose deadline elapsed with no verdict — the caller must apply the
/// fail-safe default (forward-with-warn or block, per policy).
#[derive(Clone, Debug)]
pub struct OverdueSegment {
    /// The buffer ticket.
    pub id: u64,
    /// Whether this was a live segment (vs VOD) — affects the fail-safe choice.
    pub live: bool,
    /// The held bytes (so the caller can forward them if the fail-safe is "warn").
    pub bytes: Bytes,
}

/// The broadcast-delay ring buffer.
pub struct DelayBuffer {
    config: BufferConfig,
    inner: Mutex<Inner>,
}

struct Inner {
    queue: VecDeque<Segment>,
    held_bytes: usize,
    next_id: u64,
    /// How far behind live the *oldest* pending segment currently is (ms). This
    /// feeds `FlowClassifier::current_delay_ms`.
    current_delay_ms: u32,
}

impl DelayBuffer {
    /// Build a buffer with the given configuration.
    pub fn new(config: BufferConfig) -> Self {
        DelayBuffer {
            config,
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                held_bytes: 0,
                next_id: 1,
                current_delay_ms: 0,
            }),
        }
    }

    /// Build a buffer with default configuration.
    pub fn with_defaults() -> Self {
        DelayBuffer::new(BufferConfig::default())
    }

    /// Admit a segment, returning its ticket or [`Admission::BackPressure`] if the
    /// buffer is at capacity. `live` selects the live-delay vs VOD budget.
    pub fn admit(&self, bytes: Bytes, live: bool) -> Admission {
        self.admit_at(bytes, live, Instant::now())
    }

    /// `admit` with an injectable clock (tests drive the deadline deterministically).
    pub fn admit_at(&self, bytes: Bytes, live: bool, now: Instant) -> Admission {
        let mut inner = self.inner.lock().unwrap();

        let would_be_bytes = inner.held_bytes.saturating_add(bytes.len());
        if inner.queue.len() >= self.config.max_segments || would_be_bytes > self.config.max_bytes {
            tracing::debug!(
                segments = inner.queue.len(),
                held_bytes = inner.held_bytes,
                incoming = bytes.len(),
                "delay buffer back-pressure",
            );
            return Admission::BackPressure;
        }

        let id = inner.next_id;
        inner.next_id += 1;
        let budget = if live {
            self.config.live_delay()
        } else {
            self.config.vod_budget()
        };
        let len = bytes.len();
        inner.queue.push_back(Segment {
            id,
            bytes,
            live,
            admitted_at: now,
            deadline: now + budget,
            state: SegState::Pending,
        });
        inner.held_bytes += len;
        inner.recompute_delay(now);
        tracing::trace!(id, len, live, "segment admitted to delay buffer");
        Admission::Admitted(id)
    }

    /// Apply a policy [`Action`] (carried back on a `Verdict`) to a held segment.
    ///
    /// * `ALLOW` / `WARN` / `LOG` → [`Released::Forward`] with the original bytes.
    /// * `BLUR` / `MUTE` → [`Released::Forward`] with `rewritten` (caller supplies
    ///   the re-encoded blurred/muted bytes); falls back to the original if
    ///   `rewritten` is `None`.
    /// * `BLOCK` → [`Released::Dropped`] (the segment is removed, never forwarded).
    /// * `ACTION_UNSPECIFIED` → treated as a `hold`: [`Released::StillHeld`].
    ///
    /// Returns [`FlowError::SegmentNotFound`] if the id is unknown (already
    /// released / dropped / shed).
    pub fn apply(
        &self,
        id: u64,
        action: Action,
        rewritten: Option<Bytes>,
    ) -> Result<Released, FlowError> {
        let mut inner = self.inner.lock().unwrap();
        let pos = inner
            .queue
            .iter()
            .position(|s| s.id == id)
            .ok_or(FlowError::SegmentNotFound(id))?;

        match action {
            Action::Block => {
                let seg = inner.queue.remove(pos).expect("position valid");
                inner.held_bytes -= seg.bytes.len();
                inner.recompute_delay(Instant::now());
                tracing::debug!(id, "segment BLOCKed → dropped from delay buffer");
                Ok(Released::Dropped)
            }
            Action::Allow | Action::Warn | Action::Log => {
                let seg = inner.queue.remove(pos).expect("position valid");
                inner.held_bytes -= seg.bytes.len();
                inner.recompute_delay(Instant::now());
                tracing::trace!(id, ?action, "segment released (forward) from delay buffer");
                Ok(Released::Forward(seg.bytes))
            }
            Action::Blur | Action::Mute => {
                let seg = inner.queue.remove(pos).expect("position valid");
                inner.held_bytes -= seg.bytes.len();
                inner.recompute_delay(Instant::now());
                let out = rewritten.unwrap_or(seg.bytes);
                tracing::debug!(id, ?action, "segment released (rewritten) from delay buffer");
                Ok(Released::Forward(out))
            }
            Action::Unspecified => {
                // No decision yet → keep holding (mark Held so it is not also
                // surfaced as overdue until its deadline truly elapses).
                if let Some(seg) = inner.queue.get_mut(pos) {
                    seg.state = SegState::Held;
                }
                Ok(Released::StillHeld)
            }
        }
    }

    /// Explicitly keep holding a segment (e.g. re-analysis pending). Idempotent.
    pub fn hold(&self, id: u64) -> Result<(), FlowError> {
        let mut inner = self.inner.lock().unwrap();
        let seg = inner
            .queue
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or(FlowError::SegmentNotFound(id))?;
        seg.state = SegState::Held;
        Ok(())
    }

    /// Segments whose deadline has elapsed with no verdict applied — the caller
    /// must apply the fail-safe default (forward-with-warn or block) and then
    /// `apply` the chosen action to clear them. Marks them `Overdue`.
    pub fn due_segments(&self) -> Vec<OverdueSegment> {
        self.due_segments_at(Instant::now())
    }

    /// [`due_segments`](Self::due_segments) with an injectable clock.
    pub fn due_segments_at(&self, now: Instant) -> Vec<OverdueSegment> {
        let mut inner = self.inner.lock().unwrap();
        let mut overdue = Vec::new();
        for seg in inner.queue.iter_mut() {
            if now >= seg.deadline && seg.state != SegState::Held {
                seg.state = SegState::Overdue;
                overdue.push(OverdueSegment {
                    id: seg.id,
                    live: seg.live,
                    bytes: seg.bytes.clone(),
                });
            }
        }
        if !overdue.is_empty() {
            tracing::debug!(count = overdue.len(), "segments overdue → fail-safe shed");
        }
        overdue
    }

    /// Number of segments currently held pending.
    pub fn pending(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    /// Total bytes currently held pending.
    pub fn held_bytes(&self) -> usize {
        self.inner.lock().unwrap().held_bytes
    }

    /// How far behind live the oldest pending segment sits (ms). Feeds
    /// `FlowClassifier::current_delay_ms`.
    pub fn current_delay_ms(&self) -> u32 {
        self.current_delay_ms_at(Instant::now())
    }

    /// [`current_delay_ms`](Self::current_delay_ms) with an injectable clock.
    pub fn current_delay_ms_at(&self, now: Instant) -> u32 {
        let mut inner = self.inner.lock().unwrap();
        inner.recompute_delay(now);
        inner.current_delay_ms
    }

    /// True if admitting `len` bytes would currently be refused (back-pressure).
    pub fn is_full_for(&self, len: usize) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.queue.len() >= self.config.max_segments
            || inner.held_bytes.saturating_add(len) > self.config.max_bytes
    }
}

impl Inner {
    /// Recompute how far behind live the oldest pending segment is.
    fn recompute_delay(&mut self, now: Instant) {
        self.current_delay_ms = self
            .queue
            .front()
            .map(|s| now.saturating_duration_since(s.admitted_at).as_millis() as u32)
            .unwrap_or(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BufferConfig {
        BufferConfig {
            max_segments: 3,
            max_bytes: 1024,
            live_delay_ms: 3000,
            vod_budget_ms: 250,
        }
    }

    #[test]
    fn admits_then_releases_on_allow() {
        let buf = DelayBuffer::new(cfg());
        let data = Bytes::from_static(b"video-segment-bytes");
        let id = match buf.admit(data.clone(), false) {
            Admission::Admitted(id) => id,
            other => panic!("expected admit, got {other:?}"),
        };
        assert_eq!(buf.pending(), 1);
        assert_eq!(buf.held_bytes(), data.len());

        // ALLOW → forwarded with the original bytes, buffer emptied.
        let released = buf.apply(id, Action::Allow, None).unwrap();
        assert_eq!(released, Released::Forward(data));
        assert_eq!(buf.pending(), 0);
        assert_eq!(buf.held_bytes(), 0);
    }

    #[test]
    fn drops_on_block() {
        let buf = DelayBuffer::new(cfg());
        let id = match buf.admit(Bytes::from_static(b"explicit-segment"), true) {
            Admission::Admitted(id) => id,
            other => panic!("{other:?}"),
        };
        let released = buf.apply(id, Action::Block, None).unwrap();
        assert_eq!(released, Released::Dropped);
        // The segment is gone — it never forwards downstream.
        assert_eq!(buf.pending(), 0);
        assert_eq!(buf.held_bytes(), 0);
        // Applying again is a not-found (proves it was truly removed).
        assert!(matches!(
            buf.apply(id, Action::Allow, None),
            Err(FlowError::SegmentNotFound(_))
        ));
    }

    #[test]
    fn blur_releases_rewritten_bytes() {
        let buf = DelayBuffer::new(cfg());
        let id = match buf.admit(Bytes::from_static(b"orig"), false) {
            Admission::Admitted(id) => id,
            other => panic!("{other:?}"),
        };
        let blurred = Bytes::from_static(b"blurred");
        let released = buf.apply(id, Action::Blur, Some(blurred.clone())).unwrap();
        assert_eq!(released, Released::Forward(blurred));
    }

    #[test]
    fn back_pressure_when_full_by_count() {
        let buf = DelayBuffer::new(cfg());
        for _ in 0..3 {
            assert!(matches!(
                buf.admit(Bytes::from_static(b"x"), true),
                Admission::Admitted(_)
            ));
        }
        // Fourth exceeds max_segments=3.
        assert_eq!(buf.admit(Bytes::from_static(b"x"), true), Admission::BackPressure);
    }

    #[test]
    fn back_pressure_when_full_by_bytes() {
        let buf = DelayBuffer::new(BufferConfig {
            max_segments: 100,
            max_bytes: 8,
            ..cfg()
        });
        assert!(matches!(
            buf.admit(Bytes::from_static(b"12345"), true),
            Admission::Admitted(_)
        ));
        // 5 + 5 > 8 bytes → back-pressure.
        assert_eq!(
            buf.admit(Bytes::from_static(b"67890"), true),
            Admission::BackPressure
        );
    }

    #[test]
    fn overdue_after_deadline_for_failsafe_shed() {
        let buf = DelayBuffer::new(cfg());
        let t0 = Instant::now();
        let id = match buf.admit_at(Bytes::from_static(b"live-seg"), true, t0) {
            Admission::Admitted(id) => id,
            other => panic!("{other:?}"),
        };
        // Before the deadline: nothing overdue.
        assert!(buf
            .due_segments_at(t0 + Duration::from_millis(100))
            .is_empty());
        // After the 3 s live delay: surfaced as overdue for fail-safe handling.
        let due = buf.due_segments_at(t0 + Duration::from_millis(3_001));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert!(due[0].live);
    }

    #[test]
    fn held_segment_is_not_overdue() {
        let buf = DelayBuffer::new(cfg());
        let t0 = Instant::now();
        let id = match buf.admit_at(Bytes::from_static(b"seg"), false, t0) {
            Admission::Admitted(id) => id,
            other => panic!("{other:?}"),
        };
        buf.hold(id).unwrap();
        // Past the VOD budget, but explicitly held → not shed.
        assert!(buf
            .due_segments_at(t0 + Duration::from_millis(1_000))
            .is_empty());
    }

    #[test]
    fn current_delay_tracks_oldest_segment() {
        let buf = DelayBuffer::new(cfg());
        let t0 = Instant::now();
        assert_eq!(buf.current_delay_ms_at(t0), 0);
        buf.admit_at(Bytes::from_static(b"a"), true, t0);
        // 1.2 s after admit, the oldest segment is ~1200 ms behind live.
        let d = buf.current_delay_ms_at(t0 + Duration::from_millis(1_200));
        assert!((1_180..=1_220).contains(&d), "delay was {d}");
    }

    #[test]
    fn unspecified_action_keeps_holding() {
        let buf = DelayBuffer::new(cfg());
        let id = match buf.admit(Bytes::from_static(b"seg"), false) {
            Admission::Admitted(id) => id,
            other => panic!("{other:?}"),
        };
        assert_eq!(buf.apply(id, Action::Unspecified, None).unwrap(), Released::StillHeld);
        assert_eq!(buf.pending(), 1);
    }
}
