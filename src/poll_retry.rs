//! Bounded retry tracking for the Green API poll loop.
//!
//! The poll loop (see `main.rs`) used to ack every notification it pulled
//! off the queue, even when downstream processing (download / OCR / ingest)
//! had failed. That worked while processing was effectively infallible, but
//! a transient SurrealDB blip — or an OCR / download hiccup — would
//! silently drop a user receipt: Green API removes the notification on
//! `deleteNotification`, so there is no second chance.
//!
//! [`AttemptTracker`] addresses that by gating the ack on a small retry
//! budget. The poll loop calls [`AttemptTracker::record_failure`] when a
//! receipt fails to process (download / OCR / ingest) and skips the ack
//! while the budget allows; after the budget is exhausted the notification
//! is acked anyway so a permanently broken receipt cannot wedge the queue.
//!
//! The tracker is intentionally a plain in-process `HashMap`:
//!
//! * Memory is bounded by both an inactivity TTL (entries whose most
//!   recent failure is older than `ttl` are evicted on every interaction)
//!   and a hard capacity (least-recently-failed eviction when the cap is
//!   hit). Either bound alone would be enough in practice; both together
//!   make the worst-case footprint obvious.
//! * The poll loop is single-threaded (the surrounding error type is
//!   `!Send`), so `&mut self` access is sufficient. No locking required.
//! * No persistence: a process restart resets the retry budget. That is
//!   intentional — Green API will redeliver any un-acked notification on
//!   its own schedule, so we lose at most one in-flight attempt count.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum number of times a single receipt may be redelivered before the
/// poll loop gives up and acks the notification anyway. The first attempt
/// counts towards this budget, so a value of 3 yields up to two
/// redeliveries before we discard the receipt.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// How long a tracker entry may live before it is considered stale and
/// evicted. Sized to comfortably outlast Green API's own redelivery
/// interval (a few minutes) while still bounding memory if the queue
/// stops draining.
pub const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// Hard cap on the number of tracked receipts. When the cap is hit we
/// evict the least-recently-failed entry to make room for the new one;
/// the eviction resets that receipt's budget on its next failure, which
/// is acceptable because hitting this cap already implies a systemic
/// backlog.
pub const DEFAULT_CAPACITY: usize = 1024;

/// Decision returned by [`AttemptTracker::record_failure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Failure is within the retry budget. Caller must NOT delete the
    /// notification from Green API so it is redelivered. `attempt` is the
    /// 1-based attempt number that just failed (1..=`max_attempts`).
    Skip { attempt: u32 },
    /// Retry budget is exhausted. Caller should ack (delete) the
    /// notification, drop the receipt, and emit a discard log so the
    /// failure is not silent. The tracker has already cleared the entry.
    AckGiveUp,
}

#[derive(Debug, Clone, Copy)]
struct AttemptEntry {
    attempts: u32,
    // Updated on every `record_failure_at` so the TTL behaves as an
    // inactivity window rather than an absolute lifetime: a receipt that
    // keeps failing within `ttl` of its previous failure stays tracked,
    // and capacity eviction drops the entry that has been quiet the
    // longest.
    last_seen: Instant,
}

/// In-process counter of consecutive processing failures (download / OCR /
/// ingest) keyed by Green API `receiptId`. See module docs for the
/// rationale and bounds.
#[derive(Debug)]
pub struct AttemptTracker {
    inner: HashMap<u64, AttemptEntry>,
    max_attempts: u32,
    ttl: Duration,
    capacity: usize,
}

impl AttemptTracker {
    /// Construct a tracker with explicit bounds. `max_attempts` is clamped
    /// to at least 2: with the give-up boundary set to `attempts ==
    /// max_attempts`, a value of 1 would discard on the first failure
    /// and revert to the old always-ack behaviour. `capacity` is clamped
    /// to at least 1 for the same kind of guard.
    pub fn new(max_attempts: u32, ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: HashMap::new(),
            max_attempts: max_attempts.max(2),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// Convenience constructor using the module-level defaults.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_ATTEMPTS, DEFAULT_TTL, DEFAULT_CAPACITY)
    }

    /// Returns the configured retry budget. Useful in log lines so the
    /// operator can see how close we are to giving up on a receipt.
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Record a processing failure (download / OCR / ingest) for
    /// `receipt_id` and decide whether the caller should skip the ack or
    /// ack-and-give-up.
    pub fn record_failure(&mut self, receipt_id: u64) -> RetryDecision {
        self.record_failure_at(receipt_id, Instant::now())
    }

    /// Test-friendly variant of [`record_failure`] that takes the current
    /// instant explicitly. Records a processing failure (download / OCR /
    /// ingest). Crate-visible only; production callers should use
    /// [`record_failure`].
    pub(crate) fn record_failure_at(&mut self, receipt_id: u64, now: Instant) -> RetryDecision {
        self.evict_stale_at(now);

        // If we are about to insert a brand-new entry and the map is full,
        // make room by dropping the oldest. Doing this BEFORE the entry()
        // call keeps the hot path branch-free for the common case
        // (receipt already tracked).
        if !self.inner.contains_key(&receipt_id) && self.inner.len() >= self.capacity {
            self.evict_oldest();
        }

        let entry = self.inner.entry(receipt_id).or_insert(AttemptEntry {
            attempts: 0,
            last_seen: now,
        });
        entry.attempts += 1;
        entry.last_seen = now;

        if entry.attempts < self.max_attempts {
            RetryDecision::Skip {
                attempt: entry.attempts,
            }
        } else {
            // Budget exhausted — drop the entry so a future receipt with
            // the same id (e.g. after a process restart aligning to a
            // Green API redelivery) starts fresh.
            self.inner.remove(&receipt_id);
            RetryDecision::AckGiveUp
        }
    }

    /// Clear any retry state for `receipt_id`. Called by the poll loop
    /// after successful processing (download / OCR / ingest) so a future
    /// failure for the same id starts from attempt 1 rather than
    /// inheriting a stale counter.
    pub fn record_success(&mut self, receipt_id: u64) {
        self.inner.remove(&receipt_id);
    }

    /// Number of receipts currently being tracked. Exposed primarily for
    /// tests and operator-visible metrics.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when no receipts are being tracked.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn evict_stale_at(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.inner
            .retain(|_, entry| now.duration_since(entry.last_seen) < ttl);
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .inner
            .iter()
            .min_by_key(|(_, entry)| entry.last_seen)
            .map(|(id, _)| *id)
        {
            self.inner.remove(&oldest);
        }
    }
}

impl Default for AttemptTracker {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper that asserts the first `max - 1` failures for `receipt_id`
    /// return `Skip { attempt }` and the `max`th failure returns
    /// `AckGiveUp`. Centralises the canonical retry-progression
    /// assertion used by several tests below.
    fn assert_skip_then_give_up(tracker: &mut AttemptTracker, receipt_id: u64) {
        let max = tracker.max_attempts();
        for attempt in 1..max {
            assert_eq!(
                tracker.record_failure(receipt_id),
                RetryDecision::Skip { attempt },
                "attempt {attempt} should be Skip",
            );
        }
        assert_eq!(
            tracker.record_failure(receipt_id),
            RetryDecision::AckGiveUp,
            "attempt {max} should be AckGiveUp",
        );
    }

    #[test]
    fn skip_twice_then_give_up_on_attempt_three() {
        let mut tracker = AttemptTracker::new(3, Duration::from_secs(60), 16);
        assert_skip_then_give_up(&mut tracker, 42);
    }

    #[test]
    fn give_up_clears_entry_so_subsequent_failures_start_fresh() {
        let mut tracker = AttemptTracker::new(3, Duration::from_secs(60), 16);
        // Burn through the budget.
        assert_eq!(
            tracker.record_failure(7),
            RetryDecision::Skip { attempt: 1 }
        );
        assert_eq!(
            tracker.record_failure(7),
            RetryDecision::Skip { attempt: 2 }
        );
        assert_eq!(tracker.record_failure(7), RetryDecision::AckGiveUp);
        // After give-up the entry is gone, so a new failure starts at attempt 1.
        assert_eq!(
            tracker.record_failure(7),
            RetryDecision::Skip { attempt: 1 }
        );
    }

    #[test]
    fn record_success_resets_attempt_count() {
        let mut tracker = AttemptTracker::new(3, Duration::from_secs(60), 16);
        assert_eq!(
            tracker.record_failure(99),
            RetryDecision::Skip { attempt: 1 }
        );
        assert_eq!(
            tracker.record_failure(99),
            RetryDecision::Skip { attempt: 2 }
        );
        tracker.record_success(99);
        assert!(tracker.is_empty(), "success must clear the entry");
        assert_eq!(
            tracker.record_failure(99),
            RetryDecision::Skip { attempt: 1 }
        );
    }

    #[test]
    fn distinct_receipts_track_independently() {
        let mut tracker = AttemptTracker::new(3, Duration::from_secs(60), 16);
        assert_eq!(
            tracker.record_failure(1),
            RetryDecision::Skip { attempt: 1 }
        );
        assert_eq!(
            tracker.record_failure(2),
            RetryDecision::Skip { attempt: 1 }
        );
        assert_eq!(
            tracker.record_failure(1),
            RetryDecision::Skip { attempt: 2 }
        );
        assert_eq!(tracker.record_failure(1), RetryDecision::AckGiveUp);
        // Receipt 2 is unaffected by receipt 1's give-up.
        assert_eq!(
            tracker.record_failure(2),
            RetryDecision::Skip { attempt: 2 }
        );
    }

    #[test]
    fn ttl_eviction_resets_an_entry_that_outlived_its_window() {
        let ttl = Duration::from_secs(60);
        let mut tracker = AttemptTracker::new(3, ttl, 16);
        let t0 = Instant::now();

        assert_eq!(
            tracker.record_failure_at(11, t0),
            RetryDecision::Skip { attempt: 1 }
        );
        let t1 = t0 + Duration::from_secs(30);
        assert_eq!(
            tracker.record_failure_at(11, t1),
            RetryDecision::Skip { attempt: 2 },
            "still within TTL — counter persists"
        );
        // Push the next failure past `ttl` from the MOST RECENT failure
        // (t1), not from t0: with inactivity-window semantics every failure
        // refreshes the TTL, so the gap that matters is `now - last_seen`.
        let after_ttl = t1 + ttl + Duration::from_secs(1);
        assert_eq!(
            tracker.record_failure_at(11, after_ttl),
            RetryDecision::Skip { attempt: 1 },
            "inactivity exceeded TTL — entry must be evicted and the counter must reset"
        );
    }

    #[test]
    fn ttl_is_an_inactivity_window_not_an_absolute_lifetime() {
        // A receipt that keeps failing within `ttl` of its previous failure
        // must remain tracked even when total elapsed time exceeds `ttl`.
        // Without this, hot entries silently reset mid-budget and the
        // skip-then-ack contract degrades to skip-forever for any receipt
        // whose redelivery cadence happens to align with the TTL.
        let ttl = Duration::from_secs(60);
        let mut tracker = AttemptTracker::new(5, ttl, 16);
        let step = ttl / 2;
        let mut now = Instant::now();

        // First failure starts the counter.
        assert_eq!(
            tracker.record_failure_at(21, now),
            RetryDecision::Skip { attempt: 1 }
        );

        // Three more failures, each a half-ttl after the previous one.
        // Total elapsed: 1.5 * ttl — well past the absolute-lifetime
        // boundary that the old `first_seen`-based TTL would have used.
        for expected_attempt in 2..=4 {
            now += step;
            assert_eq!(
                tracker.record_failure_at(21, now),
                RetryDecision::Skip {
                    attempt: expected_attempt
                },
                "failure at +{:?} must keep the entry alive",
                step * (expected_attempt - 1),
            );
        }
    }

    #[test]
    fn capacity_eviction_drops_least_recently_failed_not_first_inserted() {
        // With inactivity-window semantics the eviction key is `last_seen`,
        // so refreshing an older entry promotes it past a younger but
        // untouched one. Guard against a regression to `first_seen`-based
        // eviction that would drop the hot entry.
        let mut tracker = AttemptTracker::new(3, Duration::from_secs(3600), 2);
        let t0 = Instant::now();

        // Receipt 100 inserted first, then 200.
        tracker.record_failure_at(100, t0);
        tracker.record_failure_at(200, t0 + Duration::from_millis(1));
        assert_eq!(tracker.len(), 2);

        // Refresh 100 — its last_seen now exceeds 200's. 100's counter is
        // now at 2 under max_attempts=3.
        tracker.record_failure_at(100, t0 + Duration::from_millis(10));

        // Inserting 300 must evict the entry with the smallest last_seen,
        // which is now 200 (t0+1ms), not 100 (t0+10ms).
        tracker.record_failure_at(300, t0 + Duration::from_millis(20));
        assert_eq!(tracker.len(), 2);

        // Strong signal that 100 survived the eviction: its counter
        // persisted across the capacity-induced eviction of 200, so the
        // next failure exhausts the budget (attempt 3 of max 3).
        //
        // We check 100 BEFORE re-inserting 200 because re-inserting at
        // capacity would itself trigger another eviction and confuse the
        // signal.
        assert_eq!(
            tracker.record_failure_at(100, t0 + Duration::from_millis(30)),
            RetryDecision::AckGiveUp,
        );
    }

    #[test]
    fn capacity_eviction_drops_the_oldest_entry_when_full() {
        let mut tracker = AttemptTracker::new(3, Duration::from_secs(3600), 2);
        let t0 = Instant::now();

        // Fill to capacity with two distinct receipts.
        tracker.record_failure_at(100, t0);
        tracker.record_failure_at(200, t0 + Duration::from_millis(1));
        assert_eq!(tracker.len(), 2);

        // Inserting a third receipt must evict the oldest (100).
        tracker.record_failure_at(300, t0 + Duration::from_millis(2));
        assert_eq!(tracker.len(), 2);

        // Receipt 100 was evicted, so its next failure starts at attempt 1.
        assert_eq!(
            tracker.record_failure_at(100, t0 + Duration::from_millis(3)),
            RetryDecision::Skip { attempt: 1 }
        );
    }

    #[test]
    fn new_clamps_zero_max_attempts_to_two() {
        // A tracker that gives up on the first attempt would be no better
        // than the old always-ack behaviour. With the give-up boundary
        // at `attempts == max_attempts`, the smallest useful value is 2:
        // one redelivery, then ack.
        let mut tracker = AttemptTracker::new(0, Duration::from_secs(60), 16);
        assert_eq!(tracker.max_attempts(), 2);
        assert_eq!(
            tracker.record_failure(1),
            RetryDecision::Skip { attempt: 1 }
        );
        assert_eq!(tracker.record_failure(1), RetryDecision::AckGiveUp);
    }
}
