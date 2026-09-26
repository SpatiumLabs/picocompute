//! Shared-host emission rate limiting.
//!
//! On a shared host, a high-frequency series is itself a side channel: watching
//! how often a sandbox-scoped counter ticks reveals the workload's rhythm even
//! when the identity attribute has been replaced. So on shared hosts the
//! noisiest series are throttled to one emission per window per key.
//!
//! The algorithm was previously written twice, identically, in
//! `pico-core` (snapshot cache metrics) and `pico-network-agent`
//! (interface stats): a 60s window, a 1024-key cap, and a sweep that drops
//! entries older than twice the window before inserting. One implementation
//! means one place to reason about the constants.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use hashbrown::HashMap;
use parking_lot::Mutex;

/// Minimum interval between emissions of the same key.
const WINDOW: Duration = Duration::from_secs(60);

/// Maximum tracked keys.
///
/// Hard bound on memory. A caller that keys on unbounded input cannot grow the
/// map past this.
const MAX_TRACKED_KEYS: usize = 1024;

/// Target size after a sweep, leaving headroom so the next insert does not
/// immediately re-trigger one.
const TARGET_KEYS: usize = MAX_TRACKED_KEYS / 2;

/// Keys dropped by a sweep once nothing is expired. Anything older than this
/// can no longer suppress an emission, so dropping it cannot change behaviour.
const RETAIN_AFTER: Duration = Duration::from_secs(120);

/// Throttles emissions to at most one per [`WINDOW`] per key.
///
/// Keyed by a caller-supplied string so that distinct series throttle
/// independently. Only consulted on shared hosts; a dedicated host does not
/// rate-limit and should not call [`RateLimiter::should_emit`].
/// Process-wide emission throttle for series that must be sampled down on
/// shared hosts.
///
/// A single instance rather than a field per metrics struct, because the
/// throttle is a property of the redaction policy and must apply identically to
/// every series that opts into it, across crate boundaries.
pub static SHARED_HOST_LIMITER: LazyLock<RateLimiter> = LazyLock::new(RateLimiter::new);

/// One emission per [`WINDOW`] per key, on shared hosts.
#[derive(Debug, Default)]
pub struct RateLimiter {
    last: Mutex<HashMap<String, Instant>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` when the caller may emit for `key`, recording the
    /// emission.
    ///
    /// Returns `false` while the previous emission for `key` is younger than
    /// [`WINDOW`]. Inserts `key` on both outcomes, so a suppressed caller stays
    /// throttled on the same schedule as an emitting one.
    ///
    /// At [`MAX_TRACKED_KEYS`] the limiter sweeps: keys older than
    /// [`RETAIN_AFTER`] are dropped because they can no longer suppress an
    /// emission. If that frees nothing, because keys are arriving faster than
    /// they age out, the oldest keys are dropped until the map is back to
    /// [`TARGET_KEYS`]. Those drops can let a still-recent key emit once more
    /// than its window allows, which is the deliberate trade for a hard
    /// memory bound on a map keyed by input.
    pub fn should_emit(&self, key: &str) -> bool {
        let mut last = self.last.lock();
        if let Some(previous) = last.get(key)
            && previous.elapsed() < WINDOW
        {
            return false;
        }
        if last.len() >= MAX_TRACKED_KEYS {
            sweep(&mut last, RETAIN_AFTER, TARGET_KEYS);
        }
        last.insert(key.to_owned(), Instant::now());
        true
    }

    /// Number of tracked keys. Exposed for tests that assert the key space
    /// stays bounded.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.last.lock().len()
    }
}

/// Frees space in `last` so a fresh insert does not immediately re-trigger a
/// sweep.
///
/// Prefers dropping keys older than `retain_after`, which can no longer suppress
/// an emission. Only when every key is younger does it fall back to dropping the
/// oldest, which is what makes the bound hard rather than advisory.
///
/// The thresholds are parameters rather than constants so tests can exercise
/// both paths without waiting out a 120-second window.
fn sweep(last: &mut HashMap<String, Instant>, retain_after: Duration, target: usize) {
    last.retain(|_, at| at.elapsed() < retain_after);
    if last.len() < target {
        return;
    }

    // Order by age, oldest first, and drop the oldest until there is headroom.
    let mut by_age: Vec<(String, Instant)> = last.drain().collect();
    by_age.sort_unstable_by_key(|(_, at)| *at);
    let excess = by_age.len().saturating_sub(target);
    for (key, at) in by_age.into_iter().skip(excess) {
        last.insert(key, at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_is_allowed() {
        assert!(RateLimiter::new().should_emit("hit"));
    }

    #[test]
    fn repeat_within_window_is_suppressed() {
        let limiter = RateLimiter::new();
        assert!(limiter.should_emit("hit"));
        assert!(!limiter.should_emit("hit"));
        assert!(!limiter.should_emit("hit"));
    }

    #[test]
    fn distinct_keys_are_independent() {
        let limiter = RateLimiter::new();
        assert!(limiter.should_emit("hit:tnt_a"));
        assert!(limiter.should_emit("miss:tnt_a"));
        assert!(limiter.should_emit("hit:tnt_b"));
        assert!(!limiter.should_emit("hit:tnt_a"));
        assert!(limiter.should_emit("evict:tnt_b"));
    }

    #[test]
    fn suppressed_callers_stay_throttled() {
        // A caller that is refused must not have its timestamp cleared, or the
        // next poll would be allowed and the series would emit every poll.
        let limiter = RateLimiter::new();
        assert!(limiter.should_emit("k"));
        for _ in 0..10 {
            assert!(!limiter.should_emit("k"));
        }
    }

    #[test]
    fn key_space_stays_bounded_when_keys_arrive_faster_than_they_age_out() {
        // Every key here is younger than RETAIN_AFTER, so the age-based part of
        // the sweep frees nothing. The oldest-first fallback is what has to hold
        // the bound, and this is the case the pre-consolidation implementation
        // got wrong: it grew without limit.
        let limiter = RateLimiter::new();
        for i in 0..(MAX_TRACKED_KEYS * 4) {
            limiter.should_emit(&format!("k{i}"));
        }
        assert!(
            limiter.tracked() <= MAX_TRACKED_KEYS,
            "tracked {} keys, expected the hard cap of {MAX_TRACKED_KEYS}",
            limiter.tracked()
        );
    }

    /// A timestamp old enough that `elapsed()` exceeds `RETAIN_AFTER`, so the
    /// age-based part of the sweep treats it as expired.
    fn expired() -> Instant {
        Instant::now() - RETAIN_AFTER - Duration::from_secs(1)
    }

    #[test]
    fn sweep_drops_the_oldest_keys_first() {
        let mut last = HashMap::new();
        let base = Instant::now();
        for i in 0..(TARGET_KEYS + 10) {
            last.insert(format!("k{i}"), base + Duration::from_millis(i as u64));
        }

        // Every key is younger than the window, so nothing is expired by age and
        // this exercises the oldest-first fallback.
        sweep(&mut last, RETAIN_AFTER, TARGET_KEYS);

        assert_eq!(last.len(), TARGET_KEYS);
        for i in 10..(TARGET_KEYS + 10) {
            assert!(last.contains_key(&format!("k{i}")), "k{i} should survive");
        }
        for i in 0..10 {
            assert!(
                !last.contains_key(&format!("k{i}")),
                "k{i} should be dropped"
            );
        }
    }

    #[test]
    fn sweep_drops_expired_keys_before_touching_recent_ones() {
        // A key that can no longer suppress an emission should go even though a
        // recent key would also be a candidate for removal.
        let mut last = HashMap::new();
        for i in 0..TARGET_KEYS {
            last.insert(format!("k{i}"), Instant::now());
        }
        last.insert("expired".to_owned(), expired());

        sweep(&mut last, RETAIN_AFTER, TARGET_KEYS);

        assert!(!last.contains_key("expired"), "expired should be dropped");
        assert_eq!(
            last.len(),
            TARGET_KEYS,
            "recent keys should all survive the age-based sweep"
        );
    }

    #[test]
    fn sweep_stops_early_when_age_already_freed_enough() {
        let mut last = HashMap::new();
        for i in 0..(TARGET_KEYS - 10) {
            last.insert(format!("k{i}"), Instant::now());
        }
        for i in 0..20 {
            last.insert(format!("stale{i}"), expired());
        }

        // Age alone brings the map under the target, so the oldest-first
        // fallback must not run and evict any of the recent keys.
        sweep(&mut last, RETAIN_AFTER, TARGET_KEYS);

        assert_eq!(last.len(), TARGET_KEYS - 10);
        for i in 0..(TARGET_KEYS - 10) {
            assert!(last.contains_key(&format!("k{i}")), "k{i} should survive");
        }
    }

    #[test]
    fn below_cap_nothing_is_swept() {
        let limiter = RateLimiter::new();
        for i in 0..MAX_TRACKED_KEYS {
            limiter.should_emit(&format!("k{i}"));
        }
        assert_eq!(limiter.tracked(), MAX_TRACKED_KEYS);
    }
}
