//! Hybrid Logical Clock (HLC) for causal ordering of events.
//!
//! Combines physical wall-clock time with a logical counter to provide
//! total causal ordering without requiring wall-clock synchronization
//! across distributed components. Per ADR-0001, every audit event
//! carries an HLC timestamp.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};

/// A Hybrid Logical Clock timestamp for causal ordering of events.
///
/// ## Ordering rules
///
/// 1. Compare `wall_time_ms`: later wall-clock time = later event.
/// 2. If wall-clock times are equal, compare `logical_counter`: higher
///    counter = later event.
/// 3. If both are equal, the events are concurrent (same source at same
///    instant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HlcTimestamp {
    /// Milliseconds since Unix epoch (wall-clock component).
    pub wall_time_ms: i64,
    /// Monotonic logical counter for ordering within the same wall-time
    /// millisecond.
    pub logical_counter: u32,
}

impl HlcTimestamp {
    /// Creates a new HLC timestamp at the current wall-clock time with
    /// logical counter `0`.
    pub fn now() -> Self {
        use time::OffsetDateTime;
        let now = OffsetDateTime::now_utc();
        let ms = now.unix_timestamp() * 1000 + now.millisecond() as i64;
        Self {
            wall_time_ms: ms,
            logical_counter: 0,
        }
    }

    /// Advances the logical counter for the same wall-time millisecond.
    ///
    /// This is used when multiple events occur within the same
    /// millisecond on the same component. Returns a new `HlcTimestamp`
    /// with `logical_counter` incremented by 1.
    pub fn tick(&self) -> Self {
        Self {
            wall_time_ms: self.wall_time_ms,
            logical_counter: self.logical_counter + 1,
        }
    }

    /// Compares two HLC timestamps for total ordering.
    ///
    /// Returns `std::cmp::Ordering::Less` if `self` happened before
    /// `other`, `Greater` if after, and `Equal` if concurrent.
    pub fn compare(&self, other: &HlcTimestamp) -> std::cmp::Ordering {
        match self.wall_time_ms.cmp(&other.wall_time_ms) {
            std::cmp::Ordering::Equal => self.logical_counter.cmp(&other.logical_counter),
            ord => ord,
        }
    }

    /// Returns the wall-time component as a Unix timestamp in seconds.
    pub fn unix_seconds(&self) -> i64 {
        self.wall_time_ms / 1000
    }

    /// Formats as an ISO 8601 UTC string with millisecond precision.
    pub fn to_iso8601(&self) -> String {
        let secs = self.wall_time_ms / 1000;
        let millis = (self.wall_time_ms % 1000) as u64;
        let dt = time::OffsetDateTime::from_unix_timestamp(secs)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        let fmt = time::format_description::well_known::Iso8601::DEFAULT;
        let base = dt
            .format(&fmt)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        if millis > 0 {
            base.replacen("Z", &format!(".{:03}Z", millis), 1)
        } else {
            base
        }
    }
}

impl PartialOrd for HlcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for HlcTimestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.compare(other)
    }
}

impl fmt::Display for HlcTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hlc({},{},{})",
            self.wall_time_ms,
            self.logical_counter,
            self.to_iso8601()
        )
    }
}

/// A global (per-process) HLC instance for generating timestamps.
///
/// Uses atomics for the logical counter to support concurrent access
/// from multiple tasks within the same process. Components that need
/// cross-process HLC coordination (e.g., across cells) must implement
/// NTP-augmented HLC propagation.
pub struct Hlc {
    last_wall_time_ms: AtomicU32,
    logical_counter: AtomicU32,
}

impl Hlc {
    /// Creates a new HLC instance starting from the current time.
    pub fn new() -> Self {
        use time::OffsetDateTime;
        let now = OffsetDateTime::now_utc();
        let ms = (now.unix_timestamp() * 1000 + now.millisecond() as i64) as u64;
        Self {
            last_wall_time_ms: AtomicU32::new((ms % (1 << 32)) as u32),
            logical_counter: AtomicU32::new(0),
        }
    }

    /// Generates the next timestamp, advancing the logical counter.
    ///
    /// If the wall clock has advanced, resets the logical counter to 0.
    /// If the wall clock has not advanced, increments the logical
    /// counter.
    pub fn next_timestamp(&self) -> HlcTimestamp {
        use time::OffsetDateTime;
        let now = OffsetDateTime::now_utc();
        let ms = (now.unix_timestamp() * 1000 + now.millisecond() as i64) as u64;
        let truncated = (ms % (1 << 32)) as u32;

        let prev = self.last_wall_time_ms.load(Ordering::Acquire);
        if truncated > prev {
            self.last_wall_time_ms.store(truncated, Ordering::Release);
            self.logical_counter.store(0, Ordering::Release);
            HlcTimestamp {
                wall_time_ms: ms as i64,
                logical_counter: 0,
            }
        } else {
            let counter = self.logical_counter.fetch_add(1, Ordering::AcqRel);
            HlcTimestamp {
                wall_time_ms: ms as i64,
                logical_counter: counter + 1,
            }
        }
    }
}

impl Default for Hlc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_now_creates_timestamp() {
        let ts = HlcTimestamp::now();
        assert!(ts.wall_time_ms > 0);
        assert_eq!(ts.logical_counter, 0);
    }

    #[test]
    fn hlc_tick_increments_logical_counter() {
        let ts = HlcTimestamp::now();
        let next = ts.tick();
        assert_eq!(next.wall_time_ms, ts.wall_time_ms);
        assert_eq!(next.logical_counter, ts.logical_counter + 1);
    }

    #[test]
    fn hlc_ordering_wall_time_dominates() {
        let earlier = HlcTimestamp {
            wall_time_ms: 1000,
            logical_counter: 5,
        };
        let later = HlcTimestamp {
            wall_time_ms: 2000,
            logical_counter: 0,
        };
        assert!(earlier < later);
        assert!(later > earlier);
    }

    #[test]
    fn hlc_ordering_logical_counter_tiebreaker() {
        let a = HlcTimestamp {
            wall_time_ms: 1000,
            logical_counter: 0,
        };
        let b = HlcTimestamp {
            wall_time_ms: 1000,
            logical_counter: 1,
        };
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn hlc_ordering_equal_for_same_values() {
        let a = HlcTimestamp {
            wall_time_ms: 1000,
            logical_counter: 0,
        };
        let b = HlcTimestamp {
            wall_time_ms: 1000,
            logical_counter: 0,
        };
        assert_eq!(a, b);
        assert!(a <= b);
        assert!(b >= a);
    }

    #[test]
    fn hlc_to_iso8601_is_valid() {
        let ts = HlcTimestamp::now();
        let iso = ts.to_iso8601();
        assert!(iso.contains('T'));
        assert!(iso.ends_with('Z') || iso.contains('.'));
    }

    #[test]
    fn hlc_serialization_roundtrip() {
        let ts = HlcTimestamp {
            wall_time_ms: 1700000000000,
            logical_counter: 42,
        };
        let json = serde_json::to_string(&ts).unwrap();
        let back: HlcTimestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, back);
    }

    #[test]
    fn hlc_display_is_readable() {
        let ts = HlcTimestamp {
            wall_time_ms: 1700000000000,
            logical_counter: 0,
        };
        let s = format!("{ts}");
        assert!(s.starts_with("hlc("));
    }

    #[test]
    fn hlc_instance_generates_monotonic_timestamps() {
        let hlc = Hlc::new();
        let ts1 = hlc.next_timestamp();
        let ts2 = hlc.next_timestamp();
        assert!(ts2 >= ts1, "HLC timestamps must be monotonic");
    }

    #[test]
    fn hlc_monotonic_across_many_ticks() {
        let ts = HlcTimestamp::now();
        let mut prev = ts;
        for _ in 0..100 {
            let next = prev.tick();
            assert!(next > prev, "HLC must be strictly monotonic across ticks");
            prev = next;
        }
    }
}
