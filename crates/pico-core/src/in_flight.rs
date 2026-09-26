//! Per-scheduler in-flight placement overlay.
//!
//! Inventory snapshots go stale between watcher polls: a scheduler that
//! places many sandboxes from one snapshot keeps seeing the same headroom
//! and herds every burst onto the same winner. The overlay closes that gap
//! without cross-instance coordination. Each scheduler instance records its
//! own recent placements locally and folds the reserved resources back into
//! the candidate capacities it evaluates, so consecutive decisions from one
//! instance spread even when the snapshot does not move.
//!
//! Entries expire after a TTL matched to the inventory staleness window, so
//! a placement the next snapshot already reflects stops double-counting.
//! Callers remove an entry early via [`InFlightOverlay::release`] when the
//! downstream assignment settles (accepted and reflected, or rejected).

use hashbrown::HashMap;
use time::{Duration, OffsetDateTime};

/// Default entry lifetime, matched to the host inventory staleness window.
pub const DEFAULT_IN_FLIGHT_TTL_SECS: i64 = 60;

/// Default bound on tracked candidates, sized above burst windows.
pub const DEFAULT_IN_FLIGHT_MAX_ENTRIES: usize = 4096;

/// Resources one scheduler instance recently placed on a candidate.
///
/// The snapshot the next decision evaluates does not reflect these yet, so
/// schedulers add them to the reported allocation before filtering and
/// scoring. Counts never overcommit: they only make the local view match
/// the placements this instance already issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InFlightReservation {
    /// Reserved vCPUs.
    pub vcpus: u64,
    /// Reserved memory in MB.
    pub memory_mb: u64,
    /// Reserved disk in MB.
    pub disk_mb: u64,
    /// Reserved sandbox slots.
    pub count: u64,
}

impl InFlightReservation {
    /// Empty reservation (no resources held).
    pub fn empty() -> Self {
        Self {
            vcpus: 0,
            memory_mb: 0,
            disk_mb: 0,
            count: 0,
        }
    }

    /// Whether any resource is held.
    pub fn is_empty(self) -> bool {
        self == Self::empty()
    }
}

/// Recent placements held against candidate IDs until snapshots refresh.
///
/// Not shared across scheduler instances by design: each instance tracks
/// only its own decisions, which is exactly the load missing from a shared
/// stale snapshot. Entries accumulate per candidate ID, expire by TTL, and
/// stay bounded by evicting the oldest entry when full.
#[derive(Debug, Clone)]
pub struct InFlightOverlay {
    entries: HashMap<String, TimestampedReservation>,
    ttl_secs: i64,
    max_entries: usize,
}

#[derive(Debug, Clone, Copy)]
struct TimestampedReservation {
    reservation: InFlightReservation,
    recorded_at: OffsetDateTime,
}

impl InFlightOverlay {
    /// Overlay with default TTL and entry bound.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_IN_FLIGHT_TTL_SECS, DEFAULT_IN_FLIGHT_MAX_ENTRIES)
    }

    /// Overlay with explicit entry lifetime and bound.
    ///
    /// Non-positive TTL disables expiry comparison edge cases by clamping
    /// to at least one second; zero max entries disables recording.
    pub fn with_limits(ttl_secs: i64, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_secs: ttl_secs.max(1),
            max_entries,
        }
    }

    /// Record a placement of the given shape against a candidate.
    ///
    /// Repeat placements on one candidate accumulate. Expired entries are
    /// pruned first; when still full, the oldest entry is evicted so the
    /// overlay stays bounded under sustained bursts.
    pub fn record(
        &mut self,
        candidate_id: &str,
        vcpus: u64,
        memory_mb: u64,
        disk_mb: u64,
        now: OffsetDateTime,
    ) {
        if self.max_entries == 0 {
            return;
        }
        self.prune_expired(now);
        if !self.entries.contains_key(candidate_id)
            && self.entries.len() >= self.max_entries
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.recorded_at)
                .map(|(id, _)| id.clone())
        {
            self.entries.remove(&oldest);
        }
        let slot = self
            .entries
            .entry(candidate_id.to_string())
            .or_insert(TimestampedReservation {
                reservation: InFlightReservation::empty(),
                recorded_at: now,
            });
        slot.reservation.vcpus = slot.reservation.vcpus.saturating_add(vcpus);
        slot.reservation.memory_mb = slot.reservation.memory_mb.saturating_add(memory_mb);
        slot.reservation.disk_mb = slot.reservation.disk_mb.saturating_add(disk_mb);
        slot.reservation.count = slot.reservation.count.saturating_add(1);
        slot.recorded_at = now;
    }

    /// Drop the entry for a candidate whose assignment settled.
    ///
    /// Returns true when an entry existed. Call when the downstream host
    /// accepted or finally rejected the placement so later decisions stop
    /// double-counting it ahead of the TTL.
    pub fn release(&mut self, candidate_id: &str) -> bool {
        self.entries.remove(candidate_id).is_some()
    }

    /// Live reservation for a candidate, or `None` when absent or expired.
    pub fn reserved_for(
        &self,
        candidate_id: &str,
        now: OffsetDateTime,
    ) -> Option<InFlightReservation> {
        let entry = self.entries.get(candidate_id)?;
        if self.is_expired(entry.recorded_at, now) {
            return None;
        }
        Some(entry.reservation)
    }

    /// Number of tracked candidates, including not-yet-pruned expired ones.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether any candidate is tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop entries older than the TTL. Runs inline on [`Self::record`].
    pub fn prune_expired(&mut self, now: OffsetDateTime) {
        let ttl_secs = self.ttl_secs;
        self.entries
            .retain(|_, entry| now - entry.recorded_at < Duration::seconds(ttl_secs));
    }

    fn is_expired(&self, recorded_at: OffsetDateTime, now: OffsetDateTime) -> bool {
        now - recorded_at >= Duration::seconds(self.ttl_secs)
    }
}

impl Default for InFlightOverlay {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[test]
    fn record_accumulates_per_candidate() {
        let mut overlay = InFlightOverlay::new();
        let at = now();
        overlay.record("cel_1", 2, 512, 0, at);
        overlay.record("cel_1", 2, 512, 0, at);
        let reserved = overlay.reserved_for("cel_1", at).unwrap();
        assert_eq!(
            reserved,
            InFlightReservation {
                vcpus: 4,
                memory_mb: 1024,
                disk_mb: 0,
                count: 2,
            }
        );
        assert!(overlay.reserved_for("cel_2", at).is_none());
    }

    #[test]
    fn release_drops_candidate() {
        let mut overlay = InFlightOverlay::new();
        let at = now();
        overlay.record("cel_1", 2, 512, 0, at);
        assert!(overlay.release("cel_1"));
        assert!(!overlay.release("cel_1"));
        assert!(overlay.reserved_for("cel_1", at).is_none());
        assert!(overlay.is_empty());
    }

    #[test]
    fn entries_expire_after_ttl() {
        let mut overlay = InFlightOverlay::with_limits(60, 16);
        let at = now();
        overlay.record("cel_1", 2, 512, 0, at);
        assert!(overlay.reserved_for("cel_1", at).is_some());
        let later = at + Duration::seconds(61);
        assert!(overlay.reserved_for("cel_1", later).is_none());
        overlay.prune_expired(later);
        assert!(overlay.is_empty());
    }

    #[test]
    fn full_overlay_evicts_oldest() {
        let mut overlay = InFlightOverlay::with_limits(3600, 2);
        let at = now();
        overlay.record("cel_1", 1, 1, 0, at);
        overlay.record("cel_2", 1, 1, 0, at + Duration::seconds(1));
        overlay.record("cel_3", 1, 1, 0, at + Duration::seconds(2));
        assert_eq!(overlay.len(), 2);
        assert!(overlay.reserved_for("cel_1", at).is_none());
        assert!(overlay.reserved_for("cel_2", at).is_some());
        assert!(overlay.reserved_for("cel_3", at).is_some());
    }

    #[test]
    fn zero_max_entries_disables_recording() {
        let mut overlay = InFlightOverlay::with_limits(60, 0);
        let at = now();
        overlay.record("cel_1", 2, 512, 0, at);
        assert!(overlay.is_empty());
    }
}
