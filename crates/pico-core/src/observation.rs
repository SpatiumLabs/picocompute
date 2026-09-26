//! Coherence rules for observed sandbox state.
//!
//! Observations are mirrors of the supervisor ledger. They are not lifecycle
//! authority, but stale observations must not be allowed to regress host-side
//! routes or cached state. This module is the single owner of the generation
//! and host-boot rules used by host caches.

use hashbrown::{DefaultHashBuilder, HashMap};

/// Non-empty SSH fields reported by an observation source.
///
/// Empty values mean "not reported" and must not erase previously observed
/// connection metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshObservation {
    /// Guest account name.
    pub username: String,
    /// Host-side SSH port.
    pub host_port: Option<u16>,
    /// Public key used for audit or reconnection.
    pub public_key: Option<String>,
}

/// Merges optional SSH fields without treating omission as deletion.
pub fn merge_ssh_observation(
    cache_username: &mut String,
    cache_host_port: &mut Option<u16>,
    cache_public_key: &mut Option<String>,
    incoming: &SshObservation,
) {
    if !incoming.username.is_empty() {
        *cache_username = incoming.username.clone();
    }
    if let Some(host_port) = incoming.host_port {
        *cache_host_port = Some(host_port);
    }
    if let Some(public_key) = incoming.public_key.as_ref()
        && !public_key.is_empty()
    {
        *cache_public_key = Some(public_key.clone());
    }
}

/// Ordering identity for an observed sandbox snapshot.
///
/// Generations are monotonic within one sandboxd process incarnation. A
/// different non-empty observation identity starts a new generation space, so a
/// lower generation from a restarted supervisor is valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObservationEpoch {
    /// Monotonic observation generation.
    pub generation: u64,
    /// Sandboxd process boot identity. Empty is retained for legacy payloads.
    pub host_boot_id: String,
}

impl ObservationEpoch {
    /// Creates an observation epoch.
    #[must_use]
    pub fn new(generation: u64, host_boot_id: impl Into<String>) -> Self {
        Self {
            generation,
            host_boot_id: host_boot_id.into(),
        }
    }

    /// Returns whether two epochs belong to the same boot space.
    ///
    /// Empty boot ids are treated as compatible with any value. This preserves
    /// compatibility with older payloads while still making a real boot change
    /// authoritative.
    #[must_use]
    pub fn same_boot(&self, other: &Self) -> bool {
        self.host_boot_id.is_empty()
            || other.host_boot_id.is_empty()
            || self.host_boot_id == other.host_boot_id
    }

    /// Returns whether `incoming` may replace this epoch.
    #[must_use]
    pub fn accepts(&self, incoming: &Self) -> bool {
        !self.same_boot(incoming) || incoming.generation >= self.generation
    }
}

/// Result of applying an observation epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoherenceDecision {
    /// The incoming epoch was stale or tombstoned.
    Rejected,
    /// The incoming epoch was accepted in the current boot space.
    Accepted,
    /// The incoming epoch was accepted after the supervisor boot changed.
    AcceptedAfterBootChange,
}

/// Per-sandbox observation ordering and invalidation state.
///
/// This state is observation-only. It never grants lifecycle authority and
/// never turns an observation into a desired-state transition.
#[derive(Debug, Default)]
pub struct ObservationCoherence {
    host_boot_id: String,
    epochs: HashMap<String, ObservationEpoch, DefaultHashBuilder>,
    tombstones: HashMap<String, ObservationEpoch, DefaultHashBuilder>,
}

impl ObservationCoherence {
    /// Creates empty coherence state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the current supervisor boot id.
    ///
    /// A non-empty change clears all per-sandbox generations and tombstones
    /// because the supervisor reset its generation counter. Returns `true` when
    /// state was cleared.
    pub fn note_host_boot_id(&mut self, host_boot_id: &str) -> bool {
        if host_boot_id.is_empty() {
            return false;
        }
        if self.host_boot_id.is_empty() {
            self.host_boot_id = host_boot_id.to_string();
            return false;
        }
        if self.host_boot_id == host_boot_id {
            return false;
        }
        self.host_boot_id = host_boot_id.to_string();
        self.epochs.clear();
        self.tombstones.clear();
        true
    }

    /// Returns the currently observed supervisor boot id.
    #[must_use]
    pub fn host_boot_id(&self) -> &str {
        &self.host_boot_id
    }

    /// Returns the accepted generation for a sandbox, if present.
    #[must_use]
    pub fn generation(&self, sandbox_id: &str) -> Option<u64> {
        self.epochs.get(sandbox_id).map(|epoch| epoch.generation)
    }

    /// Returns the accepted epoch for a sandbox, if present.
    #[must_use]
    pub fn epoch(&self, sandbox_id: &str) -> Option<&ObservationEpoch> {
        self.epochs.get(sandbox_id)
    }

    /// Returns tracked sandbox ids with their accepted generations.
    pub fn tracked_epochs(&self) -> impl Iterator<Item = (&str, u64)> {
        self.epochs
            .iter()
            .map(|(id, epoch)| (id.as_str(), epoch.generation))
    }

    /// Accepts an incoming epoch if it is not stale or tombstoned.
    ///
    /// On acceptance, the epoch becomes the new floor for that sandbox and any
    /// prior tombstone is removed. On rejection, all state is unchanged.
    /// A boot-change decision tells caches when dependent route state must be
    /// cleared without duplicating the ordering comparison.
    pub fn accept(&mut self, sandbox_id: &str, incoming: &ObservationEpoch) -> CoherenceDecision {
        let boot_changed = self.note_host_boot_id(&incoming.host_boot_id);
        let normalized = ObservationEpoch::new(
            incoming.generation,
            if incoming.host_boot_id.is_empty() {
                self.host_boot_id.clone()
            } else {
                incoming.host_boot_id.clone()
            },
        );

        if let Some(tombstone) = self.tombstones.get(sandbox_id)
            && tombstone.same_boot(&normalized)
            && normalized.generation <= tombstone.generation
        {
            return CoherenceDecision::Rejected;
        }
        if let Some(current) = self.epochs.get(sandbox_id)
            && !current.accepts(&normalized)
        {
            return CoherenceDecision::Rejected;
        }

        self.epochs.insert(sandbox_id.to_string(), normalized);
        self.tombstones.remove(sandbox_id);
        if boot_changed {
            CoherenceDecision::AcceptedAfterBootChange
        } else {
            CoherenceDecision::Accepted
        }
    }

    /// Invalidates a sandbox and returns the installed tombstone epoch.
    ///
    /// The tombstone blocks observations at or below the last accepted
    /// generation until a newer generation or a new host boot is observed.
    pub fn invalidate(&mut self, sandbox_id: &str) -> ObservationEpoch {
        let tombstone = self
            .epochs
            .remove(sandbox_id)
            .unwrap_or_else(|| ObservationEpoch::new(u64::MAX, self.host_boot_id.clone()));
        self.tombstones
            .insert(sandbox_id.to_string(), tombstone.clone());
        tombstone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_merge_preserves_omitted_fields() {
        let mut username = "root".into();
        let mut host_port = Some(22);
        let mut public_key = Some("key-a".into());
        merge_ssh_observation(
            &mut username,
            &mut host_port,
            &mut public_key,
            &SshObservation {
                username: String::new(),
                host_port: Some(22022),
                public_key: None,
            },
        );
        assert_eq!(username, "root");
        assert_eq!(host_port, Some(22022));
        assert_eq!(public_key.as_deref(), Some("key-a"));
    }

    #[test]
    fn same_boot_is_ordered_by_generation() {
        let current = ObservationEpoch::new(4, "boot-a");
        assert!(current.accepts(&ObservationEpoch::new(4, "boot-a")));
        assert!(current.accepts(&ObservationEpoch::new(5, "boot-a")));
        assert!(!current.accepts(&ObservationEpoch::new(3, "boot-a")));
    }

    #[test]
    fn new_boot_accepts_lower_generation() {
        let current = ObservationEpoch::new(99, "boot-a");
        assert!(current.accepts(&ObservationEpoch::new(0, "boot-b")));
    }

    #[test]
    fn empty_boot_is_legacy_compatible() {
        let current = ObservationEpoch::new(9, "boot-a");
        assert!(!current.accepts(&ObservationEpoch::new(8, "")));
        assert!(current.accepts(&ObservationEpoch::new(10, "")));
    }

    #[test]
    fn boot_change_clears_old_epochs_and_tombstones() {
        let mut coherence = ObservationCoherence::new();
        assert_eq!(
            coherence.accept("sbx", &ObservationEpoch::new(9, "boot-a")),
            CoherenceDecision::Accepted
        );
        coherence.invalidate("sbx");
        assert_eq!(coherence.generation("sbx"), None);
        assert!(coherence.note_host_boot_id("boot-b"));
        assert_eq!(
            coherence.accept("sbx", &ObservationEpoch::new(1, "boot-b")),
            CoherenceDecision::Accepted
        );
        assert_eq!(coherence.generation("sbx"), Some(1));
    }

    #[test]
    fn first_boot_is_not_reported_as_a_boot_change() {
        let mut coherence = ObservationCoherence::new();
        assert_eq!(
            coherence.accept("sbx", &ObservationEpoch::new(0, "boot-a")),
            CoherenceDecision::Accepted
        );
    }

    #[test]
    fn accept_reports_boot_change_explicitly() {
        let mut coherence = ObservationCoherence::new();
        assert_eq!(
            coherence.accept("sbx", &ObservationEpoch::new(9, "boot-a")),
            CoherenceDecision::Accepted
        );
        assert_eq!(
            coherence.accept("sbx", &ObservationEpoch::new(1, "boot-b")),
            CoherenceDecision::AcceptedAfterBootChange
        );
    }

    #[test]
    fn tombstone_rejects_equal_and_older_generations() {
        let mut coherence = ObservationCoherence::new();
        assert_eq!(
            coherence.accept("sbx", &ObservationEpoch::new(5, "boot-a")),
            CoherenceDecision::Accepted
        );
        coherence.invalidate("sbx");
        assert_eq!(
            coherence.accept("sbx", &ObservationEpoch::new(5, "boot-a")),
            CoherenceDecision::Rejected
        );
        assert_eq!(
            coherence.accept("sbx", &ObservationEpoch::new(4, "boot-a")),
            CoherenceDecision::Rejected
        );
        assert_eq!(
            coherence.accept("sbx", &ObservationEpoch::new(6, "boot-a")),
            CoherenceDecision::Accepted
        );
        assert_eq!(coherence.generation("sbx"), Some(6));
    }
}
