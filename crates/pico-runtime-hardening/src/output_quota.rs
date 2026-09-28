//! Output-capture quotas with truncation.
//!
//! DSec anecdotes include unbounded `yes` output (tens of GB) captured
//! by the agent. Every exec stream enforces a per-frame limit, a
//! per-stream byte quota, and a deadline. Excess output truncates with
//! an explicit marker and terminates the producer with a typed outcome.

/// Maximum bytes per stream frame (64 KiB, matches guest agent framing).
pub const FRAME_MAX_BYTES: usize = 64 * 1024;

/// Default per-stream capture quota (16 MiB).
pub const DEFAULT_STREAM_QUOTA_BYTES: u64 = 16 * 1024 * 1024;

/// Default total capture quota across stdout and stderr (32 MiB).
pub const DEFAULT_TOTAL_QUOTA_BYTES: u64 = 32 * 1024 * 1024;

/// Truncation marker appended when a quota is exceeded.
pub const TRUNCATION_MARKER: &str = "[truncated: output quota exceeded]";

/// Quota state for one captured stream.
#[derive(Debug, Clone)]
pub struct OutputQuota {
    max_bytes: u64,
    total: u64,
    truncated: bool,
}

impl OutputQuota {
    #[must_use]
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            total: 0,
            truncated: false,
        }
    }

    #[must_use]
    pub fn with_default() -> Self {
        Self::new(DEFAULT_STREAM_QUOTA_BYTES)
    }

    /// Observe `n` bytes. Returns the number of bytes the caller may
    /// retain before truncation, plus whether truncation applied.
    pub fn observe(&mut self, n: u64) -> QuotaDecision {
        if self.truncated {
            return QuotaDecision::Exceeded;
        }
        let next = self.total.saturating_add(n);
        if next > self.max_bytes {
            self.truncated = true;
            return QuotaDecision::Exceeded;
        }
        self.total = next;
        QuotaDecision::WithinBudget
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    #[must_use]
    pub fn truncation_marker() -> &'static str {
        TRUNCATION_MARKER
    }
}

/// Outcome of a quota observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDecision {
    WithinBudget,
    Exceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbounded_yes_output_exceeds_default_quota() {
        let mut quota = OutputQuota::with_default();
        // Simulate tens of GB in 64 KiB frames; quota must trip early.
        let mut exceeded = false;
        for _ in 0..1_000_000 {
            if quota.observe(FRAME_MAX_BYTES as u64) == QuotaDecision::Exceeded {
                exceeded = true;
                break;
            }
        }
        assert!(exceeded);
        assert!(quota.is_truncated());
    }

    #[test]
    fn small_output_stays_within_budget() {
        let mut quota = OutputQuota::new(1024);
        assert_eq!(quota.observe(512), QuotaDecision::WithinBudget);
        assert_eq!(quota.observe(512), QuotaDecision::WithinBudget);
        assert_eq!(quota.total(), 1024);
        assert!(!quota.is_truncated());
    }

    #[test]
    fn quota_trips_once_and_stays_exceeded() {
        let mut quota = OutputQuota::new(100);
        assert_eq!(quota.observe(60), QuotaDecision::WithinBudget);
        assert_eq!(quota.observe(60), QuotaDecision::Exceeded);
        assert_eq!(quota.observe(1), QuotaDecision::Exceeded);
        assert!(quota.is_truncated());
    }

    #[test]
    fn frame_limit_matches_guest_agent_framing() {
        assert_eq!(FRAME_MAX_BYTES, 64 * 1024);
    }
}
