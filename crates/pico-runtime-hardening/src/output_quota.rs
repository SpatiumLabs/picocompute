//! Output-capture quotas with truncation.
//!
//! DSec anecdotes include unbounded `yes` output (tens of GB) captured
//! by the agent. The guest agent (`pico-guest-agent/src/exec.rs`)
//! enforces per-stream `max_stdout_bytes`/`max_stderr_bytes` with a typed
//! `OutputLimitExceeded` outcome; this module is the canonical policy
//! definition for those quotas plus host-side capture helpers.
//! Excess output truncates with an explicit marker and terminates the
//! producer.

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

    /// Observe `n` bytes and return whether the stream is still within budget.
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

    /// Marker to append when [`Self::is_truncated`] is true.
    #[must_use]
    pub fn truncation_marker() -> &'static str {
        TRUNCATION_MARKER
    }

    /// Truncated output notice including current totals.
    #[must_use]
    pub fn truncated_notice(&self) -> String {
        format!(
            "{} (captured {} of {} byte quota)",
            Self::truncation_marker(),
            self.total,
            self.max_bytes
        )
    }
}

/// Combined stdout and stderr quota using [`DEFAULT_TOTAL_QUOTA_BYTES`].
///
/// Guest-agent streams enforce per-stream quotas; the host applies this
/// total bound across both streams before buffering.
#[derive(Debug, Clone)]
pub struct OutputQuotaSet {
    stdout: OutputQuota,
    stderr: OutputQuota,
    max_total: u64,
    total: u64,
    truncated: bool,
}

impl OutputQuotaSet {
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            stdout: OutputQuota::with_default(),
            stderr: OutputQuota::with_default(),
            max_total: DEFAULT_TOTAL_QUOTA_BYTES,
            total: 0,
            truncated: false,
        }
    }

    /// Observe stdout bytes against per-stream and total quotas.
    pub fn observe_stdout(&mut self, n: u64) -> QuotaDecision {
        self.observe(true, n)
    }

    /// Observe stderr bytes against per-stream and total quotas.
    pub fn observe_stderr(&mut self, n: u64) -> QuotaDecision {
        self.observe(false, n)
    }

    fn observe(&mut self, is_stdout: bool, n: u64) -> QuotaDecision {
        if self.truncated {
            return QuotaDecision::Exceeded;
        }
        let stream_decision = if is_stdout {
            self.stdout.observe(n)
        } else {
            self.stderr.observe(n)
        };
        if stream_decision == QuotaDecision::Exceeded {
            self.truncated = true;
            return QuotaDecision::Exceeded;
        }
        let next = self.total.saturating_add(n);
        if next > self.max_total {
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
        assert!(
            quota
                .truncated_notice()
                .contains(OutputQuota::truncation_marker())
        );
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

    #[test]
    fn total_quota_bounds_combined_streams() {
        let mut set = OutputQuotaSet::with_defaults();
        assert_eq!(
            set.observe_stdout(DEFAULT_STREAM_QUOTA_BYTES),
            QuotaDecision::WithinBudget
        );
        // Second stream pushes the combined total over 32 MiB.
        assert_eq!(
            set.observe_stderr(DEFAULT_STREAM_QUOTA_BYTES + 1),
            QuotaDecision::Exceeded
        );
        assert!(set.is_truncated());
        assert!(set.total() <= DEFAULT_TOTAL_QUOTA_BYTES);
    }
}
