//! Fencing tokens for preventing stale operations.
//!
//! A fencing token combines a monotonic epoch (global policy version)
//! with a local sequence number. Operations carrying stale tokens are
//! rejected, preventing replay attacks and split-brain scenarios.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::ids::OperationId;

/// A fencing token that prevents stale operations.
///
/// Combines a monotonic epoch (global policy version) with a local
/// sequence number to create a token that must be greater than any
/// previously seen token for a given resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencingToken {
    /// Global policy epoch.
    pub epoch: u64,
    /// Monotonic sequence within the epoch.
    pub sequence: u64,
}

impl Default for FencingToken {
    fn default() -> Self {
        Self::new(1)
    }
}

impl FencingToken {
    /// Creates a new fencing token at the start of an epoch.
    pub const fn new(epoch: u64) -> Self {
        Self { epoch, sequence: 0 }
    }

    /// Returns the next fencing token in sequence.
    pub const fn next_sequence(self) -> Self {
        Self {
            epoch: self.epoch,
            sequence: self.sequence + 1,
        }
    }

    /// Returns the next fencing token at a new epoch.
    pub const fn next_epoch(self) -> Self {
        Self {
            epoch: self.epoch + 1,
            sequence: 0,
        }
    }

    /// Checks whether `self` is strictly newer than `other`.
    ///
    /// A newer token has either a higher epoch or the same epoch with
    /// a higher sequence.
    pub fn is_newer_than(&self, other: &FencingToken) -> bool {
        self.epoch > other.epoch || (self.epoch == other.epoch && self.sequence > other.sequence)
    }

    /// Checks whether `self` is stale relative to `current`.
    ///
    /// A token is stale if it is behind the current fencing token.
    pub fn is_stale(&self, current: &FencingToken) -> bool {
        current.is_newer_than(self)
    }
}

impl PartialOrd for FencingToken {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FencingToken {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.epoch.cmp(&other.epoch) {
            std::cmp::Ordering::Equal => self.sequence.cmp(&other.sequence),
            ord => ord,
        }
    }
}

impl fmt::Display for FencingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.epoch, self.sequence)
    }
}

impl std::str::FromStr for FencingToken {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (epoch, sequence) = s
            .split_once('.')
            .ok_or_else(|| format!("fencing token must be epoch.sequence, got {s:?}"))?;
        let epoch = epoch
            .parse::<u64>()
            .map_err(|err| format!("invalid fencing token epoch in {s:?}: {err}"))?;
        let sequence = sequence
            .parse::<u64>()
            .map_err(|err| format!("invalid fencing token sequence in {s:?}: {err}"))?;
        Ok(Self { epoch, sequence })
    }
}

/// Checks whether a fencing token is stale relative to the current
/// token and should cause operation rejection.
///
/// Returns an error describing the staleness if the token is stale.
pub fn check_fencing_token(
    request_token: Option<FencingToken>,
    current_token: Option<FencingToken>,
) -> Result<(), String> {
    match (request_token, current_token) {
        (Some(req), Some(cur)) if req.is_stale(&cur) => Err(format!(
            "stale fencing token: request {} is behind current {}",
            req, cur
        )),
        _ => Ok(()),
    }
}

/// Checks whether a policy epoch from a request is stale relative to
/// the current epoch.
///
/// Returns an error if the request epoch is behind the current epoch,
/// indicating the caller is operating with outdated policy.
pub fn check_policy_epoch(request_epoch: Option<u64>, current_epoch: u64) -> Result<(), String> {
    match request_epoch {
        Some(epoch) if epoch < current_epoch => Err(format!(
            "stale policy epoch: request uses epoch {epoch}, current is {current_epoch}"
        )),
        _ => Ok(()),
    }
}

/// Checks whether an operation should be rejected as replayed.
///
/// An operation is replayed if a given operation ID has already been
/// processed. This is a convenience wrapper around checking the set of
/// known operation IDs.
pub fn is_replayed_operation(op_id: &OperationId, processed_ids: &[OperationId]) -> bool {
    processed_ids.contains(op_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fencing_token_new_starts_at_zero() {
        let ft = FencingToken::new(7);
        assert_eq!(ft.epoch, 7);
        assert_eq!(ft.sequence, 0);
    }

    #[test]
    fn fencing_token_default_starts_at_epoch_1() {
        let ft = FencingToken::default();
        assert_eq!(ft.epoch, 1);
        assert_eq!(ft.sequence, 0);
    }

    #[test]
    fn fencing_token_next_sequence_increments() {
        let ft = FencingToken::new(1);
        let next = ft.next_sequence();
        assert_eq!(next.epoch, 1);
        assert_eq!(next.sequence, 1);
    }

    #[test]
    fn fencing_token_next_epoch_resets_sequence() {
        let ft = FencingToken {
            epoch: 1,
            sequence: 5,
        };
        let next = ft.next_epoch();
        assert_eq!(next.epoch, 2);
        assert_eq!(next.sequence, 0);
    }

    #[test]
    fn fencing_token_is_newer_than() {
        let old = FencingToken {
            epoch: 1,
            sequence: 0,
        };
        let newer_same_epoch = FencingToken {
            epoch: 1,
            sequence: 1,
        };
        let newer_epoch = FencingToken {
            epoch: 2,
            sequence: 0,
        };

        assert!(newer_same_epoch.is_newer_than(&old));
        assert!(newer_epoch.is_newer_than(&old));
        assert!(newer_epoch.is_newer_than(&newer_same_epoch));
        assert!(!old.is_newer_than(&old));
    }

    #[test]
    fn fencing_token_is_stale() {
        let current = FencingToken {
            epoch: 2,
            sequence: 3,
        };
        let stale_epoch = FencingToken {
            epoch: 1,
            sequence: 9,
        };
        let stale_sequence = FencingToken {
            epoch: 2,
            sequence: 1,
        };
        let equal = FencingToken {
            epoch: 2,
            sequence: 3,
        };

        assert!(stale_epoch.is_stale(&current));
        assert!(stale_sequence.is_stale(&current));
        assert!(!equal.is_stale(&current));
    }

    #[test]
    fn fencing_token_ordering() {
        let a = FencingToken {
            epoch: 1,
            sequence: 0,
        };
        let b = FencingToken {
            epoch: 1,
            sequence: 5,
        };
        let c = FencingToken {
            epoch: 2,
            sequence: 0,
        };

        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn fencing_token_display() {
        let ft = FencingToken {
            epoch: 42,
            sequence: 7,
        };
        assert_eq!(format!("{ft}"), "42.7");
    }

    #[test]
    fn fencing_token_from_str_round_trip() {
        let ft: FencingToken = "42.7".parse().unwrap();
        assert_eq!(ft.epoch, 42);
        assert_eq!(ft.sequence, 7);
        assert!("not-a-token".parse::<FencingToken>().is_err());
        assert!("1".parse::<FencingToken>().is_err());
    }

    #[test]
    fn fencing_token_serialization() {
        let ft = FencingToken {
            epoch: 3,
            sequence: 5,
        };
        let json = serde_json::to_string(&ft).unwrap();
        let back: FencingToken = serde_json::from_str(&json).unwrap();
        assert_eq!(ft, back);
    }

    #[test]
    fn fencing_token_check_passes_when_none() {
        assert!(check_fencing_token(None, None).is_ok());
    }

    #[test]
    fn fencing_token_check_passes_when_no_current() {
        let req = Some(FencingToken {
            epoch: 1,
            sequence: 0,
        });
        assert!(check_fencing_token(req, None).is_ok());
    }

    #[test]
    fn fencing_token_check_fails_when_stale() {
        let req = Some(FencingToken {
            epoch: 1,
            sequence: 0,
        });
        let cur = Some(FencingToken {
            epoch: 2,
            sequence: 0,
        });
        assert!(check_fencing_token(req, cur).is_err());
    }

    #[test]
    fn policy_epoch_check_passes_when_current() {
        assert!(check_policy_epoch(Some(5), 5).is_ok());
        assert!(check_policy_epoch(Some(6), 5).is_ok());
        assert!(check_policy_epoch(None, 5).is_ok());
    }

    #[test]
    fn policy_epoch_check_fails_when_stale() {
        assert!(check_policy_epoch(Some(3), 5).is_err());
    }

    #[test]
    fn replayed_operation_is_detected() {
        let op = OperationId::generate();
        let processed = vec![op.clone()];
        assert!(is_replayed_operation(&op, &processed));
    }

    #[test]
    fn new_operation_is_not_replayed() {
        let op = OperationId::generate();
        let other = OperationId::generate();
        assert!(!is_replayed_operation(&op, &[other]));
    }

    #[test]
    fn operation_replay_detected_with_fencing_token() {
        let current = FencingToken {
            epoch: 2,
            sequence: 5,
        };

        let replayed = FencingToken {
            epoch: 1,
            sequence: 9,
        };
        assert!(replayed.is_stale(&current));

        let valid = FencingToken {
            epoch: 2,
            sequence: 5,
        };
        assert!(!valid.is_stale(&current));
    }
}
