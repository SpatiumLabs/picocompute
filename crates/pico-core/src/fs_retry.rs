//! Bounded retries for transient host filesystem removals.
//!
//! Destroy and GC teardown hit cgroup and workspace paths that can fail briefly
//! while the kernel drains processes (EBUSY) or finishes unlinking children
//! (ENOTEMPTY). Retrying those errors in-process converges cleanup to released
//! receipts without operator review. Permanent failures (permission, wrong
//! path type, unknown resources) are not retried here.

use std::io;
use std::time::Duration;

use tracing::debug;

/// Attempts for one removal, including the first try.
pub const TRANSIENT_FS_MAX_ATTEMPTS: u32 = 8;

/// Initial backoff between attempts; doubles each retry up to
/// [`TRANSIENT_FS_MAX_DELAY`].
pub const TRANSIENT_FS_BASE_DELAY: Duration = Duration::from_millis(25);

/// Cap on a single backoff sleep so destroy stays inside operation deadlines.
pub const TRANSIENT_FS_MAX_DELAY: Duration = Duration::from_millis(200);

/// Policy for [`retry_transient_fs_op_with`].
#[derive(Debug, Clone, Copy)]
pub struct TransientFsRetryPolicy {
    /// Total attempts including the first try.
    pub max_attempts: u32,
    /// Delay before the second attempt; doubles each subsequent retry.
    pub base_delay: Duration,
    /// Upper bound for one sleep.
    pub max_delay: Duration,
}

impl Default for TransientFsRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: TRANSIENT_FS_MAX_ATTEMPTS,
            base_delay: TRANSIENT_FS_BASE_DELAY,
            max_delay: TRANSIENT_FS_MAX_DELAY,
        }
    }
}

/// Returns true when the error is safe to retry for directory teardown.
#[must_use]
pub fn is_transient_fs_error(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock
        | io::ErrorKind::TimedOut
        | io::ErrorKind::ResourceBusy
        | io::ErrorKind::DirectoryNotEmpty => true,
        _ => match err.raw_os_error() {
            #[cfg(unix)]
            Some(code) => {
                code == libc::EBUSY
                    || code == libc::EAGAIN
                    || code == libc::EINTR
                    || code == libc::ENOTEMPTY
            }
            #[cfg(not(unix))]
            Some(_) => false,
            None => false,
        },
    }
}

/// Runs `op` with the default transient filesystem retry policy.
///
/// Sleeps on the calling thread between attempts. Callers that must not block
/// an async worker should run this on a blocking pool.
pub fn retry_transient_fs_op<T>(op_name: &str, op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry_transient_fs_op_with(op_name, TransientFsRetryPolicy::default(), op)
}

/// Runs `op` with an explicit retry policy (tests use zero delay).
pub fn retry_transient_fs_op_with<T>(
    op_name: &str,
    policy: TransientFsRetryPolicy,
    mut op: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let max_attempts = policy.max_attempts.max(1);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if is_transient_fs_error(&err) && attempt < max_attempts => {
                let exp = attempt.saturating_sub(1).min(16);
                let delay = policy
                    .base_delay
                    .saturating_mul(2u32.saturating_pow(exp))
                    .min(policy.max_delay);
                debug!(
                    op = op_name,
                    attempt,
                    max_attempts,
                    delay_ms = delay.as_millis() as u64,
                    error = %err,
                    "transient filesystem error, retrying"
                );
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn zero_delay_policy(max_attempts: u32) -> TransientFsRetryPolicy {
        TransientFsRetryPolicy {
            max_attempts,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    #[test]
    fn classifies_busy_and_not_empty_as_transient() {
        assert!(is_transient_fs_error(&Error::from(ErrorKind::ResourceBusy)));
        assert!(is_transient_fs_error(&Error::from(
            ErrorKind::DirectoryNotEmpty
        )));
        assert!(is_transient_fs_error(&Error::from(ErrorKind::Interrupted)));
        assert!(!is_transient_fs_error(&Error::from(
            ErrorKind::PermissionDenied
        )));
        assert!(!is_transient_fs_error(&Error::from(ErrorKind::NotFound)));
        assert!(!is_transient_fs_error(&Error::from(
            ErrorKind::InvalidInput
        )));
    }

    #[test]
    fn retries_transient_errors_until_success() {
        let tries = AtomicU32::new(0);
        let value = retry_transient_fs_op_with("test-op", zero_delay_policy(5), || {
            let n = tries.fetch_add(1, Ordering::SeqCst);
            if n < 3 {
                Err(Error::from(ErrorKind::ResourceBusy))
            } else {
                Ok(7_u32)
            }
        })
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(tries.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn does_not_retry_permanent_errors() {
        let tries = AtomicU32::new(0);
        let err = retry_transient_fs_op_with("test-op", zero_delay_policy(5), || {
            tries.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(Error::from(ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(tries.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exhausts_retries_on_persistent_transient_error() {
        let tries = AtomicU32::new(0);
        let err = retry_transient_fs_op_with("test-op", zero_delay_policy(3), || {
            tries.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(Error::from(ErrorKind::DirectoryNotEmpty))
        })
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DirectoryNotEmpty);
        assert_eq!(tries.load(Ordering::SeqCst), 3);
    }
}
