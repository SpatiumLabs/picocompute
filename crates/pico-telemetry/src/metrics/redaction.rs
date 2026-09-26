//! The single shared-host metric redaction flag.
//!
//! PicoCompute runs on both dedicated-tenancy and shared multi-tenant hosts. On a
//! shared host, per-sandbox identity must not reach exported metrics, because
//! metric sampling alone would otherwise let one tenant infer another tenant's
//! activity. `shared_host_metric_redaction` turns that substitution on.
//!
//! This flag used to be duplicated as a private `AtomicBool` in each of
//! `pico-core`, `pico-network-agent`, and `pico-host-agent`, all set
//! from a single call site at startup. One flag with one setter removes the
//! possibility of the copies diverging, and gives [`Labels`](super::Labels) a
//! single decision to consult.
//!
//! [`Labels::tenant`](super::Labels::tenant) and
//! [`Labels::sandbox`](super::Labels::sandbox) read it; nothing else should.

use std::sync::atomic::{AtomicBool, Ordering};

static SHARED_HOST_REDACTION: AtomicBool = AtomicBool::new(false);

/// Enables or disables shared-host metric redaction for the process.
///
/// Called once during agent bootstrap from the
/// `shared_host_metric_redaction` host-agent config field, overridable with
/// `PICO_SHARED_HOST_METRIC_REDACTION`. Off by default, which is correct for
/// dedicated-tenancy hosts.
pub fn set_shared_host_redaction(enabled: bool) {
    SHARED_HOST_REDACTION.store(enabled, Ordering::Release);
}

/// Whether identity attributes are currently being redacted.
pub fn shared_host_redaction() -> bool {
    SHARED_HOST_REDACTION.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes against the other redaction-touching tests in this crate and
    /// restores the prior value on drop.
    struct Guard {
        previous: bool,
        _lock: parking_lot::MutexGuard<'static, ()>,
    }

    impl Guard {
        fn set(enabled: bool) -> Self {
            let lock = crate::metrics::STATE_LOCK.lock();
            let guard = Self {
                previous: shared_host_redaction(),
                _lock: lock,
            };
            set_shared_host_redaction(enabled);
            guard
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            set_shared_host_redaction(self.previous);
        }
    }

    #[test]
    fn defaults_to_disabled() {
        let _guard = Guard::set(false);
        assert!(!shared_host_redaction());
    }

    #[test]
    fn round_trips() {
        let _guard = Guard::set(false);

        set_shared_host_redaction(true);
        assert!(shared_host_redaction());

        set_shared_host_redaction(false);
        assert!(!shared_host_redaction());
    }
}
