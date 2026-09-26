//! Copy-on-write fork observability metrics.
//!
//! Emits fork_workspace_started, fork_workspace_completed,
//! fork_workspace_failed, shared_bytes, and private_bytes metrics.

use std::sync::LazyLock;

use pico_telemetry::metrics::{Counter, Gauge};

const FORK_WORKSPACE_STARTED: &str = "pico_fork_workspace_started";
const FORK_WORKSPACE_COMPLETED: &str = "pico_fork_workspace_completed";
const FORK_WORKSPACE_FAILED: &str = "pico_fork_workspace_failed";
const SHARED_BYTES: &str = "pico_fork_shared_bytes";
const PRIVATE_BYTES: &str = "pico_fork_private_bytes";

/// Metrics exposed from COW fork operations.
pub struct CowForkMetrics {
    /// Incremented each time a fork operation begins.
    pub fork_started: Counter,
    /// Incremented each time a fork operation completes successfully.
    pub fork_completed: Counter,
    /// Incremented each time a fork operation fails.
    pub fork_failed: Counter,
    /// Current shared bytes across all workspaces.
    pub shared_bytes: Gauge,
    /// Current private bytes across all workspaces.
    pub private_bytes: Gauge,
}

/// Global metrics singleton for COW fork operations.
pub static COW_FORK_METRICS: LazyLock<CowForkMetrics> = LazyLock::new(CowForkMetrics::register);

impl CowForkMetrics {
    fn register() -> Self {
        Self {
            fork_started: Counter::register(FORK_WORKSPACE_STARTED),
            fork_completed: Counter::register(FORK_WORKSPACE_COMPLETED),
            fork_failed: Counter::register(FORK_WORKSPACE_FAILED),
            shared_bytes: Gauge::register(SHARED_BYTES),
            private_bytes: Gauge::register(PRIVATE_BYTES),
        }
    }
}
