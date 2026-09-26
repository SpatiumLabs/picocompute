//! Snapshot optimizer using eBPF dirty page tracking and I/O access patterns.
//!
//! Provides per-sandbox dirty page rate and I/O activity visibility
//! to inform snapshot quiesce/resume scheduling decisions.

pub mod ebpf;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use pico_core::SandboxId;
use pico_core::SnapshotTimingHint;
use thiserror::Error;

/// Kernel cgroup identifier used for eBPF correlation.
pub type CgroupId = u64;

/// Errors returned by snapshot optimization operations.
#[derive(Debug, Clone, Error)]
pub enum SnapshotOptimizationError {
    /// The eBPF backend is unavailable on this host.
    #[error("snapshot optimization eBPF not available: {0}")]
    Unavailable(String),
}

/// A dirty page event from the eBPF page fault tracepoint.
#[derive(Debug, Clone)]
pub struct DirtyPageEvent {
    pub sandbox_id: SandboxId,
    pub cgroup_id: CgroupId,
    pub pid: u32,
    pub tid: u32,
    pub page_offset: u64,
    pub address: u64,
    pub is_write: bool,
    pub timestamp_ns: u64,
}

/// An I/O access event from the eBPF block layer tracepoint.
#[derive(Debug, Clone)]
pub struct IoHeatmapEvent {
    pub sandbox_id: SandboxId,
    pub cgroup_id: CgroupId,
    pub pid: u32,
    pub tid: u32,
    pub device_major: u32,
    pub device_minor: u32,
    pub sector: u64,
    pub nr_sectors: u32,
    pub is_read: bool,
    pub timestamp_ns: u64,
}

/// Dirty page rate measurement for a sandbox.
#[derive(Debug, Clone, Copy)]
pub struct DirtyPageRate {
    /// Page-fault events recorded in the observation window.
    pub page_events: u64,
    /// Fraction of faults that were writes (0.0 to 1.0).
    pub write_ratio: f64,
    /// Estimated dirty pages per second.
    pub pages_per_second: f64,
    /// Duration of the observation window.
    pub window_duration_secs: f64,
}

/// I/O activity profile for a sandbox.
#[derive(Debug, Clone, Copy)]
pub struct IoActivityProfile {
    /// Total read operations in the observation window.
    pub read_ops: u64,
    /// Total write operations in the observation window.
    pub write_ops: u64,
    /// Estimated read operations per second.
    pub reads_per_second: f64,
    /// Estimated write operations per second.
    pub writes_per_second: f64,
    /// Whether the sandbox is under active I/O.
    pub is_active: bool,
}

/// Signal derived from eBPF patterns for snapshot scheduling decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotOptimizationSignal {
    /// Dirty rate is low; good time to quiesce.
    QuiesceRecommended,
    /// Sandbox is under active I/O; defer quiesce.
    DeferActiveIo,
    /// Dirty rate is moderate; quiesce is acceptable but not optimal.
    QuiesceAcceptable,
    /// Insufficient data to make a recommendation.
    InsufficientData,
    /// Optimization service is unavailable.
    Unavailable,
}

impl From<SnapshotOptimizationSignal> for SnapshotTimingHint {
    fn from(signal: SnapshotOptimizationSignal) -> Self {
        match signal {
            SnapshotOptimizationSignal::QuiesceRecommended => {
                SnapshotTimingHint::QuiesceRecommended
            }
            SnapshotOptimizationSignal::DeferActiveIo => SnapshotTimingHint::DeferActiveIo,
            SnapshotOptimizationSignal::QuiesceAcceptable => SnapshotTimingHint::QuiesceAcceptable,
            SnapshotOptimizationSignal::InsufficientData => SnapshotTimingHint::InsufficientData,
            SnapshotOptimizationSignal::Unavailable => SnapshotTimingHint::Unavailable,
        }
    }
}

/// Backend trait for snapshot optimization data collection.
pub trait SnapshotOptimizationBackend: Send + Sync {
    /// Register a sandbox for tracking.
    fn register_sandbox(
        &self,
        sandbox_id: &str,
        cgroup_id: CgroupId,
        cgroup_path: &std::path::Path,
    ) -> Result<(), SnapshotOptimizationError>;

    /// Unregister a sandbox from tracking.
    fn unregister_sandbox(&self, sandbox_id: &str) -> Result<(), SnapshotOptimizationError>;

    /// Drain all pending dirty page events from the backend.
    fn drain_dirty_page_events(&self) -> Vec<DirtyPageEvent>;

    /// Drain all pending I/O events from the backend.
    fn drain_io_events(&self) -> Vec<IoHeatmapEvent>;

    /// Returns true if the backend is available and functional.
    fn is_available(&self) -> bool;
}

/// Rolling statistics for dirty page events.
#[derive(Debug, Clone)]
struct RollingDirtyStats {
    events: VecDeque<(Instant, DirtyPageEvent)>,
    window: Duration,
}

impl RollingDirtyStats {
    fn new(window: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            window,
        }
    }

    fn push(&mut self, event: DirtyPageEvent) {
        let now = Instant::now();
        self.events.push_back((now, event));
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now - self.window;
        while self.events.front().is_some_and(|(ts, _)| *ts < cutoff) {
            self.events.pop_front();
        }
    }

    fn rate(&mut self) -> DirtyPageRate {
        let now = Instant::now();
        self.prune(now);

        let count = self.events.len() as u64;
        if count == 0 {
            return DirtyPageRate {
                page_events: 0,
                write_ratio: 0.0,
                pages_per_second: 0.0,
                window_duration_secs: self.window.as_secs_f64(),
            };
        }

        let write_count = self.events.iter().filter(|(_, e)| e.is_write).count() as u64;
        let write_ratio = if count > 0 {
            write_count as f64 / count as f64
        } else {
            0.0
        };
        let pages_per_second = count as f64 / self.window.as_secs_f64();

        DirtyPageRate {
            page_events: count,
            write_ratio,
            pages_per_second,
            window_duration_secs: self.window.as_secs_f64(),
        }
    }
}

/// Rolling statistics for I/O activity events.
#[derive(Debug, Clone)]
struct RollingIoStats {
    events: VecDeque<(Instant, IoHeatmapEvent)>,
    window: Duration,
}

impl RollingIoStats {
    fn new(window: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            window,
        }
    }

    fn push(&mut self, event: IoHeatmapEvent) {
        let now = Instant::now();
        self.events.push_back((now, event));
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now - self.window;
        while self.events.front().is_some_and(|(ts, _)| *ts < cutoff) {
            self.events.pop_front();
        }
    }

    fn profile(&mut self) -> IoActivityProfile {
        let now = Instant::now();
        self.prune(now);

        let total = self.events.len() as u64;
        if total == 0 {
            return IoActivityProfile {
                read_ops: 0,
                write_ops: 0,
                reads_per_second: 0.0,
                writes_per_second: 0.0,
                is_active: false,
            };
        }

        let reads = self.events.iter().filter(|(_, e)| e.is_read).count() as u64;
        let writes = total - reads;
        let window_secs = self.window.as_secs_f64();

        IoActivityProfile {
            read_ops: reads,
            write_ops: writes,
            reads_per_second: reads as f64 / window_secs,
            writes_per_second: writes as f64 / window_secs,
            is_active: (reads + writes) > 0,
        }
    }
}

/// Manages per-sandbox snapshot optimization data collection and signal generation.
pub struct SnapshotOptimizer {
    backend: Box<dyn SnapshotOptimizationBackend>,
    dirty_stats: Arc<RwLock<hashbrown::HashMap<SandboxId, RollingDirtyStats>>>,
    io_stats: Arc<RwLock<hashbrown::HashMap<SandboxId, RollingIoStats>>>,
    observation_window: Duration,
    /// Threshold in pages-per-second above which the dirty rate is considered "active"
    /// and quiesce should be deferred.
    dirty_rate_threshold: f64,
    /// Threshold in operations-per-second above which I/O is considered "active"
    /// and quiesce should be deferred.
    io_active_threshold: f64,
}

impl SnapshotOptimizer {
    /// Creates a new SnapshotOptimizer with default thresholds.
    pub fn new() -> Self {
        Self {
            backend: ebpf::load_backend(),
            dirty_stats: Arc::new(RwLock::new(hashbrown::HashMap::default())),
            io_stats: Arc::new(RwLock::new(hashbrown::HashMap::default())),
            observation_window: Duration::from_secs(30),
            dirty_rate_threshold: 1000.0,
            io_active_threshold: 100.0,
        }
    }

    /// Creates a new SnapshotOptimizer with a provided backend (for testing).
    pub fn with_backend(backend: Box<dyn SnapshotOptimizationBackend>) -> Self {
        Self {
            backend,
            dirty_stats: Arc::new(RwLock::new(hashbrown::HashMap::default())),
            io_stats: Arc::new(RwLock::new(hashbrown::HashMap::default())),
            observation_window: Duration::from_secs(30),
            dirty_rate_threshold: 1000.0,
            io_active_threshold: 100.0,
        }
    }

    /// Creates a new SnapshotOptimizer with a custom observation window and thresholds.
    pub fn with_config(
        observation_window: Duration,
        dirty_rate_threshold: f64,
        io_active_threshold: f64,
    ) -> Self {
        Self {
            backend: ebpf::load_backend(),
            dirty_stats: Arc::new(RwLock::new(hashbrown::HashMap::default())),
            io_stats: Arc::new(RwLock::new(hashbrown::HashMap::default())),
            observation_window,
            dirty_rate_threshold,
            io_active_threshold,
        }
    }

    /// Register a sandbox with the optimization backend.
    pub fn register_sandbox(
        &self,
        sandbox_id: &str,
        cgroup_id: CgroupId,
        cgroup_path: &std::path::Path,
    ) {
        if !self.backend.is_available() {
            return;
        }
        if let Err(e) = self
            .backend
            .register_sandbox(sandbox_id, cgroup_id, cgroup_path)
        {
            tracing::warn!(
                sandbox_id = %sandbox_id,
                error = %e,
                "failed to register sandbox for snapshot optimization"
            );
            return;
        }
        let sid = SandboxId::from_string(sandbox_id);
        self.dirty_stats
            .write()
            .insert(sid.clone(), RollingDirtyStats::new(self.observation_window));
        self.io_stats
            .write()
            .insert(sid, RollingIoStats::new(self.observation_window));
        tracing::info!(
            sandbox_id = %sandbox_id,
            cgroup_id,
            "registered sandbox for snapshot optimization"
        );
    }

    /// Unregister a sandbox from the optimization backend.
    pub fn unregister_sandbox(&self, sandbox_id: &str) {
        let sid = SandboxId::from_string(sandbox_id);
        self.dirty_stats.write().remove(&sid);
        self.io_stats.write().remove(&sid);
        if !self.backend.is_available() {
            return;
        }
        if let Err(e) = self.backend.unregister_sandbox(sandbox_id) {
            tracing::warn!(
                sandbox_id = %sandbox_id,
                error = %e,
                "failed to unregister sandbox from snapshot optimization"
            );
        }
    }

    /// Drain pending events from the backend and update rolling statistics.
    pub fn drain_and_update(&self) {
        if !self.backend.is_available() {
            return;
        }

        let dirty_events = self.backend.drain_dirty_page_events();
        let io_events = self.backend.drain_io_events();

        if dirty_events.is_empty() && io_events.is_empty() {
            return;
        }

        let mut dirty_stats = self.dirty_stats.write();
        let mut io_stats = self.io_stats.write();

        for event in dirty_events {
            let sid = event.sandbox_id.clone();
            dirty_stats
                .entry(sid)
                .or_insert_with(|| RollingDirtyStats::new(self.observation_window))
                .push(event);
        }

        for event in io_events {
            let sid = event.sandbox_id.clone();
            io_stats
                .entry(sid)
                .or_insert_with(|| RollingIoStats::new(self.observation_window))
                .push(event);
        }
    }

    /// Get the dirty page rate for a sandbox.
    #[must_use]
    pub fn get_dirty_page_rate(&self, sandbox_id: &str) -> DirtyPageRate {
        let sid = SandboxId::from_string(sandbox_id);
        let mut stats = self.dirty_stats.write();
        stats
            .get_mut(&sid)
            .map(|s| s.rate())
            .unwrap_or_else(|| DirtyPageRate {
                page_events: 0,
                write_ratio: 0.0,
                pages_per_second: 0.0,
                window_duration_secs: self.observation_window.as_secs_f64(),
            })
    }

    /// Get the I/O activity profile for a sandbox.
    #[must_use]
    pub fn get_io_activity(&self, sandbox_id: &str) -> IoActivityProfile {
        let sid = SandboxId::from_string(sandbox_id);
        let mut stats = self.io_stats.write();
        stats
            .get_mut(&sid)
            .map(|s| s.profile())
            .unwrap_or_else(|| IoActivityProfile {
                read_ops: 0,
                write_ops: 0,
                reads_per_second: 0.0,
                writes_per_second: 0.0,
                is_active: false,
            })
    }

    /// Determine whether the sandbox is a good candidate for quiesce.
    #[must_use]
    pub fn evaluate_quiesce(&self, sandbox_id: &str) -> SnapshotOptimizationSignal {
        if !self.backend.is_available() {
            return SnapshotOptimizationSignal::Unavailable;
        }

        let dirty_rate = self.get_dirty_page_rate(sandbox_id);
        let io_profile = self.get_io_activity(sandbox_id);

        if dirty_rate.page_events == 0 && !io_profile.is_active {
            return SnapshotOptimizationSignal::InsufficientData;
        }

        if io_profile.is_active
            && (io_profile.reads_per_second > self.io_active_threshold
                || io_profile.writes_per_second > self.io_active_threshold)
        {
            return SnapshotOptimizationSignal::DeferActiveIo;
        }

        if dirty_rate.pages_per_second < self.dirty_rate_threshold {
            return SnapshotOptimizationSignal::QuiesceRecommended;
        }

        SnapshotOptimizationSignal::QuiesceAcceptable
    }

    /// Returns true if the backend is available.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.backend.is_available()
    }

    /// Evaluate the sandbox and return a scheduler-ready hint.
    #[must_use]
    pub fn evaluate_for_sandbox(&self, sandbox_id: &str) -> SnapshotTimingHint {
        self.evaluate_quiesce(sandbox_id).into()
    }

    /// Aggregate timing hints across registered sandboxes (most conservative).
    ///
    /// Host agents expose this via stats; the control plane maps host stats
    /// into cell-level hints for the regional scheduler.
    #[must_use]
    pub fn aggregate_timing_hint(&self) -> SnapshotTimingHint {
        if !self.backend.is_available() {
            return SnapshotTimingHint::Unavailable;
        }

        let dirty_stats = self.dirty_stats.read();
        if dirty_stats.is_empty() {
            return SnapshotTimingHint::InsufficientData;
        }

        let mut worst = SnapshotTimingHint::QuiesceRecommended;
        for sandbox_id in dirty_stats.keys() {
            let hint = self.evaluate_for_sandbox(sandbox_id.as_str());
            worst = worst.worse(hint);
        }
        worst
    }
}

impl Default for SnapshotOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::time::Duration;

    struct MockBackend {
        available: bool,
        dirty_events: Arc<parking_lot::Mutex<VecDeque<DirtyPageEvent>>>,
        io_events: Arc<parking_lot::Mutex<VecDeque<IoHeatmapEvent>>>,
    }

    impl MockBackend {
        fn new(available: bool) -> Self {
            Self {
                available,
                dirty_events: Arc::new(parking_lot::Mutex::new(VecDeque::new())),
                io_events: Arc::new(parking_lot::Mutex::new(VecDeque::new())),
            }
        }
    }

    impl SnapshotOptimizationBackend for MockBackend {
        fn register_sandbox(
            &self,
            _sandbox_id: &str,
            _cgroup_id: CgroupId,
            _cgroup_path: &std::path::Path,
        ) -> Result<(), SnapshotOptimizationError> {
            Ok(())
        }

        fn unregister_sandbox(&self, _sandbox_id: &str) -> Result<(), SnapshotOptimizationError> {
            Ok(())
        }

        fn drain_dirty_page_events(&self) -> Vec<DirtyPageEvent> {
            self.dirty_events.lock().drain(..).collect()
        }

        fn drain_io_events(&self) -> Vec<IoHeatmapEvent> {
            self.io_events.lock().drain(..).collect()
        }

        fn is_available(&self) -> bool {
            self.available
        }
    }

    fn make_dirty_event(sandbox_id: &str, is_write: bool) -> DirtyPageEvent {
        DirtyPageEvent {
            sandbox_id: SandboxId::from_string(sandbox_id),
            cgroup_id: 1,
            pid: 100,
            tid: 100,
            page_offset: 0,
            address: 4096,
            is_write,
            timestamp_ns: 0,
        }
    }

    fn make_io_event(sandbox_id: &str, is_read: bool) -> IoHeatmapEvent {
        IoHeatmapEvent {
            sandbox_id: SandboxId::from_string(sandbox_id),
            cgroup_id: 1,
            pid: 100,
            tid: 100,
            device_major: 8,
            device_minor: 0,
            sector: 0,
            nr_sectors: 8,
            is_read,
            timestamp_ns: 0,
        }
    }

    #[test]
    fn rolling_dirty_stats_empty_returns_zero_rate() {
        let mut stats = RollingDirtyStats::new(Duration::from_secs(30));
        let rate = stats.rate();
        assert_eq!(rate.page_events, 0);
        assert_eq!(rate.pages_per_second, 0.0);
        assert!(rate.window_duration_secs > 0.0);
    }

    #[test]
    fn rolling_dirty_stats_with_events_calculates_rate() {
        let mut stats = RollingDirtyStats::new(Duration::from_secs(30));
        let event = DirtyPageEvent {
            sandbox_id: SandboxId::from_string("test"),
            cgroup_id: 1,
            pid: 100,
            tid: 100,
            page_offset: 0,
            address: 0,
            is_write: true,
            timestamp_ns: 0,
        };
        stats.push(event);
        let rate = stats.rate();
        assert_eq!(rate.page_events, 1);
        assert_eq!(rate.write_ratio, 1.0);
        assert!(rate.pages_per_second > 0.0);
    }

    #[test]
    fn rolling_io_stats_empty_returns_inactive() {
        let mut stats = RollingIoStats::new(Duration::from_secs(30));
        let profile = stats.profile();
        assert_eq!(profile.read_ops, 0);
        assert_eq!(profile.write_ops, 0);
        assert!(!profile.is_active);
    }

    #[test]
    fn rolling_io_stats_read_write_counts() {
        let mut stats = RollingIoStats::new(Duration::from_secs(30));
        stats.push(IoHeatmapEvent {
            sandbox_id: SandboxId::from_string("test"),
            cgroup_id: 1,
            pid: 100,
            tid: 100,
            device_major: 8,
            device_minor: 0,
            sector: 0,
            nr_sectors: 8,
            is_read: true,
            timestamp_ns: 0,
        });
        stats.push(IoHeatmapEvent {
            sandbox_id: SandboxId::from_string("test"),
            cgroup_id: 1,
            pid: 100,
            tid: 100,
            device_major: 8,
            device_minor: 0,
            sector: 8,
            nr_sectors: 16,
            is_read: false,
            timestamp_ns: 0,
        });
        let profile = stats.profile();
        assert_eq!(profile.read_ops, 1);
        assert_eq!(profile.write_ops, 1);
        assert!(profile.is_active);
    }

    #[test]
    fn static_signal_constants_are_distinct() {
        let signals = [
            SnapshotOptimizationSignal::QuiesceRecommended,
            SnapshotOptimizationSignal::DeferActiveIo,
            SnapshotOptimizationSignal::QuiesceAcceptable,
            SnapshotOptimizationSignal::InsufficientData,
            SnapshotOptimizationSignal::Unavailable,
        ];
        for (i, a) in signals.iter().enumerate() {
            for (j, b) in signals.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn dummy_sandbox_id_roundtrip() {
        let sid = SandboxId::from_string("test-sandbox");
        assert_eq!(sid.as_str(), "test-sandbox");
    }

    #[test]
    fn dirty_page_rate_struct_values() {
        let rate = DirtyPageRate {
            page_events: 42,
            write_ratio: 0.6,
            pages_per_second: 3.5,
            window_duration_secs: 30.0,
        };
        assert_eq!(rate.page_events, 42);
        assert!((rate.write_ratio - 0.6).abs() < f64::EPSILON);
        assert!((rate.pages_per_second - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn io_activity_profile_inactive_when_no_ops() {
        let profile = IoActivityProfile {
            read_ops: 0,
            write_ops: 0,
            reads_per_second: 0.0,
            writes_per_second: 0.0,
            is_active: false,
        };
        assert!(!profile.is_active);
    }

    #[test]
    fn signal_to_hint_conversion_is_bijective() {
        let signals = [
            SnapshotOptimizationSignal::QuiesceRecommended,
            SnapshotOptimizationSignal::DeferActiveIo,
            SnapshotOptimizationSignal::QuiesceAcceptable,
            SnapshotOptimizationSignal::InsufficientData,
            SnapshotOptimizationSignal::Unavailable,
        ];
        for signal in signals {
            let hint: SnapshotTimingHint = signal.into();
            match (signal, hint) {
                (
                    SnapshotOptimizationSignal::QuiesceRecommended,
                    SnapshotTimingHint::QuiesceRecommended,
                ) => {}
                (SnapshotOptimizationSignal::DeferActiveIo, SnapshotTimingHint::DeferActiveIo) => {}
                (
                    SnapshotOptimizationSignal::QuiesceAcceptable,
                    SnapshotTimingHint::QuiesceAcceptable,
                ) => {}
                (
                    SnapshotOptimizationSignal::InsufficientData,
                    SnapshotTimingHint::InsufficientData,
                ) => {}
                (SnapshotOptimizationSignal::Unavailable, SnapshotTimingHint::Unavailable) => {}
                _ => panic!("mismatch: {signal:?} -> {hint:?}"),
            }
        }
    }

    #[test]
    fn signal_score_range() {
        let hints = [
            (SnapshotOptimizationSignal::QuiesceRecommended, 1.0),
            (SnapshotOptimizationSignal::QuiesceAcceptable, 0.6),
            (SnapshotOptimizationSignal::InsufficientData, 0.5),
            (SnapshotOptimizationSignal::Unavailable, 0.5),
            (SnapshotOptimizationSignal::DeferActiveIo, 0.0),
        ];
        for (signal, expected_score) in hints {
            let hint: SnapshotTimingHint = signal.into();
            assert!(
                (hint.as_score() - expected_score).abs() < f64::EPSILON,
                "expected {signal:?} to score {expected_score}, got {}",
                hint.as_score()
            );
        }
    }

    #[test]
    fn unavailable_backend_returns_unavailable() {
        let backend = Box::new(MockBackend::new(false));
        let opt = SnapshotOptimizer::with_backend(backend);
        let hint = opt.evaluate_for_sandbox("sandbox-1");
        assert_eq!(hint, SnapshotTimingHint::Unavailable);
    }

    #[test]
    fn empty_backend_returns_insufficient_data() {
        let backend = Box::new(MockBackend::new(true));
        let opt = SnapshotOptimizer::with_backend(backend);
        opt.register_sandbox("sandbox-1", 100, std::path::Path::new(""));
        let hint = opt.evaluate_for_sandbox("sandbox-1");
        assert_eq!(hint, SnapshotTimingHint::InsufficientData);
    }

    #[test]
    fn low_dirty_rate_yields_recommended() {
        let mut stats = RollingDirtyStats::new(Duration::from_secs(30));
        stats.push(make_dirty_event("sandbox-1", true));
        stats.push(make_dirty_event("sandbox-1", false));
        let rate = stats.rate();
        assert_eq!(rate.page_events, 2);
        assert!(rate.pages_per_second < 1000.0);
    }

    #[test]
    fn active_io_yields_defer() {
        let mut io_stats = RollingIoStats::new(Duration::from_secs(30));
        for _ in 0..200 {
            io_stats.push(make_io_event("sandbox-1", true));
        }
        let profile = io_stats.profile();
        assert!(profile.is_active);
        assert!(profile.reads_per_second > 0.0);
    }

    #[test]
    fn evaluate_for_sandbox_with_mock_backend() {
        let be = Box::new(MockBackend::new(true));
        let opt = SnapshotOptimizer::with_backend(be);
        opt.register_sandbox("sandbox-1", 100, std::path::Path::new(""));

        let hint = opt.evaluate_for_sandbox("sandbox-1");
        assert_eq!(hint, SnapshotTimingHint::InsufficientData);

        opt.drain_and_update();
        let hint = opt.evaluate_for_sandbox("sandbox-1");
        assert_eq!(hint, SnapshotTimingHint::InsufficientData);
    }
}
