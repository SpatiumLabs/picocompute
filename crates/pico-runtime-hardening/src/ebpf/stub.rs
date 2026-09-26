use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::mpsc;

use parking_lot::RwLock;

use super::SyscallFimObserver;
use super::syscall::{MONITORED_SYSCALL_COUNT, SyscallEvent};
use crate::anomaly::{AnomalyDetector, DetectorConfig};

/// Non-Linux stub: eBPF attach unavailable; userspace anomaly detection works.
pub struct EbpfSyscallMonitor {
    anomaly_detector: Arc<AnomalyDetector>,
    fim_observer: Arc<RwLock<Option<SyscallFimObserver>>>,
}

impl EbpfSyscallMonitor {
    /// Userspace-only monitor. BPF map ops and ringbuf attach fail.
    pub fn load() -> Result<Self, String> {
        Ok(Self {
            anomaly_detector: Arc::new(AnomalyDetector::with_defaults()),
            fim_observer: Arc::new(RwLock::new(None)),
        })
    }

    /// Install or replace the FIM observer.
    pub fn set_fim_observer(&self, observer: SyscallFimObserver) {
        *self.fim_observer.write() = Some(observer);
    }

    /// Manually feed a syscall event through the FIM observer (tests / bridge).
    pub fn observe_fim(&self, sandbox_id: &str, event: &SyscallEvent) {
        if let Some(obs) = self.fim_observer.read().as_ref() {
            obs(sandbox_id, event);
        }
    }

    pub fn set_anomaly_config(&mut self, config: DetectorConfig) {
        self.anomaly_detector = Arc::new(AnomalyDetector::new(config));
    }

    pub fn anomaly_detector(&self) -> Arc<AnomalyDetector> {
        Arc::clone(&self.anomaly_detector)
    }

    pub fn configure_sandbox(
        &mut self,
        _cgroup_id: u64,
        _enabled: bool,
        _sample_rate: u32,
    ) -> Result<(), String> {
        Err("eBPF syscall audit not available on this platform".into())
    }

    pub fn remove_sandbox(&mut self, _cgroup_id: u64) -> Result<(), String> {
        Err("eBPF syscall audit not available on this platform".into())
    }

    #[expect(
        dead_code,
        reason = "used by run_consumer in linux module; unused in stub"
    )]
    pub(crate) fn run_event_loop(
        &mut self,
        _tx: mpsc::UnboundedSender<SyscallEvent>,
        _shutdown: tokio::sync::watch::Receiver<bool>,
        _dropped: Arc<AtomicU64>,
    ) -> Result<std::thread::JoinHandle<()>, String> {
        Err("eBPF syscall audit not available on this platform".into())
    }

    pub fn run_consumer(
        &mut self,
        _shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(std::thread::JoinHandle<()>, tokio::task::JoinHandle<()>), String> {
        Err("eBPF syscall audit not available on this platform".into())
    }

    pub fn dropped_events(&self) -> u64 {
        0
    }

    pub fn associate_sandbox(&self, _sandbox_id: &str, _cgroup_id: u64) {}

    pub fn associate_sandbox_type(&self, sandbox_id: &str, sandbox_type: &str) {
        self.anomaly_detector
            .register_sandbox(sandbox_id, sandbox_type);
    }

    /// Userspace registration: type key is required for shared baselines.
    /// BPF configure is a no-op error on this platform; type registration still applies.
    pub fn register_sandbox_audit(
        &mut self,
        sandbox_id: &str,
        _cgroup_id: u64,
        sandbox_type: &str,
        _enabled: bool,
        _sample_rate: u32,
    ) -> Result<(), String> {
        self.associate_sandbox(sandbox_id, _cgroup_id);
        self.associate_sandbox_type(sandbox_id, sandbox_type);
        Ok(())
    }

    pub fn unregister_sandbox_audit(
        &mut self,
        sandbox_id: &str,
        _cgroup_id: u64,
    ) -> Result<(), String> {
        self.dissociate_sandbox(sandbox_id);
        Ok(())
    }

    pub fn dissociate_sandbox(&self, sandbox_id: &str) {
        self.anomaly_detector.unregister_sandbox(sandbox_id);
    }

    pub fn active_sandbox_count(&self) -> usize {
        self.anomaly_detector.active_sandbox_count()
    }

    pub fn syscall_count(&self, _cgroup_id: u64, _syscall_nr: u32) -> Result<u64, String> {
        Err("SYSCALL_COUNTS not available on this platform".into())
    }

    pub fn syscall_histogram(&self, _cgroup_id: u64) -> Result<Vec<(u32, u64)>, String> {
        Ok((0..MONITORED_SYSCALL_COUNT as u32)
            .map(|nr| (nr, 0u64))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::sandbox_type_key;
    use crate::ebpf::syscall::{SYSCALL_OPEN, SYSCALL_PTRACE, syscall_name};
    use crate::telemetry::emit_behavioral_anomaly;
    use std::time::Duration;

    fn enter(nr: u32) -> crate::ebpf::syscall::SyscallEvent {
        crate::ebpf::syscall::SyscallEvent {
            cgroup_id: 7,
            pid: 1,
            tid: 1,
            uid: 0,
            gid: 0,
            syscall_name: syscall_name(nr).to_string(),
            syscall_nr: nr,
            timestamp_ns: 1,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            retval: -1,
            string_arg0: None,
            string_arg1: None,
            is_enter: true,
        }
    }

    #[test]
    fn load_exposes_anomaly_detector_without_ebpf() {
        let mut mon = EbpfSyscallMonitor::load().expect("userspace monitor");
        mon.associate_sandbox_type("sb", "img:wl");
        assert_eq!(mon.active_sandbox_count(), 1);
        assert_eq!(mon.dropped_events(), 0);
        assert!(mon.anomaly_detector().is_learning("sb"));
        assert!(
            mon.configure_sandbox(1, true, 0).is_err(),
            "BPF maps unavailable on stub"
        );
    }

    #[test]
    fn register_sandbox_audit_requires_type_key_for_shared_baselines() {
        let mut mon = EbpfSyscallMonitor::load().expect("userspace monitor");
        let type_key = sandbox_type_key("alpine-3.18", "agent");
        mon.register_sandbox_audit("sb-a", 100, &type_key, true, 10)
            .expect("register");
        mon.register_sandbox_audit("sb-b", 101, &type_key, true, 10)
            .expect("register");
        assert_eq!(mon.anomaly_detector().baseline_type_count(), 1);
        mon.unregister_sandbox_audit("sb-a", 100)
            .expect("unregister");
        assert_eq!(mon.active_sandbox_count(), 1);
    }

    #[test]
    fn warm_start_prior_via_detector_api() {
        use crate::anomaly::TypePrior;
        let mon = EbpfSyscallMonitor::load().expect("userspace monitor");
        let det = mon.anomaly_detector();
        let mut prior = TypePrior::empty();
        prior.sample_events = 500;
        prior.ewma_rate[0] = 3.0;
        det.seed_type_prior("img:wl", prior);
        det.register_sandbox("sb", "img:wl");
        assert!(!det.is_learning("sb"));
        assert_eq!(det.prior_count(), 1);
    }

    #[test]
    fn end_to_end_detector_to_telemetry_emission() {
        let mut mon = EbpfSyscallMonitor::load().expect("userspace monitor");
        mon.set_anomaly_config(DetectorConfig {
            learning_duration: Duration::from_millis(1),
            min_events_for_baseline: 3,
            spike_threshold_multiplier: 3.0,
            ewma_alpha: 0.5,
            rate_window: Duration::from_millis(5),
            ewma_idle_decay: 0.95,
            privilege_escalation_window: Duration::from_secs(2),
            alert_dangerous_during_learning: true,
        });
        let type_key = sandbox_type_key("img", "wl");
        mon.register_sandbox_audit("sb-1", 42, &type_key, true, 1)
            .expect("register");

        let det = mon.anomaly_detector();
        for _ in 0..3 {
            let findings = det.observe("sb-1", &enter(SYSCALL_OPEN));
            for f in findings {
                emit_behavioral_anomaly(&f);
            }
        }
        std::thread::sleep(Duration::from_millis(3));
        let _ = det.observe("sb-1", &enter(SYSCALL_OPEN));
        let findings = det.observe("sb-1", &enter(SYSCALL_PTRACE));
        assert!(!findings.is_empty());
        for f in &findings {
            emit_behavioral_anomaly(f);
        }
        assert!(findings.iter().any(|f| f.anomaly_type
            == crate::anomaly::AnomalyType::DangerousSyscallFirstUse
            || f.anomaly_type == crate::anomaly::AnomalyType::DangerousSyscallDuringLearning));
    }
}
