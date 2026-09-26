use std::time::Instant;

use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

use super::baseline::{BaselineRegistry, DetectorConfig, TypePrior};
use super::signatures::{
    dangerous_first_use_severity, is_dangerous_syscall, is_privilege_syscall,
    match_escape_signature,
};
use super::types::{AnomalyEvent, AnomalySeverity, AnomalyType};
use crate::ebpf::syscall::{SYSCALL_EXECVE, SyscallEvent};

const SANDBOX_SHARDS: usize = 32;

struct SandboxState {
    sandbox_type: String,
    last_execve: HashMap<u32, Instant>,
}

/// Thread-safe behavioral anomaly detector with sharded sandbox state.
///
/// # Hot path
///
/// `observe` takes one shard mutex (of [`SANDBOX_SHARDS`]) plus a short
/// `RwLock` write on the shared baseline registry. Prefer raising
/// `sample_rate` under extreme load before further sharding.
pub struct AnomalyDetector {
    global_config: RwLock<DetectorConfig>,
    baselines: RwLock<BaselineRegistry>,
    sandboxes: [Mutex<HashMap<String, SandboxState>>; SANDBOX_SHARDS],
}

fn shard_index(sandbox_id: &str) -> usize {
    // FNV-1a 64-bit (no extra hasher dep).
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in sandbox_id.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    (h as usize) % SANDBOX_SHARDS
}

impl AnomalyDetector {
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            global_config: RwLock::new(config),
            baselines: RwLock::new(BaselineRegistry::new()),
            sandboxes: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DetectorConfig::default())
    }

    /// Replace the process-wide default detector config.
    pub fn set_global_config(&self, config: DetectorConfig) {
        *self.global_config.write() = config;
    }

    /// Per-type override of learning/spike knobs.
    pub fn set_type_config(&self, sandbox_type: &str, config: DetectorConfig) {
        self.baselines.write().set_type_config(sandbox_type, config);
    }

    /// Seed a warm-start prior for an image/workload type (global or offline).
    pub fn seed_type_prior(&self, sandbox_type: &str, prior: TypePrior) {
        self.baselines.write().seed_prior(sandbox_type, prior);
    }

    /// Snapshot a completed baseline into the warm-start prior store.
    pub fn publish_type_prior(&self, sandbox_type: &str) {
        self.baselines
            .write()
            .publish_prior_from_baseline(sandbox_type);
    }

    pub fn register_sandbox(&self, sandbox_id: &str, sandbox_type: &str) {
        {
            let mut map = self.sandboxes[shard_index(sandbox_id)].lock();
            match map.get_mut(sandbox_id) {
                Some(state) => {
                    if state.sandbox_type != sandbox_type {
                        state.sandbox_type = sandbox_type.to_string();
                    }
                }
                None => {
                    map.insert(
                        sandbox_id.to_string(),
                        SandboxState {
                            sandbox_type: sandbox_type.to_string(),
                            last_execve: HashMap::new(),
                        },
                    );
                }
            }
        }
        let global = self.global_config.read().clone();
        let _ = self.baselines.write().get_or_create(sandbox_type, &global);
    }

    pub fn is_registered(&self, sandbox_id: &str) -> bool {
        self.sandboxes[shard_index(sandbox_id)]
            .lock()
            .contains_key(sandbox_id)
    }

    pub fn unregister_sandbox(&self, sandbox_id: &str) {
        let sandbox_type = self.sandboxes[shard_index(sandbox_id)]
            .lock()
            .remove(sandbox_id)
            .map(|s| s.sandbox_type);
        if let Some(ty) = sandbox_type {
            self.publish_type_prior(&ty);
        }
    }

    pub fn active_sandbox_count(&self) -> usize {
        self.sandboxes.iter().map(|s| s.lock().len()).sum()
    }

    pub fn baseline_type_count(&self) -> usize {
        self.baselines.read().len()
    }

    pub fn prior_count(&self) -> usize {
        self.baselines.read().prior_count()
    }

    pub fn is_learning(&self, sandbox_id: &str) -> bool {
        let sandbox_type = {
            let map = self.sandboxes[shard_index(sandbox_id)].lock();
            let Some(state) = map.get(sandbox_id) else {
                return true;
            };
            state.sandbox_type.clone()
        };
        let global = self.global_config.read();
        self.baselines
            .read()
            .get(&sandbox_type)
            .map(|b| b.is_learning(&global))
            .unwrap_or(true)
    }

    pub fn observe(&self, sandbox_id: &str, event: &SyscallEvent) -> Vec<AnomalyEvent> {
        if !event.is_enter {
            return Vec::new();
        }

        let shard = shard_index(sandbox_id);
        let mut sandbox_map = self.sandboxes[shard].lock();
        let sandbox_type = sandbox_map
            .get(sandbox_id)
            .map(|s| s.sandbox_type.clone())
            .unwrap_or_else(|| format!("cgroup-{}", event.cgroup_id));

        if !sandbox_map.contains_key(sandbox_id) {
            sandbox_map.insert(
                sandbox_id.to_string(),
                SandboxState {
                    sandbox_type: sandbox_type.clone(),
                    last_execve: HashMap::new(),
                },
            );
        }

        let mut findings = Vec::new();

        if let Some(hit) = match_escape_signature(
            event.syscall_nr,
            event.pid,
            event.arg0,
            event.arg1,
            event.arg2,
            event.string_arg0.as_deref(),
            event.string_arg1.as_deref(),
        ) {
            findings.push(
                AnomalyEvent {
                    sandbox_id: sandbox_id.to_string(),
                    sandbox_type: sandbox_type.clone(),
                    anomaly_type: hit.anomaly_type,
                    severity: hit.severity,
                    confidence: hit.confidence,
                    detail: hit.detail.to_string(),
                    syscall_name: event.syscall_name.clone(),
                    timestamp_ns: event.timestamp_ns,
                }
                .confidence_clamped(),
            );
        }

        let global = self.global_config.read().clone();
        let privesc_window = global.privilege_escalation_window;

        if event.syscall_nr == SYSCALL_EXECVE
            && let Some(state) = sandbox_map.get_mut(sandbox_id)
        {
            state
                .last_execve
                .retain(|_, at| at.elapsed() <= privesc_window);
            state.last_execve.insert(event.pid, Instant::now());
        }

        if is_privilege_syscall(event.syscall_nr) {
            let recent_exec = sandbox_map
                .get(sandbox_id)
                .and_then(|s| s.last_execve.get(&event.pid))
                .is_some_and(|t| t.elapsed() <= privesc_window);
            if recent_exec {
                findings.push(
                    AnomalyEvent {
                        sandbox_id: sandbox_id.to_string(),
                        sandbox_type: sandbox_type.clone(),
                        anomaly_type: AnomalyType::PrivilegeEscalation,
                        severity: AnomalySeverity::High,
                        confidence: 0.85,
                        detail: format!(
                            "{} shortly after execve (pid={})",
                            event.syscall_name, event.pid
                        ),
                        syscall_name: event.syscall_name.clone(),
                        timestamp_ns: event.timestamp_ns,
                    }
                    .confidence_clamped(),
                );
            }
        }

        // Drop sandbox shard lock before baseline write to reduce hold time.
        drop(sandbox_map);

        let mut baselines = self.baselines.write();
        let (learning_before, seen_in_learning, first_use_alerted, rate, alert_during) = {
            let baseline = baselines.get_or_create(&sandbox_type, &global);
            let learning_before = baseline.is_learning(&global);
            let seen_in_learning = baseline.seen_during_learning(event.syscall_nr);
            let first_use_alerted = baseline.first_use_already_alerted(event.syscall_nr);
            let alert_during = baseline
                .effective_config(&global)
                .alert_dangerous_during_learning;
            let rate = baseline.record(event.syscall_nr, &global);
            (
                learning_before,
                seen_in_learning,
                first_use_alerted,
                rate,
                alert_during,
            )
        };

        if is_dangerous_syscall(event.syscall_nr) {
            if learning_before && alert_during {
                findings.push(
                    AnomalyEvent {
                        sandbox_id: sandbox_id.to_string(),
                        sandbox_type: sandbox_type.clone(),
                        anomaly_type: AnomalyType::DangerousSyscallDuringLearning,
                        severity: dangerous_first_use_severity(event.syscall_nr),
                        confidence: 0.8,
                        detail: format!(
                            "{} observed during baseline learning (not silent-trained)",
                            event.syscall_name
                        ),
                        syscall_name: event.syscall_name.clone(),
                        timestamp_ns: event.timestamp_ns,
                    }
                    .confidence_clamped(),
                );
            } else if !learning_before && !seen_in_learning && !first_use_alerted {
                if let Some(bl) = baselines.get_mut(&sandbox_type) {
                    bl.mark_first_use_alerted(event.syscall_nr);
                }
                findings.push(
                    AnomalyEvent {
                        sandbox_id: sandbox_id.to_string(),
                        sandbox_type: sandbox_type.clone(),
                        anomaly_type: AnomalyType::DangerousSyscallFirstUse,
                        severity: dangerous_first_use_severity(event.syscall_nr),
                        confidence: 0.95,
                        detail: format!(
                            "first use of {} after baseline learning",
                            event.syscall_name
                        ),
                        syscall_name: event.syscall_name.clone(),
                        timestamp_ns: event.timestamp_ns,
                    }
                    .confidence_clamped(),
                );
            }
        }

        if !learning_before
            && let Some(rate) = rate
            && let Some(bl) = baselines.get(&sandbox_type)
            && bl.is_spike(event.syscall_nr, rate, &global)
        {
            let confidence = bl.spike_confidence(event.syscall_nr, rate, &global);
            findings.push(
                AnomalyEvent {
                    sandbox_id: sandbox_id.to_string(),
                    sandbox_type: sandbox_type.clone(),
                    anomaly_type: AnomalyType::FrequencySpike,
                    severity: AnomalySeverity::Medium,
                    confidence,
                    detail: format!(
                        "{} rate={rate:.2}/s ewma={:.2}/s threshold={}x",
                        event.syscall_name,
                        bl.ewma_rate(event.syscall_nr),
                        bl.effective_config(&global).spike_threshold_multiplier
                    ),
                    syscall_name: event.syscall_name.clone(),
                    timestamp_ns: event.timestamp_ns,
                }
                .confidence_clamped(),
            );
        }

        if !learning_before {
            baselines.publish_prior_from_baseline(&sandbox_type);
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::syscall::{
        SYSCALL_OPEN, SYSCALL_PTRACE, SYSCALL_SETNS, SYSCALL_SETUID, syscall_name,
    };
    use std::time::Duration;

    fn enter_event(nr: u32, pid: u32, path: Option<&str>) -> SyscallEvent {
        SyscallEvent {
            cgroup_id: 99,
            pid,
            tid: pid,
            uid: 1000,
            gid: 1000,
            syscall_name: syscall_name(nr).to_string(),
            syscall_nr: nr,
            timestamp_ns: 1_000_000,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            retval: -1,
            string_arg0: path.map(str::to_string),
            string_arg1: None,
            is_enter: true,
        }
    }

    fn fast_detector() -> AnomalyDetector {
        AnomalyDetector::new(DetectorConfig {
            learning_duration: Duration::from_millis(1),
            min_events_for_baseline: 5,
            spike_threshold_multiplier: 3.0,
            ewma_alpha: 0.5,
            rate_window: Duration::from_millis(5),
            ewma_idle_decay: 0.95,
            privilege_escalation_window: Duration::from_secs(2),
            alert_dangerous_during_learning: true,
        })
    }

    #[test]
    fn ignores_exit_events() {
        let det = AnomalyDetector::with_defaults();
        det.register_sandbox("sb-1", "img:wl");
        let mut ev = enter_event(SYSCALL_OPEN, 10, None);
        ev.is_enter = false;
        ev.retval = 0;
        assert!(det.observe("sb-1", &ev).is_empty());
    }

    #[test]
    fn detects_ptrace_first_use_after_learning() {
        let det = fast_detector();
        det.register_sandbox("sb-1", "python:worker");
        for _ in 0..5 {
            let _ = det.observe("sb-1", &enter_event(SYSCALL_OPEN, 10, None));
        }
        std::thread::sleep(Duration::from_millis(3));
        let _ = det.observe("sb-1", &enter_event(SYSCALL_OPEN, 10, None));
        assert!(!det.is_learning("sb-1"));
        let findings = det.observe("sb-1", &enter_event(SYSCALL_PTRACE, 10, None));
        assert!(
            findings
                .iter()
                .any(|f| f.anomaly_type == AnomalyType::DangerousSyscallFirstUse)
        );
    }

    #[test]
    fn ptrace_during_learning_alerts_when_enabled() {
        let det = fast_detector();
        det.register_sandbox("sb-1", "python:worker");
        let findings = det.observe("sb-1", &enter_event(SYSCALL_PTRACE, 10, None));
        assert!(
            findings
                .iter()
                .any(|f| f.anomaly_type == AnomalyType::DangerousSyscallDuringLearning)
        );
    }

    #[test]
    fn ptrace_during_learning_can_be_silent_when_disabled() {
        let det = AnomalyDetector::new(DetectorConfig {
            alert_dangerous_during_learning: false,
            learning_duration: Duration::from_secs(3600),
            min_events_for_baseline: 1000,
            ..DetectorConfig::default()
        });
        det.register_sandbox("sb-1", "python:worker");
        let findings = det.observe("sb-1", &enter_event(SYSCALL_PTRACE, 10, None));
        assert!(findings.iter().all(|f| f.anomaly_type
            != AnomalyType::DangerousSyscallDuringLearning
            && f.anomaly_type != AnomalyType::DangerousSyscallFirstUse));
    }

    #[test]
    fn detects_setuid_after_execve() {
        let det = fast_detector();
        det.register_sandbox("sb-1", "img:wl");
        let _ = det.observe("sb-1", &enter_event(SYSCALL_EXECVE, 42, Some("/bin/sh")));
        let findings = det.observe("sb-1", &enter_event(SYSCALL_SETUID, 42, None));
        assert!(
            findings
                .iter()
                .any(|f| f.anomaly_type == AnomalyType::PrivilegeEscalation)
        );
    }

    #[test]
    fn setns_from_non_init_alerts() {
        let det = fast_detector();
        det.register_sandbox("sb-1", "img:wl");
        let findings = det.observe("sb-1", &enter_event(SYSCALL_SETNS, 99, None));
        assert!(
            findings
                .iter()
                .any(|f| f.anomaly_type == AnomalyType::ContainerEscape)
        );
    }

    #[test]
    fn release_agent_path_alerts() {
        let det = fast_detector();
        det.register_sandbox("sb-1", "img:wl");
        let findings = det.observe(
            "sb-1",
            &enter_event(
                SYSCALL_OPEN,
                10,
                Some("/sys/fs/cgroup/memory/release_agent"),
            ),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.anomaly_type == AnomalyType::ContainerEscape)
        );
    }

    #[test]
    fn shared_baseline_across_sandboxes_of_same_type() {
        let det = fast_detector();
        det.register_sandbox("sb-a", "type-x");
        det.register_sandbox("sb-b", "type-x");
        for _ in 0..6 {
            let _ = det.observe("sb-a", &enter_event(SYSCALL_OPEN, 1, None));
        }
        std::thread::sleep(Duration::from_millis(3));
        let _ = det.observe("sb-a", &enter_event(SYSCALL_OPEN, 1, None));
        assert_eq!(det.baseline_type_count(), 1);
        assert!(!det.is_learning("sb-b"));
    }

    #[test]
    fn warm_start_prior_skips_learning() {
        let det = fast_detector();
        let mut prior = TypePrior::empty();
        prior.sample_events = 500;
        prior.ewma_rate[SYSCALL_OPEN as usize] = 8.0;
        det.seed_type_prior("warm:type", prior);
        det.register_sandbox("sb-w", "warm:type");
        assert!(!det.is_learning("sb-w"));
    }

    #[test]
    fn per_type_config_override() {
        let det = AnomalyDetector::new(DetectorConfig {
            min_events_for_baseline: 10_000,
            learning_duration: Duration::from_secs(3600),
            ..DetectorConfig::default()
        });
        det.set_type_config(
            "fast:type",
            DetectorConfig {
                min_events_for_baseline: 3,
                learning_duration: Duration::from_secs(3600),
                ..DetectorConfig::default()
            },
        );
        det.register_sandbox("sb-f", "fast:type");
        for _ in 0..3 {
            let _ = det.observe("sb-f", &enter_event(SYSCALL_OPEN, 1, None));
        }
        assert!(!det.is_learning("sb-f"));
    }
}
