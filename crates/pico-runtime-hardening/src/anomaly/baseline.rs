use std::time::{Duration, Instant};

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::ebpf::syscall::MONITORED_SYSCALL_COUNT;

/// Configuration for behavioral baseline learning and spike detection.
///
/// # Time-to-baseline
///
/// Learning completes when **either**:
/// - at least [`Self::min_events_for_baseline`] enter events have been seen, **or**
/// - [`Self::learning_duration`] has elapsed (idle / low-traffic workloads).
///
/// With a warm-start prior, learning may complete immediately when the prior
/// already has enough samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    pub learning_duration: Duration,
    pub min_events_for_baseline: u64,
    /// Spike if instantaneous rate exceeds `multiplier * ewma_rate`.
    ///
    /// Also used as an absolute events/sec floor when EWMA is zero.
    pub spike_threshold_multiplier: f64,
    pub ewma_alpha: f64,
    /// On each window boundary, rates for active syscalls are updated and idle
    /// EWMA entries are decayed by [`Self::ewma_idle_decay`]. Cost is O(N) over
    /// the fixed monitored set (currently 14).
    pub rate_window: Duration,
    /// Multiplicative decay for EWMA rates with zero traffic in a window.
    pub ewma_idle_decay: f64,
    pub privilege_escalation_window: Duration,
    /// Emit alerts for dangerous syscalls during learning (anti-evasion).
    pub alert_dangerous_during_learning: bool,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            learning_duration: Duration::from_secs(5 * 60),
            min_events_for_baseline: 100,
            spike_threshold_multiplier: 5.0,
            ewma_alpha: 0.2,
            rate_window: Duration::from_secs(10),
            ewma_idle_decay: 0.95,
            privilege_escalation_window: Duration::from_secs(2),
            alert_dangerous_during_learning: true,
        }
    }
}

/// Snapshot of learned rates used to warm-start new sandboxes of the same type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypePrior {
    pub ewma_rate: Vec<f64>,
    pub seen_during_learning: Vec<bool>,
    pub sample_events: u64,
}

impl TypePrior {
    pub fn empty() -> Self {
        Self {
            ewma_rate: vec![0.0; MONITORED_SYSCALL_COUNT],
            seen_during_learning: vec![false; MONITORED_SYSCALL_COUNT],
            sample_events: 0,
        }
    }

    fn normalized(mut self) -> Self {
        self.ewma_rate.resize(MONITORED_SYSCALL_COUNT, 0.0);
        self.seen_during_learning
            .resize(MONITORED_SYSCALL_COUNT, false);
        self
    }
}

/// Running histogram and EWMA rates for one sandbox type (image + workload).
#[derive(Debug, Clone)]
pub(super) struct TypeBaseline {
    created_at: Instant,
    total_events: u64,
    counts: [u64; MONITORED_SYSCALL_COUNT],
    ewma_rate: [f64; MONITORED_SYSCALL_COUNT],
    seen_during_learning: [bool; MONITORED_SYSCALL_COUNT],
    first_use_alerted: [bool; MONITORED_SYSCALL_COUNT],
    learning_complete: bool,
    last_rate_sample_at: Instant,
    window_counts: [u64; MONITORED_SYSCALL_COUNT],
    /// Optional per-type override; falls back to detector global config.
    config_override: Option<DetectorConfig>,
}

impl TypeBaseline {
    pub(super) fn new() -> Self {
        let now = Instant::now();
        Self {
            created_at: now,
            total_events: 0,
            counts: [0; MONITORED_SYSCALL_COUNT],
            ewma_rate: [0.0; MONITORED_SYSCALL_COUNT],
            seen_during_learning: [false; MONITORED_SYSCALL_COUNT],
            first_use_alerted: [false; MONITORED_SYSCALL_COUNT],
            learning_complete: false,
            last_rate_sample_at: now,
            window_counts: [0; MONITORED_SYSCALL_COUNT],
            config_override: None,
        }
    }

    /// Warm-start from a previously learned prior (image/global seed).
    pub(super) fn from_prior(prior: &TypePrior, global: &DetectorConfig) -> Self {
        let prior = prior.clone().normalized();
        let mut bl = Self::new();
        for i in 0..MONITORED_SYSCALL_COUNT {
            bl.ewma_rate[i] = prior.ewma_rate[i];
            bl.seen_during_learning[i] = prior.seen_during_learning[i];
        }
        bl.total_events = prior.sample_events;
        if prior.sample_events >= global.min_events_for_baseline {
            bl.learning_complete = true;
        }
        bl
    }

    pub(super) fn set_config_override(&mut self, config: Option<DetectorConfig>) {
        self.config_override = config;
    }

    pub(super) fn effective_config<'a>(&'a self, global: &'a DetectorConfig) -> &'a DetectorConfig {
        self.config_override.as_ref().unwrap_or(global)
    }

    pub(super) fn is_learning(&self, global: &DetectorConfig) -> bool {
        let config = self.effective_config(global);
        !self.learning_complete && !self.should_complete_learning(config)
    }

    fn should_complete_learning(&self, config: &DetectorConfig) -> bool {
        self.total_events >= config.min_events_for_baseline
            || self.created_at.elapsed() >= config.learning_duration
    }

    /// Record one enter event. Returns instantaneous rate for `syscall_nr`
    /// when a full rate window has elapsed.
    pub(super) fn record(&mut self, syscall_nr: u32, global: &DetectorConfig) -> Option<f64> {
        let idx = syscall_nr as usize;
        if idx >= MONITORED_SYSCALL_COUNT {
            return None;
        }
        let config = self
            .config_override
            .clone()
            .unwrap_or_else(|| global.clone());

        self.total_events = self.total_events.saturating_add(1);
        self.counts[idx] = self.counts[idx].saturating_add(1);
        self.window_counts[idx] = self.window_counts[idx].saturating_add(1);

        if !self.learning_complete {
            self.seen_during_learning[idx] = true;
            if self.should_complete_learning(&config) {
                self.learning_complete = true;
                if self.ewma_rate.iter().all(|&r| r <= 0.0) {
                    self.seed_ewma_from_learning();
                }
            }
        }

        let elapsed = self.last_rate_sample_at.elapsed();
        if elapsed < config.rate_window {
            return None;
        }

        let secs = elapsed.as_secs_f64().max(1e-6);
        let alpha = config.ewma_alpha.clamp(0.01, 1.0);
        let idle_decay = config.ewma_idle_decay.clamp(0.0, 1.0);
        let mut current_rate = None;
        for i in 0..MONITORED_SYSCALL_COUNT {
            let count = self.window_counts[i];
            if count == 0 {
                if self.ewma_rate[i] > 0.0 && idle_decay < 1.0 {
                    self.ewma_rate[i] *= idle_decay;
                }
                continue;
            }
            let rate = count as f64 / secs;
            if self.ewma_rate[i] <= 0.0 {
                self.ewma_rate[i] = rate;
            } else {
                self.ewma_rate[i] = alpha * rate + (1.0 - alpha) * self.ewma_rate[i];
            }
            if i == idx {
                current_rate = Some(rate);
            }
        }

        self.window_counts = [0; MONITORED_SYSCALL_COUNT];
        self.last_rate_sample_at = Instant::now();
        current_rate
    }

    fn seed_ewma_from_learning(&mut self) {
        let secs = self.created_at.elapsed().as_secs_f64().max(1e-6);
        for i in 0..MONITORED_SYSCALL_COUNT {
            self.ewma_rate[i] = self.counts[i] as f64 / secs;
        }
    }

    pub(super) fn export_prior(&self) -> TypePrior {
        TypePrior {
            ewma_rate: self.ewma_rate.to_vec(),
            seen_during_learning: self.seen_during_learning.to_vec(),
            sample_events: self.total_events,
        }
    }

    pub(super) fn seen_during_learning(&self, syscall_nr: u32) -> bool {
        let idx = syscall_nr as usize;
        if idx >= MONITORED_SYSCALL_COUNT {
            return false;
        }
        self.seen_during_learning[idx]
    }

    pub(super) fn mark_first_use_alerted(&mut self, syscall_nr: u32) {
        let idx = syscall_nr as usize;
        if idx < MONITORED_SYSCALL_COUNT {
            self.first_use_alerted[idx] = true;
        }
    }

    pub(super) fn first_use_already_alerted(&self, syscall_nr: u32) -> bool {
        let idx = syscall_nr as usize;
        if idx >= MONITORED_SYSCALL_COUNT {
            return false;
        }
        self.first_use_alerted[idx]
    }

    pub(super) fn ewma_rate(&self, syscall_nr: u32) -> f64 {
        let idx = syscall_nr as usize;
        if idx >= MONITORED_SYSCALL_COUNT {
            return 0.0;
        }
        self.ewma_rate[idx]
    }

    pub(super) fn is_spike(&self, syscall_nr: u32, rate: f64, global: &DetectorConfig) -> bool {
        if !self.learning_complete {
            return false;
        }
        let config = self.effective_config(global);
        let baseline = self.ewma_rate(syscall_nr);
        if baseline <= 0.0 {
            return rate >= config.spike_threshold_multiplier;
        }
        rate >= baseline * config.spike_threshold_multiplier
    }

    /// Map spike magnitude to confidence in [0.5, 1.0].
    ///
    /// At the spike threshold confidence is 0.5; it rises linearly to 1.0 at
    /// 3× the threshold (excess ratio clamped).
    pub(super) fn spike_confidence(
        &self,
        syscall_nr: u32,
        rate: f64,
        global: &DetectorConfig,
    ) -> f64 {
        let config = self.effective_config(global);
        let baseline = self.ewma_rate(syscall_nr).max(1e-6);
        let ratio = rate / baseline;
        let excess = (ratio / config.spike_threshold_multiplier).clamp(0.0, 3.0);
        (0.5 + 0.5 * (excess - 1.0).clamp(0.0, 1.0)).clamp(0.0, 1.0)
    }

    pub(super) fn learning_complete(&self) -> bool {
        self.learning_complete
    }
}

impl Default for TypeBaseline {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) type SandboxTypeKey = String;

/// Build the canonical sandbox type key for shared baselines.
///
/// Callers **must** pass this (or an equivalent stable key) via
/// [`crate::ebpf::EbpfSyscallMonitor::register_sandbox_audit`].
pub fn sandbox_type_key(image: &str, workload: &str) -> String {
    let image = if image.is_empty() { "unknown" } else { image };
    let workload = if workload.is_empty() {
        "unknown"
    } else {
        workload
    };
    format!("{image}:{workload}")
}

/// Registry of type baselines and warm-start priors.
#[derive(Debug, Default)]
pub(super) struct BaselineRegistry {
    baselines: HashMap<SandboxTypeKey, TypeBaseline>,
    priors: HashMap<SandboxTypeKey, TypePrior>,
    type_configs: HashMap<SandboxTypeKey, DetectorConfig>,
}

impl BaselineRegistry {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn get_or_create(
        &mut self,
        sandbox_type: &str,
        global: &DetectorConfig,
    ) -> &mut TypeBaseline {
        if !self.baselines.contains_key(sandbox_type) {
            let mut bl = if let Some(prior) = self.priors.get(sandbox_type) {
                TypeBaseline::from_prior(prior, global)
            } else {
                TypeBaseline::new()
            };
            if let Some(cfg) = self.type_configs.get(sandbox_type) {
                bl.set_config_override(Some(cfg.clone()));
            }
            self.baselines.insert(sandbox_type.to_string(), bl);
        }
        self.baselines.get_mut(sandbox_type).expect("just inserted")
    }

    pub(super) fn get(&self, sandbox_type: &str) -> Option<&TypeBaseline> {
        self.baselines.get(sandbox_type)
    }

    pub(super) fn get_mut(&mut self, sandbox_type: &str) -> Option<&mut TypeBaseline> {
        self.baselines.get_mut(sandbox_type)
    }

    pub(super) fn set_type_config(&mut self, sandbox_type: &str, config: DetectorConfig) {
        self.type_configs
            .insert(sandbox_type.to_string(), config.clone());
        if let Some(bl) = self.baselines.get_mut(sandbox_type) {
            bl.set_config_override(Some(config));
        }
    }

    pub(super) fn seed_prior(&mut self, sandbox_type: &str, prior: TypePrior) {
        self.priors
            .insert(sandbox_type.to_string(), prior.normalized());
    }

    /// Persist current baseline as the warm-start prior for this type.
    pub(super) fn publish_prior_from_baseline(&mut self, sandbox_type: &str) {
        if let Some(bl) = self.baselines.get(sandbox_type)
            && bl.learning_complete()
        {
            self.priors
                .insert(sandbox_type.to_string(), bl.export_prior());
        }
    }

    pub(super) fn len(&self) -> usize {
        self.baselines.len()
    }

    pub(super) fn prior_count(&self) -> usize {
        self.priors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::syscall::{SYSCALL_CONNECT, SYSCALL_OPEN};

    fn fast_config() -> DetectorConfig {
        DetectorConfig {
            learning_duration: Duration::from_millis(50),
            min_events_for_baseline: 5,
            spike_threshold_multiplier: 3.0,
            ewma_alpha: 0.5,
            rate_window: Duration::from_millis(1),
            ewma_idle_decay: 0.9,
            privilege_escalation_window: Duration::from_millis(50),
            alert_dangerous_during_learning: true,
        }
    }

    #[test]
    fn learning_completes_on_min_events_without_waiting_duration() {
        let config = DetectorConfig {
            learning_duration: Duration::from_secs(3600),
            min_events_for_baseline: 5,
            ..fast_config()
        };
        let mut bl = TypeBaseline::new();
        for _ in 0..5 {
            bl.record(SYSCALL_OPEN, &config);
        }
        assert!(!bl.is_learning(&config));
    }

    #[test]
    fn learning_completes_on_duration_without_min_events() {
        let config = DetectorConfig {
            learning_duration: Duration::from_millis(5),
            min_events_for_baseline: 10_000,
            ..fast_config()
        };
        let mut bl = TypeBaseline::new();
        bl.record(SYSCALL_OPEN, &config);
        assert!(bl.is_learning(&config));
        std::thread::sleep(Duration::from_millis(8));
        bl.record(SYSCALL_OPEN, &config);
        assert!(!bl.is_learning(&config));
    }

    #[test]
    fn warm_start_skips_learning_when_prior_is_rich() {
        let config = fast_config();
        let mut prior = TypePrior::empty();
        prior.sample_events = 200;
        prior.ewma_rate[SYSCALL_OPEN as usize] = 12.0;
        prior.seen_during_learning[SYSCALL_OPEN as usize] = true;
        let bl = TypeBaseline::from_prior(&prior, &config);
        assert!(!bl.is_learning(&config));
        assert!((bl.ewma_rate(SYSCALL_OPEN) - 12.0).abs() < f64::EPSILON);
    }

    #[test]
    fn per_type_config_override_applies() {
        let global = DetectorConfig {
            min_events_for_baseline: 1000,
            learning_duration: Duration::from_secs(3600),
            ..fast_config()
        };
        let override_cfg = DetectorConfig {
            min_events_for_baseline: 3,
            learning_duration: Duration::from_secs(3600),
            ..fast_config()
        };
        let mut bl = TypeBaseline::new();
        bl.set_config_override(Some(override_cfg));
        for _ in 0..3 {
            bl.record(SYSCALL_OPEN, &global);
        }
        assert!(!bl.is_learning(&global));
    }

    #[test]
    fn idle_decay_reduces_ewma_without_traffic() {
        let config = fast_config();
        let mut bl = TypeBaseline::new();
        for _ in 0..10 {
            let _ = bl.record(SYSCALL_OPEN, &config);
        }
        std::thread::sleep(Duration::from_millis(2));
        let _ = bl.record(SYSCALL_OPEN, &config);
        let before = bl.ewma_rate(SYSCALL_OPEN);
        assert!(before > 0.0);
        std::thread::sleep(Duration::from_millis(2));
        let _ = bl.record(SYSCALL_CONNECT, &config);
        assert!(bl.ewma_rate(SYSCALL_OPEN) < before);
    }

    #[test]
    fn sandbox_type_key_formats_image_workload() {
        assert_eq!(
            sandbox_type_key("python-3.12", "worker"),
            "python-3.12:worker"
        );
        assert_eq!(sandbox_type_key("", ""), "unknown:unknown");
    }

    #[test]
    fn registry_seeds_from_prior() {
        let global = fast_config();
        let mut reg = BaselineRegistry::new();
        let mut prior = TypePrior::empty();
        prior.sample_events = 200;
        prior.ewma_rate[0] = 5.0;
        reg.seed_prior("img:wl", prior);
        let bl = reg.get_or_create("img:wl", &global);
        assert!(!bl.is_learning(&global));
        assert_eq!(reg.prior_count(), 1);
    }
}
