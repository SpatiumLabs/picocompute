use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    FrequencySpike,
    /// Dangerous syscall never observed during learning (post-baseline).
    DangerousSyscallFirstUse,
    /// Dangerous syscall observed while the type baseline is still learning.
    /// Prevents early-compromise evasion of first-use detection.
    DangerousSyscallDuringLearning,
    PrivilegeEscalation,
    ContainerEscape,
}

impl AnomalyType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrequencySpike => "frequency_spike",
            Self::DangerousSyscallFirstUse => "dangerous_syscall_first_use",
            Self::DangerousSyscallDuringLearning => "dangerous_syscall_during_learning",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::ContainerEscape => "container_escape",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AnomalySeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Anomaly finding ready for the security audit plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub sandbox_id: String,
    pub sandbox_type: String,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    /// Confidence in [0.0, 1.0].
    pub confidence: f64,
    pub detail: String,
    pub syscall_name: String,
    pub timestamp_ns: u64,
}

impl AnomalyEvent {
    pub fn confidence_clamped(mut self) -> Self {
        self.confidence = self.confidence.clamp(0.0, 1.0);
        self
    }
}
