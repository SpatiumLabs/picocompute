//! Health reporting for the host agent.
//!
//! `GET /rpc/v1/health` is a readiness endpoint. It reports `degraded` when
//! sandboxd is unreachable or when the supervisor carries `review_findings`
//! after restart reconciliation. The scheduler and cell controller should
//! treat `degraded` as serviceable but not fully ready; liveness should be
//! derived from process existence, not this endpoint.

use pico_core::RuntimeType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthStatus {
    Ready,
    Degraded,
    Draining,
    Unsafe,
}

impl HealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Unsafe => "unsafe",
        }
    }

    pub fn is_serviceable(self) -> bool {
        matches!(self, Self::Ready | Self::Degraded)
    }
}

/// Network health status as observed by the host-agent.
/// Mirrors the network-agent's reconciliation health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkHealth {
    /// Network appears healthy; reconciliation found no issues.
    Ready,
    /// Network has degraded state; stale objects were cleaned but host is serviceable.
    Degraded,
    /// Network has ambiguous objects that could not be resolved.
    Unsafe,
    /// Network health is unknown (not yet reported or agent unreachable).
    Unknown,
}

impl NetworkHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Unsafe => "unsafe",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostHealth {
    pub status: HealthStatus,
    pub sandbox_count: usize,
    pub supported_backends: Vec<RuntimeType>,
    pub network_health: NetworkHealth,
    pub message: Option<String>,
}

impl HostHealth {
    pub fn ready(sandbox_count: usize, backends: Vec<RuntimeType>) -> Self {
        Self {
            status: HealthStatus::Ready,
            sandbox_count,
            supported_backends: backends,
            network_health: NetworkHealth::Unknown,
            message: None,
        }
    }

    pub fn degraded(sandbox_count: usize, backends: Vec<RuntimeType>, reason: String) -> Self {
        Self {
            status: HealthStatus::Degraded,
            sandbox_count,
            supported_backends: backends,
            network_health: NetworkHealth::Unknown,
            message: Some(reason),
        }
    }

    pub fn draining(sandbox_count: usize, backends: Vec<RuntimeType>) -> Self {
        Self {
            status: HealthStatus::Draining,
            sandbox_count,
            supported_backends: backends,
            network_health: NetworkHealth::Unknown,
            message: Some("host is draining connections".into()),
        }
    }

    pub fn unsafe_state(sandbox_count: usize, backends: Vec<RuntimeType>, reason: String) -> Self {
        Self {
            status: HealthStatus::Unsafe,
            sandbox_count,
            supported_backends: backends,
            network_health: NetworkHealth::Unknown,
            message: Some(reason),
        }
    }

    /// Set the observed network health status.
    pub fn with_network_health(mut self, nh: NetworkHealth) -> Self {
        self.network_health = nh;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_values() {
        assert_eq!(HealthStatus::Ready.as_str(), "ready");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        assert_eq!(HealthStatus::Draining.as_str(), "draining");
        assert_eq!(HealthStatus::Unsafe.as_str(), "unsafe");
    }

    #[test]
    fn ready_is_serviceable() {
        assert!(HealthStatus::Ready.is_serviceable());
        assert!(HealthStatus::Degraded.is_serviceable());
        assert!(!HealthStatus::Draining.is_serviceable());
        assert!(!HealthStatus::Unsafe.is_serviceable());
    }

    #[test]
    fn network_health_values() {
        assert_eq!(NetworkHealth::Ready.as_str(), "ready");
        assert_eq!(NetworkHealth::Degraded.as_str(), "degraded");
        assert_eq!(NetworkHealth::Unsafe.as_str(), "unsafe");
        assert_eq!(NetworkHealth::Unknown.as_str(), "unknown");
    }

    #[test]
    fn host_health_builder_with_network_health() {
        let health = HostHealth::ready(5, vec![]).with_network_health(NetworkHealth::Ready);
        assert_eq!(health.network_health, NetworkHealth::Ready);
        assert_eq!(health.sandbox_count, 5);
        assert_eq!(health.status, HealthStatus::Ready);
    }

    #[test]
    fn network_health_serialization() {
        let health = HostHealth::ready(1, vec![]).with_network_health(NetworkHealth::Degraded);
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("degraded"));
        let parsed: HostHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.network_health, NetworkHealth::Degraded);
    }
}
