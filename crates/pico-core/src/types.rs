//! API request and response models shared across PicoCompute components.

use hashbrown::HashMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::macros::format_description;
use ulid::Ulid;

use crate::SandboxState;
use crate::identity::{LeaseId, PolicyDecisionId, PrincipalId, TenantId};
use crate::overcommit::ServiceClass;
use crate::runtime::RuntimeType;

/// Per-device I/O limit for cgroup v2 `io.max`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IoLimit {
    pub device_major: u32,
    pub device_minor: u32,
    #[serde(default)]
    pub rbps: Option<u64>,
    #[serde(default)]
    pub wbps: Option<u64>,
    #[serde(default)]
    pub riops: Option<u64>,
    #[serde(default)]
    pub wiops: Option<u64>,
}

/// CPU bandwidth cap for cgroup v2 `cpu.max`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuBandwidth {
    pub max_us: u32,
    pub period_us: u32,
}

impl Default for CpuBandwidth {
    fn default() -> Self {
        Self {
            max_us: 100_000,
            period_us: 100_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub id: String,
    pub cpu_shares: u32,
    pub cpu_bandwidth: Option<CpuBandwidth>,
    pub memory_limit_bytes: u64,
    pub memory_soft_limit_bytes: Option<u64>,
    pub max_pids: Option<u32>,
    pub io_limits: Vec<IoLimit>,
    pub network_isolated: bool,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    /// Per-sandbox CPU pinning set (logical CPU indices).
    /// When set, the sandbox's vCPU threads or sentry process will be pinned
    /// to these CPUs via `sched_setaffinity(2)`. None means no pinning.
    #[serde(default)]
    pub cpu_set: Option<Vec<u32>>,
    /// Per-sandbox egress bandwidth cap in bytes per second (None = unlimited).
    #[serde(default)]
    pub bandwidth_limit_bps: Option<u64>,
    /// Per-sandbox maximum concurrent connections (None = unlimited).
    #[serde(default)]
    pub max_connections: Option<u32>,
    /// Per-sandbox maximum packets per second (None = unlimited).
    #[serde(default)]
    pub max_pps: Option<u32>,
    /// Scheduling service class for host-control treatment.
    ///
    /// Serde-defaults to [`ServiceClass::LatencySensitive`]. Best-effort
    /// sandboxes get deprioritized cgroup controls (see
    /// [`crate::overcommit::controls_for_class`]).
    #[serde(default)]
    pub service_class: ServiceClass,
}

const DEFAULT_CPU_SHARES: u32 = 100;
const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 256 * 1024 * 1024;

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            cpu_shares: DEFAULT_CPU_SHARES,
            cpu_bandwidth: None,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            memory_soft_limit_bytes: None,
            max_pids: None,
            io_limits: Vec::new(),
            network_isolated: false,
            ssh_port: None,
            cpu_set: None,
            bandwidth_limit_bps: None,
            max_connections: None,
            max_pps: None,
            service_class: ServiceClass::LatencySensitive,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    #[serde(default)]
    pub runtime: Option<RuntimeType>,
    pub id: Option<String>,
    pub ports: Option<Vec<u16>>,
    pub env: Option<HashMap<String, String>>,
    pub memory_mb: Option<u64>,
    pub vcpus: Option<u32>,
    pub idle_timeout_secs: Option<u64>,
    pub ssh_public_key: Option<String>,
    #[serde(default)]
    pub ssh_key_type: Option<String>,
    #[serde(default)]
    pub image_id: Option<String>,
    #[serde(default)]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub credential_request: Option<CredentialRequestSpec>,
    /// Scheduling service class for this sandbox.
    ///
    /// `None` (the default) inherits the tenant default via
    /// [`crate::overcommit::resolve_service_class`] at the API boundary.
    /// Explicit `BestEffort` without tenant opt-in fails closed. The
    /// orchestrator threads the resolved value into cell placement and
    /// host controls unchanged.
    #[serde(default)]
    pub service_class: Option<ServiceClass>,
    // TODO: expose the following from the API once the policy engine
    // and quota system are ready to validate per-sandbox PID/IO/bandwidth
    // controls. The internal types (SandboxConfig, ResourceLimits) and cgroup
    // enforcement already support these; this is purely an API-contract gate.
    //
    // pub memory_soft_mb: Option<u64>,
    // pub max_pids: Option<u32>,
    // pub io_limits: Option<Vec<IoLimit>>,
    // pub cpu_bandwidth: Option<CpuBandwidth>,
}

/// Specification for credentials to be injected into a sandbox on boot and
/// refreshed on resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequestSpec {
    pub tenant_id: TenantId,
    pub lease_id: LeaseId,
    pub policy_decision_id: Option<PolicyDecisionId>,
    pub credential_types: Vec<String>,
    /// Signed access-lease blob issued by admission. When present, enforcers
    /// verify the blob instead of looking the lease up in a local store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub id: String,
    pub state: SandboxState,
    pub ports: Vec<u16>,
    pub container_id: Option<String>,
    pub created_at: String,
    pub last_activity_at: String,
    pub ssh_port: Option<u16>,
    pub ssh_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshInfo {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub private_key: Option<String>,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub env: Option<HashMap<String, String>>,
    pub working_dir: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PageRequest {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl PageRequest {
    pub const DEFAULT_LIMIT: usize = 50;
    pub const MAX_LIMIT: usize = 250;

    /// Returns `(limit, cursor)` after validation. Per spec §2.6, an out-of-range
    /// `limit` is a `400 BadRequest`, not a silent clamp.
    pub fn normalized(&self) -> Result<(usize, Option<String>), crate::error::SandboxError> {
        let limit = self.limit.unwrap_or(Self::DEFAULT_LIMIT);
        if !(1..=Self::MAX_LIMIT).contains(&limit) {
            return Err(crate::error::SandboxError::BadRequest(format!(
                "limit must be between 1 and {} (got {})",
                Self::MAX_LIMIT,
                limit
            )));
        }
        Ok((limit, self.cursor.clone()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

// ---- Files (declared; Chunk 2 fills the impl) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWriteRequest {
    pub path: String,
    pub content: String,
    #[serde(default)]
    pub append: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReadResponse {
    pub path: String,
    pub content: String,
    pub size: u64,
    pub modified_at: String,
}

// ---- Tasks (declared; Chunk 4 fills the impl) ----

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl TaskState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Running => "Running",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Cancelled => "Cancelled",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRequest {
    pub prompt: String,
    pub agent: String,
    pub model: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub id: String,
    pub state: TaskState,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskEvent {
    Stdout { ts: String, data: String },
    Stderr { ts: String, data: String },
    Status { ts: String, state: TaskState },
    Result { ts: String, exit_code: i32 },
    Error { ts: String, message: String },
}

pub fn new_ulid(prefix: &str) -> String {
    format!("{}_{}", prefix, Ulid::generate())
}

/// State of a port-forward endpoint.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortForwardEndpointState {
    Active,
    Expired,
    Revoked,
}

/// A controlled port-forward endpoint exposing a sandbox guest port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortForwardEndpoint {
    pub endpoint_id: String,
    pub sandbox_id: String,
    pub tenant_id: TenantId,
    pub lease_id: LeaseId,
    pub policy_decision_id: PolicyDecisionId,
    pub owner: PrincipalId,
    pub guest_port: u16,
    pub host_port: u16,
    pub host: String,
    pub localhost_only: bool,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub state: PortForwardEndpointState,
    pub max_connections: Option<usize>,
    pub active_connections: usize,
}

/// Request to expose a sandbox guest port through a platform-managed endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardRequest {
    pub tenant_id: TenantId,
    pub lease_id: LeaseId,
    pub guest_port: u16,
    #[serde(default)]
    pub requested_host_port: Option<u16>,
    #[serde(default)]
    pub localhost_only: bool,
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Signed access-lease blob issued by admission. When present, enforcers
    /// verify the blob instead of looking the lease up in a local store.
    #[serde(default)]
    pub lease: Option<String>,
}

/// Response returned after creating a port-forward endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardResponse {
    pub endpoint: PortForwardEndpoint,
}

pub fn new_port_forward_id() -> String {
    new_ulid("epf")
}

pub fn now_iso() -> String {
    let fmt = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    OffsetDateTime::now_utc()
        .format(&fmt)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SandboxError;

    #[test]
    fn sandbox_state_debug_and_clone() {
        let states = [
            SandboxState::Pending,
            SandboxState::Scheduled,
            SandboxState::Preparing,
            SandboxState::Booting,
            SandboxState::Running,
            SandboxState::Suspending,
            SandboxState::Suspended,
            SandboxState::Resuming,
            SandboxState::Stopped,
            SandboxState::Destroying,
            SandboxState::Destroyed,
            SandboxState::Failed,
        ];
        for state in &states {
            let cloned = *state;
            assert_eq!(state, &cloned);
            assert!(!format!("{cloned:?}").is_empty());
        }
    }

    #[test]
    fn sandbox_state_partial_eq() {
        assert_eq!(SandboxState::Running, SandboxState::Running);
        assert_ne!(SandboxState::Running, SandboxState::Booting);
        assert_eq!(SandboxState::Failed, SandboxState::Failed);
    }

    #[test]
    fn sandbox_config_construction() {
        let cfg = SandboxConfig {
            id: "sbx_test".into(),
            cpu_shares: 200,
            memory_limit_bytes: 512 * 1024 * 1024,
            network_isolated: true,
            ..Default::default()
        };
        assert_eq!(cfg.id, "sbx_test");
        assert_eq!(cfg.cpu_shares, 200);
        assert_eq!(cfg.memory_limit_bytes, 512 * 1024 * 1024);
        assert!(cfg.network_isolated);
    }

    #[test]
    fn exec_request_construction() {
        let req = ExecRequest {
            command: "echo".into(),
            args: vec!["hello".into()],
            env: Some(HashMap::from([("PATH".into(), "/usr/bin".into())])),
            working_dir: Some("/tmp".into()),
            timeout_secs: Some(30),
        };
        assert_eq!(req.command, "echo");
        assert_eq!(req.args, vec!["hello"]);
        assert!(req.working_dir.is_some());
        assert_eq!(req.timeout_secs, Some(30));
    }

    #[test]
    fn exec_response_construction() {
        let resp = ExecResponse {
            exit_code: 0,
            stdout: "ok".into(),
            stderr: String::new(),
            duration_ms: 42,
        };
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "ok");
        assert!(resp.stderr.is_empty());
        assert_eq!(resp.duration_ms, 42);
    }

    #[test]
    fn sandbox_serde_roundtrip() {
        let cfg = SandboxConfig {
            id: "sbx_serde".into(),
            network_isolated: false,
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let deserialized: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, cfg.id);
        assert_eq!(deserialized.cpu_shares, cfg.cpu_shares);
    }

    #[test]
    fn page_request_default_limit() {
        let p = PageRequest {
            limit: None,
            cursor: None,
        };
        assert_eq!(p.normalized().unwrap().0, 50);
    }

    #[test]
    fn page_request_over_max_is_bad_request() {
        let p = PageRequest {
            limit: Some(10_000),
            cursor: None,
        };
        assert!(matches!(
            p.normalized().unwrap_err(),
            SandboxError::BadRequest(_)
        ));
    }

    #[test]
    fn page_request_zero_is_bad_request() {
        let p = PageRequest {
            limit: Some(0),
            cursor: None,
        };
        assert!(matches!(
            p.normalized().unwrap_err(),
            SandboxError::BadRequest(_)
        ));
    }

    #[test]
    fn page_request_at_max_is_ok() {
        let p = PageRequest {
            limit: Some(250),
            cursor: None,
        };
        assert_eq!(p.normalized().unwrap().0, 250);
    }

    #[test]
    fn task_state_terminal_classification() {
        assert!(!TaskState::Pending.is_terminal());
        assert!(!TaskState::Running.is_terminal());
        assert!(TaskState::Completed.is_terminal());
        assert!(TaskState::Failed.is_terminal());
        assert!(TaskState::Cancelled.is_terminal());
    }

    #[test]
    fn new_ulid_has_prefix_and_length() {
        let id = new_ulid("sbx");
        assert!(id.starts_with("sbx_"));
        assert_eq!(id.len(), 4 + 26);
    }

    #[test]
    fn exec_request_deserializes_minimal() {
        let r: ExecRequest = serde_json::from_str(r#"{"command":"echo"}"#).unwrap();
        assert_eq!(r.command, "echo");
        assert!(r.args.is_empty());
        assert!(r.env.is_none());
    }

    #[test]
    fn sandbox_spec_runtime_defaults_to_none() {
        let spec: SandboxSpec = serde_json::from_str(r#"{"id":"sbx_runtime"}"#).unwrap();
        assert_eq!(spec.runtime, None);
    }

    #[test]
    fn sandbox_spec_runtime_deserializes_qemu() {
        let spec: SandboxSpec =
            serde_json::from_str(r#"{"id":"sbx_runtime","runtime":"qemu"}"#).unwrap();
        assert_eq!(spec.runtime, Some(RuntimeType::Qemu));
    }

    #[test]
    fn sandbox_spec_runtime_deserializes_remote_firecracker() {
        let spec: SandboxSpec =
            serde_json::from_str(r#"{"id":"sbx_runtime","runtime":"remote-firecracker"}"#).unwrap();
        assert_eq!(spec.runtime, Some(RuntimeType::RemoteFirecracker));
    }

    #[test]
    fn now_iso_is_rfc3339_utc() {
        let s = now_iso();
        assert!(s.ends_with('Z'));
        assert_eq!(s.len(), 20);
    }

    #[test]
    fn sandbox_state_keeps_suspend_variants() {
        // Spec §10.1: runtime trait keeps suspend/resume.
        let _ = SandboxState::Suspending;
        let _ = SandboxState::Suspended;
        let _ = SandboxState::Resuming;
    }
}
