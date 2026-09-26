//! Conversions between wire protos and supervisor types.
//!
//! Wire typing only: Outcome kind/status/reason/observed_state and
//! runtime/backend are proto enums, not strings. Host capability evidence is
//! the shared `HostShape` message (`v1::HostShape`), validated once in
//! `checked_host_shape` so adding `disk_mb` touches one module, not four
//! layers (Parts -> Request -> Params -> Command).

use pico_core::{
    FencingToken, NonReadyReason as CoreNonReady, OperationId, RuntimeType as CoreRuntime,
    SandboxConfig, SandboxId, SandboxState as CoreState, now_iso,
};
use pico_sandboxd_proto::SupervisorErrorClass;
use pico_sandboxd_proto::v1::{
    self, CommandMeta, HealthResponse, HostShape, NonReadyReason as ProtoNonReady,
    OperationKind as ProtoKind, Outcome, OutcomeReason as ProtoReason,
    OutcomeStatus as ProtoStatus, PortTarget, RuntimeType as ProtoRuntime, SandboxObservation,
    SandboxState as ProtoState, port_target,
};
use tonic::Status;

use crate::{
    CommandContext, GuestSessionError, HostResourceSpec, ObservationWatchEvent, OperationKind,
    OperationOutcome, OutcomeReason, OutcomeStatus, PortTargetObservation, ResolvedPortTarget,
    SandboxObservationSnapshot, SecretsCoordinationError, SupervisorError, SupervisorHealth,
};

/// Maximum length for identifier strings (must match `ID_CAPACITY` in `ids.rs`).
const ID_MAX_LEN: usize = 128;

/// Parses [`CommandMeta`] into a supervisor [`CommandContext`].
pub(crate) fn command_context(meta: CommandMeta) -> Result<CommandContext, Status> {
    if meta.sandbox_id.is_empty() {
        return Err(Status::invalid_argument(
            "command meta sandbox_id is required",
        ));
    }
    if meta.sandbox_id.len() > ID_MAX_LEN {
        return Err(Status::invalid_argument(
            "sandbox_id exceeds maximum length",
        ));
    }
    if meta.operation_id.is_empty() {
        return Err(Status::invalid_argument(
            "command meta operation_id is required",
        ));
    }
    if meta.operation_id.len() > ID_MAX_LEN {
        return Err(Status::invalid_argument(
            "operation_id exceeds maximum length",
        ));
    }
    let assignment_fencing_token = meta
        .assignment_fencing_token
        .parse::<FencingToken>()
        .map_err(Status::invalid_argument)?;
    Ok(CommandContext {
        sandbox_id: SandboxId::from_string(meta.sandbox_id),
        operation_id: OperationId::from_string(meta.operation_id),
        assignment_fencing_token,
        policy_epoch: meta.policy_epoch,
        deadline_unix_ms: meta.deadline_unix_ms,
    })
}

/// Maps proto prepare config into core [`SandboxConfig`].
pub(crate) fn sandbox_config(config: v1::SandboxConfig) -> Result<SandboxConfig, Status> {
    if config.id.is_empty() {
        return Err(Status::invalid_argument("sandbox config id is required"));
    }
    let ssh_port = match config.ssh_port {
        Some(port) => Some(
            u16::try_from(port)
                .map_err(|_| Status::invalid_argument("ssh_port out of u16 range"))?,
        ),
        None => None,
    };
    let cpu_set = if config.cpu_set.is_empty() {
        None
    } else {
        Some(config.cpu_set)
    };
    Ok(SandboxConfig {
        id: config.id,
        memory_limit_bytes: config.memory_limit_bytes,
        cpu_shares: config.cpu_shares,
        memory_soft_limit_bytes: config.memory_soft_limit_bytes,
        max_pids: config.max_pids,
        network_isolated: config.network_isolated,
        ssh_port,
        cpu_set,
        ..SandboxConfig::default()
    })
}

/// Parses a wire runtime enum into core [`CoreRuntime`].
pub(crate) fn runtime_type(value: i32) -> Result<CoreRuntime, Status> {
    let proto = ProtoRuntime::try_from(value).map_err(|_| {
        Status::invalid_argument(format!(
            "unknown runtime_type {value}; expected proto RuntimeType"
        ))
    })?;
    proto_runtime_to_core(proto)
}

/// Maps the optional wire host resource spec into supervisor inputs.
///
/// A missing spec yields defaults so resource-constrained values are derived
/// from the runtime config instead. Image, SSH, and idle fields are retained
/// for handshake validation and observation (full wiring); they do not drive
/// allocation.
pub(crate) fn host_resource_spec(
    spec: Option<v1::HostResourceSpec>,
) -> Result<HostResourceSpec, Status> {
    let Some(spec) = spec else {
        return Ok(HostResourceSpec::default());
    };
    if spec
        .tenant_id
        .as_deref()
        .is_some_and(|tenant| tenant.len() > ID_MAX_LEN)
    {
        return Err(Status::invalid_argument("tenant_id exceeds maximum length"));
    }
    let mut requested_ports = Vec::with_capacity(spec.requested_ports.len());
    for port in spec.requested_ports {
        let port = u16::try_from(port).map_err(|_| {
            Status::invalid_argument(format!("requested_ports value {port} out of u16 range"))
        })?;
        if port != 0 {
            requested_ports.push(port);
        }
    }
    Ok(HostResourceSpec {
        vcpus: spec.vcpus,
        memory_mb: u64::from(spec.memory_mb),
        requested_ports,
        tenant_id: spec.tenant_id.filter(|tenant| !tenant.is_empty()),
        cross_tenant_host: spec.cross_tenant_host,
        idle_timeout_secs: spec.idle_timeout_secs,
        image_id: spec.image_id.filter(|s| !s.is_empty()),
        image_digest: spec.image_digest.filter(|s| !s.is_empty()),
        ssh_public_key: spec.ssh_public_key.filter(|s| !s.is_empty()),
        ssh_key_type: spec.ssh_key_type.filter(|s| !s.is_empty()),
    })
}

/// Validated snapshot restore inputs (wire parsing).
///
/// Supervisor execution lands in phase 2; this struct pins the wire
/// validation boundary so malformed requests fail with `InvalidArgument`
/// before any ledger, blob, or runtime side effect. Host evidence is the
/// shared [`HostShape`] so `disk_mb` is added once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestoreParams {
    /// Snapshot to restore from.
    pub snapshot_id: String,
    /// Tenant requesting restore. Must match snapshot tenant at execution.
    pub request_tenant_id: String,
    /// True when caller needs memory profile.
    pub requires_memory: bool,
    /// Runtime family the host selected.
    pub runtime: CoreRuntime,
    /// Shared host capability evidence.
    pub host: HostShape,
}

/// Validated fork inputs (wire parsing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForkParams {
    /// Parent snapshot to branch from.
    pub parent_snapshot_id: String,
    /// Tenant requesting fork.
    pub request_tenant_id: String,
    /// Child sandbox identity. Must differ from the parent sandbox at execution.
    pub child_sandbox_id: String,
    /// True when caller needs memory profile.
    pub requires_memory: bool,
    /// Runtime family the host selected.
    pub runtime: CoreRuntime,
    /// Shared host capability evidence, same shape as restore.
    pub host: HostShape,
}

fn checked_id(value: &str, field: &str) -> Result<String, Status> {
    if value.is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }
    if value.len() > ID_MAX_LEN {
        return Err(Status::invalid_argument(format!(
            "{field} exceeds maximum length"
        )));
    }
    Ok(value.to_string())
}

fn checked_host_shape(shape: &HostShape) -> Result<(), Status> {
    if shape.backend_type.is_empty() {
        return Err(Status::invalid_argument("host.backend_type is required"));
    }
    if shape.backend_version.is_empty() {
        return Err(Status::invalid_argument("host.backend_version is required"));
    }
    if shape.protocol_version.is_empty() {
        return Err(Status::invalid_argument(
            "host.protocol_version is required",
        ));
    }
    if shape.cpu_arch.is_empty() {
        return Err(Status::invalid_argument("host.cpu_arch is required"));
    }
    if shape.memory_mb == 0 {
        return Err(Status::invalid_argument("host.memory_mb must be non-zero"));
    }
    if shape.vcpus == 0 {
        return Err(Status::invalid_argument("host.vcpus must be non-zero"));
    }
    if shape.machine_type.is_empty() {
        return Err(Status::invalid_argument("host.machine_type is required"));
    }
    // disk_mb 0 means unspecified (older clients). Carried for future
    // compatibility gating; not yet enforced by restore validation.
    Ok(())
}

/// Parses and validates a wire `RestoreRequest` without side effects.
pub(crate) fn restore_params(request: &v1::RestoreRequest) -> Result<RestoreParams, Status> {
    let snapshot_id = checked_id(&request.snapshot_id, "snapshot_id")?;
    let request_tenant_id = checked_id(&request.request_tenant_id, "request_tenant_id")?;
    let runtime = runtime_type(request.runtime_type)?;
    let host = request
        .host
        .clone()
        .ok_or_else(|| Status::invalid_argument("restore host is required"))?;
    checked_host_shape(&host)?;
    Ok(RestoreParams {
        snapshot_id,
        request_tenant_id,
        requires_memory: request.requires_memory,
        runtime,
        host,
    })
}

/// Parses and validates a wire `ForkRequest` without side effects.
pub(crate) fn fork_params(request: &v1::ForkRequest) -> Result<ForkParams, Status> {
    let parent_snapshot_id = checked_id(&request.parent_snapshot_id, "parent_snapshot_id")?;
    let request_tenant_id = checked_id(&request.request_tenant_id, "request_tenant_id")?;
    let child_sandbox_id = checked_id(&request.child_sandbox_id, "child_sandbox_id")?;
    let runtime = runtime_type(request.runtime_type)?;
    let host = request
        .host
        .clone()
        .ok_or_else(|| Status::invalid_argument("fork host is required"))?;
    checked_host_shape(&host)?;
    Ok(ForkParams {
        parent_snapshot_id,
        request_tenant_id,
        child_sandbox_id,
        requires_memory: request.requires_memory,
        runtime,
        host,
    })
}

/// Maps a supervisor outcome plus optional observed state onto the wire.
///
/// Inlined kind/status/reason matches (single-use converters absorbed here)
/// so the seam stays deep: one function owns all Outcome wire typing.
pub(crate) fn outcome_to_proto(
    outcome: OperationOutcome,
    observed_state: Option<CoreState>,
) -> Outcome {
    let kind = match outcome.kind {
        OperationKind::Prepare => ProtoKind::Prepare,
        OperationKind::Boot => ProtoKind::Boot,
        OperationKind::Exec => ProtoKind::Exec,
        OperationKind::Suspend => ProtoKind::Suspend,
        OperationKind::Resume => ProtoKind::Resume,
        OperationKind::Destroy => ProtoKind::Destroy,
        OperationKind::Process => ProtoKind::Process,
        OperationKind::Restore => ProtoKind::Restore,
        OperationKind::Fork => ProtoKind::Fork,
    } as i32;
    let status = match outcome.status {
        OutcomeStatus::Running => ProtoStatus::Running,
        OutcomeStatus::Succeeded => ProtoStatus::Succeeded,
        OutcomeStatus::Failed => ProtoStatus::Failed,
        OutcomeStatus::Canceled => ProtoStatus::Canceled,
        OutcomeStatus::TimedOut => ProtoStatus::TimedOut,
        OutcomeStatus::RequiresReview => ProtoStatus::RequiresReview,
    } as i32;
    let reason_code = match outcome.reason {
        OutcomeReason::InProgress => ProtoReason::InProgress,
        OutcomeReason::Completed => ProtoReason::Completed,
        OutcomeReason::BackendFailure => ProtoReason::BackendFailure,
        OutcomeReason::CanceledByHost => ProtoReason::CanceledByHost,
        OutcomeReason::DeadlineExceeded => ProtoReason::DeadlineExceeded,
        OutcomeReason::PartialCleanup => ProtoReason::PartialCleanup,
        OutcomeReason::SupervisorRestarted => ProtoReason::SupervisorRestarted,
        OutcomeReason::ProcessExited => ProtoReason::ProcessExited,
        OutcomeReason::ProcessSignaled => ProtoReason::ProcessSignaled,
        OutcomeReason::ProcessFailure => ProtoReason::ProcessFailure,
        OutcomeReason::RestoreRejected => ProtoReason::RestoreRejected,
    } as i32;
    let non_ready_reason = match outcome.non_ready_reason {
        None => ProtoNonReady::Unspecified as i32,
        Some(CoreNonReady::Image) => ProtoNonReady::Image as i32,
        Some(CoreNonReady::Network) => ProtoNonReady::Network as i32,
        Some(CoreNonReady::Resource) => ProtoNonReady::Resource as i32,
        Some(CoreNonReady::Backend) => ProtoNonReady::Backend as i32,
        Some(CoreNonReady::Protocol) => ProtoNonReady::Protocol as i32,
        Some(CoreNonReady::Timeout) => ProtoNonReady::Timeout as i32,
        Some(CoreNonReady::Cleanup) => ProtoNonReady::Cleanup as i32,
    };
    let observed_state = match observed_state {
        None => ProtoState::Unspecified as i32,
        Some(s) => core_state_to_proto(s) as i32,
    };
    Outcome {
        operation_id: outcome.operation_id.to_string(),
        sandbox_id: outcome.sandbox_id.to_string(),
        kind,
        status,
        reason_code,
        non_ready_reason,
        message: outcome.message,
        resources: Vec::new(),
        observed_state,
        completed_at: outcome.completed_at,
    }
}

/// Maps an enriched supervisor observation onto the wire snapshot.
///
/// SSH is wired from prepare (host port + public key); username stays
/// host-side authoritative (empty preserves host cache in `apply_observation`).
pub(crate) fn snapshot_to_observation(snapshot: SandboxObservationSnapshot) -> SandboxObservation {
    let SandboxObservationSnapshot {
        status,
        generation,
        guest_boot_id,
        ports,
        ssh_host_port,
        ssh_public_key,
    } = snapshot;
    let ssh = match (ssh_host_port, ssh_public_key) {
        (None, None) => None,
        (port, key) => Some(v1::SshObservation {
            host_port: port.map(u32::from),
            username: String::new(),
            public_key: key,
        }),
    };
    SandboxObservation {
        sandbox_id: status.sandbox_id.to_string(),
        observed_state: core_state_to_proto(status.observed_state) as i32,
        generation,
        host_boot_id: status.host_boot_id,
        guest_boot_id,
        backend: core_runtime_to_proto(status.runtime) as i32,
        ports: ports.into_iter().map(port_target_to_proto).collect(),
        ssh,
        policy_epoch: status.policy_epoch,
        assignment_fencing_token: status.assignment_fencing_token.to_string(),
        updated_at: status.updated_at,
    }
}

/// Maps one resolved port target onto the wire `PortTarget`.
pub(crate) fn port_target_to_proto(port: PortTargetObservation) -> PortTarget {
    let target = match port.target {
        ResolvedPortTarget::Tcp(addr) => port_target::Target::TcpAddr(addr.to_string()),
        ResolvedPortTarget::BackendManaged => port_target::Target::BackendManaged(true),
        ResolvedPortTarget::Unsupported => port_target::Target::Unsupported(true),
    };
    PortTarget {
        guest_port: u32::from(port.guest_port),
        target: Some(target),
    }
}

/// Maps an internal watch event onto the wire `WatchEvent`.
pub(crate) fn watch_event_to_proto(
    event: ObservationWatchEvent,
) -> pico_sandboxd_proto::v1::WatchEvent {
    use pico_sandboxd_proto::v1::{ReconcileStatus, WatchEvent, watch_event};
    match event {
        ObservationWatchEvent::Upsert(snapshot) => WatchEvent {
            body: Some(watch_event::Body::Upsert(snapshot_to_observation(snapshot))),
        },
        ObservationWatchEvent::Removed(sandbox_id) => WatchEvent {
            body: Some(watch_event::Body::RemovedSandboxId(sandbox_id.to_string())),
        },
        ObservationWatchEvent::Reconcile {
            complete,
            review_findings,
            host_boot_id,
        } => WatchEvent {
            body: Some(watch_event::Body::Reconcile(ReconcileStatus {
                complete,
                review_findings,
                host_boot_id,
            })),
        },
    }
}

/// Maps supervisor health into the Health RPC response.
///
/// `supported_runtimes` is the sandboxd registry's actual set of registered
/// backend families, so the host advertises exactly what placement can run.
/// `reconcile_complete` is tracked separately from `ready` so the wire can
/// distinguish future states (today coupled: reconcile runs before ready).
pub(crate) fn health_to_proto(
    health: SupervisorHealth,
    host_boot_id: &str,
    supported_runtimes: &[CoreRuntime],
) -> HealthResponse {
    HealthResponse {
        ready_for_work: health.ready,
        reconcile_complete: health.reconcile_complete,
        review_findings: health.review_required,
        host_boot_id: host_boot_id.to_string(),
        supported_runtimes: supported_runtimes
            .iter()
            .map(|r| core_runtime_to_proto(*r) as i32)
            .collect(),
    }
}

/// Builds a cancel Outcome. Only called when the supervisor actually canceled; the
/// "no active operation" case returns `NotFound` at the service layer.
pub(crate) fn cancel_outcome(operation_id: &str, sandbox_id: &str) -> Outcome {
    Outcome {
        operation_id: operation_id.to_string(),
        sandbox_id: sandbox_id.to_string(),
        kind: ProtoKind::Unspecified as i32,
        status: ProtoStatus::Canceled as i32,
        reason_code: ProtoReason::CanceledByHost as i32,
        non_ready_reason: ProtoNonReady::Unspecified as i32,
        message: Some("operation cancel requested".into()),
        resources: Vec::new(),
        observed_state: ProtoState::Unspecified as i32,
        completed_at: now_iso(),
    }
}

/// Maps supervisor errors to gRPC statuses (not Outcome bodies).
pub(crate) fn supervisor_error_to_status(error: SupervisorError) -> Status {
    let class = match &error {
        SupervisorError::Ledger(_) => SupervisorErrorClass::Ledger,
        SupervisorError::Io(_) => SupervisorErrorClass::Io,
        SupervisorError::InvalidLedgerValue(_) => SupervisorErrorClass::InvalidLedgerValue,
        SupervisorError::StaleFencingToken { .. } => SupervisorErrorClass::StaleFencingToken,
        SupervisorError::OperationInProgress(_) => SupervisorErrorClass::OperationInProgress,
        SupervisorError::OperationIdentityConflict(_) => {
            SupervisorErrorClass::OperationIdentityConflict
        }
        SupervisorError::StalePolicyEpoch { .. } => SupervisorErrorClass::StalePolicyEpoch,
        SupervisorError::RuntimeNotAttached(_) => SupervisorErrorClass::RuntimeNotAttached,
        SupervisorError::SandboxMismatch { .. } => SupervisorErrorClass::SandboxMismatch,
        SupervisorError::InvalidProcessRequest(_) => SupervisorErrorClass::InvalidProcessRequest,
        SupervisorError::GuestSession(GuestSessionError::OutputLimit { .. }) => {
            return Status::resource_exhausted(error.to_string());
        }
        SupervisorError::GuestSession(GuestSessionError::NoSession { .. }) => {
            return Status::unavailable(error.to_string());
        }
        SupervisorError::GuestSession(GuestSessionError::ExecCanceled) => {
            return Status::aborted(error.to_string());
        }
        SupervisorError::GuestSession(GuestSessionError::ExecTimedOut) => {
            return Status::deadline_exceeded(error.to_string());
        }
        SupervisorError::GuestSession(
            GuestSessionError::ReplayNotSupported | GuestSessionError::RpcFailed { .. },
        ) => SupervisorErrorClass::Internal,
        SupervisorError::SnapshotRestore(_) => SupervisorErrorClass::SnapshotRestore,
        SupervisorError::Secrets(err) => match err {
            SecretsCoordinationError::LeaseValidation(_) => {
                return Status::permission_denied(error.to_string());
            }
            SecretsCoordinationError::InvalidRequest(_) => {
                return Status::invalid_argument(error.to_string());
            }
            SecretsCoordinationError::Broker(_) | SecretsCoordinationError::GuestInjection(_) => {
                SupervisorErrorClass::Internal
            }
        },
    };
    class.status(error.to_string())
}

pub(crate) fn core_runtime_to_proto(rt: CoreRuntime) -> ProtoRuntime {
    match rt {
        CoreRuntime::Firecracker => ProtoRuntime::Firecracker,
        CoreRuntime::Qemu => ProtoRuntime::Qemu,
        CoreRuntime::GVisor => ProtoRuntime::Gvisor,
        CoreRuntime::RemoteFirecracker => ProtoRuntime::RemoteFirecracker,
    }
}

pub(crate) fn proto_runtime_to_core(rt: ProtoRuntime) -> Result<CoreRuntime, Status> {
    match rt {
        ProtoRuntime::Firecracker => Ok(CoreRuntime::Firecracker),
        ProtoRuntime::Qemu => Ok(CoreRuntime::Qemu),
        ProtoRuntime::Gvisor => Ok(CoreRuntime::GVisor),
        ProtoRuntime::RemoteFirecracker => Ok(CoreRuntime::RemoteFirecracker),
        ProtoRuntime::Unspecified => Err(Status::invalid_argument(
            "runtime_type UNSPECIFIED is not a valid backend",
        )),
    }
}

pub(crate) fn core_state_to_proto(state: CoreState) -> ProtoState {
    match state {
        CoreState::Pending => ProtoState::Pending,
        CoreState::Scheduled => ProtoState::Scheduled,
        CoreState::Preparing => ProtoState::Preparing,
        CoreState::Booting => ProtoState::Booting,
        CoreState::Running => ProtoState::Running,
        CoreState::Suspending => ProtoState::Suspending,
        CoreState::Suspended => ProtoState::Suspended,
        CoreState::Resuming => ProtoState::Resuming,
        CoreState::Stopped => ProtoState::Stopped,
        CoreState::Destroying => ProtoState::Destroying,
        CoreState::Destroyed => ProtoState::Destroyed,
        CoreState::Failed => ProtoState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use pico_core::{FencingToken, SandboxId};
    use pico_sandboxd_proto::v1::{port_target, watch_event};

    use crate::SandboxStatus;

    #[test]
    fn parses_fencing_token_meta() {
        let meta = CommandMeta {
            sandbox_id: "sbx_1".into(),
            operation_id: "op_1".into(),
            assignment_fencing_token: "7.3".into(),
            policy_epoch: 1,
            deadline_unix_ms: 1,
        };
        let ctx = command_context(meta).unwrap();
        assert_eq!(
            ctx.assignment_fencing_token,
            FencingToken {
                epoch: 7,
                sequence: 3
            }
        );
    }

    #[test]
    fn rejects_oversized_sandbox_id() {
        let mut meta = CommandMeta {
            sandbox_id: "sbx_1".into(),
            operation_id: "opr_1".into(),
            assignment_fencing_token: "7.3".into(),
            policy_epoch: 1,
            deadline_unix_ms: 1,
        };
        meta.sandbox_id = format!("sbx_{:0>200}", "");
        let err = command_context(meta).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn rejects_oversized_operation_id() {
        let mut meta = CommandMeta {
            sandbox_id: "sbx_1".into(),
            operation_id: "opr_1".into(),
            assignment_fencing_token: "7.3".into(),
            policy_epoch: 1,
            deadline_unix_ms: 1,
        };
        meta.operation_id = format!("opr_{:0>200}", "");
        let err = command_context(meta).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn rejects_bad_fencing_token() {
        let meta = CommandMeta {
            sandbox_id: "sbx_1".into(),
            operation_id: "op_1".into(),
            assignment_fencing_token: "not-a-token".into(),
            policy_epoch: 1,
            deadline_unix_ms: 1,
        };
        let err = command_context(meta).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn host_resource_spec_parses_requested_ports_and_skips_zero() {
        let spec = host_resource_spec(Some(v1::HostResourceSpec {
            vcpus: 2,
            memory_mb: 512,
            requested_ports: vec![0, 22, 8080],
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(spec.requested_ports, vec![22, 8080]);
        assert_eq!(spec.vcpus, 2);
        assert_eq!(spec.memory_mb, 512);
    }

    #[test]
    fn host_resource_spec_rejects_port_outside_u16() {
        let err = host_resource_spec(Some(v1::HostResourceSpec {
            vcpus: 1,
            memory_mb: 128,
            requested_ports: vec![u32::from(u16::MAX) + 1],
            ..Default::default()
        }))
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("out of u16 range"));
    }

    #[test]
    fn host_resource_spec_none_is_default() {
        let spec = host_resource_spec(None).unwrap();
        assert!(spec.requested_ports.is_empty());
    }

    #[test]
    fn host_resource_spec_retains_image_and_ssh() {
        let spec = host_resource_spec(Some(v1::HostResourceSpec {
            vcpus: 1,
            memory_mb: 128,
            image_id: Some("img-1".into()),
            image_digest: Some("sha256:abc".into()),
            ssh_public_key: Some("ssh-ed25519 AAA".into()),
            ssh_key_type: Some("ed25519".into()),
            idle_timeout_secs: Some(60),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(spec.image_id.as_deref(), Some("img-1"));
        assert_eq!(spec.image_digest.as_deref(), Some("sha256:abc"));
        assert_eq!(spec.ssh_public_key.as_deref(), Some("ssh-ed25519 AAA"));
        assert_eq!(spec.idle_timeout_secs, Some(60));
    }

    #[test]
    fn port_target_to_proto_maps_all_variants() {
        let tcp = port_target_to_proto(PortTargetObservation {
            guest_port: 8080,
            target: ResolvedPortTarget::Tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))),
        });
        assert_eq!(tcp.guest_port, 8080);
        assert!(matches!(
            tcp.target,
            Some(port_target::Target::TcpAddr(addr)) if addr == "127.0.0.1:8080"
        ));

        let managed = port_target_to_proto(PortTargetObservation {
            guest_port: 22,
            target: ResolvedPortTarget::BackendManaged,
        });
        assert!(matches!(
            managed.target,
            Some(port_target::Target::BackendManaged(true))
        ));

        let unsupported = port_target_to_proto(PortTargetObservation {
            guest_port: 9,
            target: ResolvedPortTarget::Unsupported,
        });
        assert!(matches!(
            unsupported.target,
            Some(port_target::Target::Unsupported(true))
        ));
    }

    fn sample_snapshot() -> SandboxObservationSnapshot {
        SandboxObservationSnapshot {
            status: SandboxStatus {
                sandbox_id: SandboxId::from_string("sbx_obs"),
                assignment_fencing_token: FencingToken {
                    epoch: 1,
                    sequence: 2,
                },
                policy_epoch: 3,
                runtime: CoreRuntime::Firecracker,
                backend_version: "mock".into(),
                observed_state: CoreState::Running,
                host_boot_id: "host-boot".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
            },
            generation: 7,
            guest_boot_id: "guest-boot".into(),
            ports: vec![PortTargetObservation {
                guest_port: 80,
                target: ResolvedPortTarget::Tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 80))),
            }],
            ssh_host_port: Some(22022),
            ssh_public_key: Some("ssh-ed25519 AAA".into()),
        }
    }

    #[test]
    fn snapshot_to_observation_copies_generation_ports_and_ids() {
        let obs = snapshot_to_observation(sample_snapshot());
        assert_eq!(obs.sandbox_id, "sbx_obs");
        assert_eq!(obs.generation, 7);
        assert_eq!(obs.guest_boot_id, "guest-boot");
        assert_eq!(obs.host_boot_id, "host-boot");
        assert_eq!(obs.observed_state, ProtoState::Running as i32);
        assert_eq!(obs.policy_epoch, 3);
        assert_eq!(obs.assignment_fencing_token, "1.2");
        assert_eq!(obs.ports.len(), 1);
        assert_eq!(obs.ports[0].guest_port, 80);
        let ssh = obs.ssh.expect("ssh wired");
        assert_eq!(ssh.host_port, Some(22022));
    }

    #[test]
    fn watch_event_to_proto_maps_upsert_removed_and_reconcile() {
        let upsert = watch_event_to_proto(ObservationWatchEvent::Upsert(sample_snapshot()));
        assert!(matches!(
            upsert.body,
            Some(watch_event::Body::Upsert(obs)) if obs.sandbox_id == "sbx_obs" && obs.generation == 7
        ));

        let removed = watch_event_to_proto(ObservationWatchEvent::Removed(SandboxId::from_string(
            "sbx_gone",
        )));
        assert!(matches!(
            removed.body,
            Some(watch_event::Body::RemovedSandboxId(id)) if id == "sbx_gone"
        ));

        let reconcile = watch_event_to_proto(ObservationWatchEvent::Reconcile {
            complete: true,
            review_findings: 2,
            host_boot_id: "boot".into(),
        });
        match reconcile.body {
            Some(watch_event::Body::Reconcile(status)) => {
                assert!(status.complete);
                assert_eq!(status.review_findings, 2);
                assert_eq!(status.host_boot_id, "boot");
            }
            other => panic!("expected reconcile, got {other:?}"),
        }
    }

    fn sample_host_shape() -> HostShape {
        HostShape {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            cpu_arch: "x86_64".into(),
            memory_mb: 4096,
            vcpus: 4,
            machine_type: "q35".into(),
            disk_mb: 0,
        }
    }

    fn sample_restore_request() -> v1::RestoreRequest {
        v1::RestoreRequest {
            meta: None,
            snapshot_id: "snp_1".into(),
            request_tenant_id: "tnt_test".into(),
            requires_memory: false,
            runtime_type: ProtoRuntime::Firecracker as i32,
            host: Some(sample_host_shape()),
        }
    }

    fn sample_fork_request() -> v1::ForkRequest {
        v1::ForkRequest {
            meta: None,
            parent_snapshot_id: "snp_parent".into(),
            request_tenant_id: "tnt_test".into(),
            child_sandbox_id: "sbx_child".into(),
            requires_memory: false,
            runtime_type: ProtoRuntime::Firecracker as i32,
            host: Some(sample_host_shape()),
        }
    }

    #[test]
    fn restore_params_accepts_valid_request() {
        let params = restore_params(&sample_restore_request()).unwrap();
        assert_eq!(params.snapshot_id, "snp_1");
        assert_eq!(params.request_tenant_id, "tnt_test");
        assert_eq!(params.runtime, CoreRuntime::Firecracker);
        assert_eq!(params.host.memory_mb, 4096);
    }

    #[test]
    fn restore_params_rejects_empty_snapshot_id() {
        let mut req = sample_restore_request();
        req.snapshot_id.clear();
        let err = restore_params(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn restore_params_rejects_empty_tenant() {
        let mut req = sample_restore_request();
        req.request_tenant_id.clear();
        let err = restore_params(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn restore_params_rejects_unknown_runtime() {
        let mut req = sample_restore_request();
        req.runtime_type = 999;
        let err = restore_params(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn restore_params_rejects_zero_host_shape() {
        let mut req = sample_restore_request();
        req.host.as_mut().unwrap().memory_mb = 0;
        let err = restore_params(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let mut req = sample_restore_request();
        req.host.as_mut().unwrap().vcpus = 0;
        let err = restore_params(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let mut req = sample_restore_request();
        req.host.as_mut().unwrap().machine_type.clear();
        let err = restore_params(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn restore_params_rejects_empty_host_identity_fields() {
        for field in [
            "backend_type",
            "backend_version",
            "protocol_version",
            "cpu_arch",
        ] {
            let mut req = sample_restore_request();
            let host = req.host.as_mut().unwrap();
            match field {
                "backend_type" => host.backend_type.clear(),
                "backend_version" => host.backend_version.clear(),
                "protocol_version" => host.protocol_version.clear(),
                "cpu_arch" => host.cpu_arch.clear(),
                _ => unreachable!(),
            }
            let err = restore_params(&req).unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "field {field}");
        }
    }

    #[test]
    fn restore_params_rejects_missing_host() {
        let mut req = sample_restore_request();
        req.host = None;
        let err = restore_params(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn host_shape_disk_mb_is_optional_and_preserved() {
        let mut req = sample_restore_request();
        req.host.as_mut().unwrap().disk_mb = 10240;
        let params = restore_params(&req).unwrap();
        assert_eq!(params.host.disk_mb, 10240);
    }

    #[test]
    fn fork_params_accepts_valid_request() {
        let params = fork_params(&sample_fork_request()).unwrap();
        assert_eq!(params.parent_snapshot_id, "snp_parent");
        assert_eq!(params.child_sandbox_id, "sbx_child");
    }

    #[test]
    fn fork_params_rejects_empty_child() {
        let mut req = sample_fork_request();
        req.child_sandbox_id.clear();
        let err = fork_params(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn fork_params_rejects_empty_parent() {
        let mut req = sample_fork_request();
        req.parent_snapshot_id.clear();
        let err = fork_params(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn guest_session_variants_map_to_stable_codes_without_string_matching() {
        use crate::GuestSessionError;
        let cases = [
            (
                SupervisorError::GuestSession(GuestSessionError::OutputLimit {
                    path: "out.bin".into(),
                    cap: 1024,
                }),
                tonic::Code::ResourceExhausted,
            ),
            (
                SupervisorError::GuestSession(GuestSessionError::NoSession {
                    sandbox_id: "sbx_1".into(),
                }),
                tonic::Code::Unavailable,
            ),
            (
                SupervisorError::GuestSession(GuestSessionError::ExecCanceled),
                tonic::Code::Aborted,
            ),
            (
                SupervisorError::GuestSession(GuestSessionError::ExecTimedOut),
                tonic::Code::DeadlineExceeded,
            ),
            (
                SupervisorError::GuestSession(GuestSessionError::ReplayNotSupported),
                tonic::Code::Internal,
            ),
            (
                SupervisorError::GuestSession(GuestSessionError::RpcFailed {
                    detail: "boom".into(),
                }),
                tonic::Code::Internal,
            ),
        ];
        for (err, code) in cases {
            let expected_message = err.to_string();
            let status = supervisor_error_to_status(err);
            assert_eq!(status.code(), code);
            assert_eq!(status.message(), expected_message);
        }
    }

    #[test]
    fn guest_session_display_preserves_operator_detail() {
        use crate::GuestSessionError;
        let err = SupervisorError::GuestSession(GuestSessionError::OutputLimit {
            path: "out.bin".into(),
            cap: 1024,
        });
        assert!(err.to_string().contains("out.bin"));
        let err = SupervisorError::GuestSession(GuestSessionError::NoSession {
            sandbox_id: "sbx_9".into(),
        });
        assert!(err.to_string().contains("sbx_9"));
    }

    #[test]
    fn runtime_enum_round_trips_all_backends() {
        for rt in [
            CoreRuntime::Firecracker,
            CoreRuntime::Qemu,
            CoreRuntime::GVisor,
            CoreRuntime::RemoteFirecracker,
        ] {
            let proto = core_runtime_to_proto(rt);
            let back = proto_runtime_to_core(proto).unwrap();
            assert_eq!(back, rt);
        }
    }

    #[test]
    fn unspecified_runtime_is_invalid_argument() {
        let err = proto_runtime_to_core(ProtoRuntime::Unspecified).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        let err = runtime_type(ProtoRuntime::Unspecified as i32).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
