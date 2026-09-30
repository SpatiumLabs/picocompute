//! gRPC client for the sandboxd control plane (Interface 1).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::observation::proto_state_to_core;
use pico_core::{
    ExecRequest, ExecResponse, FencingToken, NonReadyReason, OperationId, Result, RuntimeType,
    SandboxConfig, SandboxError, SandboxId, SandboxState,
};
use pico_sandboxd_proto::METADATA_TOKEN_KEY;
use pico_sandboxd_proto::v1::sandboxd_client::SandboxdClient;
use pico_sandboxd_proto::v1::{
    self, BootRequest, CancelRequest, CommandMeta, DestroyRequest, ForkRequest,
    GetPortTargetRequest, GetPortTargetResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    InjectSecretsRequest, ListSandboxesRequest, NonReadyReason as ProtoNonReady,
    OperationKind as ProtoKind, OutcomeReason as ProtoReason, OutcomeStatus as ProtoStatus,
    PrepareRequest, RestoreRequest, ResumeRequest, RuntimeType as ProtoRuntime, SandboxObservation,
    SuspendRequest, WatchEvent, WatchRequest, exec_event,
};
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};

/// Default sandboxd UDS path when `PICO_SANDBOXD_SOCKET` is unset.
pub(crate) const DEFAULT_SANDBOXD_SOCKET_PATH: &str = "/var/run/pico/sandboxd.sock";

/// Connection parameters for sandboxd over a Unix domain socket.
#[derive(Debug, Clone)]
pub struct SandboxdConnect {
    /// Path to the sandboxd UDS.
    pub socket_path: std::path::PathBuf,
    /// Shared auth token sent as `x-pico-sandboxd-token`.
    pub auth_token: String,
}

impl SandboxdConnect {
    /// Builds connection params from the sandboxd environment variables.
    ///
    /// Reads `PICO_SANDBOXD_SOCKET` and `PICO_SANDBOXD_TOKEN`, falling
    /// back to the default socket path and an empty token.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            socket_path: std::env::var("PICO_SANDBOXD_SOCKET")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_SANDBOXD_SOCKET_PATH)),
            auth_token: std::env::var("PICO_SANDBOXD_TOKEN").unwrap_or_default(),
        }
    }
}

/// Host-side view of a supervised operation outcome.
///
/// Kind/status/reason are proto enums (no string parsing). Observed state and
/// non-ready reason map to core types for host logic.
#[derive(Debug, Clone)]
pub struct RpcOutcome {
    /// Operation identity echoed by sandboxd.
    pub operation_id: String,
    /// Sandbox identity echoed by sandboxd.
    pub sandbox_id: String,
    /// Operation kind wire enum.
    pub kind: ProtoKind,
    /// Outcome status wire enum.
    pub status: ProtoStatus,
    /// Machine-readable reason code.
    pub reason_code: ProtoReason,
    /// Optional non-ready classification.
    pub non_ready_reason: Option<NonReadyReason>,
    /// Optional redacted message.
    pub message: Option<String>,
    /// Observed sandbox state after the operation, when present.
    pub observed_state: Option<SandboxState>,
    /// Completion timestamp from sandboxd.
    pub completed_at: String,
}

impl RpcOutcome {
    /// True when sandboxd reported success.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status == ProtoStatus::Succeeded
    }

    /// True when sandboxd left cleanup for operator review.
    #[must_use]
    pub fn requires_review(&self) -> bool {
        self.status == ProtoStatus::RequiresReview
    }

    /// True when the operation timed out.
    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.status == ProtoStatus::TimedOut
    }
}

/// Cloneable handle to sandboxd. Each RPC clones the underlying tonic client.
#[derive(Clone)]
pub struct SandboxdHandle {
    channel: Channel,
    token: MetadataValue<Ascii>,
}

#[derive(Clone)]
struct TokenInterceptor {
    token: MetadataValue<Ascii>,
}

impl Interceptor for TokenInterceptor {
    fn call(&mut self, mut request: Request<()>) -> std::result::Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert(METADATA_TOKEN_KEY, self.token.clone());
        Ok(request)
    }
}

impl SandboxdHandle {
    /// Connects to sandboxd with retries until `timeout` elapses.
    pub async fn connect(connect: &SandboxdConnect, timeout: Duration) -> Result<Self> {
        let token = MetadataValue::try_from(connect.auth_token.as_str()).map_err(|err| {
            SandboxError::Other(format!("invalid sandboxd auth token metadata: {err}"))
        })?;
        let channel = connect_uds(&connect.socket_path, timeout).await?;
        Ok(Self { channel, token })
    }

    /// Builds a handle from an already-connected channel (tests).
    pub fn from_channel(channel: Channel, auth_token: &str) -> Result<Self> {
        let token = MetadataValue::try_from(auth_token).map_err(|err| {
            SandboxError::Other(format!("invalid sandboxd auth token metadata: {err}"))
        })?;
        Ok(Self { channel, token })
    }

    fn client(
        &self,
    ) -> SandboxdClient<tonic::service::interceptor::InterceptedService<Channel, TokenInterceptor>>
    {
        SandboxdClient::with_interceptor(
            self.channel.clone(),
            TokenInterceptor {
                token: self.token.clone(),
            },
        )
    }

    /// Issues Prepare with the given config and host resource inputs.
    pub async fn prepare(
        &self,
        meta: CommandMetaParts,
        config: &SandboxConfig,
        runtime: RuntimeType,
        host: HostResourceParts,
    ) -> Result<RpcOutcome> {
        let request = PrepareRequest {
            meta: Some(meta.into_proto()),
            config: Some(sandbox_config_to_proto(config)),
            runtime_type: core_runtime_to_proto(runtime) as i32,
            host: Some(host.into_proto()),
        };
        let outcome = self
            .client()
            .prepare(request)
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(outcome_from_proto(outcome))
    }

    /// Issues Boot for a prepared sandbox.
    pub async fn boot(&self, meta: CommandMetaParts) -> Result<RpcOutcome> {
        let outcome = self
            .client()
            .boot(BootRequest {
                meta: Some(meta.into_proto()),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(outcome_from_proto(outcome))
    }

    /// Issues Suspend.
    pub async fn suspend(&self, meta: CommandMetaParts) -> Result<RpcOutcome> {
        let outcome = self
            .client()
            .suspend(SuspendRequest {
                meta: Some(meta.into_proto()),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(outcome_from_proto(outcome))
    }

    /// Issues Resume.
    pub async fn resume(&self, meta: CommandMetaParts) -> Result<RpcOutcome> {
        let outcome = self
            .client()
            .resume(ResumeRequest {
                meta: Some(meta.into_proto()),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(outcome_from_proto(outcome))
    }

    /// Issues Destroy (also used for host stop/purge).
    pub async fn destroy(&self, meta: CommandMetaParts) -> Result<RpcOutcome> {
        let outcome = self
            .client()
            .destroy(DestroyRequest {
                meta: Some(meta.into_proto()),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(outcome_from_proto(outcome))
    }

    /// Issues Restore for a snapshot (wire stub).
    ///
    /// Phase 1 pins the wire boundary: valid requests fail closed with
    /// `Unimplemented` from sandboxd until supervisor restore lands.
    /// Malformed requests fail with `BadRequest` via server validation.
    pub async fn restore(&self, meta: CommandMetaParts, parts: RestoreParts) -> Result<RpcOutcome> {
        let outcome = self
            .client()
            .restore(RestoreRequest {
                meta: Some(meta.into_proto()),
                snapshot_id: parts.snapshot_id,
                request_tenant_id: parts.request_tenant_id,
                requires_memory: parts.requires_memory,
                runtime_type: core_runtime_to_proto(parts.runtime) as i32,
                host: Some(parts.host),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(outcome_from_proto(outcome))
    }

    /// Issues Fork for a parent snapshot (wire stub).
    pub async fn fork(&self, meta: CommandMetaParts, parts: ForkParts) -> Result<RpcOutcome> {
        let outcome = self
            .client()
            .fork(ForkRequest {
                meta: Some(meta.into_proto()),
                parent_snapshot_id: parts.parent_snapshot_id,
                request_tenant_id: parts.request_tenant_id,
                child_sandbox_id: parts.child_sandbox_id,
                requires_memory: parts.requires_memory,
                runtime_type: core_runtime_to_proto(parts.runtime) as i32,
                host: Some(parts.host),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(outcome_from_proto(outcome))
    }

    /// Injects secrets into the guest via sandboxd (lease proof + optional material).
    pub async fn inject_secrets(
        &self,
        meta: CommandMetaParts,
        credentials: v1::CredentialInjectSpec,
    ) -> Result<RpcOutcome> {
        let outcome = self
            .client()
            .inject_secrets(InjectSecretsRequest {
                meta: Some(meta.into_proto()),
                spec: Some(credentials),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(outcome_from_proto(outcome))
    }

    /// Cancels an in-flight operation by id.
    pub async fn cancel(&self, operation_id: &str, sandbox_id: &str) -> Result<RpcOutcome> {
        let outcome = self
            .client()
            .cancel(CancelRequest {
                operation_id: operation_id.into(),
                sandbox_id: sandbox_id.into(),
            })
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(outcome_from_proto(outcome))
    }

    /// Runs guest exec via the streaming Exec RPC and collects the full response.
    pub async fn exec(&self, meta: CommandMetaParts, req: ExecRequest) -> Result<ExecResponse> {
        let started = std::time::Instant::now();
        let timeout_secs = req.timeout_secs;
        let timeout_ms =
            timeout_secs.and_then(|secs| i64::try_from(secs.saturating_mul(1000)).ok());
        let request = v1::ExecRequest {
            meta: Some(meta.into_proto()),
            command: req.command,
            args: req.args,
            env: req.env.unwrap_or_default().into_iter().collect(),
            working_dir: req.working_dir.unwrap_or_default(),
            timeout_ms,
            max_stdout_bytes: EXEC_OUTPUT_CAP_BYTES as u64,
            max_stderr_bytes: EXEC_OUTPUT_CAP_BYTES as u64,
        };
        let mut stream = self
            .client()
            .exec(request)
            .await
            .map_err(status_to_error)?
            .into_inner();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut stdout_truncated = false;
        let mut stderr_truncated = false;
        let mut exit_code = 0i32;
        let mut saw_terminal = false;

        let collect = async {
            while let Some(event) = stream.message().await.map_err(status_to_error)? {
                match event.body {
                    Some(exec_event::Body::Started(_)) => {}
                    Some(exec_event::Body::Stdout(chunk)) => {
                        stdout_truncated |= append_bounded(&mut stdout, &chunk.data);
                    }
                    Some(exec_event::Body::Stderr(chunk)) => {
                        stderr_truncated |= append_bounded(&mut stderr, &chunk.data);
                    }
                    Some(exec_event::Body::Exited(exited)) => {
                        exit_code = exited.exit_code;
                        saw_terminal = true;
                        break;
                    }
                    Some(exec_event::Body::Failed(failed)) => {
                        // Preserve the structured failure classification so callers
                        // get the same Conflict/NotReady semantics as lifecycle RPCs.
                        return Err(match failed.outcome {
                            Some(outcome) => outcome_error(&outcome_from_proto(outcome)),
                            None => SandboxError::Other("exec failed".into()),
                        });
                    }
                    None => {}
                }
            }
            Ok(())
        };

        match timeout_secs {
            // Guard the read loop so a hung sandboxd cannot wedge this task
            // past the caller's timeout (plus a grace period for in-flight
            // terminal events).
            Some(secs) => {
                let deadline = tokio::time::Instant::now()
                    + Duration::from_secs(secs)
                    + Duration::from_secs(5);
                match tokio::time::timeout_at(deadline, collect).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(_) => {
                        return Err(SandboxError::NotReady(
                            "exec stream from sandboxd timed out before a terminal event".into(),
                        ));
                    }
                }
            }
            // No caller-specified timeout: run until the stream ends or the
            // server enforces its own bound; never impose a client-side cap.
            None => match collect.await {
                Ok(()) => {}
                Err(err) => return Err(err),
            },
        }

        if !saw_terminal {
            return Err(SandboxError::Other(
                "exec stream ended without a terminal event".into(),
            ));
        }

        let mut stdout = String::from_utf8_lossy(&stdout).into_owned();
        let mut stderr = String::from_utf8_lossy(&stderr).into_owned();
        if stdout_truncated {
            stdout.push_str("\n[pico: output truncated at 4 MiB]");
        }
        if stderr_truncated {
            stderr.push_str("\n[pico: output truncated at 4 MiB]");
        }

        Ok(ExecResponse {
            exit_code,
            stdout,
            stderr,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// Fetches a single sandbox observation.
    pub async fn get_sandbox(&self, sandbox_id: &str) -> Result<SandboxObservation> {
        self.client()
            .get_sandbox(GetSandboxRequest {
                sandbox_id: sandbox_id.into(),
            })
            .await
            .map_err(status_to_error)
            .map(tonic::Response::into_inner)
    }

    /// Lists all sandboxes known to sandboxd.
    pub async fn list_sandboxes(&self) -> Result<Vec<SandboxObservation>> {
        let response = self
            .client()
            .list_sandboxes(ListSandboxesRequest {})
            .await
            .map_err(status_to_error)?
            .into_inner();
        Ok(response.sandboxes)
    }

    /// Resolves one guest port target from sandboxd.
    ///
    /// Unknown sandbox or port returns [`SandboxError::SandboxNotFound`] so the
    /// proxy can fail closed.
    pub async fn get_port_target(
        &self,
        sandbox_id: &str,
        guest_port: u16,
    ) -> Result<GetPortTargetResponse> {
        self.client()
            .get_port_target(GetPortTargetRequest {
                sandbox_id: sandbox_id.into(),
                guest_port: u32::from(guest_port),
            })
            .await
            .map_err(status_to_error)
            .map(tonic::Response::into_inner)
    }

    /// Opens the observation Watch server stream.
    ///
    /// An empty `sandbox_ids` filter watches every sandbox on the host.
    pub async fn watch(
        &self,
        sandbox_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<tonic::Streaming<WatchEvent>> {
        let request = WatchRequest {
            sandbox_ids: sandbox_ids.into_iter().map(Into::into).collect(),
        };
        self.client()
            .watch(request)
            .await
            .map_err(status_to_error)
            .map(tonic::Response::into_inner)
    }

    /// Queries sandboxd process health.
    pub async fn health(&self) -> Result<HealthResponse> {
        self.client()
            .health(HealthRequest {})
            .await
            .map_err(status_to_error)
            .map(tonic::Response::into_inner)
    }
}

/// Command identity carried on mutating RPCs.
#[derive(Debug, Clone)]
pub struct CommandMetaParts {
    /// Target sandbox.
    pub sandbox_id: SandboxId,
    /// Operation identity for idempotency.
    pub operation_id: OperationId,
    /// Assignment fencing token.
    pub assignment_fencing_token: FencingToken,
    /// Policy epoch admitted by the host.
    pub policy_epoch: u64,
    /// Relative deadline converted to an absolute unix ms timestamp.
    pub deadline: Duration,
}

impl CommandMetaParts {
    /// Builds command meta from host admission fields.
    #[must_use]
    pub fn new(
        sandbox_id: impl Into<String>,
        operation_id: OperationId,
        assignment_fencing_token: FencingToken,
        policy_epoch: u64,
        deadline: Duration,
    ) -> Self {
        Self {
            sandbox_id: SandboxId::from_string(sandbox_id.into()),
            operation_id,
            assignment_fencing_token,
            policy_epoch,
            deadline,
        }
    }

    fn into_proto(self) -> CommandMeta {
        CommandMeta {
            sandbox_id: self.sandbox_id.to_string(),
            operation_id: self.operation_id.to_string(),
            assignment_fencing_token: self.assignment_fencing_token.to_string(),
            policy_epoch: self.policy_epoch,
            deadline_unix_ms: deadline_unix_ms(self.deadline),
        }
    }
}

/// Host resource inputs for Prepare.
#[derive(Debug, Clone, Default)]
pub struct HostResourceParts {
    /// Requested vCPU count.
    pub vcpus: u32,
    /// Requested memory in mebibytes.
    pub memory_mb: u32,
    /// Optional idle timeout hint.
    pub idle_timeout_secs: Option<u64>,
    /// Optional image id.
    pub image_id: Option<String>,
    /// Optional image digest.
    pub image_digest: Option<String>,
    /// Optional SSH public key.
    pub ssh_public_key: Option<String>,
    /// Optional SSH key type.
    pub ssh_key_type: Option<String>,
    /// Guest ports requested by the caller.
    pub requested_ports: Vec<u32>,
    /// Whether the host mixes tenants.
    pub cross_tenant_host: bool,
    /// Optional tenant identity for isolation policy.
    pub tenant_id: Option<String>,
}

impl HostResourceParts {
    fn into_proto(self) -> v1::HostResourceSpec {
        v1::HostResourceSpec {
            vcpus: self.vcpus,
            memory_mb: self.memory_mb,
            idle_timeout_secs: self.idle_timeout_secs,
            image_id: self.image_id,
            image_digest: self.image_digest,
            ssh_public_key: self.ssh_public_key,
            ssh_key_type: self.ssh_key_type,
            requested_ports: self.requested_ports,
            cross_tenant_host: self.cross_tenant_host,
            tenant_id: self.tenant_id,
        }
    }
}

/// Snapshot restore inputs for the sandboxd Restore RPC.
///
/// Host evidence is the shared `HostShape` so `disk_mb` is added once.
#[derive(Debug, Clone)]
pub struct RestoreParts {
    /// Snapshot to restore from.
    pub snapshot_id: String,
    /// Tenant requesting restore.
    pub request_tenant_id: String,
    /// True when caller needs memory profile.
    pub requires_memory: bool,
    /// Runtime family the host selected.
    pub runtime: RuntimeType,
    /// Shared host capability evidence.
    pub host: v1::HostShape,
}

/// Fork inputs for the sandboxd Fork RPC.
#[derive(Debug, Clone)]
pub struct ForkParts {
    /// Parent snapshot to branch from.
    pub parent_snapshot_id: String,
    /// Tenant requesting fork.
    pub request_tenant_id: String,
    /// Child sandbox identity.
    pub child_sandbox_id: String,
    /// True when caller needs memory profile.
    pub requires_memory: bool,
    /// Runtime family the host selected.
    pub runtime: RuntimeType,
    /// Shared host capability evidence, same shape as restore.
    pub host: v1::HostShape,
}

/// Maps a failed RPC outcome into the host error model.
///
/// Matches the typed `reason_code` wire enum (exact equality, never
/// substring search): restore validation failures stay unprocessable,
/// cleanup failures stay conflicts, and everything else is not-ready.
#[must_use]
pub fn outcome_error(outcome: &RpcOutcome) -> SandboxError {
    let message = outcome
        .message
        .clone()
        .unwrap_or_else(|| format!("sandbox operation ended with status {:?}", outcome.status));
    if outcome.non_ready_reason == Some(NonReadyReason::Cleanup) {
        SandboxError::Conflict(message)
    } else if outcome.reason_code == ProtoReason::RestoreRejected {
        SandboxError::Unprocessable(message)
    } else {
        SandboxError::NotReady(message)
    }
}

async fn connect_uds(socket: &Path, timeout: Duration) -> Result<Channel> {
    let path = socket.display().to_string();
    let uri = format!("unix://{path}");
    let endpoint = Endpoint::from_shared(uri)
        .map_err(|err| SandboxError::Other(format!("invalid sandboxd unix uri: {err}")))?
        // Defense in depth: bound every RPC client-side so a hung sandboxd
        // cannot wedge host-agent tasks even if it ignores deadline_unix_ms.
        .timeout(Duration::from_secs(120))
        .connect_timeout(timeout);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut delay = Duration::from_millis(25);
    loop {
        match endpoint.connect().await {
            Ok(channel) => return Ok(channel),
            Err(err) if tokio::time::Instant::now() < deadline => {
                tracing::debug!(error = %err, path = %path, "sandboxd connect retry");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(500));
            }
            Err(err) => {
                return Err(SandboxError::Other(format!(
                    "failed to connect to sandboxd at {path}: {err}"
                )));
            }
        }
    }
}

/// Client-side cap for buffered exec stdout/stderr, mirroring the cap advertised
/// to sandboxd so a misbehaving server cannot exhaust host memory.
const EXEC_OUTPUT_CAP_BYTES: usize = 4 * 1024 * 1024;

/// Appends `data` to `out`, truncating at [`EXEC_OUTPUT_CAP_BYTES`]. Returns
/// true when the stream hit the cap (so callers can surface the truncation).
fn append_bounded(out: &mut Vec<u8>, data: &[u8]) -> bool {
    let remaining = EXEC_OUTPUT_CAP_BYTES.saturating_sub(out.len());
    if remaining == 0 {
        return true;
    }
    let chunk = &data[..data.len().min(remaining)];
    out.extend_from_slice(chunk);
    chunk.len() < data.len()
}

fn deadline_unix_ms(timeout: Duration) -> i64 {
    let deadline = SystemTime::now()
        .checked_add(timeout)
        .unwrap_or(SystemTime::now());
    deadline
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

fn sandbox_config_to_proto(config: &SandboxConfig) -> v1::SandboxConfig {
    v1::SandboxConfig {
        id: config.id.clone(),
        memory_limit_bytes: config.memory_limit_bytes,
        cpu_shares: config.cpu_shares,
        memory_soft_limit_bytes: config.memory_soft_limit_bytes,
        max_pids: config.max_pids,
        network_isolated: config.network_isolated,
        ssh_port: config.ssh_port.map(u32::from),
        cpu_set: config.cpu_set.clone().unwrap_or_default(),
        service_class: core_service_class_to_proto(config.service_class) as i32,
    }
}

/// Maps a core service class onto the wire enum.
///
/// Latency-sensitive (the strict default) maps explicitly rather than as
/// UNSPECIFIED so the wire always names the class it enforces; older
/// servers that predate the field ignore it and keep strict packing.
fn core_service_class_to_proto(class: pico_core::ServiceClass) -> v1::ServiceClass {
    match class {
        pico_core::ServiceClass::LatencySensitive => v1::ServiceClass::LatencySensitive,
        pico_core::ServiceClass::BestEffort => v1::ServiceClass::BestEffort,
    }
}

fn outcome_from_proto(outcome: v1::Outcome) -> RpcOutcome {
    let kind = ProtoKind::try_from(outcome.kind).unwrap_or(ProtoKind::Unspecified);
    let status = ProtoStatus::try_from(outcome.status).unwrap_or(ProtoStatus::Unspecified);
    let reason_code =
        ProtoReason::try_from(outcome.reason_code).unwrap_or(ProtoReason::Unspecified);
    let observed_state = proto_state_to_core(outcome.observed_state);
    let non_ready_reason = proto_non_ready_to_core(outcome.non_ready_reason);
    RpcOutcome {
        operation_id: outcome.operation_id,
        sandbox_id: outcome.sandbox_id,
        kind,
        status,
        reason_code,
        non_ready_reason,
        message: outcome.message,
        observed_state,
        completed_at: outcome.completed_at,
    }
}

fn proto_non_ready_to_core(value: i32) -> Option<NonReadyReason> {
    let proto = ProtoNonReady::try_from(value).ok()?;
    match proto {
        ProtoNonReady::Unspecified => None,
        ProtoNonReady::Image => Some(NonReadyReason::Image),
        ProtoNonReady::Network => Some(NonReadyReason::Network),
        ProtoNonReady::Resource => Some(NonReadyReason::Resource),
        ProtoNonReady::Backend => Some(NonReadyReason::Backend),
        ProtoNonReady::Protocol => Some(NonReadyReason::Protocol),
        ProtoNonReady::Timeout => Some(NonReadyReason::Timeout),
        ProtoNonReady::Cleanup => Some(NonReadyReason::Cleanup),
    }
}

fn core_runtime_to_proto(rt: RuntimeType) -> ProtoRuntime {
    match rt {
        RuntimeType::Firecracker => ProtoRuntime::Firecracker,
        RuntimeType::Qemu => ProtoRuntime::Qemu,
        RuntimeType::GVisor => ProtoRuntime::Gvisor,
        RuntimeType::RemoteFirecracker => ProtoRuntime::RemoteFirecracker,
    }
}

fn status_to_error(status: Status) -> SandboxError {
    let message = status.message().to_string();
    match status.code() {
        tonic::Code::NotFound => {
            if message.is_empty() {
                SandboxError::SandboxNotFound("unknown".into())
            } else {
                SandboxError::SandboxNotFound(message)
            }
        }
        tonic::Code::AlreadyExists => SandboxError::Conflict(message),
        tonic::Code::FailedPrecondition => SandboxError::OperationStale(message),
        tonic::Code::InvalidArgument => SandboxError::BadRequest(message),
        tonic::Code::DeadlineExceeded | tonic::Code::Unavailable => SandboxError::NotReady(message),
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
            // The typed variant carries no message slot, so surface the server detail
            // in the operational log for triage.
            tracing::warn!(message = %message, "sandboxd authorization denied");
            SandboxError::Unauthorized
        }
        tonic::Code::ResourceExhausted => {
            // Resource bounds carry detail but no quota numbers: report the
            // server detail verbatim instead of fabricating limit/current.
            let detail = if message.is_empty() {
                "sandboxd".to_string()
            } else {
                format!("sandboxd: {message}")
            };
            SandboxError::ResourceExhausted { detail }
        }
        _ => SandboxError::Other(message),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pico_runtime::mock::MockBackend;
    use pico_sandboxd::config::SandboxdConfig;
    use pico_sandboxd::grpc::server::{bind_uds, serve_uds};
    use pico_sandboxd::registry::AdapterRegistry;
    use pico_sandboxd::{HostResourceConfig, SandboxSupervisor};
    use tempfile::TempDir;

    use super::*;
    use crate::observation::{ObservationSnapshot, apply_observation};
    use pico_sandboxd_proto::v1::SandboxState as ProtoState;

    const TOKEN: &str = "test-host-sandboxd-token";

    fn meta(sandbox_id: &str) -> CommandMetaParts {
        CommandMetaParts::new(
            sandbox_id,
            OperationId::generate(),
            FencingToken {
                epoch: 1,
                sequence: 1,
            },
            1,
            Duration::from_secs(30),
        )
    }

    fn outcome(status: ProtoStatus, observed_state: ProtoState) -> v1::Outcome {
        v1::Outcome {
            operation_id: "opr_1".into(),
            sandbox_id: "sbx_1".into(),
            kind: ProtoKind::Prepare as i32,
            status: status as i32,
            reason_code: ProtoReason::Completed as i32,
            non_ready_reason: ProtoNonReady::Unspecified as i32,
            message: Some("redacted detail".into()),
            resources: Vec::new(),
            observed_state: observed_state as i32,
            completed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    /// Starts an in-process sandboxd over UDS, returning the socket path and
    /// the handles that keep the server alive for the test scope.
    async fn spawn_server(
        dir: &TempDir,
    ) -> (
        std::path::PathBuf,
        tokio::task::JoinHandle<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let socket = dir.path().join("sandboxd.sock");
        let ledger = dir.path().join("state.db");
        let workspace = dir.path().join("workspaces");
        std::fs::create_dir_all(&workspace).unwrap();

        let supervisor =
            SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone()))
                .unwrap()
                .with_guest_session(false);
        supervisor.reconcile().await.unwrap();

        let mut registry = AdapterRegistry::new();
        registry.register(
            RuntimeType::Firecracker,
            || Arc::new(MockBackend::default()),
        );

        let config = SandboxdConfig {
            socket_path: socket.clone(),
            auth_token: TOKEN.into(),
            ledger_path: ledger,
            workspace_root: workspace,
            cpu_isolation_policy: Default::default(),
            cross_tenant_host: false,
            allowed_peer_uids: Vec::new(),
            log_format: Default::default(),
            dns_proxy_listen_addr: None,
            network_enabled: false,
        };

        let listener = bind_uds(&socket).await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let serve = serve_uds(listener, supervisor, registry, &config, async move {
                let _ = shutdown_rx.await;
            });
            let _ = serve.await;
        });
        (socket, server, shutdown_tx)
    }

    // ═══════════════════════════════════════════════════════════════
    // RPC round-trips
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn health_roundtrip_reports_ready_and_registered_backends() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let health = handle.health().await.unwrap();
        assert!(health.ready_for_work);
        assert_eq!(
            health.supported_runtimes,
            vec![ProtoRuntime::Firecracker as i32],
            "health must advertise the registry's registered runtimes"
        );
    }

    #[tokio::test]
    async fn prepare_roundtrip_echoes_sandbox_and_operation() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let meta = meta("sbx_rpc");
        let config = SandboxConfig {
            id: "sbx_rpc".into(),
            cpu_shares: 128,
            memory_limit_bytes: 256 * 1024 * 1024,
            network_isolated: true,
            ..SandboxConfig::default()
        };
        let outcome = handle
            .prepare(
                meta.clone(),
                &config,
                RuntimeType::Firecracker,
                HostResourceParts::default(),
            )
            .await
            .unwrap();
        assert!(outcome.succeeded());
        assert_eq!(outcome.sandbox_id, "sbx_rpc");
        assert_eq!(outcome.operation_id, meta.operation_id.to_string());

        let observation = handle.get_sandbox("sbx_rpc").await.unwrap();
        assert_eq!(observation.sandbox_id, "sbx_rpc");
        assert_eq!(observation.backend, ProtoRuntime::Firecracker as i32);
    }

    #[tokio::test]
    async fn missing_sandbox_maps_to_not_found() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let err = handle.get_sandbox("sbx_missing").await.unwrap_err();
        assert!(matches!(err, SandboxError::SandboxNotFound(_)));
    }

    #[tokio::test]
    async fn exec_without_guest_session_fails_not_ready() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let prepare_meta = meta("sbx_exec");
        let config = SandboxConfig {
            id: "sbx_exec".into(),
            ..SandboxConfig::default()
        };
        let prepared = handle
            .prepare(
                prepare_meta.clone(),
                &config,
                RuntimeType::Firecracker,
                HostResourceParts::default(),
            )
            .await
            .unwrap();
        assert!(prepared.succeeded());
        // Boot is a distinct operation: fresh operation id and the next
        // fencing sequence, mirroring how the host advances admission.
        let mut boot_meta = meta("sbx_exec");
        boot_meta.assignment_fencing_token = FencingToken {
            epoch: 1,
            sequence: 2,
        };
        let booted = handle.boot(boot_meta).await.unwrap();
        assert!(booted.succeeded());

        let mut exec_meta = meta("sbx_exec");
        exec_meta.assignment_fencing_token = FencingToken {
            epoch: 1,
            sequence: 3,
        };
        let err = handle
            .exec(
                exec_meta,
                ExecRequest {
                    command: "echo".into(),
                    args: vec!["hi".into()],
                    env: None,
                    working_dir: None,
                    timeout_secs: Some(5),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::NotReady(_)));
    }

    // ═══════════════════════════════════════════════════════════════
    // Pure conversion and mapping functions
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn rpc_outcome_status_predicates() {
        fn base(status: ProtoStatus) -> RpcOutcome {
            RpcOutcome {
                operation_id: String::new(),
                sandbox_id: String::new(),
                kind: ProtoKind::Unspecified,
                status,
                reason_code: ProtoReason::Unspecified,
                non_ready_reason: None,
                message: None,
                observed_state: None,
                completed_at: String::new(),
            }
        }
        let ok = base(ProtoStatus::Succeeded);
        assert!(ok.succeeded());
        assert!(!ok.requires_review());
        assert!(!ok.timed_out());

        let review = base(ProtoStatus::RequiresReview);
        assert!(review.requires_review());
        assert!(!review.succeeded());

        let timeout = base(ProtoStatus::TimedOut);
        assert!(timeout.timed_out());
    }

    #[test]
    fn connect_from_env_reads_socket_and_token() {
        unsafe {
            std::env::set_var("PICO_SANDBOXD_SOCKET", "/tmp/test-pico.sock");
            std::env::set_var("PICO_SANDBOXD_TOKEN", "env-token");
        }
        let connect = SandboxdConnect::from_env();
        assert_eq!(
            connect.socket_path,
            std::path::PathBuf::from("/tmp/test-pico.sock")
        );
        assert_eq!(connect.auth_token, "env-token");
        unsafe {
            std::env::remove_var("PICO_SANDBOXD_SOCKET");
            std::env::remove_var("PICO_SANDBOXD_TOKEN");
        }
        let connect = SandboxdConnect::from_env();
        assert_eq!(
            connect.socket_path,
            std::path::PathBuf::from(DEFAULT_SANDBOXD_SOCKET_PATH)
        );
        assert!(connect.auth_token.is_empty());
    }

    #[test]
    fn command_meta_encodes_wire_fields() {
        let proto = meta("sbx_meta").into_proto();
        assert_eq!(proto.sandbox_id, "sbx_meta");
        assert_eq!(proto.assignment_fencing_token, "1.1");
        assert_eq!(proto.policy_epoch, 1);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert!(
            proto.deadline_unix_ms >= now_ms,
            "deadline must be absolute unix ms in the future"
        );
    }

    #[test]
    fn host_resource_parts_encodes_all_fields() {
        let proto = HostResourceParts {
            vcpus: 2,
            memory_mb: 512,
            idle_timeout_secs: Some(60),
            image_id: Some("img-1".into()),
            image_digest: Some("sha256:abc".into()),
            ssh_public_key: Some("ssh-ed25519 AAA".into()),
            ssh_key_type: Some("ed25519".into()),
            requested_ports: vec![22, 8080],
            cross_tenant_host: true,
            tenant_id: Some("tenant-1".into()),
        }
        .into_proto();
        assert_eq!(proto.vcpus, 2);
        assert_eq!(proto.memory_mb, 512);
        assert_eq!(proto.idle_timeout_secs, Some(60));
        assert_eq!(proto.image_id.as_deref(), Some("img-1"));
        assert_eq!(proto.image_digest.as_deref(), Some("sha256:abc"));
        assert_eq!(proto.ssh_public_key.as_deref(), Some("ssh-ed25519 AAA"));
        assert_eq!(proto.ssh_key_type.as_deref(), Some("ed25519"));
        assert_eq!(proto.requested_ports, vec![22, 8080]);
        assert!(proto.cross_tenant_host);
        assert_eq!(proto.tenant_id.as_deref(), Some("tenant-1"));
    }

    #[test]
    fn sandbox_config_maps_wire_fields() {
        let proto = sandbox_config_to_proto(&SandboxConfig {
            id: "sbx_cfg".into(),
            cpu_shares: 256,
            memory_limit_bytes: 1 << 30,
            memory_soft_limit_bytes: Some(512 << 20),
            max_pids: Some(64),
            network_isolated: true,
            ssh_port: Some(22),
            cpu_set: Some(vec![0, 1]),
            ..SandboxConfig::default()
        });
        assert_eq!(proto.id, "sbx_cfg");
        assert_eq!(proto.cpu_shares, 256);
        assert_eq!(proto.memory_limit_bytes, 1 << 30);
        assert_eq!(proto.memory_soft_limit_bytes, Some(512 << 20));
        assert_eq!(proto.max_pids, Some(64));
        assert!(proto.network_isolated);
        assert_eq!(proto.ssh_port, Some(22));
        assert_eq!(proto.cpu_set, vec![0, 1]);
    }

    #[test]
    fn sandbox_config_maps_service_class_both_ways() {
        use pico_core::ServiceClass;
        for (core, expected) in [
            (
                ServiceClass::LatencySensitive,
                v1::ServiceClass::LatencySensitive as i32,
            ),
            (
                ServiceClass::BestEffort,
                v1::ServiceClass::BestEffort as i32,
            ),
        ] {
            let proto = sandbox_config_to_proto(&SandboxConfig {
                id: "sbx_class".into(),
                service_class: core,
                ..SandboxConfig::default()
            });
            assert_eq!(proto.service_class, expected, "class {core:?}");
        }
        // Default config (LS) maps explicitly, never UNSPECIFIED, so the
        // wire always names the enforced class.
        let default_proto = sandbox_config_to_proto(&SandboxConfig::default());
        assert_eq!(
            default_proto.service_class,
            v1::ServiceClass::LatencySensitive as i32
        );
    }

    #[test]
    fn deadline_unix_ms_is_absolute_and_positive() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let deadline = deadline_unix_ms(Duration::from_secs(120));
        assert!(deadline >= now_ms);
        assert!(deadline - now_ms >= 119_000);
    }

    #[test]
    fn outcome_from_proto_parses_state_and_reason() {
        let parsed = outcome_from_proto(outcome(ProtoStatus::Succeeded, ProtoState::Running));
        assert_eq!(parsed.status, ProtoStatus::Succeeded);
        assert_eq!(parsed.observed_state, Some(SandboxState::Running));
        assert!(parsed.succeeded());

        let empty_state = outcome_from_proto(v1::Outcome {
            observed_state: ProtoState::Unspecified as i32,
            ..outcome(ProtoStatus::Failed, ProtoState::Running)
        });
        assert_eq!(empty_state.observed_state, None);
        assert!(!empty_state.succeeded());
    }

    #[test]
    fn outcome_from_proto_parses_non_ready_reason() {
        let parsed = outcome_from_proto(v1::Outcome {
            non_ready_reason: ProtoNonReady::Cleanup as i32,
            ..outcome(ProtoStatus::Failed, ProtoState::Running)
        });
        assert_eq!(parsed.non_ready_reason, Some(NonReadyReason::Cleanup));

        let unknown = outcome_from_proto(v1::Outcome {
            non_ready_reason: 9999,
            ..outcome(ProtoStatus::Failed, ProtoState::Running)
        });
        assert_eq!(unknown.non_ready_reason, None);
    }

    #[test]
    fn outcome_from_proto_maps_unknown_enums_to_unspecified() {
        let parsed = outcome_from_proto(v1::Outcome {
            kind: 9999,
            status: 9999,
            reason_code: 9999,
            ..outcome(ProtoStatus::Failed, ProtoState::Running)
        });
        assert_eq!(parsed.kind, ProtoKind::Unspecified);
        assert_eq!(parsed.status, ProtoStatus::Unspecified);
        assert_eq!(parsed.reason_code, ProtoReason::Unspecified);
        assert!(!parsed.succeeded());
    }

    #[test]
    fn proto_state_to_core_maps_known_variants() {
        assert_eq!(
            proto_state_to_core(ProtoState::Running as i32),
            Some(SandboxState::Running)
        );
        assert_eq!(proto_state_to_core(ProtoState::Unspecified as i32), None);
        assert_eq!(proto_state_to_core(9999), None);
    }

    #[test]
    fn proto_non_ready_to_core_maps_known_variants() {
        assert_eq!(
            proto_non_ready_to_core(ProtoNonReady::Protocol as i32),
            Some(NonReadyReason::Protocol)
        );
        assert_eq!(
            proto_non_ready_to_core(ProtoNonReady::Unspecified as i32),
            None
        );
        assert_eq!(proto_non_ready_to_core(9999), None);
    }

    #[test]
    fn outcome_error_maps_cleanup_to_conflict() {
        fn base() -> RpcOutcome {
            RpcOutcome {
                operation_id: String::new(),
                sandbox_id: String::new(),
                kind: ProtoKind::Unspecified,
                status: ProtoStatus::Failed,
                reason_code: ProtoReason::Unspecified,
                non_ready_reason: Some(NonReadyReason::Cleanup),
                message: Some("partial cleanup".into()),
                observed_state: None,
                completed_at: String::new(),
            }
        }

        let cleanup = base();
        assert!(matches!(outcome_error(&cleanup), SandboxError::Conflict(_)));

        let protocol = RpcOutcome {
            non_ready_reason: Some(NonReadyReason::Protocol),
            ..cleanup.clone()
        };
        assert!(matches!(
            outcome_error(&protocol),
            SandboxError::NotReady(_)
        ));

        let silent = RpcOutcome {
            message: None,
            ..cleanup
        };
        let err = outcome_error(&silent);
        assert!(matches!(err, SandboxError::Conflict(_)));
    }

    #[test]
    fn outcome_error_maps_restore_rejected_to_unprocessable() {
        let rejected = RpcOutcome {
            operation_id: "opr_1".into(),
            sandbox_id: "sbx_1".into(),
            kind: ProtoKind::Restore,
            status: ProtoStatus::Failed,
            reason_code: ProtoReason::RestoreRejected,
            non_ready_reason: None,
            message: Some("backend incompatible".into()),
            observed_state: None,
            completed_at: String::new(),
        };
        match outcome_error(&rejected) {
            SandboxError::Unprocessable(message) => {
                assert_eq!(message, "backend incompatible");
            }
            other => panic!("expected Unprocessable, got {other:?}"),
        }
    }

    #[test]
    fn apply_observation_enforces_generation_guard() {
        let mut cache = ObservationSnapshot::default();
        let newer = SandboxObservation {
            sandbox_id: "sbx_obs".into(),
            observed_state: ProtoState::Running as i32,
            generation: 7,
            host_boot_id: "boot-7".into(),
            guest_boot_id: "guest-7".into(),
            backend: ProtoRuntime::Firecracker as i32,
            ports: Vec::new(),
            ssh: None,
            policy_epoch: 1,
            assignment_fencing_token: "1.1".into(),
            updated_at: "2026-01-01T00:00:01Z".into(),
        };
        apply_observation(&mut cache, &newer);
        assert_eq!(cache.generation, 7);
        assert_eq!(cache.observed_state, SandboxState::Running);
        assert_eq!(cache.backend, "firecracker");
        assert_eq!(cache.host_boot_id, "boot-7");
        assert_eq!(cache.guest_boot_id, "guest-7");

        // A stale observation must not regress any cached field.
        let stale = SandboxObservation {
            generation: 3,
            observed_state: ProtoState::Stopped as i32,
            backend: ProtoRuntime::Qemu as i32,
            ..newer.clone()
        };
        apply_observation(&mut cache, &stale);
        assert_eq!(cache.generation, 7);
        assert_eq!(cache.observed_state, SandboxState::Running);
        assert_eq!(cache.backend, "firecracker");

        // sandboxd restart resets in-memory generation; a new host_boot_id
        // must replace the cache even when generation is lower.
        let restarted = SandboxObservation {
            generation: 1,
            host_boot_id: "boot-new".into(),
            observed_state: ProtoState::Pending as i32,
            backend: ProtoRuntime::Firecracker as i32,
            ..newer
        };
        apply_observation(&mut cache, &restarted);
        assert_eq!(cache.generation, 1);
        assert_eq!(cache.host_boot_id, "boot-new");
        assert_eq!(cache.observed_state, SandboxState::Pending);
    }

    #[test]
    fn apply_observation_carries_ssh_fields() {
        let mut cache = ObservationSnapshot::default();
        assert_eq!(cache.ssh_host_port, None);
        let observation = SandboxObservation {
            sandbox_id: "sbx_ssh".into(),
            observed_state: ProtoState::Running as i32,
            generation: 1,
            host_boot_id: String::new(),
            guest_boot_id: String::new(),
            backend: ProtoRuntime::Firecracker as i32,
            ports: Vec::new(),
            ssh: Some(pico_sandboxd_proto::v1::SshObservation {
                host_port: Some(22022),
                username: "root".into(),
                public_key: None,
            }),
            policy_epoch: 1,
            assignment_fencing_token: "1.1".into(),
            updated_at: "2026-01-01T00:00:02Z".into(),
        };
        apply_observation(&mut cache, &observation);
        assert_eq!(cache.ssh_host_port, Some(22022));
        assert_eq!(cache.ssh_username, "root");

        // Empty username keeps the prior default instead of clearing it.
        let anonymous = SandboxObservation {
            generation: 2,
            ssh: Some(pico_sandboxd_proto::v1::SshObservation {
                host_port: Some(22023),
                username: String::new(),
                public_key: None,
            }),
            ..observation
        };
        apply_observation(&mut cache, &anonymous);
        assert_eq!(cache.ssh_host_port, Some(22023));
        assert_eq!(cache.ssh_username, "root");
    }

    #[test]
    fn append_bounded_truncates_at_cap() {
        let mut out = Vec::new();
        let chunk = vec![0xABu8; 1024];
        for _ in 0..4096 {
            assert!(!append_bounded(&mut out, &chunk));
        }
        assert_eq!(out.len(), EXEC_OUTPUT_CAP_BYTES);
        assert!(
            append_bounded(&mut out, &chunk),
            "overflow must be reported"
        );
        assert_eq!(
            out.len(),
            EXEC_OUTPUT_CAP_BYTES,
            "buffer never exceeds the cap"
        );
    }

    #[test]
    fn append_bounded_reports_partial_overflow() {
        let mut out = Vec::new();
        let cap_minus_one = EXEC_OUTPUT_CAP_BYTES - 1;
        out.extend(std::iter::repeat_n(0u8, cap_minus_one));
        // A chunk that crosses the cap is clipped and reported.
        assert!(append_bounded(&mut out, &[1u8; 8]));
        assert_eq!(out.len(), EXEC_OUTPUT_CAP_BYTES);
        // An exact-fit chunk is not reported.
        let mut exact = Vec::new();
        assert!(!append_bounded(&mut exact, &[0u8; EXEC_OUTPUT_CAP_BYTES]));
        assert_eq!(exact.len(), EXEC_OUTPUT_CAP_BYTES);
        // A full buffer reports any further append, even an empty one.
        assert!(append_bounded(&mut exact, &[]));
    }

    #[test]
    fn status_to_error_maps_all_wire_codes() {
        use tonic::Code;
        for code in [
            Code::NotFound,
            Code::AlreadyExists,
            Code::FailedPrecondition,
            Code::InvalidArgument,
            Code::DeadlineExceeded,
            Code::Unavailable,
            Code::Unauthenticated,
            Code::PermissionDenied,
            Code::ResourceExhausted,
            Code::Internal,
        ] {
            let err = status_to_error(Status::new(code, "wire detail"));
            let matches = match code {
                Code::NotFound => matches!(err, SandboxError::SandboxNotFound(_)),
                Code::AlreadyExists => matches!(err, SandboxError::Conflict(_)),
                Code::FailedPrecondition => matches!(err, SandboxError::OperationStale(_)),
                Code::InvalidArgument => matches!(err, SandboxError::BadRequest(_)),
                Code::DeadlineExceeded | Code::Unavailable => {
                    matches!(err, SandboxError::NotReady(_))
                }
                Code::Unauthenticated | Code::PermissionDenied => {
                    matches!(err, SandboxError::Unauthorized)
                }
                Code::ResourceExhausted => {
                    matches!(err, SandboxError::ResourceExhausted { .. })
                }
                _ => matches!(err, SandboxError::Other(_)),
            };
            assert!(matches, "code {code:?} mapped to an unexpected error");
        }
    }

    #[test]
    fn status_to_error_preserves_not_found_detail() {
        let err = status_to_error(Status::not_found(
            "sandbox sbx_x has no attached runtime handle",
        ));
        match err {
            SandboxError::SandboxNotFound(message) => {
                assert_eq!(message, "sandbox sbx_x has no attached runtime handle");
            }
            other => panic!("expected SandboxNotFound, got {other:?}"),
        }
    }

    #[test]
    fn status_to_error_preserves_resource_detail_without_quota_numbers() {
        let err = status_to_error(Status::resource_exhausted("exec output exceeds max_bytes"));
        match err {
            SandboxError::ResourceExhausted { detail } => {
                assert_eq!(detail, "sandboxd: exec output exceeds max_bytes");
            }
            other => panic!("expected ResourceExhausted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_port_target_returns_tcp_addr_and_generation() {
        use pico_sandboxd_proto::v1::port_target;

        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let config = SandboxConfig {
            id: "sbx_port".into(),
            ..SandboxConfig::default()
        };
        let host = HostResourceParts {
            requested_ports: vec![8080],
            ..HostResourceParts::default()
        };
        assert!(
            handle
                .prepare(meta("sbx_port"), &config, RuntimeType::Firecracker, host)
                .await
                .unwrap()
                .succeeded()
        );
        assert!(handle.boot(meta("sbx_port")).await.unwrap().succeeded());

        let response = handle.get_port_target("sbx_port", 8080).await.unwrap();
        assert!(response.generation >= 1);
        match response.target.unwrap().target {
            Some(port_target::Target::TcpAddr(addr)) => {
                assert_eq!(addr, "127.0.0.1:8080");
            }
            other => panic!("expected tcp_addr target, got {other:?}"),
        }

        let observation = handle.get_sandbox("sbx_port").await.unwrap();
        assert_eq!(observation.generation, response.generation);
        assert_eq!(observation.ports.len(), 1);
        assert_eq!(observation.ports[0].guest_port, 8080);
    }

    #[tokio::test]
    async fn get_port_target_fail_closed_after_destroy() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let config = SandboxConfig {
            id: "sbx_port_gone".into(),
            ..SandboxConfig::default()
        };
        let host = HostResourceParts {
            requested_ports: vec![22],
            ..HostResourceParts::default()
        };
        assert!(
            handle
                .prepare(
                    meta("sbx_port_gone"),
                    &config,
                    RuntimeType::Firecracker,
                    host
                )
                .await
                .unwrap()
                .succeeded()
        );
        assert!(
            handle
                .boot(meta("sbx_port_gone"))
                .await
                .unwrap()
                .succeeded()
        );
        assert!(
            handle
                .get_port_target("sbx_port_gone", 22)
                .await
                .unwrap()
                .target
                .is_some()
        );
        assert!(
            handle
                .destroy(meta("sbx_port_gone"))
                .await
                .unwrap()
                .succeeded()
        );

        let err = handle
            .get_port_target("sbx_port_gone", 22)
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::SandboxNotFound(_)));
    }

    #[tokio::test]
    async fn resume_bumps_observation_generation() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let config = SandboxConfig {
            id: "sbx_resume_gen".into(),
            ..SandboxConfig::default()
        };
        let host = HostResourceParts {
            requested_ports: vec![8080],
            ..HostResourceParts::default()
        };
        assert!(
            handle
                .prepare(
                    meta("sbx_resume_gen"),
                    &config,
                    RuntimeType::Firecracker,
                    host
                )
                .await
                .unwrap()
                .succeeded()
        );
        assert!(
            handle
                .boot(meta("sbx_resume_gen"))
                .await
                .unwrap()
                .succeeded()
        );
        let before = handle.get_sandbox("sbx_resume_gen").await.unwrap();
        assert!(
            handle
                .suspend(meta("sbx_resume_gen"))
                .await
                .unwrap()
                .succeeded()
        );
        assert!(
            handle
                .resume(meta("sbx_resume_gen"))
                .await
                .unwrap()
                .succeeded()
        );
        let after = handle.get_sandbox("sbx_resume_gen").await.unwrap();
        assert!(
            after.generation > before.generation,
            "resume must bump generation (before={}, after={})",
            before.generation,
            after.generation
        );
    }

    #[tokio::test]
    async fn watch_streams_upsert_and_reconcile() {
        use pico_sandboxd_proto::v1::watch_event;
        use tokio::time::timeout;

        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let config = SandboxConfig {
            id: "sbx_watch".into(),
            ..SandboxConfig::default()
        };
        assert!(
            handle
                .prepare(
                    meta("sbx_watch"),
                    &config,
                    RuntimeType::Firecracker,
                    HostResourceParts {
                        requested_ports: vec![80],
                        ..HostResourceParts::default()
                    }
                )
                .await
                .unwrap()
                .succeeded()
        );

        let mut stream = handle.watch(std::iter::empty::<String>()).await.unwrap();
        let first = timeout(Duration::from_secs(2), stream.message())
            .await
            .expect("watch timed out")
            .unwrap()
            .expect("watch closed");
        match first.body {
            Some(watch_event::Body::Upsert(obs)) => {
                assert_eq!(obs.sandbox_id, "sbx_watch");
                assert!(obs.generation >= 1);
            }
            other => panic!("expected initial upsert, got {other:?}"),
        }
        let second = timeout(Duration::from_secs(2), stream.message())
            .await
            .expect("reconcile timed out")
            .unwrap()
            .expect("watch closed");
        assert!(matches!(second.body, Some(watch_event::Body::Reconcile(_))));
    }

    #[tokio::test]
    async fn list_sandboxes_includes_ports_and_generation() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let config = SandboxConfig {
            id: "sbx_list_ports".into(),
            ..SandboxConfig::default()
        };
        assert!(
            handle
                .prepare(
                    meta("sbx_list_ports"),
                    &config,
                    RuntimeType::Firecracker,
                    HostResourceParts {
                        requested_ports: vec![22, 8080],
                        ..HostResourceParts::default()
                    }
                )
                .await
                .unwrap()
                .succeeded()
        );

        let listed = handle.list_sandboxes().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sandbox_id, "sbx_list_ports");
        assert!(listed[0].generation >= 1);
        assert_eq!(listed[0].ports.len(), 2);
        assert_eq!(listed[0].ports[0].guest_port, 22);
        assert_eq!(listed[0].ports[1].guest_port, 8080);
    }

    #[tokio::test]
    async fn get_port_target_unrequested_port_is_not_found() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let config = SandboxConfig {
            id: "sbx_port_filter".into(),
            ..SandboxConfig::default()
        };
        assert!(
            handle
                .prepare(
                    meta("sbx_port_filter"),
                    &config,
                    RuntimeType::Firecracker,
                    HostResourceParts {
                        requested_ports: vec![8080],
                        ..HostResourceParts::default()
                    }
                )
                .await
                .unwrap()
                .succeeded()
        );

        let err = handle
            .get_port_target("sbx_port_filter", 9)
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::SandboxNotFound(_)));
    }

    #[tokio::test]
    async fn watch_filters_by_sandbox_id_and_emits_removed() {
        use pico_sandboxd_proto::v1::watch_event;
        use tokio::time::timeout;

        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        for id in ["sbx_keep", "sbx_other"] {
            let config = SandboxConfig {
                id: id.into(),
                ..SandboxConfig::default()
            };
            assert!(
                handle
                    .prepare(
                        meta(id),
                        &config,
                        RuntimeType::Firecracker,
                        HostResourceParts::default()
                    )
                    .await
                    .unwrap()
                    .succeeded()
            );
        }

        let mut stream = handle.watch(["sbx_keep"]).await.unwrap();
        let first = timeout(Duration::from_secs(2), stream.message())
            .await
            .expect("watch timed out")
            .unwrap()
            .expect("watch closed");
        match first.body {
            Some(watch_event::Body::Upsert(obs)) => {
                assert_eq!(obs.sandbox_id, "sbx_keep");
            }
            other => panic!("expected filtered upsert, got {other:?}"),
        }
        let second = timeout(Duration::from_secs(2), stream.message())
            .await
            .expect("reconcile timed out")
            .unwrap()
            .expect("watch closed");
        assert!(matches!(second.body, Some(watch_event::Body::Reconcile(_))));

        assert!(handle.destroy(meta("sbx_keep")).await.unwrap().succeeded());
        let removed = timeout(Duration::from_secs(2), async {
            loop {
                let event = stream.message().await.unwrap().expect("watch closed");
                if matches!(
                    event.body,
                    Some(watch_event::Body::RemovedSandboxId(ref id)) if id == "sbx_keep"
                ) {
                    return event;
                }
            }
        })
        .await
        .expect("removed timed out");
        assert!(matches!(
            removed.body,
            Some(watch_event::Body::RemovedSandboxId(id)) if id == "sbx_keep"
        ));
    }

    fn restore_parts(snapshot_id: &str) -> RestoreParts {
        RestoreParts {
            snapshot_id: snapshot_id.into(),
            request_tenant_id: "tnt_test".into(),
            requires_memory: false,
            runtime: RuntimeType::Firecracker,
            host: v1::HostShape {
                backend_type: "firecracker".into(),
                backend_version: "1.10.0".into(),
                protocol_version: "2.0".into(),
                cpu_arch: "x86_64".into(),
                memory_mb: 4096,
                vcpus: 4,
                machine_type: "q35".into(),
                disk_mb: 0,
            },
        }
    }

    fn fork_parts(parent: &str, child: &str) -> ForkParts {
        ForkParts {
            parent_snapshot_id: parent.into(),
            request_tenant_id: "tnt_test".into(),
            child_sandbox_id: child.into(),
            requires_memory: false,
            runtime: RuntimeType::Firecracker,
            host: v1::HostShape {
                backend_type: "firecracker".into(),
                backend_version: "1.10.0".into(),
                protocol_version: "2.0".into(),
                cpu_arch: "x86_64".into(),
                memory_mb: 4096,
                vcpus: 4,
                machine_type: "q35".into(),
                disk_mb: 0,
            },
        }
    }

    #[tokio::test]
    async fn restore_valid_request_fails_closed_without_stores() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let err = handle
            .restore(meta("sbx_restore"), restore_parts("snp_1"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::OperationStale(_)),
            "valid restore without configured stores must fail closed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn restore_empty_snapshot_is_bad_request() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let err = handle
            .restore(meta("sbx_restore"), restore_parts(""))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::BadRequest(_)),
            "empty snapshot_id must be BadRequest, got {err:?}"
        );
    }

    #[tokio::test]
    async fn fork_valid_request_fails_closed_without_stores() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let err = handle
            .fork(meta("sbx_fork"), fork_parts("snp_parent", "sbx_child"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::OperationStale(_)),
            "valid fork without configured stores must fail closed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn fork_empty_child_is_bad_request() {
        let dir = TempDir::new().unwrap();
        let (socket, _server, _shutdown) = spawn_server(&dir).await;
        let handle = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let err = handle
            .fork(meta("sbx_fork"), fork_parts("snp_parent", ""))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::BadRequest(_)),
            "empty child_sandbox_id must be BadRequest, got {err:?}"
        );
    }
}
