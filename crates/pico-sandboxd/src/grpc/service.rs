//! `Sandboxd` gRPC service backed by [`SandboxSupervisor`].

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use pico_core::{OperationId, SandboxId};
use pico_sandboxd_proto::SupervisorErrorClass;
use pico_sandboxd_proto::v1::{self, sandboxd_server::Sandboxd};
use pico_sandboxd_proto::v1::{
    BootRequest, CancelRequest, CommandMeta, DestroyRequest, ExecEvent, ExecExited, ExecFailed,
    ExecRequest, ExecStarted, ExecStderr, ExecStdout, FileEntry, FileListRequest, FileListResponse,
    FileReadRequest, FileReadResponse, FileWriteRequest, FileWriteResponse, ForkRequest,
    GetPortTargetRequest, GetPortTargetResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    InjectSecretsRequest, ListSandboxesRequest, ListSandboxesResponse, Outcome, PrepareRequest,
    RestoreRequest, ResumeRequest, SandboxObservation, SuspendRequest, WatchEvent, WatchRequest,
    exec_event,
};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::convert::{
    cancel_outcome, command_context, fork_params, health_to_proto, host_resource_spec,
    outcome_to_proto, port_target_to_proto, restore_params, runtime_type, sandbox_config,
    snapshot_to_observation, supervisor_error_to_status, watch_event_to_proto,
};
use crate::ObservationWatchEvent;
use crate::guest::ExecStreamEvent;
use crate::registry::AdapterRegistry;
use crate::{CommandContext, OperationOutcome, SandboxSupervisor};

/// gRPC service implementation for Interface 1 lifecycle RPCs.
#[derive(Clone)]
pub struct SandboxdService {
    pub(crate) supervisor: SandboxSupervisor,
    registry: AdapterRegistry,
}

impl SandboxdService {
    /// Creates a service over an opened supervisor and backend registry.
    #[must_use]
    pub fn new(supervisor: SandboxSupervisor, registry: AdapterRegistry) -> Self {
        Self {
            supervisor,
            registry,
        }
    }

    async fn respond_outcome(
        &self,
        outcome: OperationOutcome,
    ) -> Result<Response<Outcome>, Status> {
        let observed = self
            .supervisor
            .status(&outcome.sandbox_id)
            .await
            .map_err(supervisor_error_to_status)?
            .map(|status| status.observed_state);
        Ok(Response::new(outcome_to_proto(outcome, observed)))
    }

    async fn run_with_meta<F, Fut>(
        &self,
        meta: Option<CommandMeta>,
        missing: &'static str,
        op: F,
    ) -> Result<Response<Outcome>, Status>
    where
        F: FnOnce(CommandContext) -> Fut,
        Fut: Future<Output = Result<OperationOutcome, crate::SupervisorError>>,
    {
        let meta = meta.ok_or_else(|| Status::invalid_argument(missing))?;
        let ctx = command_context(meta)?;
        match op(ctx).await {
            Ok(outcome) => self.respond_outcome(outcome).await,
            Err(err) => Err(supervisor_error_to_status(err)),
        }
    }
}

type ExecStream = Pin<Box<dyn Stream<Item = Result<ExecEvent, Status>> + Send + 'static>>;
type WatchStream = Pin<Box<dyn Stream<Item = Result<WatchEvent, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl Sandboxd for SandboxdService {
    async fn prepare(&self, request: Request<PrepareRequest>) -> Result<Response<Outcome>, Status> {
        let request = request.into_inner();
        let config = request
            .config
            .ok_or_else(|| Status::invalid_argument("prepare config is required"))?;
        let config = sandbox_config(config)?;
        let host = host_resource_spec(request.host)?;
        let runtime = runtime_type(request.runtime_type)?;
        let backend = self
            .registry
            .create(runtime)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let supervisor = self.supervisor.clone();
        self.run_with_meta(
            request.meta,
            "prepare meta is required",
            move |ctx| async move { supervisor.prepare(ctx, backend, &config, &host).await },
        )
        .await
    }

    async fn boot(&self, request: Request<BootRequest>) -> Result<Response<Outcome>, Status> {
        let supervisor = self.supervisor.clone();
        self.run_with_meta(
            request.into_inner().meta,
            "boot meta is required",
            move |ctx| async move { supervisor.boot(ctx).await },
        )
        .await
    }

    type ExecStream = ExecStream;

    async fn exec(
        &self,
        request: Request<ExecRequest>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let request = request.into_inner();
        let meta = request
            .meta
            .ok_or_else(|| Status::invalid_argument("exec meta is required"))?;
        let operation_id = meta.operation_id.clone();
        let ctx = command_context(meta)?;
        let timeout = request
            .timeout_ms
            .map(|ms| Duration::from_millis(u64::try_from(ms.max(0)).unwrap_or(0)));
        let env = request.env.into_iter().collect();
        let rx = self
            .supervisor
            .exec_guest_stream(
                ctx,
                request.command,
                request.args,
                env,
                request.working_dir,
                timeout,
            )
            .await
            .map_err(supervisor_error_to_status)?;

        let (tx, out_rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(item) = rx.recv().await {
                let event = match item {
                    Ok(ExecStreamEvent::Started) => ExecEvent {
                        body: Some(exec_event::Body::Started(ExecStarted {
                            guest_operation_id: operation_id.clone(),
                        })),
                    },
                    Ok(ExecStreamEvent::Stdout(data)) => ExecEvent {
                        body: Some(exec_event::Body::Stdout(ExecStdout { data })),
                    },
                    Ok(ExecStreamEvent::Stderr(data)) => ExecEvent {
                        body: Some(exec_event::Body::Stderr(ExecStderr { data })),
                    },
                    Ok(ExecStreamEvent::Exited {
                        exit_code,
                        duration_ms: _,
                    }) => ExecEvent {
                        body: Some(exec_event::Body::Exited(ExecExited {
                            exit_code,
                            outcome: None,
                        })),
                    },
                    Ok(ExecStreamEvent::Failed { status }) => ExecEvent {
                        body: Some(exec_event::Body::Failed(ExecFailed {
                            outcome: Some(Outcome {
                                operation_id: operation_id.clone(),
                                message: Some(status),
                                ..Default::default()
                            }),
                        })),
                    },
                    Err(err) => {
                        let _ = tx.send(Err(Status::internal(err.to_string()))).await;
                        break;
                    }
                };
                if tx.send(Ok(event)).await.is_err() {
                    break;
                }
            }
        });

        let stream = ReceiverStream::new(out_rx);
        Ok(Response::new(Box::pin(stream) as Self::ExecStream))
    }

    async fn cancel(&self, request: Request<CancelRequest>) -> Result<Response<Outcome>, Status> {
        let request = request.into_inner();
        if request.operation_id.is_empty() {
            return Err(Status::invalid_argument("cancel operation_id is required"));
        }
        if request.operation_id.len() > 128 {
            return Err(Status::invalid_argument(
                "cancel operation_id exceeds maximum length",
            ));
        }
        let operation_id = OperationId::from_string(request.operation_id);
        let sandbox_id = if request.sandbox_id.is_empty() {
            SandboxId::from_string("unknown")
        } else {
            SandboxId::from_string(request.sandbox_id.clone())
        };
        if !self
            .supervisor
            .cancel_with_guest(&operation_id, &sandbox_id)
            .await
        {
            return Err(SupervisorErrorClass::NotFound
                .status(format!("no active operation {operation_id} to cancel")));
        }
        Ok(Response::new(cancel_outcome(
            operation_id.as_str(),
            sandbox_id.as_str(),
        )))
    }

    async fn suspend(&self, request: Request<SuspendRequest>) -> Result<Response<Outcome>, Status> {
        let supervisor = self.supervisor.clone();
        self.run_with_meta(
            request.into_inner().meta,
            "suspend meta is required",
            move |ctx| async move { supervisor.suspend(ctx).await },
        )
        .await
    }

    async fn resume(&self, request: Request<ResumeRequest>) -> Result<Response<Outcome>, Status> {
        let supervisor = self.supervisor.clone();
        self.run_with_meta(
            request.into_inner().meta,
            "resume meta is required",
            move |ctx| async move { supervisor.resume(ctx).await },
        )
        .await
    }

    async fn destroy(&self, request: Request<DestroyRequest>) -> Result<Response<Outcome>, Status> {
        let supervisor = self.supervisor.clone();
        self.run_with_meta(
            request.into_inner().meta,
            "destroy meta is required",
            move |ctx| async move { supervisor.destroy(ctx).await },
        )
        .await
    }

    async fn restore(&self, request: Request<RestoreRequest>) -> Result<Response<Outcome>, Status> {
        let request = request.into_inner();
        let meta = request
            .meta
            .clone()
            .ok_or_else(|| Status::invalid_argument("restore meta is required"))?;
        let params = restore_params(&request)?;
        let cmd = crate::RestoreCommand {
            snapshot_id: params.snapshot_id,
            request_tenant_id: params.request_tenant_id,
            requires_memory: params.requires_memory,
            runtime: params.runtime,
            host: params.host,
        };
        let supervisor = self.supervisor.clone();
        self.run_with_meta(
            Some(meta),
            "restore meta is required",
            move |ctx| async move { supervisor.restore(ctx, cmd).await },
        )
        .await
    }

    async fn fork(&self, request: Request<ForkRequest>) -> Result<Response<Outcome>, Status> {
        let request = request.into_inner();
        let meta = request
            .meta
            .clone()
            .ok_or_else(|| Status::invalid_argument("fork meta is required"))?;
        let params = fork_params(&request)?;
        let cmd = crate::ForkCommand {
            parent_snapshot_id: params.parent_snapshot_id,
            request_tenant_id: params.request_tenant_id,
            child_sandbox_id: params.child_sandbox_id,
            requires_memory: params.requires_memory,
            runtime: params.runtime,
            host: params.host,
        };
        let supervisor = self.supervisor.clone();
        self.run_with_meta(Some(meta), "fork meta is required", move |ctx| async move {
            supervisor.fork(ctx, cmd).await
        })
        .await
    }

    async fn file_read(
        &self,
        request: Request<FileReadRequest>,
    ) -> Result<Response<FileReadResponse>, Status> {
        let request = request.into_inner();
        let meta = request
            .meta
            .ok_or_else(|| Status::invalid_argument("file_read meta is required"))?;
        let ctx = command_context(meta)?;
        if request.path.is_empty() {
            return Err(Status::invalid_argument("file_read path is required"));
        }
        let result = self
            .supervisor
            .guest_file_read(
                &ctx.sandbox_id,
                &request.path,
                ctx.operation_id.as_str(),
                request.max_bytes,
            )
            .await
            .map_err(supervisor_error_to_status)?;
        Ok(Response::new(FileReadResponse {
            path: request.path,
            content: result.data,
            size_bytes: result.size,
        }))
    }

    async fn file_write(
        &self,
        request: Request<FileWriteRequest>,
    ) -> Result<Response<FileWriteResponse>, Status> {
        let request = request.into_inner();
        let meta = request
            .meta
            .ok_or_else(|| Status::invalid_argument("file_write meta is required"))?;
        let ctx = command_context(meta)?;
        if request.path.is_empty() {
            return Err(Status::invalid_argument("file_write path is required"));
        }
        let mode = request.mode.unwrap_or(0o644);
        let size = self
            .supervisor
            .guest_file_write(
                &ctx.sandbox_id,
                &request.path,
                &request.content,
                mode,
                ctx.operation_id.as_str(),
            )
            .await
            .map_err(supervisor_error_to_status)?;
        Ok(Response::new(FileWriteResponse {
            path: request.path,
            size_bytes: size,
        }))
    }

    async fn file_list(
        &self,
        request: Request<FileListRequest>,
    ) -> Result<Response<FileListResponse>, Status> {
        let request = request.into_inner();
        let meta = request
            .meta
            .ok_or_else(|| Status::invalid_argument("file_list meta is required"))?;
        let ctx = command_context(meta)?;
        if request.dir.is_empty() {
            return Err(Status::invalid_argument("file_list dir is required"));
        }
        let entries = self
            .supervisor
            .guest_file_list(
                &ctx.sandbox_id,
                &request.dir,
                request.recursive,
                ctx.operation_id.as_str(),
            )
            .await
            .map_err(supervisor_error_to_status)?;
        Ok(Response::new(FileListResponse {
            entries: entries
                .into_iter()
                .map(|(path, is_dir, size_bytes)| FileEntry {
                    path,
                    is_dir,
                    size_bytes,
                })
                .collect(),
        }))
    }

    async fn inject_secrets(
        &self,
        request: Request<InjectSecretsRequest>,
    ) -> Result<Response<Outcome>, Status> {
        let request = request.into_inner();
        let meta = request
            .meta
            .ok_or_else(|| Status::invalid_argument("inject_secrets meta is required"))?;
        let ctx = command_context(meta)?;
        let credentials = request
            .spec
            .ok_or_else(|| Status::invalid_argument("inject_secrets spec is required"))?;
        self.supervisor
            .inject_secrets(
                &ctx.sandbox_id,
                ctx.operation_id.as_str(),
                ctx.policy_epoch,
                &credentials,
            )
            .await
            .map_err(supervisor_error_to_status)?;
        // InjectSecrets is not a ledger lifecycle op; return a synthetic succeeded
        // outcome so the host client can share RpcOutcome parsing.
        Ok(Response::new(Outcome {
            operation_id: ctx.operation_id.to_string(),
            sandbox_id: ctx.sandbox_id.to_string(),
            kind: v1::OperationKind::InjectSecrets as i32,
            status: v1::OutcomeStatus::Succeeded as i32,
            reason_code: v1::OutcomeReason::Completed as i32,
            non_ready_reason: v1::NonReadyReason::Unspecified as i32,
            message: None,
            resources: Vec::new(),
            observed_state: v1::SandboxState::Running as i32,
            completed_at: pico_core::now_iso(),
        }))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxObservation>, Status> {
        let sandbox_id = request.into_inner().sandbox_id;
        if sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        if sandbox_id.len() > 128 {
            return Err(Status::invalid_argument(
                "sandbox_id exceeds maximum length",
            ));
        }
        let sandbox_id = SandboxId::from_string(sandbox_id);
        match self.supervisor.observation(&sandbox_id).await {
            Ok(Some(snapshot)) => Ok(Response::new(snapshot_to_observation(snapshot))),
            Ok(None) => {
                Err(SupervisorErrorClass::NotFound
                    .status(format!("sandbox {sandbox_id} not found")))
            }
            Err(err) => Err(supervisor_error_to_status(err)),
        }
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        match self.supervisor.observations().await {
            Ok(snapshots) => Ok(Response::new(ListSandboxesResponse {
                sandboxes: snapshots.into_iter().map(snapshot_to_observation).collect(),
            })),
            Err(err) => Err(supervisor_error_to_status(err)),
        }
    }

    async fn get_port_target(
        &self,
        request: Request<GetPortTargetRequest>,
    ) -> Result<Response<GetPortTargetResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        if request.sandbox_id.len() > 128 {
            return Err(Status::invalid_argument(
                "sandbox_id exceeds maximum length",
            ));
        }
        let guest_port = u16::try_from(request.guest_port).map_err(|_| {
            Status::invalid_argument(format!(
                "guest_port {} out of u16 range",
                request.guest_port
            ))
        })?;
        if guest_port == 0 {
            return Err(Status::invalid_argument("guest_port must be non-zero"));
        }
        let sandbox_id = SandboxId::from_string(request.sandbox_id);
        match self.supervisor.port_target(&sandbox_id, guest_port).await {
            Ok(Some((port, generation))) => Ok(Response::new(GetPortTargetResponse {
                target: Some(port_target_to_proto(port)),
                generation,
            })),
            Ok(None) => Err(SupervisorErrorClass::NotFound.status(format!(
                "port target for sandbox {sandbox_id} guest_port {guest_port} not found"
            ))),
            Err(err) => Err(supervisor_error_to_status(err)),
        }
    }

    type WatchStream = WatchStream;

    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let filter: std::collections::HashSet<String> = request
            .into_inner()
            .sandbox_ids
            .into_iter()
            .filter(|id| !id.is_empty())
            .collect();
        let filter = if filter.is_empty() {
            None
        } else {
            Some(filter)
        };

        let mut rx = self.supervisor.subscribe_watch();
        let snapshots = self
            .supervisor
            .observations()
            .await
            .map_err(supervisor_error_to_status)?;
        let health = self.supervisor.health().await;
        let host_boot_id = self.supervisor.host_boot_id().to_string();

        let (tx, out_rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            for snapshot in snapshots {
                if let Some(filter) = &filter
                    && !filter.contains(snapshot.status.sandbox_id.as_str())
                {
                    continue;
                }
                if tx
                    .send(Ok(watch_event_to_proto(ObservationWatchEvent::Upsert(
                        snapshot,
                    ))))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            if tx
                .send(Ok(watch_event_to_proto(ObservationWatchEvent::Reconcile {
                    complete: health.ready,
                    review_findings: health.review_required,
                    host_boot_id,
                })))
                .await
                .is_err()
            {
                return;
            }

            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if let Some(filter) = &filter {
                            match &event {
                                ObservationWatchEvent::Upsert(snapshot)
                                    if !filter.contains(snapshot.status.sandbox_id.as_str()) =>
                                {
                                    continue;
                                }
                                ObservationWatchEvent::Removed(id)
                                    if !filter.contains(id.as_str()) =>
                                {
                                    continue;
                                }
                                _ => {}
                            }
                        }
                        if tx.send(Ok(watch_event_to_proto(event))).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Dropped events: close so the host Lists immediately
                        // instead of waiting for the next periodic reconcile.
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(
            Box::pin(ReceiverStream::new(out_rx)) as Self::WatchStream
        ))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let health = self.supervisor.health().await;
        Ok(Response::new(health_to_proto(
            health,
            self.supervisor.host_boot_id(),
            &self.registry.supported_backends(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use pico_core::{
        FencingToken, OperationId, RuntimeBackend, RuntimeType, SandboxConfig, SandboxId,
    };
    use pico_runtime::mock::MockBackend;
    use pico_sandboxd_proto::v1::sandboxd_server::Sandboxd;
    use pico_sandboxd_proto::v1::{
        HostResourceSpec, PrepareRequest, WatchRequest, port_target, watch_event,
    };
    use tokio::time::timeout;
    use tokio_stream::StreamExt;

    use super::*;
    use crate::HostResourceSpec as SupervisorHostSpec;
    use crate::registry::AdapterRegistry;
    use crate::{CommandContext, OutcomeStatus};

    fn ctx(sandbox_id: &str, sequence: u64) -> CommandContext {
        CommandContext::with_timeout(
            SandboxId::from_string(sandbox_id),
            OperationId::generate(),
            FencingToken { epoch: 1, sequence },
            1,
            Duration::from_secs(5),
        )
    }

    fn empty_service() -> SandboxdService {
        SandboxdService::new(
            SandboxSupervisor::in_memory().with_guest_session(false),
            AdapterRegistry::new(),
        )
    }

    async fn prepare_sandbox(service: &SandboxdService, sandbox_id: &str, ports: Vec<u16>) {
        let runtime: Arc<dyn RuntimeBackend> = Arc::new(MockBackend::default());
        let config = SandboxConfig {
            id: sandbox_id.into(),
            ..SandboxConfig::default()
        };
        let host = SupervisorHostSpec {
            requested_ports: ports,
            ..SupervisorHostSpec::default()
        };
        let outcome = service
            .supervisor
            .prepare(ctx(sandbox_id, 1), runtime, &config, &host)
            .await
            .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Succeeded);
    }

    #[tokio::test]
    async fn get_port_target_returns_tcp_and_generation() {
        let service = empty_service();
        prepare_sandbox(&service, "sbx_svc_port", vec![8080]).await;

        let response = service
            .get_port_target(Request::new(GetPortTargetRequest {
                sandbox_id: "sbx_svc_port".into(),
                guest_port: 8080,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.generation >= 1);
        match response.target.unwrap().target {
            Some(port_target::Target::TcpAddr(addr)) => {
                assert_eq!(addr, "127.0.0.1:8080");
            }
            other => panic!("expected tcp addr, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_port_target_rejects_zero_and_missing_sandbox() {
        let service = empty_service();

        let zero = service
            .get_port_target(Request::new(GetPortTargetRequest {
                sandbox_id: "sbx_x".into(),
                guest_port: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(zero.code(), tonic::Code::InvalidArgument);

        let missing = service
            .get_port_target(Request::new(GetPortTargetRequest {
                sandbox_id: "sbx_missing".into(),
                guest_port: 22,
            }))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn get_sandbox_and_list_include_generation_and_ports() {
        let service = empty_service();
        prepare_sandbox(&service, "sbx_svc_list", vec![80, 443]).await;

        let got = service
            .get_sandbox(Request::new(GetSandboxRequest {
                sandbox_id: "sbx_svc_list".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.sandbox_id, "sbx_svc_list");
        assert!(got.generation >= 1);
        assert_eq!(got.ports.len(), 2);

        let listed = service
            .list_sandboxes(Request::new(ListSandboxesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.sandboxes.len(), 1);
        assert_eq!(listed.sandboxes[0].ports.len(), 2);
    }

    #[tokio::test]
    async fn watch_streams_snapshot_reconcile_and_removed() {
        let service = empty_service();
        prepare_sandbox(&service, "sbx_svc_watch", vec![22]).await;

        let mut stream = service
            .watch(Request::new(WatchRequest {
                sandbox_ids: vec!["sbx_svc_watch".into()],
            }))
            .await
            .unwrap()
            .into_inner();

        let first = timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("upsert timeout")
            .expect("stream ended")
            .unwrap();
        match first.body {
            Some(watch_event::Body::Upsert(obs)) => {
                assert_eq!(obs.sandbox_id, "sbx_svc_watch");
                assert_eq!(obs.ports.len(), 1);
            }
            other => panic!("expected upsert, got {other:?}"),
        }

        let second = timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("reconcile timeout")
            .expect("stream ended")
            .unwrap();
        assert!(matches!(second.body, Some(watch_event::Body::Reconcile(_))));

        let destroy = service
            .supervisor
            .destroy(ctx("sbx_svc_watch", 2))
            .await
            .unwrap();
        assert_eq!(destroy.status, OutcomeStatus::Succeeded);

        let removed = timeout(Duration::from_secs(2), async {
            loop {
                let event = stream.next().await.expect("stream ended").unwrap();
                if matches!(
                    event.body,
                    Some(watch_event::Body::RemovedSandboxId(ref id)) if id == "sbx_svc_watch"
                ) {
                    return event;
                }
            }
        })
        .await
        .expect("removed timeout");
        assert!(matches!(
            removed.body,
            Some(watch_event::Body::RemovedSandboxId(id)) if id == "sbx_svc_watch"
        ));
    }

    #[tokio::test]
    async fn prepare_rpc_accepts_requested_ports_via_host_spec() {
        let mut registry = AdapterRegistry::new();
        registry.register(
            RuntimeType::Firecracker,
            || Arc::new(MockBackend::default()),
        );
        let service = SandboxdService::new(
            SandboxSupervisor::in_memory().with_guest_session(false),
            registry,
        );

        let outcome = service
            .prepare(Request::new(PrepareRequest {
                meta: Some(CommandMeta {
                    sandbox_id: "sbx_svc_prepare".into(),
                    operation_id: OperationId::generate().to_string(),
                    assignment_fencing_token: "1.1".into(),
                    policy_epoch: 1,
                    deadline_unix_ms: i64::MAX / 2,
                }),
                config: Some(pico_sandboxd_proto::v1::SandboxConfig {
                    id: "sbx_svc_prepare".into(),
                    memory_limit_bytes: 64 * 1024 * 1024,
                    cpu_shares: 100,
                    memory_soft_limit_bytes: None,
                    max_pids: None,
                    network_isolated: true,
                    ssh_port: None,
                    cpu_set: Vec::new(),
                }),
                runtime_type: v1::RuntimeType::Firecracker as i32,
                host: Some(HostResourceSpec {
                    vcpus: 1,
                    memory_mb: 128,
                    requested_ports: vec![9090],
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(outcome.status, v1::OutcomeStatus::Succeeded as i32);

        let obs = service
            .get_sandbox(Request::new(GetSandboxRequest {
                sandbox_id: "sbx_svc_prepare".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(obs.ports.len(), 1);
        assert_eq!(obs.ports[0].guest_port, 9090);
    }

    fn restore_meta(sandbox_id: &str) -> CommandMeta {
        CommandMeta {
            sandbox_id: sandbox_id.into(),
            operation_id: OperationId::generate().to_string(),
            assignment_fencing_token: "1.1".into(),
            policy_epoch: 1,
            deadline_unix_ms: i64::MAX / 2,
        }
    }

    fn sample_host_shape() -> v1::HostShape {
        v1::HostShape {
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

    fn valid_restore_request(sandbox_id: &str) -> pico_sandboxd_proto::v1::RestoreRequest {
        pico_sandboxd_proto::v1::RestoreRequest {
            meta: Some(restore_meta(sandbox_id)),
            snapshot_id: "snp_1".into(),
            request_tenant_id: "tnt_test".into(),
            requires_memory: false,
            runtime_type: v1::RuntimeType::Firecracker as i32,
            host: Some(sample_host_shape()),
        }
    }

    fn valid_fork_request(sandbox_id: &str) -> pico_sandboxd_proto::v1::ForkRequest {
        pico_sandboxd_proto::v1::ForkRequest {
            meta: Some(restore_meta(sandbox_id)),
            parent_snapshot_id: "snp_parent".into(),
            request_tenant_id: "tnt_test".into(),
            child_sandbox_id: "sbx_child".into(),
            requires_memory: false,
            runtime_type: v1::RuntimeType::Firecracker as i32,
            host: Some(sample_host_shape()),
        }
    }

    #[tokio::test]
    async fn restore_valid_request_fails_closed_without_stores() {
        let service = empty_service();
        let err = service
            .restore(Request::new(valid_restore_request("sbx_restore")))
            .await
            .unwrap_err();
        // No snapshot stores installed: the supervisor fails closed with
        // FailedPrecondition instead of touching the ledger or runtime.
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn restore_rejects_missing_meta_and_empty_snapshot() {
        let service = empty_service();
        let mut req = valid_restore_request("sbx_restore");
        req.meta = None;
        let err = service.restore(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let mut req = valid_restore_request("sbx_restore");
        req.snapshot_id.clear();
        let err = service.restore(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let mut req = valid_restore_request("sbx_restore");
        req.request_tenant_id.clear();
        let err = service.restore(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn fork_valid_request_fails_closed_without_stores() {
        let service = empty_service();
        let err = service
            .fork(Request::new(valid_fork_request("sbx_fork")))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn fork_rejects_empty_child_and_parent() {
        let service = empty_service();
        let mut req = valid_fork_request("sbx_fork");
        req.child_sandbox_id.clear();
        let err = service.fork(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let mut req = valid_fork_request("sbx_fork");
        req.parent_snapshot_id.clear();
        let err = service.fork(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
