//! Host-side operational protocol client for the PicoCompute guest agent.

use pico_guest_protocol::operational_v1::*;
use pico_guest_protocol::{exec as guest_exec, framed};

use std::time::Instant;

use crate::handshake::perform_handshake_exchange;
pub use crate::handshake::{HandshakeConfig, HandshakeError, HandshakeOutcome};
use crate::metrics;

#[derive(Debug, Clone)]
pub struct ExecResult {
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: String,
}

#[derive(Debug, Clone)]
pub enum QuiesceStatus {
    Quiesced,
    TimedOut,
    Busy,
    Unsupported,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct QuiesceResult {
    pub quiesced: bool,
    pub duration_ms: u64,
    pub status: QuiesceStatus,
}

#[derive(Debug, Clone)]
pub enum ResumeNotifyStatus {
    Accepted,
    StalePolicyEpoch,
    SessionMismatch,
    ResourcesUnavailable,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ResumeNotifyResult {
    pub accepted: bool,
    pub duration_ms: u64,
    pub status: ResumeNotifyStatus,
}

#[derive(Debug, Clone)]
pub struct PutFileResult {
    pub bytes_written: u64,
    pub checksum: String,
}

#[derive(Debug, Clone)]
pub struct GetFileResult {
    pub data: Vec<u8>,
    pub size: u64,
    pub mode: u32,
    pub checksum: String,
}

#[derive(Debug, Clone)]
pub struct MountWorkspaceResult {
    pub mounted: bool,
}

#[derive(Debug, Clone)]
pub struct ShutdownResult {
    pub shutting_down: bool,
}

#[derive(Debug, Clone)]
pub struct InjectSecretsResult {
    pub injected: bool,
}

pub struct GuestConnection {
    conn: framed::FramedConnection,
    session_id: Vec<u8>,
    sandbox_id: String,
    policy_epoch: u64,
    protocol_version: (u32, u32),
    negotiated_capabilities: Vec<String>,
    guest_agent_version: String,
    guest_boot_id: String,
}

impl GuestConnection {
    pub async fn connect(config: &HandshakeConfig) -> std::result::Result<Self, HandshakeError> {
        let addr = config.transport_addr;
        let stream = tokio::time::timeout(config.timeout, tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| {
                HandshakeError::ConnectionRefused(format!(
                    "timeout connecting to guest agent at {addr}"
                ))
            })?
            .map_err(|err| {
                HandshakeError::ConnectionRefused(format!(
                    "failed to connect to guest agent at {addr}: {err}"
                ))
            })?;
        let mut conn = framed::FramedConnection::new(stream, config.timeout);
        let outcome = perform_handshake_exchange(&mut conn, config).await?;
        Ok(Self {
            conn,
            session_id: outcome.session_id.to_vec(),
            sandbox_id: config.sandbox_id.clone(),
            policy_epoch: config.policy_epoch,
            protocol_version: outcome.negotiated_version,
            negotiated_capabilities: outcome.negotiated_capabilities.clone(),
            guest_agent_version: outcome.guest_agent_version.clone(),
            guest_boot_id: outcome.guest_boot_id.clone(),
        })
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    pub fn capabilities(&self) -> &[String] {
        &self.negotiated_capabilities
    }

    pub fn guest_agent_version(&self) -> &str {
        &self.guest_agent_version
    }

    pub fn guest_boot_id(&self) -> &str {
        &self.guest_boot_id
    }

    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    #[cfg(test)]
    pub(crate) fn from_framed(
        conn: framed::FramedConnection,
        session_id: Vec<u8>,
        sandbox_id: String,
        policy_epoch: u64,
        protocol_version: (u32, u32),
    ) -> Self {
        Self {
            conn,
            session_id,
            sandbox_id,
            policy_epoch,
            protocol_version,
            negotiated_capabilities: Vec::new(),
            guest_agent_version: String::new(),
            guest_boot_id: String::new(),
        }
    }

    fn make_context(&self, operation_id: &str) -> RequestContext {
        let trace_context = build_trace_context();
        RequestContext {
            request_id: ulid::Ulid::generate().to_string(),
            operation_id: operation_id.into(),
            sandbox_id: self.sandbox_id.clone(),
            session_id: self.session_id.clone(),
            policy_epoch: self.policy_epoch,
            protocol_version: (self.protocol_version.0 << 16) | self.protocol_version.1,
            deadline: None,
            trace_context,
        }
    }

    pub async fn exec(
        &mut self,
        command: &str,
        args: &[String],
        env: &hashbrown::HashMap<String, String>,
        working_dir: &str,
        operation_id: &str,
        timeout: Option<std::time::Duration>,
    ) -> std::result::Result<ExecResult, ExecClientError> {
        use prost_types::Duration as ProtoDuration;

        let proto_timeout = timeout.map(|d| ProtoDuration {
            seconds: d.as_secs() as i64,
            nanos: d.subsec_nanos() as i32,
        });

        let context = self.make_context(operation_id);
        let request = ExecRequest {
            context: Some(context),
            command: command.into(),
            args: args.to_vec(),
            env: env.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            working_dir: working_dir.into(),
            timeout: proto_timeout,
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        };

        self.conn
            .send_tagged(framed::TAG_EXEC_REQUEST, &request)
            .await
            .map_err(|e| ExecClientError::Io(format!("failed to send exec request: {e}")))?;

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        loop {
            let (tag, response): (u8, ExecResponse) =
                self.conn.recv_tagged().await.map_err(|e| {
                    ExecClientError::Io(format!("failed to read exec response: {e}"))
                })?;

            if tag != framed::TAG_EXEC_RESPONSE {
                return Err(ExecClientError::Protocol(format!(
                    "unexpected response tag: {tag}"
                )));
            }

            let frame = response
                .frame
                .ok_or_else(|| ExecClientError::Protocol("empty exec response frame".into()))?;

            match frame {
                exec_response::Frame::Stdout(data) => {
                    if let Some(f) = data.frame
                        && !f.payload.is_empty()
                    {
                        stdout_buf.extend_from_slice(&f.payload);
                    }
                }
                exec_response::Frame::Stderr(data) => {
                    if let Some(f) = data.frame
                        && !f.payload.is_empty()
                    {
                        stderr_buf.extend_from_slice(&f.payload);
                    }
                }
                exec_response::Frame::Ack(_) => {}
                exec_response::Frame::Outcome(outcome) => {
                    let result = match outcome.status {
                        Some(operation_outcome::Status::Success(success)) => {
                            let (exit_code, duration_ms) =
                                guest_exec::parse_exec_exit(&success.result_payload);
                            ExecResult {
                                exit_code,
                                duration_ms,
                                stdout: stdout_buf,
                                stderr: stderr_buf,
                                status: "success".into(),
                            }
                        }
                        Some(operation_outcome::Status::Failure(failure)) => ExecResult {
                            exit_code: -1,
                            duration_ms: 0,
                            stdout: stdout_buf,
                            stderr: stderr_buf,
                            status: format!("failure: {}: {}", failure.code, failure.message),
                        },
                        Some(operation_outcome::Status::Canceled(canceled)) => ExecResult {
                            exit_code: -1,
                            duration_ms: 0,
                            stdout: stdout_buf,
                            stderr: stderr_buf,
                            status: format!("canceled: {}", canceled.reason),
                        },
                        Some(operation_outcome::Status::TimedOut(_)) => ExecResult {
                            exit_code: -1,
                            duration_ms: 0,
                            stdout: stdout_buf,
                            stderr: stderr_buf,
                            status: "timed out".into(),
                        },
                        _ => {
                            return Err(ExecClientError::Protocol(
                                "unknown operation outcome".into(),
                            ));
                        }
                    };
                    emit_exec_metrics(&result, None);
                    return Ok(result);
                }
            }
        }
    }

    pub async fn cancel(
        &mut self,
        operation_id: &str,
    ) -> std::result::Result<CancelResponse, ExecClientError> {
        let context = self.make_context(operation_id);
        let request = CancelRequest {
            context: Some(context),
            operation_id: operation_id.into(),
        };
        self.conn
            .send_tagged(framed::TAG_CANCEL_REQUEST, &request)
            .await
            .map_err(|e| ExecClientError::Io(format!("failed to send cancel: {e}")))?;
        let (tag, response): (u8, CancelResponse) = self
            .conn
            .recv_tagged()
            .await
            .map_err(|e| ExecClientError::Io(format!("failed to read cancel response: {e}")))?;
        if tag != framed::TAG_CANCEL_RESPONSE {
            return Err(ExecClientError::Protocol(format!(
                "unexpected response tag: {tag}"
            )));
        }
        Ok(response)
    }

    pub async fn signal(
        &mut self,
        operation_id: &str,
        signal: i32,
    ) -> std::result::Result<SignalResponse, ExecClientError> {
        let context = self.make_context(operation_id);
        let request = SignalRequest {
            context: Some(context),
            operation_id: operation_id.into(),
            signal,
        };
        self.conn
            .send_tagged(framed::TAG_SIGNAL_REQUEST, &request)
            .await
            .map_err(|e| ExecClientError::Io(format!("failed to send signal: {e}")))?;
        let (tag, response): (u8, SignalResponse) = self
            .conn
            .recv_tagged()
            .await
            .map_err(|e| ExecClientError::Io(format!("failed to read signal response: {e}")))?;
        if tag != framed::TAG_SIGNAL_RESPONSE {
            return Err(ExecClientError::Protocol(format!(
                "unexpected response tag: {tag}"
            )));
        }
        Ok(response)
    }

    /// Send a quiesce request to the guest agent.
    ///
    /// The `drain_mode` controls how active operations are handled:
    /// - `Graceful`: wait for active operations to complete within the deadline.
    /// - `Force`: terminate all active operations immediately.
    ///
    /// `deadline` is the absolute time by which quiesce must complete.
    /// The guest will block new exec requests and drain or cancel active
    /// operations accordingly.
    pub async fn quiesce(
        &mut self,
        drain_mode: i32,
        deadline: Option<std::time::SystemTime>,
        operation_id: &str,
    ) -> std::result::Result<QuiesceResponse, ExecClientError> {
        use prost_types::Timestamp;

        let context = self.make_context(operation_id);
        let quiesce_deadline = deadline.map(|ts| {
            let d = ts.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            Timestamp {
                seconds: d.as_secs() as i64,
                nanos: d.subsec_nanos() as i32,
            }
        });

        let request = QuiesceRequest {
            context: Some(context),
            drain_mode,
            quiesce_deadline,
        };

        self.conn
            .send_tagged(framed::TAG_QUIESCE_REQUEST, &request)
            .await
            .map_err(|e| ExecClientError::Io(format!("failed to send quiesce: {e}")))?;

        let (tag, response): (u8, QuiesceResponse) =
            self.conn.recv_tagged().await.map_err(|e| {
                ExecClientError::Io(format!("failed to read quiesce response: {e}"))
            })?;

        if tag != framed::TAG_QUIESCE_RESPONSE {
            return Err(ExecClientError::Protocol(format!(
                "unexpected response tag: {tag}"
            )));
        }

        Ok(response)
    }

    /// Notify the guest agent that it has been restored from a snapshot
    /// (or forked). The guest receives a fresh sandbox identity and
    /// policy epoch, refreshes non-restorable resources, and confirms
    /// readiness.
    ///
    /// `sandbox_id` is the new per-boot sandbox identity after restore.
    /// `policy_epoch` is the new policy epoch for the resumed sandbox.
    /// `lineage_id` tracks snapshot ancestry for lineage validation.
    /// `snapshot_taken_at` is the timestamp when the snapshot was taken.
    pub async fn resume_notify(
        &mut self,
        sandbox_id: &str,
        policy_epoch: u64,
        lineage_id: &str,
        snapshot_taken_at: Option<std::time::SystemTime>,
        operation_id: &str,
    ) -> std::result::Result<ResumeNotifyResponse, ExecClientError> {
        use prost_types::Timestamp;

        let context = self.make_context(operation_id);
        let snapshot_ts = snapshot_taken_at.map(|ts| {
            let d = ts.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            Timestamp {
                seconds: d.as_secs() as i64,
                nanos: d.subsec_nanos() as i32,
            }
        });

        let request = ResumeNotifyRequest {
            context: Some(context),
            sandbox_id: sandbox_id.into(),
            policy_epoch,
            lineage_id: lineage_id.into(),
            snapshot_taken_at: snapshot_ts,
        };

        self.conn
            .send_tagged(framed::TAG_RESUME_NOTIFY_REQUEST, &request)
            .await
            .map_err(|e| ExecClientError::Io(format!("failed to send resume notify: {e}")))?;

        let (tag, response): (u8, ResumeNotifyResponse) =
            self.conn.recv_tagged().await.map_err(|e| {
                ExecClientError::Io(format!("failed to read resume notify response: {e}"))
            })?;

        if tag != framed::TAG_RESUME_NOTIFY_RESPONSE {
            return Err(ExecClientError::Protocol(format!(
                "unexpected response tag: {tag}"
            )));
        }

        Ok(response)
    }

    pub async fn put_file(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
        overwrite: bool,
        operation_id: &str,
    ) -> std::result::Result<PutFileResponse, ExecClientError> {
        let context = self.make_context(operation_id);
        let metadata = put_file_request::Payload::Metadata(PutFileMetadata {
            context: Some(context),
            path: path.into(),
            mode,
            expected_size: data.len() as u64,
            overwrite,
        });

        let meta_req = PutFileRequest {
            payload: Some(metadata),
        };

        self.conn
            .send_tagged(framed::TAG_PUT_FILE_REQUEST, &meta_req)
            .await
            .map_err(|e| ExecClientError::Io(format!("send put file metadata: {e}")))?;

        const CHUNK_SIZE: usize = 64 * 1024;
        let chunks = data.chunks(CHUNK_SIZE);
        for (seq, chunk) in (1_u64..).zip(chunks) {
            let end_of_stream = seq as usize * CHUNK_SIZE >= data.len();
            let frame = StreamFrame {
                sequence: seq,
                payload: chunk.to_vec(),
                end_of_stream,
            };

            let chunk_req = PutFileRequest {
                payload: Some(put_file_request::Payload::Chunk(frame)),
            };

            self.conn
                .send_tagged(framed::TAG_PUT_FILE_REQUEST, &chunk_req)
                .await
                .map_err(|e| ExecClientError::Io(format!("send chunk: {e}")))?;

            if end_of_stream {
                break;
            }
        }

        let (tag, response): (u8, PutFileResponse) = self
            .conn
            .recv_tagged()
            .await
            .map_err(|e| ExecClientError::Io(format!("read put file response: {e}")))?;

        if tag != framed::TAG_PUT_FILE_RESPONSE {
            return Err(ExecClientError::Protocol(format!(
                "unexpected response tag: {tag}"
            )));
        }

        Ok(response)
    }

    pub async fn get_file(
        &mut self,
        path: &str,
        operation_id: &str,
    ) -> std::result::Result<GetFileResult, ExecClientError> {
        let context = self.make_context(operation_id);
        let request = GetFileRequest {
            context: Some(context),
            path: path.into(),
        };

        self.conn
            .send_tagged(framed::TAG_GET_FILE_REQUEST, &request)
            .await
            .map_err(|e| ExecClientError::Io(format!("send get file request: {e}")))?;

        let mut data = Vec::new();
        let mut file_size: u64 = 0;
        let mut file_mode: u32 = 0;
        let mut checksum = String::new();
        let deadline = Instant::now() + self.conn.timeout();

        loop {
            if Instant::now() > deadline {
                return Err(ExecClientError::Protocol("get file timed out".into()));
            }

            let (tag, response): (u8, GetFileResponse) = self
                .conn
                .recv_tagged()
                .await
                .map_err(|e| ExecClientError::Io(format!("read get file response: {e}")))?;

            if tag != framed::TAG_GET_FILE_RESPONSE {
                return Err(ExecClientError::Protocol(format!(
                    "unexpected response tag: {tag}"
                )));
            }

            match response.frame {
                Some(get_file_response::Frame::Metadata(m)) => {
                    file_size = m.size;
                    file_mode = m.mode;
                }
                Some(get_file_response::Frame::Chunk(f)) => {
                    data.extend_from_slice(&f.payload);
                }
                Some(get_file_response::Frame::Outcome(outcome)) => {
                    if let Some(operation_outcome::Status::Success(s)) = outcome.status {
                        checksum = String::from_utf8_lossy(&s.result_payload).to_string();
                    }
                    break;
                }
                None => {
                    return Err(ExecClientError::Protocol(
                        "empty get file response frame".into(),
                    ));
                }
            }
        }

        Ok(GetFileResult {
            data,
            size: file_size,
            mode: file_mode,
            checksum,
        })
    }

    pub async fn mount_workspace(
        &mut self,
        mount_point: &str,
        fs_type: &str,
        options: &hashbrown::HashMap<String, String>,
        operation_id: &str,
    ) -> std::result::Result<MountWorkspaceResponse, ExecClientError> {
        let context = self.make_context(operation_id);
        let request = MountWorkspaceRequest {
            context: Some(context),
            mount_point: mount_point.into(),
            fs_type: fs_type.into(),
            options: options
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };
        self.call_rpc(
            framed::TAG_MOUNT_WORKSPACE_REQUEST,
            framed::TAG_MOUNT_WORKSPACE_RESPONSE,
            &request,
            "mount workspace",
        )
        .await
    }

    pub async fn stats(
        &mut self,
        operation_id: &str,
    ) -> std::result::Result<StatsResponse, ExecClientError> {
        let context = self.make_context(operation_id);
        let request = StatsRequest {
            context: Some(context),
        };
        self.call_rpc(
            framed::TAG_STATS_REQUEST,
            framed::TAG_STATS_RESPONSE,
            &request,
            "stats",
        )
        .await
    }

    pub async fn health(
        &mut self,
        operation_id: &str,
    ) -> std::result::Result<HealthResponse, ExecClientError> {
        let context = self.make_context(operation_id);
        let request = HealthRequest {
            context: Some(context),
        };
        self.call_rpc(
            framed::TAG_HEALTH_REQUEST,
            framed::TAG_HEALTH_RESPONSE,
            &request,
            "health",
        )
        .await
    }

    pub async fn shutdown(
        &mut self,
        reason: &str,
        force: bool,
        operation_id: &str,
    ) -> std::result::Result<ShutdownResponse, ExecClientError> {
        let context = self.make_context(operation_id);
        let request = ShutdownRequest {
            context: Some(context),
            reason: reason.into(),
            force,
        };
        self.call_rpc(
            framed::TAG_SHUTDOWN_REQUEST,
            framed::TAG_SHUTDOWN_RESPONSE,
            &request,
            "shutdown",
        )
        .await
    }

    /// Inject secrets into the guest agent via the operational protocol.
    ///
    /// Credentials are written into a tmpfs-backed secrets directory that
    /// is excluded from snapshots. Each credential is a file with mode 0400.
    pub async fn inject_secrets(
        &mut self,
        lease_id: &str,
        policy_decision_id: &str,
        credentials: &[SecretCredential],
        operation_id: &str,
    ) -> std::result::Result<InjectSecretsResult, ExecClientError> {
        let request = InjectSecretsRequest {
            context: Some(self.make_context(operation_id)),
            lease_id: lease_id.into(),
            policy_decision_id: policy_decision_id.into(),
            credentials: credentials.to_vec(),
        };
        let response: InjectSecretsResponse = self
            .call_rpc(
                framed::TAG_INJECT_SECRETS_REQUEST,
                framed::TAG_INJECT_SECRETS_RESPONSE,
                &request,
                "inject secrets",
            )
            .await?;
        match response.result {
            Some(inject_secrets_response::Result::Injected(true)) => {
                Ok(InjectSecretsResult { injected: true })
            }
            _ => Err(ExecClientError::Io("inject secrets denied".into())),
        }
    }

    async fn call_rpc<Req, Resp>(
        &mut self,
        request_tag: u8,
        response_tag: u8,
        request: &Req,
        rpc_name: &str,
    ) -> std::result::Result<Resp, ExecClientError>
    where
        Req: prost::Message,
        Resp: prost::Message + Default,
    {
        self.conn
            .send_tagged(request_tag, request)
            .await
            .map_err(|e| ExecClientError::Io(format!("send {rpc_name} request: {e}")))?;
        let (tag, response): (u8, Resp) = self
            .conn
            .recv_tagged()
            .await
            .map_err(|e| ExecClientError::Io(format!("read {rpc_name} response: {e}")))?;
        if tag != response_tag {
            return Err(ExecClientError::Protocol(format!(
                "unexpected response tag: {tag} for {rpc_name}"
            )));
        }
        Ok(response)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ExecClientError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("handshake error: {0}")]
    Handshake(String),
}

impl From<HandshakeError> for ExecClientError {
    fn from(err: HandshakeError) -> Self {
        ExecClientError::Handshake(err.to_string())
    }
}

pub(crate) fn emit_exec_metrics(result: &ExecResult, tenant_id: Option<&str>) {
    let output_bytes = (result.stdout.len() + result.stderr.len()) as f64;

    let status = if result.status == "success" {
        metrics::val::EXEC_SUCCEEDED
    } else if result.status.contains("cancel") {
        metrics::val::EXEC_CANCELED
    } else if result.status.contains("timed out") {
        metrics::val::EXEC_TIMED_OUT
    } else {
        metrics::val::EXEC_FAILED
    };

    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.exec_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .exec_duration
        .record(result.duration_ms as f64 / 1000.0, &latency_attrs);

    metrics::HOST_METRICS
        .exec_output_bytes
        .record(output_bytes, &latency_attrs);
}

pub(crate) fn emit_exec_started(tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(metrics::val::EXEC_STARTED, tenant_id);
    metrics::HOST_METRICS.exec_events.inc(&attrs);
}

pub(crate) fn emit_exec_not_completed(tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(metrics::val::EXEC_NOT_COMPLETED, tenant_id);
    metrics::HOST_METRICS.exec_events.inc(&attrs);
}

#[expect(
    dead_code,
    reason = "used by host-agent lib.rs when calling quiesce RPC"
)]
pub(crate) fn emit_quiesce_started(tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(metrics::val::QUIESCE_STARTED, tenant_id);
    metrics::HOST_METRICS.quiesce_events.inc(&attrs);
}

#[expect(
    dead_code,
    reason = "lifecycle telemetry retained for resume/restore paths"
)]
pub(crate) fn emit_quiesce_result(result: &QuiesceResult, tenant_id: Option<&str>) {
    let status = match &result.status {
        QuiesceStatus::Quiesced => metrics::val::QUIESCE_READY,
        QuiesceStatus::TimedOut => metrics::val::QUIESCE_TIMED_OUT,
        QuiesceStatus::Busy => metrics::val::QUIESCE_BUSY,
        QuiesceStatus::Unsupported => metrics::val::QUIESCE_UNSUPPORTED,
        QuiesceStatus::Failed(_) => metrics::val::QUIESCE_FAILED,
    };

    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.quiesce_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .quiesce_duration
        .record(result.duration_ms as f64 / 1000.0, &latency_attrs);
}

#[expect(
    dead_code,
    reason = "used by host-agent lib.rs when calling resume_notify RPC"
)]
pub(crate) fn emit_resume_notify_started(tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(metrics::val::RESUME_NOTIFY_STARTED, tenant_id);
    metrics::HOST_METRICS.resume_notify_events.inc(&attrs);
}

#[expect(
    dead_code,
    reason = "lifecycle telemetry retained for resume/restore paths"
)]
pub(crate) fn emit_resume_notify_result(result: &ResumeNotifyResult, tenant_id: Option<&str>) {
    let status = match &result.status {
        ResumeNotifyStatus::Accepted => metrics::val::RESUME_NOTIFY_ACCEPTED,
        ResumeNotifyStatus::StalePolicyEpoch => metrics::val::RESUME_NOTIFY_STALE_EPOCH,
        ResumeNotifyStatus::SessionMismatch => metrics::val::RESUME_NOTIFY_SESSION_MISMATCH,
        ResumeNotifyStatus::ResourcesUnavailable => {
            metrics::val::RESUME_NOTIFY_RESOURCES_UNAVAILABLE
        }
        ResumeNotifyStatus::Failed(_) => metrics::val::RESUME_NOTIFY_FAILED,
    };

    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.resume_notify_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .resume_notify_duration
        .record(result.duration_ms as f64 / 1000.0, &latency_attrs);
}

pub(crate) fn emit_suspend_started(tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(metrics::val::SUSPEND_STARTED, tenant_id);
    metrics::HOST_METRICS.suspend_events.inc(&attrs);
}

pub(crate) fn emit_suspend_completed(latency_ms: u64, tenant_id: Option<&str>) {
    let status = metrics::val::SUSPEND_COMPLETED;
    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.suspend_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .suspend_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);
}

pub(crate) fn emit_suspend_failed(latency_ms: u64, tenant_id: Option<&str>) {
    let status = metrics::val::SUSPEND_FAILED;
    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.suspend_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .suspend_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);
}

pub(crate) fn emit_suspend_timed_out(latency_ms: u64, tenant_id: Option<&str>) {
    let status = metrics::val::SUSPEND_TIMED_OUT;
    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.suspend_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .suspend_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);
}

pub(crate) fn emit_resume_started(tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(metrics::val::RESUME_STARTED, tenant_id);
    metrics::HOST_METRICS.resume_events.inc(&attrs);
}

pub(crate) fn emit_resume_completed(latency_ms: u64, tenant_id: Option<&str>) {
    let status = metrics::val::RESUME_COMPLETED;
    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.resume_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .resume_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);
}

pub(crate) fn emit_resume_failed(latency_ms: u64, tenant_id: Option<&str>) {
    let status = metrics::val::RESUME_FAILED;
    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.resume_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .resume_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);
}

pub(crate) fn emit_resume_timed_out(latency_ms: u64, tenant_id: Option<&str>) {
    let status = metrics::val::RESUME_TIMED_OUT;
    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.resume_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .resume_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);
}

pub(crate) fn emit_restore_started(tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(metrics::val::RESTORE_STARTED, tenant_id);
    metrics::HOST_METRICS.restore_events.inc(&attrs);
}

pub(crate) fn emit_restore_completed(latency_ms: u64, tenant_id: Option<&str>) {
    let status = metrics::val::RESTORE_COMPLETED;
    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.restore_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .restore_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);
}

pub(crate) fn emit_restore_memory_restored(latency_ms: u64, tenant_id: Option<&str>) {
    let status = metrics::val::RESTORE_MEMORY_RESTORED;
    let event_attrs = crate::metrics::event_attrs(status, tenant_id);
    metrics::HOST_METRICS.restore_events.inc(&event_attrs);

    let latency_attrs = crate::metrics::latency_attrs(status, tenant_id);
    metrics::HOST_METRICS
        .restore_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);
}

pub(crate) fn emit_restore_failed(tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(metrics::val::RESTORE_FAILED, tenant_id);
    metrics::HOST_METRICS.restore_events.inc(&attrs);
}

pub(crate) fn emit_restore_partial_cleanup(tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(metrics::val::RESTORE_PARTIAL_CLEANUP, tenant_id);
    metrics::HOST_METRICS.restore_events.inc(&attrs);
}

/// Builds a [`TraceContext`] protobuf message from the current OpenTelemetry span.
fn build_trace_context() -> Option<TraceContext> {
    let trace_id = pico_telemetry::trace_context::current_trace_id_hex()?;
    let span_id = pico_telemetry::trace_context::current_span_id_hex()?;
    let trace_flags = pico_telemetry::trace_context::current_trace_flags()
        .map(|f| f.to_u8() as u32)
        .unwrap_or(0);

    let trace_state = pico_telemetry::trace_context::current_trace_state().unwrap_or_default();
    Some(TraceContext {
        trace_id,
        span_id,
        trace_flags,
        trace_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    use tokio::net::TcpListener;

    use pico_guest_protocol::framed;

    #[tokio::test]
    async fn exec_protocol_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read tagged exec request directly (no handshake preamble)
            let (tag, request) =
                framed::read_tagged::<ExecRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            assert_eq!(request.command, "echo");

            // Send stdout frame
            let stdout_resp = ExecResponse {
                frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                    frame: Some(StreamFrame {
                        sequence: 1,
                        payload: b"hello\n".to_vec(),
                        end_of_stream: false,
                    }),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_EXEC_RESPONSE,
                &stdout_resp,
                Duration::from_secs(5),
            )
            .await
            .unwrap();

            // Send terminal outcome
            let outcome = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: {
                                let mut p = Vec::new();
                                p.extend_from_slice(&0i32.to_be_bytes());
                                p.extend_from_slice(&42u64.to_be_bytes());
                                p
                            },
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_EXEC_RESPONSE,
                &outcome,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send tagged exec request
        let request = ExecRequest {
            context: Some(RequestContext {
                request_id: "test-req".into(),
                operation_id: "test-op".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            command: "echo".into(),
            args: vec![],
            env: HashMap::new(),
            working_dir: String::new(),
            timeout: None,
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_EXEC_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // Read response frames
        let mut stdout_buf = Vec::new();
        loop {
            let (tag, response) =
                framed::read_tagged::<ExecResponse>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

            match response.frame.unwrap() {
                exec_response::Frame::Stdout(data) => {
                    if let Some(f) = data.frame {
                        stdout_buf.extend_from_slice(&f.payload);
                    }
                }
                exec_response::Frame::Outcome(outcome) => {
                    assert!(matches!(
                        outcome.status,
                        Some(operation_outcome::Status::Success(_))
                    ));
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(stdout_buf, b"hello\n");

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn exec_cancel_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read exec request
            let (tag, _req) =
                framed::read_tagged::<ExecRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            // Read cancel request
            let (tag, cancel_req) =
                framed::read_tagged::<CancelRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_CANCEL_REQUEST);
            assert_eq!(cancel_req.operation_id, "test-op-cancel");

            // Send cancel response
            let cancel_resp = CancelResponse {
                result: Some(cancel_response::Result::Accepted(Ack {})),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_CANCEL_RESPONSE,
                &cancel_resp,
                Duration::from_secs(5),
            )
            .await
            .unwrap();

            // Send terminal outcome
            let outcome = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Canceled(
                        operation_outcome::Canceled {
                            reason: "cancelled by test".into(),
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_EXEC_RESPONSE,
                &outcome,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send exec request
        let req = ExecRequest {
            context: Some(RequestContext {
                request_id: "test-req".into(),
                operation_id: "test-op-cancel".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            command: "sleep".into(),
            args: vec!["30".into()],
            env: HashMap::new(),
            working_dir: String::new(),
            timeout: None,
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_EXEC_REQUEST,
            &req,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // Send cancel
        let cancel_req = CancelRequest {
            context: Some(RequestContext {
                request_id: "cancel-req".into(),
                operation_id: "test-op-cancel".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            operation_id: "test-op-cancel".into(),
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_CANCEL_REQUEST,
            &cancel_req,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // Read cancel response
        let (tag, resp) =
            framed::read_tagged::<CancelResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_CANCEL_RESPONSE);
        assert!(matches!(
            resp.result,
            Some(cancel_response::Result::Accepted(_))
        ));

        // Read terminal outcome
        let (tag, exec_resp) =
            framed::read_tagged::<ExecResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
        match exec_resp.frame.unwrap() {
            exec_response::Frame::Outcome(outcome) => {
                assert!(matches!(
                    outcome.status,
                    Some(operation_outcome::Status::Canceled(_))
                ));
            }
            _ => panic!("expected terminal outcome"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn quiesce_idle_guest_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, req) =
                framed::read_tagged::<QuiesceRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_QUIESCE_REQUEST);
            assert_eq!(req.drain_mode, quiesce_request::DrainMode::Graceful as i32);

            let response = QuiesceResponse {
                result: Some(quiesce_response::Result::Quiesced(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_QUIESCE_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = QuiesceRequest {
            context: Some(RequestContext {
                request_id: "quiesce-req".into(),
                operation_id: "quiesce-idle".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            drain_mode: quiesce_request::DrainMode::Graceful as i32,
            quiesce_deadline: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_QUIESCE_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<QuiesceResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_QUIESCE_RESPONSE);
        assert!(matches!(
            resp.result,
            Some(quiesce_response::Result::Quiesced(true))
        ));

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn quiesce_busy_guest_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, req) =
                framed::read_tagged::<ExecRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            assert_eq!(req.command, "sleep");

            let (tag, quiesce_req) =
                framed::read_tagged::<QuiesceRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_QUIESCE_REQUEST);
            assert_eq!(
                quiesce_req.drain_mode,
                quiesce_request::DrainMode::Force as i32
            );

            let cancel_resp = CancelResponse {
                result: Some(cancel_response::Result::Accepted(Ack {})),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_CANCEL_RESPONSE,
                &cancel_resp,
                Duration::from_secs(5),
            )
            .await
            .unwrap();

            let outcome = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Canceled(
                        operation_outcome::Canceled {
                            reason: "force cancelled for quiesce".into(),
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_EXEC_RESPONSE,
                &outcome,
                Duration::from_secs(5),
            )
            .await
            .unwrap();

            let response = QuiesceResponse {
                result: Some(quiesce_response::Result::Quiesced(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_QUIESCE_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let exec_req = ExecRequest {
            context: Some(RequestContext {
                request_id: "exec-req".into(),
                operation_id: "op-1".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            command: "sleep".into(),
            args: vec!["30".into()],
            env: HashMap::new(),
            working_dir: String::new(),
            timeout: None,
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_EXEC_REQUEST,
            &exec_req,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let quiesce_req = QuiesceRequest {
            context: Some(RequestContext {
                request_id: "quiesce-req".into(),
                operation_id: "quiesce-busy".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            drain_mode: quiesce_request::DrainMode::Force as i32,
            quiesce_deadline: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_QUIESCE_REQUEST,
            &quiesce_req,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, _cancel_resp) =
            framed::read_tagged::<CancelResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_CANCEL_RESPONSE);

        // Read the cancelled exec outcome (sent by the exec handler)
        let (tag, _exec_outcome) =
            framed::read_tagged::<ExecResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

        let (tag, quiesce_resp) =
            framed::read_tagged::<QuiesceResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_QUIESCE_RESPONSE);
        assert!(matches!(
            quiesce_resp.result,
            Some(quiesce_response::Result::Quiesced(true))
        ));

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn quiesce_timeout_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ExecRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let (tag, _req) =
                framed::read_tagged::<QuiesceRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_QUIESCE_REQUEST);

            let response = QuiesceResponse {
                result: Some(quiesce_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::TimedOut(
                        operation_outcome::TimedOut {
                            budget_remaining: None,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_QUIESCE_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let exec_req = ExecRequest {
            context: Some(RequestContext {
                request_id: "exec-req".into(),
                operation_id: "op-1".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            command: "sleep".into(),
            args: vec!["300".into()],
            env: HashMap::new(),
            working_dir: String::new(),
            timeout: None,
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_EXEC_REQUEST,
            &exec_req,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let quiesce_req = QuiesceRequest {
            context: Some(RequestContext {
                request_id: "quiesce-req".into(),
                operation_id: "quiesce-timeout".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            drain_mode: quiesce_request::DrainMode::Graceful as i32,
            quiesce_deadline: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_QUIESCE_REQUEST,
            &quiesce_req,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<QuiesceResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_QUIESCE_RESPONSE);
        match resp.result {
            Some(quiesce_response::Result::Error(outcome)) => {
                assert!(matches!(
                    outcome.status,
                    Some(operation_outcome::Status::TimedOut(_))
                ));
            }
            _ => panic!("expected timeout error"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn quiesce_exec_blocked() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<QuiesceRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_QUIESCE_REQUEST);

            let (tag, _exec_req) =
                framed::read_tagged::<ExecRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let rejection = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "Quiescing".into(),
                            message: "guest is preparing for checkpoint".into(),
                            retryable: true,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_EXEC_RESPONSE,
                &rejection,
                Duration::from_secs(5),
            )
            .await
            .unwrap();

            let response = QuiesceResponse {
                result: Some(quiesce_response::Result::Quiesced(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_QUIESCE_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let quiesce_req = QuiesceRequest {
            context: Some(RequestContext {
                request_id: "quiesce-req".into(),
                operation_id: "quiesce-block".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            drain_mode: quiesce_request::DrainMode::Graceful as i32,
            quiesce_deadline: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_QUIESCE_REQUEST,
            &quiesce_req,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let exec_req = ExecRequest {
            context: Some(RequestContext {
                request_id: "exec-req".into(),
                operation_id: "op-blocked".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            command: "echo".into(),
            args: vec![],
            env: HashMap::new(),
            working_dir: String::new(),
            timeout: None,
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_EXEC_REQUEST,
            &exec_req,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, exec_resp) =
            framed::read_tagged::<ExecResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
        match exec_resp.frame {
            Some(exec_response::Frame::Outcome(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "Quiescing");
                    assert!(f.retryable);
                }
                _ => panic!("expected failure outcome"),
            },
            _ => panic!("expected outcome frame"),
        }

        let (tag, quiesce_resp) =
            framed::read_tagged::<QuiesceResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_QUIESCE_RESPONSE);
        assert!(matches!(
            quiesce_resp.result,
            Some(quiesce_response::Result::Quiesced(true))
        ));

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_basic_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);
            assert_eq!(req.sandbox_id, "new-sbx-after-restore");
            assert_eq!(req.policy_epoch, 42);
            assert_eq!(req.lineage_id, "snapshot-lineage-uuid");

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Accepted(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-op".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: "new-sbx-after-restore".into(),
            policy_epoch: 42,
            lineage_id: "snapshot-lineage-uuid".into(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        assert!(matches!(
            resp.result,
            Some(resume_notify_response::Result::Accepted(true))
        ));

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_stale_policy_epoch_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);
            assert_eq!(req.policy_epoch, 3);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "StalePolicyEpoch".into(),
                            message: "policy epoch 3 is older than current 10".into(),
                            retryable: false,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-stale".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 10,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 3,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "StalePolicyEpoch");
                }
                _ => panic!("expected stale policy epoch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_session_mismatch_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "SessionMismatch".into(),
                            message: "session_id does not match".into(),
                            retryable: false,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-mismatch".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"wrong-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 0,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "SessionMismatch");
                }
                _ => panic!("expected session mismatch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_with_fork_identity_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);
            assert_eq!(req.sandbox_id, "child-sandbox-42");
            assert_eq!(req.policy_epoch, 100);
            assert_eq!(req.lineage_id, "parent-snap-lineage");

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Accepted(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-fork".into(),
                sandbox_id: "parent-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 50,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: "child-sandbox-42".into(),
            policy_epoch: 100,
            lineage_id: "parent-snap-lineage".into(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        assert!(matches!(
            resp.result,
            Some(resume_notify_response::Result::Accepted(true))
        ));

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_protocol_version_mismatch_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "ProtocolVersionMismatch".into(),
                            message: "protocol_version does not match".into(),
                            retryable: false,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-version-mismatch".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0002_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 0,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "ProtocolVersionMismatch");
                }
                _ => panic!("expected protocol version mismatch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_resources_unavailable_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "ResourcesUnavailable".into(),
                            message: "non-restorable resources could not be refreshed".into(),
                            retryable: true,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-resources-unavailable".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session-1234".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 0,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "ResourcesUnavailable");
                    assert!(f.retryable);
                }
                _ => panic!("expected resources unavailable failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }
}
