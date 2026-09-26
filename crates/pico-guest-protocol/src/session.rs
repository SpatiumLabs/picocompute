//! Unified guest session: handshake + operational RPCs over a single
//! framed transport.
//!
//! `GuestSession` is the single entry-point for host-to-guest
//! communication. It performs the bootstrap handshake and then exposes
//! every operational RPC (exec, file transfer, lifecycle, secrets, etc.)
//! over the same framed connection.
//!
//! The session is generic over any [`TransportStream`], enabling TCP for
//! tests and vsock (or other transports) for production.

use std::time::{Duration, Instant};

use prost::Message;
use tokio::net::TcpStream;

use crate::exec as guest_exec;
use crate::framed::{self, FramedConnection, TransportStream};
use crate::handshake::{
    HandshakeConfig, HandshakeError, HandshakeOutcome, perform_handshake_exchange,
};
use crate::operational_v1::*;

// ── Bounded buffering limits ────────────────────────────────────────────────────

/// Maximum payload bytes per stream frame (proto spec: 64 KiB).
///
/// Frames larger than this are rejected with [`SessionError::OutputLimitExceeded`]
/// before they are buffered.
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 64 * 1024;

/// Default cap for buffered stdout in [`GuestSession::exec`] (1 MiB).
///
/// Mirrors the per-stream replay buffer bound in ADR-0003. Use
/// [`GuestSession::exec_with_limits`] for a custom ceiling.
pub const DEFAULT_MAX_STDOUT_BYTES: usize = 1024 * 1024;

/// Default cap for buffered stderr in [`GuestSession::exec`] (1 MiB).
pub const DEFAULT_MAX_STDERR_BYTES: usize = 1024 * 1024;

/// Default cap for buffered file content in [`GuestSession::get_file`] (16 MiB).
///
/// File transfer is chunked at 64 KiB, so larger files do not require larger
/// messages. Use [`GuestSession::get_file_with_limit`] for a custom ceiling.
/// Matches the supervisor read cap so the session layer never rejects a file
/// the supervisor would accept.
pub const DEFAULT_MAX_FILE_BYTES: usize = 16 * 1024 * 1024;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Unified error type for guest session operations.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Handshake failed; the session was never established.
    #[error("handshake error: {0}")]
    Handshake(#[from] HandshakeError),

    /// Transport-level I/O failure.
    #[error("I/O error: {0}")]
    Io(String),

    /// Protocol-level failure (unexpected tag, malformed message, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Buffered stdout/stderr exceeded the configured ceiling, or a stream
    /// frame exceeded [`MAX_FRAME_PAYLOAD_BYTES`].
    ///
    /// The session is mid-stream when this occurs; drop it instead of
    /// issuing further RPCs on the same connection.
    #[error("output limit exceeded: {0}")]
    OutputLimitExceeded(String),

    /// File metadata or accumulated chunks exceeded the configured ceiling.
    ///
    /// Checked before buffering where possible (metadata size). The session
    /// may be mid-stream; drop it instead of reusing the connection.
    #[error("file too large: {0}")]
    FileTooLarge(String),
}

impl SessionError {
    /// Stable machine-readable label for metrics and alert routing.
    ///
    /// Mirrors [`HandshakeError::kind`] so callers wrapping this error into
    /// stringly-typed outer errors keep the underlying variant information.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Handshake(e) => e.kind(),
            Self::Io(_) => "session_io",
            Self::Protocol(_) => "session_protocol",
            Self::OutputLimitExceeded(_) => "session_output_limit",
            Self::FileTooLarge(_) => "session_file_too_large",
        }
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

/// Aggregated exec result (buffered API).
#[derive(Debug, Clone)]
pub struct ExecResult {
    /// Process exit code.
    pub exit_code: i32,
    /// Guest-reported duration in milliseconds.
    pub duration_ms: u64,
    /// Captured stdout.
    pub stdout: Vec<u8>,
    /// Captured stderr.
    pub stderr: Vec<u8>,
    /// Terminal status label.
    pub status: String,
}

/// Result of a guest file read.
#[derive(Debug, Clone)]
pub struct GetFileResult {
    /// File contents.
    pub data: Vec<u8>,
    /// Reported size.
    pub size: u64,
    /// File mode bits.
    pub mode: u32,
    /// Checksum string from the guest outcome payload.
    pub checksum: String,
}

/// Result of a secret injection.
#[derive(Debug, Clone)]
pub struct InjectSecretsResult {
    /// Whether the secrets were injected.
    pub injected: bool,
}

// ── GuestSession ──────────────────────────────────────────────────────────────

/// An established, authenticated session with a guest agent.
///
/// `GuestSession` owns the underlying transport and provides typed methods
/// for every operational RPC. It is created via [`GuestSession::connect_tcp`]
/// (for TCP) or [`GuestSession::from_connection`] (for any pre-connected
/// transport such as vsock).
///
/// # Concurrency invariant
///
/// A session allows exactly **one in-flight RPC at a time**: every method
/// takes `&mut self` and interleaves request/response frames on the single
/// framed connection, so callers must serialize access (e.g., hold a lock
/// for the full RPC duration, including any streamed frames). Callers
/// needing concurrent operations must open independent sessions instead -
/// per-request locking within one session risks response frames being
/// attributed to the wrong request. A multiplexed design (per-request
/// locking + explicit sequence numbering on the wire) is future work.
pub struct GuestSession<S: TransportStream> {
    conn: FramedConnection<S>,
    session_id: Vec<u8>,
    sandbox_id: String,
    policy_epoch: u64,
    protocol_version: (u32, u32),
    negotiated_capabilities: Vec<String>,
    guest_agent_version: String,
    guest_boot_id: String,
}

impl GuestSession<TcpStream> {
    /// Connect to a guest agent over TCP and perform the handshake.
    ///
    /// This is the primary constructor used in tests and development.
    /// For production vsock transport, use [`GuestSession::from_connection`]
    /// after establishing the vsock stream.
    pub async fn connect_tcp(config: &HandshakeConfig) -> Result<Self, SessionError> {
        let addr = config.transport_addr;
        let stream = tokio::time::timeout(config.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                SessionError::Handshake(HandshakeError::ConnectionRefused(format!(
                    "timeout connecting to guest agent at {addr}"
                )))
            })?
            .map_err(|err| {
                SessionError::Handshake(HandshakeError::ConnectionRefused(format!(
                    "failed to connect to guest agent at {addr}: {err}"
                )))
            })?;

        let mut conn = FramedConnection::new(stream, config.timeout);
        let outcome = perform_handshake_exchange(&mut conn, config).await?;
        Ok(Self::from_outcome(conn, config, outcome))
    }
}

impl<S: TransportStream> GuestSession<S> {
    /// Create a session from an already-connected framed transport.
    ///
    /// Performs the handshake over the provided connection.
    pub async fn connect(
        conn: FramedConnection<S>,
        config: &HandshakeConfig,
    ) -> Result<Self, SessionError> {
        let mut conn = conn;
        let outcome = perform_handshake_exchange(&mut conn, config).await?;
        Ok(Self::from_outcome(conn, config, outcome))
    }

    fn from_outcome(
        conn: FramedConnection<S>,
        config: &HandshakeConfig,
        outcome: HandshakeOutcome,
    ) -> Self {
        Self {
            conn,
            session_id: outcome.session_id.to_vec(),
            sandbox_id: config.sandbox_id.clone(),
            policy_epoch: config.policy_epoch,
            protocol_version: outcome.negotiated_version,
            negotiated_capabilities: outcome.negotiated_capabilities,
            guest_agent_version: outcome.guest_agent_version,
            guest_boot_id: outcome.guest_boot_id,
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    /// Session identifier bytes.
    #[must_use]
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Negotiated capability identifiers.
    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        &self.negotiated_capabilities
    }

    /// Guest agent version string.
    #[must_use]
    pub fn guest_agent_version(&self) -> &str {
        &self.guest_agent_version
    }

    /// Guest boot identifier.
    #[must_use]
    pub fn guest_boot_id(&self) -> &str {
        &self.guest_boot_id
    }

    /// Policy epoch bound into the session.
    #[must_use]
    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    /// Negotiated protocol version as `(major, minor)`.
    #[must_use]
    pub fn protocol_version(&self) -> (u32, u32) {
        self.protocol_version
    }

    /// Returns a reference to the underlying framed connection.
    pub fn connection(&self) -> &FramedConnection<S> {
        &self.conn
    }

    /// Returns a mutable reference to the underlying framed connection.
    pub fn connection_mut(&mut self) -> &mut FramedConnection<S> {
        &mut self.conn
    }

    /// Consumes the session and returns the inner transport stream.
    pub fn into_inner(self) -> S {
        self.conn.into_inner()
    }

    // ── Operational RPCs ──────────────────────────────────────────────────

    fn make_context(&self, operation_id: &str) -> RequestContext {
        RequestContext {
            request_id: ulid::Ulid::generate().to_string(),
            operation_id: operation_id.into(),
            sandbox_id: self.sandbox_id.clone(),
            session_id: self.session_id.clone(),
            policy_epoch: self.policy_epoch,
            protocol_version: (self.protocol_version.0 << 16) | self.protocol_version.1,
            deadline: None,
            trace_context: None,
        }
    }

    /// Execute a command in the guest and buffer output until completion.
    ///
    /// Buffering is bounded by [`DEFAULT_MAX_STDOUT_BYTES`] and
    /// [`DEFAULT_MAX_STDERR_BYTES`]. The limits are also sent to the guest
    /// via `max_stdout_bytes`/`max_stderr_bytes` so a cooperative guest stops
    /// early. A malicious guest that ignores the limits is stopped by the
    /// host-side check, which returns [`SessionError::OutputLimitExceeded`].
    /// Drop the session after a limit error; the connection is mid-stream.
    pub async fn exec(
        &mut self,
        command: &str,
        args: &[String],
        env: &hashbrown::HashMap<String, String>,
        working_dir: &str,
        operation_id: &str,
        timeout: Option<Duration>,
    ) -> Result<ExecResult, SessionError> {
        self.exec_with_limits(
            command,
            args,
            env,
            working_dir,
            operation_id,
            timeout,
            DEFAULT_MAX_STDOUT_BYTES,
            DEFAULT_MAX_STDERR_BYTES,
        )
        .await
    }

    /// Execute with explicit output ceilings.
    ///
    /// `max_stdout_bytes` and `max_stderr_bytes` bound host-side buffering.
    /// Zero means "use the default" rather than unlimited, so callers cannot
    /// accidentally request unbounded buffering. Per-frame payloads larger
    /// than [`MAX_FRAME_PAYLOAD_BYTES`] are rejected.
    #[expect(
        clippy::too_many_arguments,
        reason = "exec needs full RPC context plus two ceilings; splitting would hide the bound"
    )]
    pub async fn exec_with_limits(
        &mut self,
        command: &str,
        args: &[String],
        env: &hashbrown::HashMap<String, String>,
        working_dir: &str,
        operation_id: &str,
        timeout: Option<Duration>,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<ExecResult, SessionError> {
        use prost_types::Duration as ProtoDuration;

        let max_stdout = if max_stdout_bytes == 0 {
            DEFAULT_MAX_STDOUT_BYTES
        } else {
            max_stdout_bytes
        };
        let max_stderr = if max_stderr_bytes == 0 {
            DEFAULT_MAX_STDERR_BYTES
        } else {
            max_stderr_bytes
        };

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
            max_stdout_bytes: max_stdout as u64,
            max_stderr_bytes: max_stderr as u64,
        };

        self.conn
            .send_tagged(framed::TAG_EXEC_REQUEST, &request)
            .await
            .map_err(|e| SessionError::Io(format!("failed to send exec request: {e}")))?;

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        loop {
            let (tag, response): (u8, ExecResponse) = self
                .conn
                .recv_tagged()
                .await
                .map_err(|e| SessionError::Io(format!("failed to read exec response: {e}")))?;

            if tag != framed::TAG_EXEC_RESPONSE {
                return Err(SessionError::Protocol(format!(
                    "unexpected response tag: {tag}"
                )));
            }

            let frame = response
                .frame
                .ok_or_else(|| SessionError::Protocol("empty exec response frame".into()))?;

            match frame {
                exec_response::Frame::Stdout(data) => {
                    if let Some(f) = data.frame
                        && !f.payload.is_empty()
                    {
                        check_frame_payload(&f.payload, "stdout")?;
                        if stdout_buf.len() + f.payload.len() > max_stdout {
                            return Err(SessionError::OutputLimitExceeded(format!(
                                "stdout {} + {} exceeds limit {max_stdout}",
                                stdout_buf.len(),
                                f.payload.len()
                            )));
                        }
                        stdout_buf.extend_from_slice(&f.payload);
                    }
                }
                exec_response::Frame::Stderr(data) => {
                    if let Some(f) = data.frame
                        && !f.payload.is_empty()
                    {
                        check_frame_payload(&f.payload, "stderr")?;
                        if stderr_buf.len() + f.payload.len() > max_stderr {
                            return Err(SessionError::OutputLimitExceeded(format!(
                                "stderr {} + {} exceeds limit {max_stderr}",
                                stderr_buf.len(),
                                f.payload.len()
                            )));
                        }
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
                            return Err(SessionError::Protocol("unknown operation outcome".into()));
                        }
                    };
                    return Ok(result);
                }
            }
        }
    }

    /// Cancel an in-flight guest operation.
    pub async fn cancel(&mut self, operation_id: &str) -> Result<CancelResponse, SessionError> {
        let context = self.make_context(operation_id);
        let request = CancelRequest {
            context: Some(context),
            operation_id: operation_id.into(),
        };
        self.call_rpc(
            framed::TAG_CANCEL_REQUEST,
            framed::TAG_CANCEL_RESPONSE,
            &request,
            "cancel",
        )
        .await
    }

    /// Send a signal to a running process in the guest.
    pub async fn signal(
        &mut self,
        operation_id: &str,
        signal: i32,
    ) -> Result<SignalResponse, SessionError> {
        let context = self.make_context(operation_id);
        let request = SignalRequest {
            context: Some(context),
            operation_id: operation_id.into(),
            signal,
        };
        self.call_rpc(
            framed::TAG_SIGNAL_REQUEST,
            framed::TAG_SIGNAL_RESPONSE,
            &request,
            "signal",
        )
        .await
    }

    /// Quiesce the guest agent (drain or force-cancel active operations).
    pub async fn quiesce(
        &mut self,
        drain_mode: i32,
        deadline: Option<std::time::SystemTime>,
        operation_id: &str,
    ) -> Result<QuiesceResponse, SessionError> {
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

        self.call_rpc(
            framed::TAG_QUIESCE_REQUEST,
            framed::TAG_QUIESCE_RESPONSE,
            &request,
            "quiesce",
        )
        .await
    }

    /// Notify the guest agent of a snapshot restore / fork.
    pub async fn resume_notify(
        &mut self,
        sandbox_id: &str,
        policy_epoch: u64,
        lineage_id: &str,
        snapshot_taken_at: Option<std::time::SystemTime>,
        operation_id: &str,
    ) -> Result<ResumeNotifyResponse, SessionError> {
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

        self.call_rpc(
            framed::TAG_RESUME_NOTIFY_REQUEST,
            framed::TAG_RESUME_NOTIFY_RESPONSE,
            &request,
            "resume notify",
        )
        .await
    }

    /// Write a file into the guest.
    ///
    /// Chunked at [`MAX_FRAME_PAYLOAD_BYTES`]. Payloads larger than
    /// [`DEFAULT_MAX_FILE_BYTES`] are rejected with
    /// [`SessionError::FileTooLarge`] before any bytes are sent.
    pub async fn put_file(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
        overwrite: bool,
        operation_id: &str,
    ) -> Result<PutFileResponse, SessionError> {
        self.put_file_with_limit(
            path,
            data,
            mode,
            overwrite,
            operation_id,
            DEFAULT_MAX_FILE_BYTES,
        )
        .await
    }

    /// Write a file with an explicit byte ceiling.
    ///
    /// Zero means "use the default" rather than unlimited, so callers cannot
    /// accidentally request unbounded sends.
    pub async fn put_file_with_limit(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
        overwrite: bool,
        operation_id: &str,
        max_file_bytes: usize,
    ) -> Result<PutFileResponse, SessionError> {
        let max_bytes = if max_file_bytes == 0 {
            DEFAULT_MAX_FILE_BYTES
        } else {
            max_file_bytes
        };
        if data.len() > max_bytes {
            return Err(SessionError::FileTooLarge(format!(
                "put file {} bytes exceeds limit {max_bytes}",
                data.len(),
            )));
        }
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
            .map_err(|e| SessionError::Io(format!("send put file metadata: {e}")))?;

        const CHUNK_SIZE: usize = MAX_FRAME_PAYLOAD_BYTES;
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
                .map_err(|e| SessionError::Io(format!("send chunk: {e}")))?;

            if end_of_stream {
                break;
            }
        }

        // Empty file: still need end-of-stream chunk.
        if data.is_empty() {
            let chunk_req = PutFileRequest {
                payload: Some(put_file_request::Payload::Chunk(StreamFrame {
                    sequence: 1,
                    payload: Vec::new(),
                    end_of_stream: true,
                })),
            };
            self.conn
                .send_tagged(framed::TAG_PUT_FILE_REQUEST, &chunk_req)
                .await
                .map_err(|e| SessionError::Io(format!("send empty chunk: {e}")))?;
        }

        let (tag, response): (u8, PutFileResponse) = self
            .conn
            .recv_tagged()
            .await
            .map_err(|e| SessionError::Io(format!("read put file response: {e}")))?;

        if tag != framed::TAG_PUT_FILE_RESPONSE {
            return Err(SessionError::Protocol(format!(
                "unexpected response tag: {tag}"
            )));
        }

        Ok(response)
    }

    /// Read a file from the guest.
    ///
    /// Buffering is bounded by [`DEFAULT_MAX_FILE_BYTES`]. Metadata declaring
    /// a larger size is rejected with [`SessionError::FileTooLarge`] before
    /// chunk allocation. Chunks larger than [`MAX_FRAME_PAYLOAD_BYTES`] or
    /// totals exceeding the ceiling are also rejected. Drop the session after
    /// a limit error; the connection may be mid-stream.
    pub async fn get_file(
        &mut self,
        path: &str,
        operation_id: &str,
    ) -> Result<GetFileResult, SessionError> {
        self.get_file_with_limit(path, operation_id, DEFAULT_MAX_FILE_BYTES)
            .await
    }

    /// Read a file with an explicit byte ceiling.
    ///
    /// Zero means "use the default" rather than unlimited.
    pub async fn get_file_with_limit(
        &mut self,
        path: &str,
        operation_id: &str,
        max_file_bytes: usize,
    ) -> Result<GetFileResult, SessionError> {
        let max_bytes = if max_file_bytes == 0 {
            DEFAULT_MAX_FILE_BYTES
        } else {
            max_file_bytes
        };
        let context = self.make_context(operation_id);
        let request = GetFileRequest {
            context: Some(context),
            path: path.into(),
        };

        self.conn
            .send_tagged(framed::TAG_GET_FILE_REQUEST, &request)
            .await
            .map_err(|e| SessionError::Io(format!("send get file request: {e}")))?;

        let mut data = Vec::new();
        let mut file_size: u64 = 0;
        let mut file_mode: u32 = 0;
        let mut checksum = String::new();
        let deadline = Instant::now() + self.conn.timeout();

        loop {
            if Instant::now() > deadline {
                return Err(SessionError::Protocol("get file timed out".into()));
            }

            let (tag, response): (u8, GetFileResponse) = self
                .conn
                .recv_tagged()
                .await
                .map_err(|e| SessionError::Io(format!("read get file response: {e}")))?;

            if tag != framed::TAG_GET_FILE_RESPONSE {
                return Err(SessionError::Protocol(format!(
                    "unexpected response tag: {tag}"
                )));
            }

            match response.frame {
                Some(get_file_response::Frame::Metadata(m)) => {
                    if m.size as usize > max_bytes {
                        return Err(SessionError::FileTooLarge(format!(
                            "file size {} exceeds limit {max_bytes}",
                            m.size
                        )));
                    }
                    file_size = m.size;
                    file_mode = m.mode;
                }
                Some(get_file_response::Frame::Chunk(f)) => {
                    check_file_frame_payload(&f.payload)?;
                    if data.len() + f.payload.len() > max_bytes {
                        return Err(SessionError::FileTooLarge(format!(
                            "file {} + {} exceeds limit {max_bytes}",
                            data.len(),
                            f.payload.len()
                        )));
                    }
                    data.extend_from_slice(&f.payload);
                }
                Some(get_file_response::Frame::Outcome(outcome)) => {
                    if let Some(operation_outcome::Status::Success(s)) = outcome.status {
                        checksum = String::from_utf8_lossy(&s.result_payload).to_string();
                    }
                    break;
                }
                None => {
                    return Err(SessionError::Protocol(
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

    /// Mount a workspace filesystem in the guest.
    pub async fn mount_workspace(
        &mut self,
        mount_point: &str,
        fs_type: &str,
        options: &hashbrown::HashMap<String, String>,
        operation_id: &str,
    ) -> Result<MountWorkspaceResponse, SessionError> {
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

    /// Request guest statistics.
    pub async fn stats(&mut self, operation_id: &str) -> Result<StatsResponse, SessionError> {
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

    /// Check guest agent health.
    pub async fn health(&mut self, operation_id: &str) -> Result<HealthResponse, SessionError> {
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

    /// Request guest shutdown.
    pub async fn shutdown(
        &mut self,
        reason: &str,
        force: bool,
        operation_id: &str,
    ) -> Result<ShutdownResponse, SessionError> {
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

    /// Inject secrets into the guest agent.
    ///
    /// Credentials are written into a tmpfs-backed secrets directory that
    /// is excluded from snapshots. Each credential is a file with mode 0400.
    pub async fn inject_secrets(
        &mut self,
        lease_id: &str,
        policy_decision_id: &str,
        credentials: &[SecretCredential],
        operation_id: &str,
    ) -> Result<InjectSecretsResult, SessionError> {
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
            Some(inject_secrets_response::Result::Injected(false)) => {
                Ok(InjectSecretsResult { injected: false })
            }
            Some(inject_secrets_response::Result::Error(outcome)) => {
                let detail = match outcome.status {
                    Some(operation_outcome::Status::Failure(f)) => {
                        format!("{}: {}", f.code, f.message)
                    }
                    Some(operation_outcome::Status::Canceled(c)) => {
                        format!("canceled: {}", c.reason)
                    }
                    Some(operation_outcome::Status::TimedOut(_)) => "timed out".into(),
                    Some(operation_outcome::Status::Unsupported(u)) => {
                        format!("unsupported: {}", u.detail)
                    }
                    Some(operation_outcome::Status::RequiresReview(r)) => {
                        format!("requires review: {}", r.detail)
                    }
                    Some(operation_outcome::Status::Success(_)) | None => "unknown outcome".into(),
                };
                Err(SessionError::Protocol(format!(
                    "inject secrets failed in guest: {detail}"
                )))
            }
            None => Err(SessionError::Protocol(
                "inject secrets response missing result".into(),
            )),
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    async fn call_rpc<Req, Resp>(
        &mut self,
        request_tag: u8,
        response_tag: u8,
        request: &Req,
        rpc_name: &str,
    ) -> Result<Resp, SessionError>
    where
        Req: Message,
        Resp: Message + Default,
    {
        self.conn
            .send_tagged(request_tag, request)
            .await
            .map_err(|e| SessionError::Io(format!("send {rpc_name} request: {e}")))?;
        let (tag, response): (u8, Resp) = self
            .conn
            .recv_tagged()
            .await
            .map_err(|e| SessionError::Io(format!("read {rpc_name} response: {e}")))?;
        if tag != response_tag {
            return Err(SessionError::Protocol(format!(
                "unexpected response tag: {tag} for {rpc_name}"
            )));
        }
        Ok(response)
    }
}

/// Rejects a stream payload larger than [`MAX_FRAME_PAYLOAD_BYTES`].
///
/// Called before buffering so a malicious guest cannot force an extra
/// allocation beyond the per-frame bound. Returns
/// [`SessionError::OutputLimitExceeded`] with a stable message.
fn check_frame_payload(payload: &[u8], stream: &str) -> Result<(), SessionError> {
    if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(SessionError::OutputLimitExceeded(format!(
            "{stream} frame {} exceeds per-frame limit {MAX_FRAME_PAYLOAD_BYTES}",
            payload.len()
        )));
    }
    Ok(())
}

/// Rejects a file-chunk payload larger than [`MAX_FRAME_PAYLOAD_BYTES`].
///
/// File-transfer violations report [`SessionError::FileTooLarge`] (kind
/// `session_file_too_large`) so metrics distinguish them from exec-output
/// overflow. Called before buffering.
fn check_file_frame_payload(payload: &[u8]) -> Result<(), SessionError> {
    if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(SessionError::FileTooLarge(format!(
            "file chunk {} exceeds per-frame limit {MAX_FRAME_PAYLOAD_BYTES}",
            payload.len()
        )));
    }
    Ok(())
}
