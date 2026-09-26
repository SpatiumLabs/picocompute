//! Framed operational guest-agent client owned by sandboxd.

use std::time::Instant;

use pico_guest_protocol::operational_v1::*;
use pico_guest_protocol::{exec as guest_exec, framed};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc;
use tokio_vsock::{VsockAddr, VsockStream};

use super::handshake::{
    HandshakeConfig, HandshakeError, HandshakeOutcome, perform_handshake_exchange,
};

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

/// Streamed exec frame demuxed for sandboxd gRPC.
#[derive(Debug, Clone)]
pub enum ExecStreamEvent {
    /// First frame observed; guest accepted the operation.
    Started,
    /// Stdout chunk.
    Stdout(Vec<u8>),
    /// Stderr chunk.
    Stderr(Vec<u8>),
    /// Successful process exit.
    Exited {
        /// Exit code.
        exit_code: i32,
        /// Duration milliseconds.
        duration_ms: u64,
    },
    /// Guest reported failure/cancel/timeout.
    Failed {
        /// Status label.
        status: String,
    },
}

/// Errors from operational guest RPCs.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GuestClientError {
    /// Transport I/O failure.
    #[error("I/O error: {0}")]
    Io(String),
    /// Protocol framing or message error.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Handshake failure.
    #[error("handshake error: {0}")]
    Handshake(String),
}

impl From<HandshakeError> for GuestClientError {
    fn from(err: HandshakeError) -> Self {
        Self::Handshake(err.to_string())
    }
}

enum GuestIo {
    Tcp(TcpStream),
    Unix(UnixStream),
    Vsock(VsockStream),
}

impl AsyncRead for GuestIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Vsock(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for GuestIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Vsock(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
            Self::Vsock(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Vsock(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Established framed session to a guest agent.
pub struct GuestConnection {
    conn: framed::FramedConnection<GuestIo>,
    session_id: Vec<u8>,
    sandbox_id: String,
    policy_epoch: u64,
    protocol_version: (u32, u32),
    negotiated_capabilities: Vec<String>,
    guest_agent_version: String,
    guest_boot_id: String,
}

impl GuestConnection {
    /// Connect over TCP and complete the fail-closed bootstrap handshake.
    ///
    /// TCP is development/test only. Production callers must use
    /// [`Self::connect_unix`], [`Self::connect_firecracker_vsock`], or
    /// [`Self::connect_vsock`].
    pub async fn connect(config: &HandshakeConfig) -> Result<Self, HandshakeError> {
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
        Self::handshake(GuestIo::Tcp(stream), config).await
    }

    /// Connect over a Unix domain socket and complete the handshake.
    pub async fn connect_unix(
        path: &str,
        config: &HandshakeConfig,
    ) -> Result<Self, HandshakeError> {
        let stream = tokio::time::timeout(config.timeout, tokio::net::UnixStream::connect(path))
            .await
            .map_err(|_| {
                HandshakeError::ConnectionRefused(format!(
                    "timeout connecting to guest agent unix socket {path}"
                ))
            })?
            .map_err(|err| {
                HandshakeError::ConnectionRefused(format!(
                    "failed to connect to guest agent unix socket {path}: {err}"
                ))
            })?;
        Self::handshake(GuestIo::Unix(stream), config).await
    }

    /// Connect through Firecracker's host vsock Unix mapping (`CONNECT <port>`).
    pub async fn connect_firecracker_vsock(
        uds_path: &str,
        port: u32,
        config: &HandshakeConfig,
    ) -> Result<Self, HandshakeError> {
        let mut stream =
            tokio::time::timeout(config.timeout, tokio::net::UnixStream::connect(uds_path))
                .await
                .map_err(|_| {
                    HandshakeError::ConnectionRefused(format!(
                        "timeout connecting to Firecracker vsock {uds_path}"
                    ))
                })?
                .map_err(|err| {
                    HandshakeError::ConnectionRefused(format!(
                        "failed to connect to Firecracker vsock {uds_path}: {err}"
                    ))
                })?;
        let connect_cmd = format!("CONNECT {port}\n");
        tokio::time::timeout(config.timeout, stream.write_all(connect_cmd.as_bytes()))
            .await
            .map_err(|_| {
                HandshakeError::ConnectionRefused(
                    "timeout writing Firecracker vsock CONNECT".into(),
                )
            })?
            .map_err(|err| {
                HandshakeError::ConnectionRefused(format!(
                    "failed to write Firecracker vsock CONNECT: {err}"
                ))
            })?;
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(config.timeout, stream.read(&mut buf))
            .await
            .map_err(|_| {
                HandshakeError::ConnectionRefused(
                    "timeout reading Firecracker vsock CONNECT reply".into(),
                )
            })?
            .map_err(|err| {
                HandshakeError::ConnectionRefused(format!(
                    "failed to read Firecracker vsock CONNECT reply: {err}"
                ))
            })?;
        let reply = std::str::from_utf8(&buf[..n]).unwrap_or("");
        if !reply.starts_with("OK ") {
            return Err(HandshakeError::ConnectionRefused(format!(
                "Firecracker vsock CONNECT {port} rejected: {}",
                reply.trim()
            )));
        }
        Self::handshake(GuestIo::Unix(stream), config).await
    }

    /// Connect to a QEMU guest over host `AF_VSOCK` and complete the handshake.
    ///
    /// This is the ADR-0003 production transport for QEMU: the host dials the
    /// guest CID assigned at boot on the reserved PicoCompute port.
    pub async fn connect_vsock(
        cid: u32,
        port: u32,
        config: &HandshakeConfig,
    ) -> Result<Self, HandshakeError> {
        let addr = VsockAddr::new(cid, port);
        let stream = tokio::time::timeout(config.timeout, VsockStream::connect(addr))
            .await
            .map_err(|_| {
                HandshakeError::ConnectionRefused(format!(
                    "timeout connecting to QEMU vsock cid={cid} port={port}"
                ))
            })?
            .map_err(|err| {
                HandshakeError::ConnectionRefused(format!(
                    "failed to connect to QEMU vsock cid={cid} port={port}: {err}"
                ))
            })?;
        Self::handshake(GuestIo::Vsock(stream), config).await
    }

    async fn handshake(stream: GuestIo, config: &HandshakeConfig) -> Result<Self, HandshakeError> {
        let mut conn = framed::FramedConnection::new(stream, config.timeout);
        let outcome = perform_handshake_exchange(&mut conn, config).await?;
        Ok(Self::from_outcome(conn, config, outcome))
    }

    fn from_outcome(
        conn: framed::FramedConnection<GuestIo>,
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

    /// Run exec and buffer all output until the terminal outcome.
    pub async fn exec(
        &mut self,
        command: &str,
        args: &[String],
        env: &hashbrown::HashMap<String, String>,
        working_dir: &str,
        operation_id: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<ExecResult, GuestClientError> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = -1;
        let mut duration_ms = 0;
        let mut status = String::from("unknown");

        let mut rx = self
            .exec_stream(command, args, env, working_dir, operation_id, timeout)
            .await?;
        while let Some(event) = rx.recv().await {
            match event? {
                ExecStreamEvent::Started => {}
                ExecStreamEvent::Stdout(chunk) => stdout.extend_from_slice(&chunk),
                ExecStreamEvent::Stderr(chunk) => stderr.extend_from_slice(&chunk),
                ExecStreamEvent::Exited {
                    exit_code: code,
                    duration_ms: dur,
                } => {
                    exit_code = code;
                    duration_ms = dur;
                    status = "success".into();
                }
                ExecStreamEvent::Failed { status: s } => {
                    status = s;
                }
            }
        }

        Ok(ExecResult {
            exit_code,
            duration_ms,
            stdout,
            stderr,
            status,
        })
    }

    /// Send an exec request and demux guest frames onto a channel.
    pub async fn exec_stream(
        &mut self,
        command: &str,
        args: &[String],
        env: &hashbrown::HashMap<String, String>,
        working_dir: &str,
        operation_id: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<mpsc::Receiver<Result<ExecStreamEvent, GuestClientError>>, GuestClientError> {
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
            .map_err(|e| GuestClientError::Io(format!("failed to send exec request: {e}")))?;

        let mut events = vec![ExecStreamEvent::Started];

        loop {
            let (tag, response): (u8, ExecResponse) =
                self.conn.recv_tagged().await.map_err(|e| {
                    GuestClientError::Io(format!("failed to read exec response: {e}"))
                })?;

            if tag != framed::TAG_EXEC_RESPONSE {
                return Err(GuestClientError::Protocol(format!(
                    "unexpected response tag: {tag}"
                )));
            }

            let frame = response
                .frame
                .ok_or_else(|| GuestClientError::Protocol("empty exec response frame".into()))?;

            match frame {
                exec_response::Frame::Stdout(data) => {
                    let payload = data.frame.map(|f| f.payload).unwrap_or_default();
                    if !payload.is_empty() {
                        events.push(ExecStreamEvent::Stdout(payload));
                    }
                }
                exec_response::Frame::Stderr(data) => {
                    let payload = data.frame.map(|f| f.payload).unwrap_or_default();
                    if !payload.is_empty() {
                        events.push(ExecStreamEvent::Stderr(payload));
                    }
                }
                exec_response::Frame::Ack(_) => {}
                exec_response::Frame::Outcome(outcome) => {
                    let terminal = match outcome.status {
                        Some(operation_outcome::Status::Success(success)) => {
                            let (exit_code, duration_ms) =
                                guest_exec::parse_exec_exit(&success.result_payload);
                            ExecStreamEvent::Exited {
                                exit_code,
                                duration_ms,
                            }
                        }
                        Some(operation_outcome::Status::Failure(failure)) => {
                            ExecStreamEvent::Failed {
                                status: format!("failure: {}: {}", failure.code, failure.message),
                            }
                        }
                        Some(operation_outcome::Status::Canceled(canceled)) => {
                            ExecStreamEvent::Failed {
                                status: format!("canceled: {}", canceled.reason),
                            }
                        }
                        Some(operation_outcome::Status::TimedOut(_)) => ExecStreamEvent::Failed {
                            status: "timed out".into(),
                        },
                        _ => {
                            return Err(GuestClientError::Protocol(
                                "unknown operation outcome".into(),
                            ));
                        }
                    };
                    events.push(terminal);
                    break;
                }
            }
        }

        let (tx, rx) = mpsc::channel(events.len().max(1));
        for event in events {
            let _ = tx.send(Ok(event)).await;
        }
        Ok(rx)
    }

    /// Cancel an in-flight guest operation.
    pub async fn cancel(&mut self, operation_id: &str) -> Result<CancelResponse, GuestClientError> {
        let context = self.make_context(operation_id);
        let request = CancelRequest {
            context: Some(context),
            operation_id: operation_id.into(),
        };
        self.conn
            .send_tagged(framed::TAG_CANCEL_REQUEST, &request)
            .await
            .map_err(|e| GuestClientError::Io(format!("failed to send cancel: {e}")))?;
        let (tag, response): (u8, CancelResponse) =
            self.conn.recv_tagged().await.map_err(|e| {
                GuestClientError::Io(format!("failed to read cancel response: {e}"))
            })?;
        if tag != framed::TAG_CANCEL_RESPONSE {
            return Err(GuestClientError::Protocol(format!(
                "unexpected response tag: {tag}"
            )));
        }
        Ok(response)
    }

    /// Write a file into the guest.
    pub async fn put_file(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
        overwrite: bool,
        operation_id: &str,
    ) -> Result<PutFileResponse, GuestClientError> {
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
            .map_err(|e| GuestClientError::Io(format!("send put file metadata: {e}")))?;

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
                .map_err(|e| GuestClientError::Io(format!("send chunk: {e}")))?;

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
                .map_err(|e| GuestClientError::Io(format!("send empty chunk: {e}")))?;
        }

        let (tag, response): (u8, PutFileResponse) = self
            .conn
            .recv_tagged()
            .await
            .map_err(|e| GuestClientError::Io(format!("read put file response: {e}")))?;

        if tag != framed::TAG_PUT_FILE_RESPONSE {
            return Err(GuestClientError::Protocol(format!(
                "unexpected response tag: {tag}"
            )));
        }

        Ok(response)
    }

    /// Inject secrets into the guest agent via the operational protocol.
    ///
    /// Credentials are written into a tmpfs-backed secrets directory that is
    /// excluded from snapshots. Each credential is a file with mode 0400.
    pub async fn inject_secrets(
        &mut self,
        lease_id: &str,
        policy_decision_id: &str,
        credentials: &[SecretCredential],
        operation_id: &str,
    ) -> Result<bool, GuestClientError> {
        let request = InjectSecretsRequest {
            context: Some(self.make_context(operation_id)),
            lease_id: lease_id.into(),
            policy_decision_id: policy_decision_id.into(),
            credentials: credentials.to_vec(),
        };
        self.conn
            .send_tagged(framed::TAG_INJECT_SECRETS_REQUEST, &request)
            .await
            .map_err(|e| GuestClientError::Io(format!("send inject secrets request: {e}")))?;
        let (tag, response): (u8, InjectSecretsResponse) = self
            .conn
            .recv_tagged()
            .await
            .map_err(|e| GuestClientError::Io(format!("read inject secrets response: {e}")))?;
        if tag != framed::TAG_INJECT_SECRETS_RESPONSE {
            return Err(GuestClientError::Protocol(format!(
                "unexpected response tag: {tag} for inject secrets"
            )));
        }
        match response.result {
            Some(inject_secrets_response::Result::Injected(true)) => Ok(true),
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
                Err(GuestClientError::Protocol(format!(
                    "inject secrets failed in guest: {detail}"
                )))
            }
            Some(inject_secrets_response::Result::Injected(false)) => Err(
                GuestClientError::Protocol("inject secrets denied by guest".into()),
            ),
            None => Err(GuestClientError::Protocol(
                "inject secrets response missing result".into(),
            )),
        }
    }

    /// Read a file from the guest.
    pub async fn get_file(
        &mut self,
        path: &str,
        operation_id: &str,
    ) -> Result<GetFileResult, GuestClientError> {
        let context = self.make_context(operation_id);
        let request = GetFileRequest {
            context: Some(context),
            path: path.into(),
        };

        self.conn
            .send_tagged(framed::TAG_GET_FILE_REQUEST, &request)
            .await
            .map_err(|e| GuestClientError::Io(format!("send get file request: {e}")))?;

        let mut data = Vec::new();
        let mut file_size: u64 = 0;
        let mut file_mode: u32 = 0;
        let mut checksum = String::new();
        let deadline = Instant::now() + self.conn.timeout();

        loop {
            if Instant::now() > deadline {
                return Err(GuestClientError::Protocol("get file timed out".into()));
            }

            let (tag, response): (u8, GetFileResponse) = self
                .conn
                .recv_tagged()
                .await
                .map_err(|e| GuestClientError::Io(format!("read get file response: {e}")))?;

            if tag != framed::TAG_GET_FILE_RESPONSE {
                return Err(GuestClientError::Protocol(format!(
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
                    return Err(GuestClientError::Protocol(
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
}
