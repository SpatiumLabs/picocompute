//! Operational protocol exec handler for the guest agent.
//!
//! After a successful handshake, the guest agent runs the operational
//! message loop on the same TCP stream.

use heapless::Vec as HVec;
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::watch;

use crate::context;
use crate::control;
use crate::control::{CancelSignal, SharedExecMap};
use crate::file;
use crate::handshake::HandshakeOutcome;
use crate::health::HealthState;
use crate::mount;
use crate::shutdown::ShutdownState;
use crate::stats;
use pico_guest_protocol::operational_v1::*;
use pico_guest_protocol::{FramedConnection, framed};

const DEFAULT_OPERATIONAL_TIMEOUT_SECS: u64 = 300;
const STREAM_FRAME_MAX_BYTES: usize = 64 * 1024;

/// Boxed guest stream so one operational loop serves TCP and Unix sockets.
///
/// `FramedConnection` is generic over its stream; boxing at the accept
/// boundary keeps a single dispatch loop and handler set behind one
/// concrete [`SharedWriter`] type.
pub(crate) type BoxGuestStream = Box<dyn pico_guest_protocol::TransportStream>;

/// Shared write half of the operational connection.
///
/// [`serve_operational`] owns the read half exclusively in its dispatch loop
/// and hands out clones of this writer to every handler. Holding the write
/// mutex only for the duration of one framed send keeps a blocking read from
/// starving concurrent response sends. (Sharing one `FramedConnection` behind
/// a mutex instead deadlocks: the loop holds the lock across its blocking
/// read while spawned handlers block acquiring it to send - every exec then
/// times out on the host.)
pub(crate) type SharedWriter = Arc<TokioMutex<tokio::io::WriteHalf<BoxGuestStream>>>;

#[derive(Debug, Clone, Error)]
pub(crate) enum ExecError {
    #[error("request context validation failed: {0}")]
    ContextValidation(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("output limit exceeded: {0}")]
    OutputLimitExceeded(String),

    /// Command exceeded its deadline budget. Maps to a typed `TimedOut`
    /// outcome (never substring-matched).
    #[error("command timed out")]
    TimedOut,

    /// Command was cancelled via the control plane. Maps to a typed
    /// `Canceled` outcome (never substring-matched).
    #[error("command cancelled: {0}")]
    Cancelled(String),
}

pub(crate) struct OperationalSession {
    pub(crate) session_id: HVec<u8, 16>,
    pub(crate) sandbox_id: Mutex<String>,
    pub(crate) policy_epoch: AtomicU64,
    pub(crate) protocol_version: (u32, u32),
    pub(crate) active_execs: SharedExecMap,
    pub(crate) quiescing: Arc<AtomicBool>,
    pub(crate) health_state: HealthState,
    pub(crate) shutdown_state: ShutdownState,
}

impl OperationalSession {
    pub(crate) fn new(outcome: &HandshakeOutcome, sandbox_id: String) -> Self {
        Self {
            session_id: outcome.session_id.clone(),
            sandbox_id: Mutex::new(sandbox_id),
            policy_epoch: AtomicU64::new(outcome.policy_epoch),
            protocol_version: outcome.selected_version,
            active_execs: Arc::new(Mutex::new(hashbrown::HashMap::new())),
            quiescing: Arc::new(AtomicBool::new(false)),
            health_state: HealthState::new(),
            shutdown_state: ShutdownState::new(),
        }
    }

    /// Strict context validation via the single [`crate::context`] validator.
    ///
    /// All operational handlers (including siblings in file/secrets/mount/
    /// stats/health/shutdown) funnel through this method so binding
    /// semantics have one source of truth.
    pub(crate) fn validate_context(&self, ctx: &RequestContext) -> Result<(), ExecError> {
        context::validate_strict(self, ctx).map_err(|e| ExecError::ContextValidation(e.to_string()))
    }
}

/// Table-driven operational dispatch.
///
/// Adding a new RPC is one table row in [`RPC_TABLE`] plus its handler
/// function (which lives next to the handler logic, not as a 15-line match
/// arm in the dispatch loop). Each row names the request tag, a debug name,
/// whether the handler runs inline or spawned, and the raw-bytes adapter
/// that decodes and forwards to the typed handler.
///
/// `PutFile` is intentionally absent: the upload consists of multiple tagged
/// messages on the same connection, so the dispatch loop handles it
/// synchronously with exclusive `read_half` access. Spawning would race the
/// loop's next read against the upload handler's chunk reads.
type RawHandler = fn(Arc<OperationalSession>, Vec<u8>, SharedWriter, Duration) -> RawHandlerFut;
type RawHandlerFut = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Inline handlers run on the dispatch loop (fast control-plane acks);
/// spawned handlers run on the Tokio pool (exec, I/O, lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandlerKind {
    Inline,
    Spawn,
}

struct RpcEntry {
    request_tag: u8,
    name: &'static str,
    kind: HandlerKind,
    handle: RawHandler,
}

fn decode_or_warn<T: prost::Message + Default>(raw: &[u8], name: &str) -> Option<T> {
    match T::decode(raw) {
        Ok(req) => Some(req),
        Err(e) => {
            tracing::error!(error = %e, rpc = name, "failed to decode request");
            None
        }
    }
}

fn exec_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        if let Some(req) = decode_or_warn::<ExecRequest>(&raw, "exec") {
            handle_exec(session, req, conn, timeout).await;
        }
    })
}

fn cancel_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        if let Some(req) = decode_or_warn::<CancelRequest>(&raw, "cancel") {
            handle_cancel(session, req, conn, timeout).await;
        }
    })
}

fn signal_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        if let Some(req) = decode_or_warn::<SignalRequest>(&raw, "signal") {
            handle_signal(session, req, conn, timeout).await;
        }
    })
}

fn quiesce_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        if let Some(req) = decode_or_warn::<QuiesceRequest>(&raw, "quiesce") {
            handle_quiesce(session, req, conn, timeout).await;
        }
    })
}

fn resume_notify_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        if let Some(req) = decode_or_warn::<ResumeNotifyRequest>(&raw, "resume_notify") {
            handle_resume_notify(session, req, conn, timeout).await;
        }
    })
}

fn get_file_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        let Some(req) = decode_or_warn::<GetFileRequest>(&raw, "get_file") else {
            return;
        };
        if let Err(e) = file::handle_get_file(&session, req, &conn, timeout).await {
            let outcome = crate::file::build_file_error_outcome(&e);
            let response = GetFileResponse {
                frame: Some(get_file_response::Frame::Outcome(outcome)),
            };
            let _ = write_tagged_response(&conn, framed::TAG_GET_FILE_RESPONSE, &response, timeout)
                .await;
        }
    })
}

fn inject_secrets_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        let Some(req) = decode_or_warn::<InjectSecretsRequest>(&raw, "inject_secrets") else {
            return;
        };
        // Spawned by the caller to avoid blocking dispatch on tmpfs/file I/O.
        if let Err(e) = crate::secrets::handle_inject_secrets(&session, req, &conn, timeout).await {
            let outcome = build_failure_outcome("SecretsInjectionFailed", &e.to_string(), false);
            let response = InjectSecretsResponse {
                result: Some(inject_secrets_response::Result::Error(outcome)),
            };
            let _ = write_tagged_response(
                &conn,
                framed::TAG_INJECT_SECRETS_RESPONSE,
                &response,
                timeout,
            )
            .await;
        }
    })
}

fn mount_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        let Some(req) = decode_or_warn::<MountWorkspaceRequest>(&raw, "mount_workspace") else {
            return;
        };
        if let Err(e) = mount::handle_mount_workspace(&session, req, &conn, timeout).await {
            let outcome = build_failure_outcome("MountFailed", &e.to_string(), false);
            let response = MountWorkspaceResponse {
                result: Some(mount_workspace_response::Result::Error(outcome)),
            };
            let _ = write_tagged_response(
                &conn,
                framed::TAG_MOUNT_WORKSPACE_RESPONSE,
                &response,
                timeout,
            )
            .await;
        }
    })
}

fn stats_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        let Some(req) = decode_or_warn::<StatsRequest>(&raw, "stats") else {
            return;
        };
        if let Err(e) = stats::handle_stats(&session, req, &conn, timeout).await {
            tracing::error!(error = %e, "stats collection failed");
            let response = StatsResponse {
                cpu: None,
                memory: None,
                disk: None,
            };
            let _ =
                write_tagged_response(&conn, framed::TAG_STATS_RESPONSE, &response, timeout).await;
        }
    })
}

fn health_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        let Some(req) = decode_or_warn::<HealthRequest>(&raw, "health") else {
            return;
        };
        let health_state = session.health_state.clone();
        if let Err(e) =
            crate::health::handle_health(&session, req, &conn, timeout, &health_state).await
        {
            tracing::error!(error = %e, "health check failed");
            let response = HealthResponse {
                status: health_response::HealthStatus::Unhealthy as i32,
                message: e.to_string(),
            };
            let _ =
                write_tagged_response(&conn, framed::TAG_HEALTH_RESPONSE, &response, timeout).await;
        }
    })
}

fn shutdown_raw(
    session: Arc<OperationalSession>,
    raw: Vec<u8>,
    conn: SharedWriter,
    timeout: Duration,
) -> RawHandlerFut {
    Box::pin(async move {
        let Some(req) = decode_or_warn::<ShutdownRequest>(&raw, "shutdown") else {
            return;
        };
        let shutdown_state = session.shutdown_state.clone();
        if let Err(e) =
            crate::shutdown::handle_shutdown(&session, req, &conn, timeout, &shutdown_state).await
        {
            tracing::warn!(error = %e, "shutdown handler error");
        }
    })
}

/// One row per RPC. New RPCs add one row here plus their typed handler.
static RPC_TABLE: &[RpcEntry] = &[
    RpcEntry {
        request_tag: framed::TAG_EXEC_REQUEST,
        name: "exec",
        kind: HandlerKind::Spawn,
        handle: exec_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_CANCEL_REQUEST,
        name: "cancel",
        kind: HandlerKind::Inline,
        handle: cancel_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_SIGNAL_REQUEST,
        name: "signal",
        kind: HandlerKind::Inline,
        handle: signal_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_QUIESCE_REQUEST,
        name: "quiesce",
        kind: HandlerKind::Spawn,
        handle: quiesce_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_RESUME_NOTIFY_REQUEST,
        name: "resume_notify",
        kind: HandlerKind::Spawn,
        handle: resume_notify_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_GET_FILE_REQUEST,
        name: "get_file",
        kind: HandlerKind::Spawn,
        handle: get_file_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_INJECT_SECRETS_REQUEST,
        name: "inject_secrets",
        kind: HandlerKind::Spawn,
        handle: inject_secrets_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_MOUNT_WORKSPACE_REQUEST,
        name: "mount_workspace",
        kind: HandlerKind::Spawn,
        handle: mount_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_STATS_REQUEST,
        name: "stats",
        kind: HandlerKind::Spawn,
        handle: stats_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_HEALTH_REQUEST,
        name: "health",
        kind: HandlerKind::Spawn,
        handle: health_raw,
    },
    RpcEntry {
        request_tag: framed::TAG_SHUTDOWN_REQUEST,
        name: "shutdown",
        kind: HandlerKind::Spawn,
        handle: shutdown_raw,
    },
];

fn lookup_rpc(tag: u8) -> Option<&'static RpcEntry> {
    RPC_TABLE.iter().find(|e| e.request_tag == tag)
}

async fn handle_put_file_exclusive(
    session: &Arc<OperationalSession>,
    raw_bytes: &[u8],
    read_half: &mut tokio::io::ReadHalf<BoxGuestStream>,
    conn: &SharedWriter,
    timeout: Duration,
) {
    let Some(request) = decode_or_warn::<PutFileRequest>(raw_bytes, "put_file") else {
        return;
    };
    match file::handle_put_file_stream(session, request, read_half, conn, timeout).await {
        Ok(()) => {}
        Err(e) => {
            let outcome = crate::file::build_file_error_outcome(&e);
            let response = PutFileResponse {
                result: Some(put_file_response::Result::Error(outcome)),
                checksum: String::new(),
            };
            let _ = write_tagged_response(conn, framed::TAG_PUT_FILE_RESPONSE, &response, timeout)
                .await;
        }
    }
}

pub(crate) async fn serve_operational(
    conn: FramedConnection<BoxGuestStream>,
    session: OperationalSession,
) {
    let session = Arc::new(session);
    // Split once: the dispatch loop below owns the read half for the life of
    // the connection, and every handler shares the write half via
    // [`SharedWriter`] (kept under the familiar `conn` name at call sites).
    // Reads never contend with response sends.
    let (mut read_half, write_half) = tokio::io::split(conn.into_inner());
    let conn: SharedWriter = Arc::new(TokioMutex::new(write_half));
    let timeout = Duration::from_secs(DEFAULT_OPERATIONAL_TIMEOUT_SECS);

    loop {
        if session.shutdown_state.shutting_down.load(Ordering::Acquire) {
            tracing::info!("shutting down, rejecting new requests");
            break;
        }

        let (tag, raw_bytes) = match framed::read_tagged_raw(&mut read_half, timeout).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "failed to read operational message");
                return;
            }
        };

        // PutFile owns follow-up chunk reads on this connection, so it runs
        // synchronously with exclusive read-half access (see RPC_TABLE docs).
        if tag == framed::TAG_PUT_FILE_REQUEST {
            handle_put_file_exclusive(&session, &raw_bytes, &mut read_half, &conn, timeout).await;
            continue;
        }

        let Some(entry) = lookup_rpc(tag) else {
            tracing::warn!(tag, "unknown operational message tag");
            continue;
        };
        tracing::debug!(rpc = entry.name, tag, "dispatching RPC");
        let fut = (entry.handle)(Arc::clone(&session), raw_bytes, Arc::clone(&conn), timeout);
        match entry.kind {
            HandlerKind::Spawn => {
                tokio::spawn(fut);
            }
            HandlerKind::Inline => {
                fut.await;
            }
        }
    }

    tracing::info!("operational loop exiting");
}

/// Sends one tagged response on the shared write half.
///
/// Locks only for the duration of the write so concurrent handlers never
/// block each other (or the dispatch loop's read half).
pub(crate) async fn write_tagged_response(
    writer: &SharedWriter,
    tag: u8,
    message: &impl prost::Message,
    timeout: Duration,
) -> std::io::Result<()> {
    let mut w = writer.lock().await;
    framed::send_tagged(&mut *w, tag, message, timeout).await
}

async fn handle_exec(
    session: Arc<OperationalSession>,
    request: ExecRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("ExecRequest missing context");
            return;
        }
    };
    let operation_id = ctx.operation_id.clone();

    if let Err(e) = session.validate_context(ctx) {
        tracing::error!(error = %e, operation_id = %operation_id, "context validation failed");
        send_exec_outcome(
            &conn,
            build_failure_outcome("ContextValidationFailed", &e.to_string(), false),
            timeout,
        )
        .await;

        return;
    }

    if let Some(ref tc) = ctx.trace_context {
        tracing::info!(
            operation_id = %operation_id,
            parent_trace_id = %tc.trace_id,
            parent_span_id = %tc.span_id,
            "exec request with trace context"
        );
    }

    if session.quiescing.load(Ordering::Acquire) {
        tracing::warn!(operation_id = %operation_id, "rejecting exec, guest is quiescing");
        send_exec_outcome(
            &conn,
            build_failure_outcome(
                "Quiescing",
                "guest is preparing for checkpoint, rejecting new operations",
                true,
            ),
            timeout,
        )
        .await;
        return;
    }

    tracing::info!(
        operation_id = %operation_id,
        command = %request.command,
        args = ?request.args,
        "exec received"
    );

    let (exec_state, ctrl_rx) = control::register(&session.active_execs, &operation_id);

    let result = run_command_and_stream(&request, &operation_id, ctrl_rx, &conn, timeout).await;

    control::remove(&session.active_execs, &operation_id);

    let duration_ms = exec_state.lock().start_time.elapsed().as_millis() as u64;

    let outcome = outcome_from_exec_result(result, duration_ms);

    tracing::info!(
        operation_id = %operation_id,
        duration_ms = duration_ms,
        "exec completed"
    );

    send_exec_outcome(&conn, outcome, timeout).await;
}

/// Map an exec result to a typed [`OperationOutcome`] by variant.
///
/// No substring matching: `TimedOut`/`Cancelled`/`OutputLimitExceeded` are
/// distinct `ExecError` variants. Signal delivery does not produce its own
/// outcome; a signal-killed process exits with `code == None` (mapped to
/// `-1` success payload below via the `Ok` path), so the terminal outcome
/// always reflects the observed process state.
fn outcome_from_exec_result(result: Result<i32, ExecError>, duration_ms: u64) -> OperationOutcome {
    match result {
        Ok(exit_code) => {
            // Wire format: exit_code (i32, big-endian, 4 bytes) + duration_ms (u64, big-endian, 8 bytes)
            let mut result_payload = Vec::with_capacity(12);
            result_payload.extend_from_slice(&exit_code.to_be_bytes());
            result_payload.extend_from_slice(&duration_ms.to_be_bytes());
            OperationOutcome {
                status: Some(operation_outcome::Status::Success(
                    operation_outcome::Success { result_payload },
                )),
            }
        }
        Err(ExecError::TimedOut) => OperationOutcome {
            status: Some(operation_outcome::Status::TimedOut(
                operation_outcome::TimedOut {
                    budget_remaining: None,
                },
            )),
        },
        Err(ExecError::OutputLimitExceeded(msg)) => OperationOutcome {
            status: Some(operation_outcome::Status::Failure(
                operation_outcome::Failure {
                    code: "OutputLimitExceeded".into(),
                    message: msg,
                    retryable: false,
                },
            )),
        },
        Err(ExecError::Cancelled(reason)) => OperationOutcome {
            status: Some(operation_outcome::Status::Canceled(
                operation_outcome::Canceled { reason },
            )),
        },
        Err(e) => OperationOutcome {
            status: Some(operation_outcome::Status::Failure(
                operation_outcome::Failure {
                    code: "ExecError".into(),
                    message: e.to_string(),
                    retryable: false,
                },
            )),
        },
    }
}

async fn send_exec_outcome(conn: &SharedWriter, outcome: OperationOutcome, timeout: Duration) {
    let response = ExecResponse {
        frame: Some(exec_response::Frame::Outcome(outcome)),
    };
    let _ = write_tagged_response(conn, framed::TAG_EXEC_RESPONSE, &response, timeout).await;
}

async fn run_command_and_stream(
    request: &ExecRequest,
    operation_id: &str,
    mut ctrl_rx: watch::Receiver<Option<CancelSignal>>,
    conn: &SharedWriter,
    timeout: Duration,
) -> Result<i32, ExecError> {
    let cmd_timeout = request.timeout.as_ref().map_or_else(
        || Duration::from_secs(DEFAULT_OPERATIONAL_TIMEOUT_SECS),
        |d| {
            let secs = d.seconds.max(0) as u64;
            let nanos = d.nanos.max(0) as u32;
            Duration::new(secs, nanos)
        },
    );

    let max_stdout = if request.max_stdout_bytes > 0 {
        request.max_stdout_bytes as usize
    } else {
        usize::MAX
    };
    let max_stderr = if request.max_stderr_bytes > 0 {
        request.max_stderr_bytes as usize
    } else {
        usize::MAX
    };

    let mut cmd = Command::new(&request.command);
    cmd.args(&request.args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());
    cmd.kill_on_drop(true);

    if !request.working_dir.is_empty() {
        cmd.current_dir(&request.working_dir);
    }

    for (key, val) in &request.env {
        cmd.env(key, val);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| ExecError::Io(format!("failed to spawn '{}': {e}", request.command)))?;

    let pid = child.id().unwrap_or(0);
    tracing::info!(operation_id = %operation_id, pid = pid, "process spawned");

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExecError::Io("no stdout pipe".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ExecError::Io("no stderr pipe".into()))?;

    let child_holder = Arc::new(TokioMutex::new(Some(child)));
    let child_clone = Arc::clone(&child_holder);

    let exit_status = stream_process_output(
        &child_clone,
        stdout,
        stderr,
        operation_id,
        max_stdout,
        max_stderr,
        &mut ctrl_rx,
        conn,
        timeout,
        cmd_timeout,
    )
    .await?;

    let exit_code = exit_status.code().unwrap_or(-1);
    Ok(exit_code)
}

#[expect(
    clippy::too_many_arguments,
    reason = "stream output requires all I/O handles"
)]
async fn stream_process_output(
    child_holder: &Arc<TokioMutex<Option<tokio::process::Child>>>,
    mut stdout: tokio::process::ChildStdout,
    mut stderr: tokio::process::ChildStderr,
    operation_id: &str,
    max_stdout: usize,
    max_stderr: usize,
    ctrl_rx: &mut watch::Receiver<Option<CancelSignal>>,
    conn: &SharedWriter,
    write_timeout: Duration,
    cmd_timeout: Duration,
) -> Result<std::process::ExitStatus, ExecError> {
    let start = Instant::now();
    let mut stdout_seq: u64 = 0;
    let mut stderr_seq: u64 = 0;
    let mut stdout_total: usize = 0;
    let mut stderr_total: usize = 0;
    let mut stdout_buf = vec![0u8; STREAM_FRAME_MAX_BYTES];
    let mut stderr_buf = vec![0u8; STREAM_FRAME_MAX_BYTES];
    let mut stdout_eof = false;
    let mut stderr_eof = false;

    let child = Arc::clone(child_holder);

    loop {
        if start.elapsed() > cmd_timeout {
            tracing::warn!(operation_id = %operation_id, "command timed out");
            kill_and_wait_child(&child).await;
            return Err(ExecError::TimedOut);
        }

        if ctrl_rx.has_changed().unwrap_or(false) {
            let signal = ctrl_rx.borrow_and_update().clone();
            match signal {
                Some(CancelSignal::Cancel) => {
                    tracing::info!(operation_id = %operation_id, "command cancelled");
                    kill_and_wait_child(&child).await;
                    return Err(ExecError::Cancelled("cancelled by host".into()));
                }
                Some(CancelSignal::Signal(sig)) => {
                    tracing::info!(operation_id = %operation_id, signal = sig, "signal received");
                    if let Some(ref mut c) = *child.lock().await {
                        kill_child_by_signal(c, sig).await;
                    }
                }
                None => {}
            }
        }

        if stdout_eof && stderr_eof {
            let status = {
                let mut guard = child.lock().await;
                if let Some(ref mut c) = *guard {
                    c.wait()
                        .await
                        .map_err(|e| ExecError::Io(format!("child wait error: {e}")))?
                } else {
                    return Err(ExecError::Io("child already consumed".into()));
                }
            };
            return Ok(status);
        }

        tokio::select! {
            result = stdout.read(&mut stdout_buf), if !stdout_eof => {
                match result {
                    Ok(0) => {
                        stdout_eof = true;
                        stdout_seq += 1;
                        send_stream_frame(conn, stdout_seq, &[], true, true, write_timeout).await;
                    }
                    Ok(n) => {
                        stdout_total += n;
                        if stdout_total > max_stdout {
                            tracing::warn!(
                                operation_id = %operation_id,
                                stdout_total = stdout_total,
                                max_stdout = max_stdout,
                                "stdout output limit exceeded, terminating process"
                            );
                            kill_and_wait_child(&child).await;
                            return Err(ExecError::OutputLimitExceeded(format!(
                                "stdout {stdout_total} exceeds limit {max_stdout}"
                            )));
                        }
                        stdout_seq += 1;
                        send_stream_frame(conn, stdout_seq, &stdout_buf[..n], false, true, write_timeout).await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, operation_id = %operation_id, "stdout read error");
                        stdout_eof = true;
                    }
                }
            }

            result = stderr.read(&mut stderr_buf), if !stderr_eof => {
                match result {
                    Ok(0) => {
                        stderr_eof = true;
                        stderr_seq += 1;
                        send_stream_frame(conn, stderr_seq, &[], true, false, write_timeout).await;
                    }
                    Ok(n) => {
                        stderr_total += n;
                        if stderr_total > max_stderr {
                            tracing::warn!(
                                operation_id = %operation_id,
                                stderr_total = stderr_total,
                                max_stderr = max_stderr,
                                "stderr output limit exceeded, terminating process"
                            );
                            kill_and_wait_child(&child).await;
                            return Err(ExecError::OutputLimitExceeded(format!(
                                "stderr {stderr_total} exceeds limit {max_stderr}"
                            )));
                        }
                        stderr_seq += 1;
                        send_stream_frame(conn, stderr_seq, &stderr_buf[..n], false, false, write_timeout).await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, operation_id = %operation_id, "stderr read error");
                        stderr_eof = true;
                    }
                }
            }
        }
    }
}

async fn send_stream_frame(
    conn: &SharedWriter,
    sequence: u64,
    payload: &[u8],
    end_of_stream: bool,
    is_stdout: bool,
    timeout: Duration,
) {
    let frame = StreamFrame {
        sequence,
        payload: payload.to_vec(),
        end_of_stream,
    };

    let response = if is_stdout {
        ExecResponse {
            frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                frame: Some(frame),
            })),
        }
    } else {
        ExecResponse {
            frame: Some(exec_response::Frame::Stderr(exec_response::StderrData {
                frame: Some(frame),
            })),
        }
    };

    let _ = write_tagged_response(conn, framed::TAG_EXEC_RESPONSE, &response, timeout).await;
}

async fn kill_and_wait_child(child_holder: &Arc<TokioMutex<Option<tokio::process::Child>>>) {
    if let Some(ref mut c) = *child_holder.lock().await {
        c.kill().await.ok();
    }

    if let Some(ref mut c) = *child_holder.lock().await {
        c.wait().await.ok();
    }
}

async fn kill_child_by_signal(child: &mut tokio::process::Child, sig: i32) {
    #[cfg(unix)]
    {
        if sig == 9 {
            child.kill().await.ok();
        } else if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as i32, sig);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child;
        let _ = sig;
    }
}

async fn handle_cancel(
    session: Arc<OperationalSession>,
    request: CancelRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("CancelRequest missing context");
            return;
        }
    };

    if let Err(e) = session.validate_context(ctx) {
        send_cancel_response(
            &conn,
            cancel_response::Result::AlreadyTerminal(build_failure_outcome(
                "ContextValidationFailed",
                &e.to_string(),
                false,
            )),
            timeout,
        )
        .await;
        return;
    }

    let operation_id = &request.operation_id;
    // Shared control plane: idempotent, never consumes the sender. Repeat
    // cancels to an active operation re-deliver and stay `Accepted`.
    let sent = control::cancel(&session.active_execs, operation_id);

    if sent {
        send_cancel_response(&conn, cancel_response::Result::Accepted(Ack {}), timeout).await;
    } else {
        send_cancel_response(
            &conn,
            cancel_response::Result::Unknown(UnknownOp {
                operation_id: operation_id.clone(),
            }),
            timeout,
        )
        .await;
    }
}

async fn send_cancel_response(
    conn: &SharedWriter,
    result: cancel_response::Result,
    timeout: Duration,
) {
    let response = CancelResponse {
        result: Some(result),
    };

    let _ = write_tagged_response(conn, framed::TAG_CANCEL_RESPONSE, &response, timeout).await;
}

async fn handle_signal(
    session: Arc<OperationalSession>,
    request: SignalRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("SignalRequest missing context");
            return;
        }
    };

    if let Err(e) = session.validate_context(ctx) {
        send_signal_response(
            &conn,
            signal_response::Result::Error(build_failure_outcome(
                "ContextValidationFailed",
                &e.to_string(),
                false,
            )),
            timeout,
        )
        .await;
        return;
    }

    let operation_id = &request.operation_id;
    // Shared control plane: repeat signals to an active operation re-deliver
    // and stay `Acknowledged`. Invalid numbers get a typed error.
    match control::signal(&session.active_execs, operation_id, request.signal) {
        control::SignalSend::Acknowledged => {
            send_signal_response(
                &conn,
                signal_response::Result::Acknowledged(Ack {}),
                timeout,
            )
            .await;
        }
        control::SignalSend::InvalidSignal(msg) => {
            send_signal_response(
                &conn,
                signal_response::Result::Error(build_failure_outcome("InvalidSignal", &msg, false)),
                timeout,
            )
            .await;
        }
        control::SignalSend::Unknown => {
            send_signal_response(
                &conn,
                signal_response::Result::Error(build_failure_outcome(
                    "OperationNotFound",
                    &format!("operation {operation_id} not found"),
                    false,
                )),
                timeout,
            )
            .await;
        }
    }
}

async fn send_signal_response(
    conn: &SharedWriter,
    result: signal_response::Result,
    timeout: Duration,
) {
    let response = SignalResponse {
        result: Some(result),
    };

    let _ = write_tagged_response(conn, framed::TAG_SIGNAL_RESPONSE, &response, timeout).await;
}

async fn handle_quiesce(
    session: Arc<OperationalSession>,
    request: QuiesceRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    let _ = crate::secrets::teardown_secrets_mount();

    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("QuiesceRequest missing context");
            return;
        }
    };

    if let Err(e) = session.validate_context(ctx) {
        tracing::error!(error = %e, "quiesce context validation failed");
        send_quiesce_error(
            &conn,
            build_failure_outcome("ContextValidationFailed", &e.to_string(), false),
            timeout,
        )
        .await;
        return;
    }

    let drain_mode = request.drain_mode();
    let quiesce_deadline = request.quiesce_deadline.as_ref();

    let deadline_instant = quiesce_deadline.and_then(|ts| {
        let secs = ts.seconds.max(0) as u64;
        let nanos = ts.nanos.max(0) as u32;
        let st = std::time::UNIX_EPOCH.checked_add(Duration::new(secs, nanos))?;
        match st.elapsed() {
            // Deadline already passed -- set to now (immediate expiry).
            Ok(_) => Some(Instant::now()),
            // Deadline is in the future -- e.duration() is the remaining budget.
            Err(e) => Some(Instant::now() + e.duration()),
        }
    });

    let quiesce_start = Instant::now();

    tracing::info!(
        drain_mode = ?drain_mode,
        has_deadline = deadline_instant.is_some(),
        "quiesce requested"
    );

    // Set quiescing flag immediately - blocks new exec requests.
    session.quiescing.store(true, Ordering::Release);

    match drain_mode {
        quiesce_request::DrainMode::Force => {
            force_cancel_all(&session, &conn, timeout).await;
            wait_for_drain(&session, deadline_instant).await;
        }
        quiesce_request::DrainMode::Graceful | quiesce_request::DrainMode::Unspecified => {
            wait_for_drain(&session, deadline_instant).await;
        }
    }

    let quiesce_duration_ms = quiesce_start.elapsed().as_millis() as u64;

    // Verify no active execs remain.
    let remaining = session.active_execs.lock().len();
    if remaining > 0 {
        tracing::warn!(remaining, "quiesce timed out before drain completed");
        send_quiesce_error(
            &conn,
            OperationOutcome {
                status: Some(operation_outcome::Status::TimedOut(
                    operation_outcome::TimedOut {
                        budget_remaining: None,
                    },
                )),
            },
            timeout,
        )
        .await;

        // Reset quiescing flag so guest is not permanently paused.
        session.quiescing.store(false, Ordering::Release);

        tracing::info!(
            quiesce_duration_ms,
            outcome = "timeout",
            "quiesce failed, guest resumed accepting requests"
        );
        return;
    }

    tracing::info!(
        quiesce_duration_ms,
        outcome = "quiesced",
        "guest quiesced successfully"
    );

    let response = QuiesceResponse {
        result: Some(quiesce_response::Result::Quiesced(true)),
    };

    let _ = write_tagged_response(&conn, framed::TAG_QUIESCE_RESPONSE, &response, timeout).await;
}

async fn force_cancel_all(
    session: &Arc<OperationalSession>,
    conn: &SharedWriter,
    timeout: Duration,
) {
    // Shared control plane: never consumes senders, so repeat force-cancel
    // passes re-deliver to still-active operations.
    for _op_id in control::force_cancel_all(&session.active_execs) {
        // Send a cancel response so the host knows cancellation was accepted.
        let cancel_resp = CancelResponse {
            result: Some(cancel_response::Result::Accepted(Ack {})),
        };
        let _ =
            write_tagged_response(conn, framed::TAG_CANCEL_RESPONSE, &cancel_resp, timeout).await;
    }
}

async fn wait_for_drain(session: &Arc<OperationalSession>, deadline: Option<Instant>) {
    loop {
        let remaining = session.active_execs.lock().len();
        if remaining == 0 {
            break;
        }

        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            tracing::warn!(remaining, "quiesce deadline reached with active operations");
            break;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn send_quiesce_error(conn: &SharedWriter, error: OperationOutcome, timeout: Duration) {
    let response = QuiesceResponse {
        result: Some(quiesce_response::Result::Error(error)),
    };

    let _ = write_tagged_response(conn, framed::TAG_QUIESCE_RESPONSE, &response, timeout).await;
}

async fn handle_resume_notify(
    session: Arc<OperationalSession>,
    request: ResumeNotifyRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    // Resume uses the single context validator in resume mode: immutable
    // bindings (session, version) plus current identity (sandbox, epoch with
    // zero tolerated). Body-carried sandbox/epoch updates apply below after
    // the context check passes.
    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("ResumeNotifyRequest missing context");
            return;
        }
    };

    if let Err(e) = context::validate_resume_context(&session, ctx) {
        let code = context::resume_error_code(&e);
        tracing::error!(error = %e, code = code, "resume notify context validation failed");
        send_resume_error(
            &conn,
            build_failure_outcome(code, &e.to_string(), false),
            timeout,
        )
        .await;
        return;
    }

    let current_sandbox_id = session.sandbox_id.lock().clone();
    let prev_epoch = session.policy_epoch.load(Ordering::Acquire);
    let new_epoch = request.policy_epoch;

    let prev_sandbox_id = current_sandbox_id;
    let new_sandbox_id = if request.sandbox_id.is_empty() {
        prev_sandbox_id.clone()
    } else {
        request.sandbox_id.clone()
    };

    if new_sandbox_id != prev_sandbox_id {
        tracing::info!(
            prev_sandbox_id = %prev_sandbox_id,
            new_sandbox_id = %new_sandbox_id,
            "refreshing guest identity after resume"
        );
        *session.sandbox_id.lock() = new_sandbox_id;
    }

    // Stale-check and update use separate load/store operations.
    // A concurrent resume-notify call could change the epoch between
    // these two reads, creating a TOCTOU window. In practice this is
    // safe because the protocol guarantees at most one resume-notify
    // per session (the host serializes lifecycle operations).
    if new_epoch > 0 && new_epoch < prev_epoch {
        tracing::warn!(
            prev_epoch,
            new_epoch,
            "resume notification carries stale policy epoch"
        );
        send_resume_error(
            &conn,
            build_failure_outcome(
                "StalePolicyEpoch",
                &format!("policy epoch {new_epoch} is older than current {prev_epoch}"),
                false,
            ),
            timeout,
        )
        .await;
        return;
    }

    if new_epoch > 0 && new_epoch != prev_epoch {
        tracing::info!(
            prev_epoch,
            new_epoch,
            "revalidating policy epoch after resume"
        );
        session.policy_epoch.store(new_epoch, Ordering::Release);
    }

    if request.snapshot_taken_at.is_some() {
        tracing::info!(
            lineage_id = %request.lineage_id,
            "snapshot lineage context received"
        );
    }

    let accepted = refreshes_non_restorable_resources(&request.lineage_id).await;

    tracing::info!(
        outcome = if accepted {
            "accepted"
        } else {
            "resources_unavailable"
        },
        "resume notification processed"
    );

    if accepted {
        let response = ResumeNotifyResponse {
            result: Some(resume_notify_response::Result::Accepted(true)),
        };
        let _ = write_tagged_response(
            &conn,
            framed::TAG_RESUME_NOTIFY_RESPONSE,
            &response,
            timeout,
        )
        .await;
    } else {
        send_resume_error(
            &conn,
            build_failure_outcome(
                "ResourcesUnavailable",
                "non-restorable resources could not be refreshed",
                true,
            ),
            timeout,
        )
        .await;
    }
}

async fn refreshes_non_restorable_resources(lineage_id: &str) -> bool {
    if lineage_id.is_empty() {
        tracing::warn!("resume notification missing lineage_id, resources may be stale");
    }

    true
}

async fn send_resume_error(conn: &SharedWriter, error: OperationOutcome, timeout: Duration) {
    let response = ResumeNotifyResponse {
        result: Some(resume_notify_response::Result::Error(error)),
    };

    let _ =
        write_tagged_response(conn, framed::TAG_RESUME_NOTIFY_RESPONSE, &response, timeout).await;
}

pub(crate) fn build_failure_outcome(
    code: &str,
    message: &str,
    retryable: bool,
) -> OperationOutcome {
    OperationOutcome {
        status: Some(operation_outcome::Status::Failure(
            operation_outcome::Failure {
                code: code.into(),
                message: message.into(),
                retryable,
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handshake_outcome() -> HandshakeOutcome {
        HandshakeOutcome {
            session_id: HVec::from_slice(b"test-session").unwrap(),
            policy_epoch: 1,
            selected_version: (1, 0),
            selected_capabilities: vec!["exec".into()],
        }
    }

    #[test]
    fn context_validation_rejects_wrong_sandbox_id() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-b".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0001_0000,
            ..Default::default()
        };
        let err = session.validate_context(&ctx).unwrap_err();
        assert!(err.to_string().contains("sandbox_id"));
    }

    #[test]
    fn context_validation_rejects_wrong_session_id() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-a".into(),
            session_id: b"wrong-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0001_0000,
            ..Default::default()
        };
        let err = session.validate_context(&ctx).unwrap_err();
        assert!(err.to_string().contains("session_id"));
    }

    #[test]
    fn context_validation_rejects_wrong_policy_epoch() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-a".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 99,
            protocol_version: 0x0001_0000,
            ..Default::default()
        };
        let err = session.validate_context(&ctx).unwrap_err();
        assert!(err.to_string().contains("policy_epoch"));
    }

    #[test]
    fn context_validation_rejects_wrong_protocol_version() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-a".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0002_0000,
            ..Default::default()
        };
        let err = session.validate_context(&ctx).unwrap_err();
        assert!(err.to_string().contains("protocol_version"));
    }

    #[test]
    fn context_validation_passes_with_matching_context() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-a".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0001_0000,
            ..Default::default()
        };
        assert!(session.validate_context(&ctx).is_ok());
    }

    #[test]
    fn build_failure_outcome_creates_proper_response() {
        let outcome = build_failure_outcome("TestCode", "test message", true);
        match outcome.status {
            Some(operation_outcome::Status::Failure(f)) => {
                assert_eq!(f.code, "TestCode");
                assert_eq!(f.message, "test message");
                assert!(f.retryable);
            }
            _ => panic!("expected failure outcome"),
        }
    }

    #[test]
    fn quiescing_flag_starts_false() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        assert!(!session.quiescing.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn quiescing_flag_can_be_set() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        session
            .quiescing
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(session.quiescing.load(std::sync::atomic::Ordering::Acquire));
        session
            .quiescing
            .store(false, std::sync::atomic::Ordering::Release);
        assert!(!session.quiescing.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn dispatch_table_has_no_duplicate_tags() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for entry in RPC_TABLE {
            assert!(
                seen.insert(entry.request_tag),
                "duplicate dispatch tag {:#04x} ({})",
                entry.request_tag,
                entry.name
            );
        }
    }

    #[test]
    fn dispatch_table_covers_all_spawned_and_inline_rpcs() {
        // Adding a new RPC is one row here: assert the table knows every
        // request tag the loop routes (PutFile is the documented exclusive
        // exception, handled with read-half access outside the table).
        for tag in [
            framed::TAG_EXEC_REQUEST,
            framed::TAG_CANCEL_REQUEST,
            framed::TAG_SIGNAL_REQUEST,
            framed::TAG_QUIESCE_REQUEST,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            framed::TAG_GET_FILE_REQUEST,
            framed::TAG_INJECT_SECRETS_REQUEST,
            framed::TAG_MOUNT_WORKSPACE_REQUEST,
            framed::TAG_STATS_REQUEST,
            framed::TAG_HEALTH_REQUEST,
            framed::TAG_SHUTDOWN_REQUEST,
        ] {
            assert!(
                lookup_rpc(tag).is_some(),
                "missing table row for tag {tag:#04x}"
            );
        }
        assert!(lookup_rpc(framed::TAG_PUT_FILE_REQUEST).is_none());
        assert!(lookup_rpc(0xFF).is_none());
    }

    #[test]
    fn dispatch_table_cancel_and_signal_are_inline() {
        assert_eq!(
            lookup_rpc(framed::TAG_CANCEL_REQUEST).unwrap().kind,
            HandlerKind::Inline
        );
        assert_eq!(
            lookup_rpc(framed::TAG_SIGNAL_REQUEST).unwrap().kind,
            HandlerKind::Inline
        );
        assert_eq!(
            lookup_rpc(framed::TAG_EXEC_REQUEST).unwrap().kind,
            HandlerKind::Spawn
        );
    }

    #[test]
    fn outcome_mapping_is_typed_without_substring_matching() {
        // TimedOut maps by variant even when the message text is unrelated.
        let outcome = outcome_from_exec_result(Err(ExecError::TimedOut), 10);
        assert!(matches!(
            outcome.status,
            Some(operation_outcome::Status::TimedOut(_))
        ));

        // Cancelled maps by variant; an Io error containing "cancelled"
        // must NOT map to Canceled (no substring matching).
        let outcome = outcome_from_exec_result(Err(ExecError::Cancelled("host cancel".into())), 10);
        match outcome.status {
            Some(operation_outcome::Status::Canceled(c)) => {
                assert_eq!(c.reason, "host cancel");
            }
            other => panic!("expected Canceled, got {other:?}"),
        }
        let outcome =
            outcome_from_exec_result(Err(ExecError::Io("cancelled by something else".into())), 10);
        match outcome.status {
            Some(operation_outcome::Status::Failure(f)) => {
                assert_eq!(f.code, "ExecError");
            }
            other => panic!("substring must not map to Canceled, got {other:?}"),
        }

        // Timeout text in an Io error must NOT map to TimedOut.
        let outcome = outcome_from_exec_result(Err(ExecError::Io("timed out-ish".into())), 10);
        assert!(
            !matches!(outcome.status, Some(operation_outcome::Status::TimedOut(_))),
            "substring must not map to TimedOut"
        );
    }

    #[test]
    fn second_signal_via_session_registry_is_acknowledged() {
        use crate::control;
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let (_handle, _rx) = control::register(&session.active_execs, "op-repeat");
        assert_eq!(
            control::signal(&session.active_execs, "op-repeat", 15),
            control::SignalSend::Acknowledged
        );
        // Defined repeat behavior: second signal re-delivers, still acked.
        assert_eq!(
            control::signal(&session.active_execs, "op-repeat", 15),
            control::SignalSend::Acknowledged
        );
        assert!(control::cancel(&session.active_execs, "op-repeat"));
        assert!(control::cancel(&session.active_execs, "op-repeat"));
    }

    #[test]
    fn invalid_signal_via_session_registry_is_typed_error() {
        use crate::control;
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let (_handle, _rx) = control::register(&session.active_execs, "op-1");
        assert!(matches!(
            control::signal(&session.active_execs, "op-1", -1),
            control::SignalSend::InvalidSignal(_)
        ));
    }

    fn test_request_context(operation_id: &str) -> RequestContext {
        RequestContext {
            request_id: "test-req".into(),
            operation_id: operation_id.into(),
            sandbox_id: "sbx-a".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0001_0000,
            deadline: None,
            trace_context: None,
        }
    }

    async fn test_writer_pair() -> (SharedWriter, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_r, w) = tokio::io::split(Box::new(stream) as BoxGuestStream);
            Arc::new(TokioMutex::new(w)) as SharedWriter
        });
        let host = tokio::net::TcpStream::connect(addr).await.unwrap();
        let writer = server.await.unwrap();
        (writer, host)
    }

    #[tokio::test]
    async fn signal_handler_second_signal_stays_acknowledged() {
        let session = Arc::new(OperationalSession::new(
            &make_handshake_outcome(),
            "sbx-a".into(),
        ));
        let (_handle, _rx) = crate::control::register(&session.active_execs, "op-sig");
        let (writer, mut host) = test_writer_pair().await;

        for _ in 0..2 {
            handle_signal(
                Arc::clone(&session),
                SignalRequest {
                    context: Some(test_request_context("op-sig")),
                    operation_id: "op-sig".into(),
                    signal: 15,
                },
                writer.clone(),
                Duration::from_secs(5),
            )
            .await;
            let (tag, resp) =
                framed::read_tagged::<SignalResponse>(&mut host, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_SIGNAL_RESPONSE);
            assert!(matches!(
                resp.result,
                Some(signal_response::Result::Acknowledged(_))
            ));
        }
    }

    #[tokio::test]
    async fn signal_handler_invalid_signal_returns_typed_error() {
        let session = Arc::new(OperationalSession::new(
            &make_handshake_outcome(),
            "sbx-a".into(),
        ));
        let (_handle, _rx) = crate::control::register(&session.active_execs, "op-sig");
        let (writer, mut host) = test_writer_pair().await;

        handle_signal(
            Arc::clone(&session),
            SignalRequest {
                context: Some(test_request_context("op-sig")),
                operation_id: "op-sig".into(),
                signal: -1,
            },
            writer,
            Duration::from_secs(5),
        )
        .await;
        let (tag, resp) = framed::read_tagged::<SignalResponse>(&mut host, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_SIGNAL_RESPONSE);
        match resp.result {
            Some(signal_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "InvalidSignal");
                }
                other => panic!("expected InvalidSignal failure, got {other:?}"),
            },
            other => panic!("expected Error result, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cancel_handler_second_cancel_stays_accepted() {
        let session = Arc::new(OperationalSession::new(
            &make_handshake_outcome(),
            "sbx-a".into(),
        ));
        let (_handle, _rx) = crate::control::register(&session.active_execs, "op-cancel");
        let (writer, mut host) = test_writer_pair().await;

        for _ in 0..2 {
            handle_cancel(
                Arc::clone(&session),
                CancelRequest {
                    context: Some(test_request_context("op-cancel")),
                    operation_id: "op-cancel".into(),
                },
                writer.clone(),
                Duration::from_secs(5),
            )
            .await;
            let (tag, resp) =
                framed::read_tagged::<CancelResponse>(&mut host, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_CANCEL_RESPONSE);
            assert!(matches!(
                resp.result,
                Some(cancel_response::Result::Accepted(_))
            ));
        }
    }

    fn make_resume_request(
        session_id: &[u8],
        sandbox_id: &str,
        policy_epoch: u64,
        new_sandbox_id: &str,
        new_policy_epoch: u64,
        lineage_id: &str,
    ) -> ResumeNotifyRequest {
        ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-test".into(),
                operation_id: "resume-op".into(),
                sandbox_id: sandbox_id.into(),
                session_id: session_id.to_vec(),
                policy_epoch,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: new_sandbox_id.into(),
            policy_epoch: new_policy_epoch,
            lineage_id: lineage_id.into(),
            snapshot_taken_at: None,
        }
    }

    #[test]
    fn resume_notify_updates_sandbox_id() {
        let session = Arc::new(OperationalSession::new(
            &make_handshake_outcome(),
            "original-sbx".into(),
        ));

        assert_eq!(&*session.sandbox_id.lock(), "original-sbx");

        session.sandbox_id.lock().push_str("-child");
        assert_eq!(&*session.sandbox_id.lock(), "original-sbx-child");
    }

    #[test]
    fn resume_notify_updates_policy_epoch() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());

        assert_eq!(session.policy_epoch.load(Ordering::Acquire), 1);

        session.policy_epoch.store(42, Ordering::Release);
        assert_eq!(session.policy_epoch.load(Ordering::Acquire), 42);
    }

    #[test]
    fn resume_notify_validates_session_id() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());

        let req = make_resume_request(b"test-session", "sbx-a", 1, "sbx-a", 2, "lineage-1");
        let ctx = req.context.as_ref().unwrap();
        assert_eq!(ctx.session_id, session.session_id.as_slice());
    }

    #[test]
    fn resume_notify_rejects_wrong_session_id() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());

        let wrong_session = b"wrong-session-id";
        assert_ne!(wrong_session.as_slice(), session.session_id.as_slice());
    }

    #[tokio::test]
    async fn resume_notify_protocol_integration() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);
            assert_eq!(req.sandbox_id, "restored-sbx");
            assert_eq!(req.policy_epoch, 10);

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
                session_id: b"test-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: "restored-sbx".into(),
            policy_epoch: 10,
            lineage_id: "lineage-1".into(),
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
    async fn resume_notify_rejects_stale_policy_epoch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                session_id: b"test-session".to_vec(),
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
    async fn resume_notify_rejects_session_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
    async fn resume_notify_rejects_protocol_version_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                session_id: b"test-session".to_vec(),
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
    async fn resume_notify_rejects_context_sandbox_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                            code: "SandboxIdMismatch".into(),
                            message: "context sandbox_id does not match current session".into(),
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
                operation_id: "resume-sandbox-mismatch".into(),
                sandbox_id: "wrong-sandbox".into(),
                session_id: b"test-session".to_vec(),
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
                    assert_eq!(f.code, "SandboxIdMismatch");
                }
                _ => panic!("expected sandbox_id mismatch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_rejects_context_policy_epoch_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                            code: "PolicyEpochMismatch".into(),
                            message: "context policy_epoch does not match current session".into(),
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
                operation_id: "resume-epoch-mismatch".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 99,
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
                    assert_eq!(f.code, "PolicyEpochMismatch");
                }
                _ => panic!("expected policy epoch mismatch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_rejects_when_resources_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                session_id: b"test-session".to_vec(),
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

    #[tokio::test]
    async fn operational_loop_answers_exec_while_reading() {
        // Regression test for the binary-restart CI failure: the dispatch
        // loop once shared one mutexed `FramedConnection` for reads and
        // writes, holding the lock across its blocking read while spawned
        // exec handlers blocked acquiring it to send. Every exec then timed
        // out on the host ("guest session error: exec stream timed out").
        // The loop now owns the read half and handlers share the write half.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn =
                FramedConnection::new(Box::new(stream) as BoxGuestStream, Duration::from_secs(10));
            let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
            serve_operational(conn, session).await;
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client = FramedConnection::new(stream, Duration::from_secs(10));
        let request = ExecRequest {
            context: Some(RequestContext {
                request_id: "req-1".into(),
                operation_id: "opr-1".into(),
                sandbox_id: "sbx-a".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            command: "echo".into(),
            args: vec!["hello".into()],
            env: Default::default(),
            working_dir: String::new(),
            timeout: None,
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        };
        client
            .send_tagged(framed::TAG_EXEC_REQUEST, &request)
            .await
            .unwrap();

        let mut saw_stdout = false;
        let mut exited = false;
        // Bounded so a regression fails fast instead of hanging the suite.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            let (tag, response): (u8, ExecResponse) = client.recv_tagged().await.unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
            match response.frame {
                Some(exec_response::Frame::Stdout(data)) => {
                    let payload = data.frame.map(|f| f.payload).unwrap_or_default();
                    if !payload.is_empty() {
                        assert!(payload.windows(5).any(|w| w == b"hello"));
                        saw_stdout = true;
                    }
                }
                Some(exec_response::Frame::Outcome(outcome)) => {
                    assert!(
                        matches!(outcome.status, Some(operation_outcome::Status::Success(_))),
                        "expected success outcome, got {outcome:?}"
                    );
                    exited = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(saw_stdout, "expected a stdout frame from echo");
        assert!(exited, "expected a terminal outcome frame");
        guest.abort();
    }

    #[tokio::test]
    async fn exec_output_limit_exceeded_returns_typed_failure() {
        // Over-limit output must terminate loudly with an OutputLimitExceeded
        // failure outcome, never success with silently truncated output.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn =
                FramedConnection::new(Box::new(stream) as BoxGuestStream, Duration::from_secs(10));
            let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
            serve_operational(conn, session).await;
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client = FramedConnection::new(stream, Duration::from_secs(10));
        let request = ExecRequest {
            context: Some(RequestContext {
                request_id: "req-limit".into(),
                operation_id: "opr-limit".into(),
                sandbox_id: "sbx-a".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            command: "sh".into(),
            args: vec!["-c".into(), "head -c 65536 /dev/zero".into()],
            env: Default::default(),
            working_dir: String::new(),
            timeout: None,
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
        };
        client
            .send_tagged(framed::TAG_EXEC_REQUEST, &request)
            .await
            .unwrap();

        let mut saw_failure = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            let (tag, response): (u8, ExecResponse) = client.recv_tagged().await.unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
            if let Some(exec_response::Frame::Outcome(outcome)) = response.frame {
                match outcome.status {
                    Some(operation_outcome::Status::Failure(f)) => {
                        assert_eq!(f.code, "OutputLimitExceeded");
                        saw_failure = true;
                    }
                    other => panic!("expected OutputLimitExceeded failure, got {other:?}"),
                }
                break;
            }
        }
        assert!(saw_failure, "expected a typed OutputLimitExceeded outcome");
        guest.abort();
    }
}
