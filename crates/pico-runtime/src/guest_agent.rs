//! Guest-agent session management for runtime adapters.
//!
//! Single wire format: length-prefixed protobuf over TCP (tests) or vsock
//! (production). The JSON-RPC path has been removed. Readiness is proven by
//! completing the bootstrap handshake - a sandbox is not Ready until the
//! session exists.

use std::net::SocketAddr;
use std::time::Duration;

use pico_core::runtime::{BackendError, BackendOperation, NonReadyReason};
use pico_core::{ExecRequest, ExecResponse, Result, SandboxError};
use pico_guest_protocol::{GuestSession, HandshakeConfig, SessionError};
use tokio::net::TcpStream;

/// Default capabilities the host offers during handshake.
const HOST_CAPABILITIES: &[&str] = &["exec", "file", "mount", "stats", "health", "shutdown"];

/// Builds a handshake config for a runtime adapter connecting to a guest.
pub fn session_config(addr: SocketAddr, sandbox_id: &str) -> HandshakeConfig {
    HandshakeConfig {
        sandbox_id: sandbox_id.into(),
        image_id: String::new(),
        image_digest: String::new(),
        host_agent_version: env!("CARGO_PKG_VERSION").into(),
        host_capabilities: HOST_CAPABILITIES.iter().map(|s| s.to_string()).collect(),
        transport_addr: addr,
        timeout: Duration::from_secs(30),
        policy_epoch: 1,
    }
}

/// Establishes a guest session (connect + handshake).
///
/// The handshake IS the readiness proof: if it completes, the guest agent
/// is up, authenticated, and operational. No separate probe is needed.
pub async fn establish_session(
    addr: SocketAddr,
    sandbox_id: &str,
) -> std::result::Result<GuestSession<TcpStream>, SessionError> {
    let config = session_config(addr, sandbox_id);
    GuestSession::connect_tcp(&config).await
}

/// Maps a session establishment failure to [`BackendError::NotReady`].
///
/// Transient transport failures (`ConnectionRefused`, `Timeout`, `Io`)
/// become [`NonReadyReason::Timeout`]; terminal handshake violations (proof,
/// version, identity, rejection) become [`NonReadyReason::Protocol`]. The
/// original variant is always preserved in the message via
/// [`SessionError::kind`], and a structured event is emitted so failed
/// handshakes are visible to metrics and alerting rather than being folded
/// into an opaque string.
pub fn not_ready_error(op: BackendOperation, err: &SessionError) -> BackendError {
    let reason = match err {
        SessionError::Handshake(e) if e.is_retryable() => NonReadyReason::Timeout,
        _ => NonReadyReason::Protocol,
    };
    tracing::warn!(
        operation = %op,
        error_kind = err.kind(),
        error = %err,
        "guest session establishment failed"
    );
    BackendError::NotReady {
        operation: op,
        reason,
        message: format!("guest session {}: {err}", err.kind()),
    }
}

/// Maps a session operation failure to [`BackendError::Failed`], preserving
/// the original variant in the message and emitting a structured event.
pub fn failed_operation_error(op: BackendOperation, err: &SessionError) -> BackendError {
    tracing::warn!(
        operation = %op,
        error_kind = err.kind(),
        error = %err,
        "guest session operation failed"
    );
    BackendError::Failed {
        operation: op,
        message: format!("guest session {}: {err}", err.kind()),
    }
}

/// Executes a command through an established guest session.
///
/// Converts between `pico_core::ExecRequest`/`ExecResponse` and the
/// protocol-level types.
pub async fn session_exec(
    session: &mut GuestSession<TcpStream>,
    req: &ExecRequest,
) -> Result<ExecResponse> {
    let env = req
        .env
        .as_ref()
        .map(|e| {
            e.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<hashbrown::HashMap<_, _>>()
        })
        .unwrap_or_default();

    let timeout = req.timeout_secs.map(Duration::from_secs);
    let operation_id = ulid::Ulid::generate().to_string();

    let result = session
        .exec(
            &req.command,
            &req.args,
            &env,
            req.working_dir.as_deref().unwrap_or("/"),
            &operation_id,
            timeout,
        )
        .await
        .map_err(|e| {
            let kind = e.kind();
            tracing::warn!(
                error_kind = kind,
                error = %e,
                command = %req.command,
                "guest session exec failed"
            );
            SandboxError::Other(format!("guest session exec failed ({kind}): {e}"))
        })?;

    Ok(ExecResponse {
        exit_code: result.exit_code,
        stdout: String::from_utf8_lossy(&result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).to_string(),
        duration_ms: result.duration_ms,
    })
}

// ── Mock guest agent (framed protocol, used by backend tests) ──

/// Spawns a mock guest agent that speaks the framed protobuf protocol.
///
/// Handles the full bootstrap handshake (deriving the shared secret from
/// the HostHello's sandbox_id, so one mock serves any test) and exec
/// requests by running commands locally. Returns the bound address.
///
/// This is the TCP test adapter; production uses vsock via the same
/// `GuestSession` type.
pub fn spawn_mock_guest_agent() -> SocketAddr {
    spawn_mock_impl(false)
}

/// Spawns a mock guest agent that closes the TCP connection (without any
/// response) on the first exec request it receives, then behaves normally
/// on subsequent connections. Used to verify that adapters drop a poisoned
/// session and re-handshake after an exec failure.
pub fn spawn_mock_guest_agent_drop_first_exec() -> SocketAddr {
    spawn_mock_impl(true)
}

fn spawn_mock_impl(drop_first_exec: bool) -> SocketAddr {
    use pico_guest_protocol::{FramedConnection, framed, operational_v1};

    let (tx, rx) = std::sync::mpsc::channel::<SocketAddr>();
    let conn_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let _ = tx.send(addr);

            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let conn_index = conn_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                tokio::spawn(async move {
                    let mut conn = FramedConnection::new(stream, Duration::from_secs(10));

                    if !serve_mock_handshake(&mut conn).await {
                        return;
                    }

                    // ── Operational loop ──
                    loop {
                        let Ok((tag, raw)) =
                            framed::read_tagged_raw(conn.stream_mut(), Duration::from_secs(30))
                                .await
                        else {
                            return;
                        };

                        match tag {
                            framed::TAG_EXEC_REQUEST => {
                                // Flaky mode: drop the first exec connection
                                // mid-request to simulate a dead guest session.
                                if drop_first_exec && conn_index == 0 {
                                    return;
                                }
                                handle_mock_exec(&mut conn, raw.as_slice()).await;
                            }
                            framed::TAG_HEALTH_REQUEST => {
                                let resp = operational_v1::HealthResponse {
                                    status: 1,
                                    message: "ok".into(),
                                };
                                let _ = conn.send_tagged(framed::TAG_HEALTH_RESPONSE, &resp).await;
                            }
                            _ => {
                                return;
                            }
                        }
                    }
                });
            }
        });
    });

    rx.recv().unwrap()
}

/// Serves the guest side of the bootstrap handshake on `conn`.
///
/// The shared secret is derived from the host's claimed `sandbox_id` (the
/// HostHello carries it) so one mock serves any test's sandbox identity.
/// Returns false on any I/O failure - the caller just closes the task.
async fn serve_mock_handshake(conn: &mut pico_guest_protocol::FramedConnection<TcpStream>) -> bool {
    use pico_core::crypto;
    use pico_guest_protocol::bootstrap_v1::*;
    use pico_guest_protocol::compute_guest_proof;

    let host_hello: HostHello = match conn.recv().await {
        Ok(h) => h,
        Err(_) => return false,
    };

    let shared_secret = crypto::derive_handshake_shared_secret(&host_hello.sandbox_id);
    let host_nonce = host_hello
        .host_nonce
        .as_ref()
        .map(|n| n.value.clone())
        .unwrap_or_default();
    let guest_nonce = crypto::generate_nonce();

    let mut guest_hello = GuestHello {
        agent_version: env!("CARGO_PKG_VERSION").into(),
        boot_id: "mock-boot-001".into(),
        image_id: host_hello.image_id.clone(),
        image_digest: host_hello.image_digest.clone(),
        supported_versions: vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        }],
        guest_capabilities: Some(CapabilitySet {
            identifiers: vec![
                "exec".into(),
                "file".into(),
                "stats".into(),
                "health".into(),
                "shutdown".into(),
            ],
        }),
        guest_nonce: Some(Nonce {
            value: guest_nonce.to_vec(),
        }),
        proof: None,
    };

    let Ok(proof) = compute_guest_proof(&shared_secret, &host_nonce, &guest_hello) else {
        return false;
    };
    guest_hello.proof = Some(Proof {
        value: proof.to_vec(),
    });

    if conn.send(&guest_hello).await.is_err() {
        return false;
    }

    let _host_reply: HostReply = match conn.recv().await {
        Ok(r) => r,
        Err(_) => return false,
    };

    let result = HandshakeResult {
        outcome: Some(handshake_result::Outcome::Established(true)),
    };
    conn.send(&result).await.is_ok()
}

/// Runs the exec command described by the raw request payload on the host
/// and streams stdout/stderr + terminal outcome frames back.
async fn handle_mock_exec(conn: &mut pico_guest_protocol::FramedConnection<TcpStream>, raw: &[u8]) {
    use pico_guest_protocol::{framed, operational_v1};
    use prost::Message;

    let req = match operational_v1::ExecRequest::decode(raw) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut cmd = std::process::Command::new(&req.command);
    cmd.args(&req.args);
    if !req.working_dir.is_empty() {
        cmd.current_dir(&req.working_dir);
    }
    for (k, v) in &req.env {
        cmd.env(k, v);
    }

    let (exit_code, stdout, stderr) = match cmd.output() {
        Ok(out) => (out.status.code().unwrap_or(-1), out.stdout, out.stderr),
        Err(e) => (
            1,
            Vec::new(),
            format!("failed to execute {}: {e}", req.command).into_bytes(),
        ),
    };

    if !stdout.is_empty() {
        let resp = operational_v1::ExecResponse {
            frame: Some(operational_v1::exec_response::Frame::Stdout(
                operational_v1::exec_response::StdoutData {
                    frame: Some(operational_v1::StreamFrame {
                        sequence: 1,
                        payload: stdout,
                        end_of_stream: false,
                    }),
                },
            )),
        };
        let _ = conn.send_tagged(framed::TAG_EXEC_RESPONSE, &resp).await;
    }

    if !stderr.is_empty() {
        let resp = operational_v1::ExecResponse {
            frame: Some(operational_v1::exec_response::Frame::Stderr(
                operational_v1::exec_response::StderrData {
                    frame: Some(operational_v1::StreamFrame {
                        sequence: 1,
                        payload: stderr,
                        end_of_stream: false,
                    }),
                },
            )),
        };
        let _ = conn.send_tagged(framed::TAG_EXEC_RESPONSE, &resp).await;
    }

    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&exit_code.to_be_bytes());
    payload.extend_from_slice(&0u64.to_be_bytes());
    let outcome = operational_v1::ExecResponse {
        frame: Some(operational_v1::exec_response::Frame::Outcome(
            operational_v1::OperationOutcome {
                status: Some(operational_v1::operation_outcome::Status::Success(
                    operational_v1::operation_outcome::Success {
                        result_payload: payload,
                    },
                )),
            },
        )),
    };
    let _ = conn.send_tagged(framed::TAG_EXEC_RESPONSE, &outcome).await;
}
