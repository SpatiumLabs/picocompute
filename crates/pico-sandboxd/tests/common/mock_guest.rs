//! Minimal framed guest mock for sandboxd integration tests.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use pico_core::crypto;
use pico_guest_protocol::bootstrap_v1::*;
use pico_guest_protocol::framed;
use pico_guest_protocol::operational_v1::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};

const TIMEOUT: Duration = Duration::from_secs(5);

/// How the mock guest answers InjectSecrets requests.
pub(crate) enum InjectBehavior {
    /// Leave the request unanswered (legacy behavior).
    Ignore,
    /// Reply `injected = true`.
    Success,
    /// Reply `error = OperationOutcome::Failure { code, message }`.
    Failure { code: String, message: String },
}

/// Spawns a mock guest that completes handshake and keeps the session open.
pub(crate) async fn spawn_mock_guest_session(sandbox_id: &str) -> SocketAddr {
    spawn_mock_guest_session_with_inject(sandbox_id, InjectBehavior::Ignore).await
}

/// Spawns a mock guest with a configurable InjectSecrets response.
pub(crate) async fn spawn_mock_guest_session_with_inject(
    sandbox_id: &str,
    inject_behavior: InjectBehavior,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sandbox_id = sandbox_id.to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_handshake(&mut stream, &sandbox_id).await.unwrap();
        serve_guest_connection(&mut stream, &inject_behavior).await;
    });
    addr
}

/// Spawns a mock guest on a Unix domain socket and serves one session.
///
/// This exercises the production (non-TCP) handshake path owned by
/// `GuestConnection::connect_unix`: the virtio-serial fallback for QEMU and
/// the gVisor socket both arrive through this transport.
pub(crate) async fn spawn_mock_guest_session_unix(sandbox_id: &str, socket_path: &Path) {
    spawn_mock_guest_session_unix_with_inject(sandbox_id, socket_path, InjectBehavior::Ignore)
        .await;
}

/// Spawns a Unix mock guest with a configurable InjectSecrets response.
pub(crate) async fn spawn_mock_guest_session_unix_with_inject(
    sandbox_id: &str,
    socket_path: &Path,
    inject_behavior: InjectBehavior,
) {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).unwrap();
    let sandbox_id = sandbox_id.to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_handshake(&mut stream, &sandbox_id).await.unwrap();
        serve_guest_connection(&mut stream, &inject_behavior).await;
    });
}

async fn serve_guest_connection(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    inject_behavior: &InjectBehavior,
) {
    while let Ok((tag, bytes)) = framed::read_tagged_raw(stream, Duration::from_secs(30)).await {
        if tag == framed::TAG_EXEC_REQUEST {
            let req = ExecRequest::decode(bytes.as_slice()).unwrap_or_default();
            serve_exec_response(stream, &req.command).await.ok();
        } else if tag == framed::TAG_INJECT_SECRETS_REQUEST {
            let resp = match &inject_behavior {
                InjectBehavior::Ignore => continue,
                InjectBehavior::Success => InjectSecretsResponse {
                    result: Some(inject_secrets_response::Result::Injected(true)),
                },
                InjectBehavior::Failure { code, message } => InjectSecretsResponse {
                    result: Some(inject_secrets_response::Result::Error(OperationOutcome {
                        status: Some(operation_outcome::Status::Failure(
                            operation_outcome::Failure {
                                code: code.clone(),
                                message: message.clone(),
                                retryable: false,
                            },
                        )),
                    })),
                },
            };
            let _ =
                framed::send_tagged(stream, framed::TAG_INJECT_SECRETS_RESPONSE, &resp, TIMEOUT)
                    .await;
        } else if tag == framed::TAG_PUT_FILE_REQUEST {
            let mut end = false;
            if let Ok(req) = PutFileRequest::decode(bytes.as_slice()) {
                end = matches!(
                    req.payload,
                    Some(put_file_request::Payload::Chunk(ref f)) if f.end_of_stream
                );
            }
            while !end {
                let Ok((t, b)) = framed::read_tagged_raw(stream, TIMEOUT).await else {
                    return;
                };
                if t != framed::TAG_PUT_FILE_REQUEST {
                    return;
                }
                if let Ok(req) = PutFileRequest::decode(b.as_slice()) {
                    end = matches!(
                        req.payload,
                        Some(put_file_request::Payload::Chunk(ref f)) if f.end_of_stream
                    );
                }
            }
            let resp = PutFileResponse {
                result: Some(put_file_response::Result::BytesWritten(5)),
                checksum: "ok".into(),
            };
            let _ =
                framed::send_tagged(stream, framed::TAG_PUT_FILE_RESPONSE, &resp, TIMEOUT).await;
        } else if tag == framed::TAG_GET_FILE_REQUEST {
            let _ = serve_get_file(stream).await;
        } else if tag == framed::TAG_CANCEL_REQUEST {
            let resp = CancelResponse {
                result: Some(cancel_response::Result::Accepted(Ack {})),
            };
            let _ = framed::send_tagged(stream, framed::TAG_CANCEL_RESPONSE, &resp, TIMEOUT).await;
        }
    }
}

async fn serve_handshake(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    sandbox_id: &str,
) -> std::io::Result<()> {
    let shared = crypto::derive_handshake_shared_secret(sandbox_id);
    let host_hello = framed::read_message::<HostHello>(stream, TIMEOUT)
        .await
        .map_err(io_err)?;
    let host_nonce = host_hello
        .host_nonce
        .as_ref()
        .map(|n| n.value.as_slice())
        .unwrap_or(&[]);
    let guest_nonce = crypto::generate_nonce();
    let identity_version = "test-guest";
    let boot_id = "boot-test";
    let image_id = host_hello.image_id.clone();
    let image_digest = host_hello.image_digest.clone();

    let mut transcript: heapless::Vec<u8, 512> = heapless::Vec::new();
    let _ = transcript.extend_from_slice(b"pico.guest.bootstrap.v1|guest");
    let _ = transcript.extend_from_slice(host_nonce);
    let _ = transcript.extend_from_slice(&guest_nonce);
    let _ = transcript.extend_from_slice(identity_version.as_bytes());
    let _ = transcript.extend_from_slice(boot_id.as_bytes());
    let _ = transcript.extend_from_slice(image_id.as_bytes());
    let _ = transcript.extend_from_slice(image_digest.as_bytes());
    let proof = crypto::blake3_mac(&shared, &transcript);

    let guest_hello = GuestHello {
        supported_versions: vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        }],
        guest_capabilities: Some(CapabilitySet {
            identifiers: vec![
                "exec".into(),
                "file".into(),
                "mount".into(),
                "stats".into(),
                "health".into(),
                "shutdown".into(),
            ],
        }),
        guest_nonce: Some(Nonce {
            value: guest_nonce.to_vec(),
        }),
        agent_version: identity_version.into(),
        boot_id: boot_id.into(),
        image_id,
        image_digest,
        proof: Some(Proof {
            value: proof.to_vec(),
        }),
    };
    framed::send_message(stream, &guest_hello, TIMEOUT)
        .await
        .map_err(io_err)?;

    let _host_reply = framed::read_message::<HostReply>(stream, TIMEOUT)
        .await
        .map_err(io_err)?;
    let result = HandshakeResult {
        outcome: Some(handshake_result::Outcome::Established(true)),
    };
    framed::send_message(stream, &result, TIMEOUT)
        .await
        .map_err(io_err)?;
    Ok(())
}

async fn serve_exec_response(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    command: &str,
) -> std::io::Result<()> {
    let stdout = format!("ran:{command}\n");
    let stdout_resp = ExecResponse {
        frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
            frame: Some(StreamFrame {
                sequence: 1,
                payload: stdout.into_bytes(),
                end_of_stream: true,
            }),
        })),
    };
    framed::send_tagged(stream, framed::TAG_EXEC_RESPONSE, &stdout_resp, TIMEOUT)
        .await
        .map_err(io_err)?;

    // Wire format: exit_code (i32, big-endian, 4 bytes) + duration_ms (u64, big-endian, 8 bytes)
    let mut payload = Vec::new();
    payload.extend_from_slice(&0i32.to_be_bytes());
    payload.extend_from_slice(&7u64.to_be_bytes());
    let outcome = ExecResponse {
        frame: Some(exec_response::Frame::Outcome(OperationOutcome {
            status: Some(operation_outcome::Status::Success(
                operation_outcome::Success {
                    result_payload: payload,
                },
            )),
        })),
    };
    framed::send_tagged(stream, framed::TAG_EXEC_RESPONSE, &outcome, TIMEOUT)
        .await
        .map_err(io_err)?;
    Ok(())
}

async fn serve_get_file(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
) -> std::io::Result<()> {
    let meta = GetFileResponse {
        frame: Some(get_file_response::Frame::Metadata(
            get_file_response::FileMetadata {
                size: 5,
                mode: 0o644,
                modified_at: None,
            },
        )),
    };
    framed::send_tagged(stream, framed::TAG_GET_FILE_RESPONSE, &meta, TIMEOUT)
        .await
        .map_err(io_err)?;
    let chunk = GetFileResponse {
        frame: Some(get_file_response::Frame::Chunk(StreamFrame {
            sequence: 1,
            payload: b"hello".to_vec(),
            end_of_stream: true,
        })),
    };
    framed::send_tagged(stream, framed::TAG_GET_FILE_RESPONSE, &chunk, TIMEOUT)
        .await
        .map_err(io_err)?;
    let outcome = GetFileResponse {
        frame: Some(get_file_response::Frame::Outcome(OperationOutcome {
            status: Some(operation_outcome::Status::Success(
                operation_outcome::Success {
                    result_payload: b"checksum".to_vec(),
                },
            )),
        })),
    };
    framed::send_tagged(stream, framed::TAG_GET_FILE_RESPONSE, &outcome, TIMEOUT)
        .await
        .map_err(io_err)?;
    Ok(())
}

fn io_err(err: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

use prost::Message;
