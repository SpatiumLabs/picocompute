//! Integration tests for [`pico_guest_protocol::GuestSession`].
//!
//! Each test runs a scripted mock guest over loopback TCP and drives the
//! real `GuestSession::connect_tcp` handshake plus operational RPCs.
//! Covers: happy paths, guest-side outcome variants, and protocol misuse
//! (wrong response tags, tampered proofs, refused connections).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use prost::Message;
use tokio::net::{TcpListener, TcpStream};

use pico_core::crypto;
use pico_guest_protocol::bootstrap_v1::*;
use pico_guest_protocol::operational_v1::*;
use pico_guest_protocol::{
    FramedConnection, GuestSession, HandshakeConfig, HandshakeError, SessionError,
    compute_guest_proof, framed,
};

const T: Duration = Duration::from_secs(5);

/// Spawns a mock guest task. The closure receives the accepted connection
/// and must run the guest side of the exchange. Returns the listener
/// address and the task handle (await it at test end to surface
/// guest-side assertion failures).
async fn guest<F, Fut>(f: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: FnOnce(FramedConnection<TcpStream>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        f(FramedConnection::new(stream, T)).await;
    });
    (addr, handle)
}

/// Runs the guest side of a successful bootstrap handshake.
async fn serve_handshake_ok(conn: &mut FramedConnection<TcpStream>) {
    let host_hello: HostHello = conn.recv().await.unwrap();
    let shared_secret = crypto::derive_handshake_shared_secret(&host_hello.sandbox_id);
    let host_nonce = host_hello
        .host_nonce
        .as_ref()
        .map(|n| n.value.clone())
        .unwrap_or_default();

    let mut guest_hello = GuestHello {
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
            value: crypto::generate_nonce().to_vec(),
        }),
        agent_version: "mock-agent/1.5".into(),
        boot_id: "boot-mock".into(),
        image_id: host_hello.image_id.clone(),
        image_digest: host_hello.image_digest.clone(),
        proof: None,
    };
    let proof = compute_guest_proof(&shared_secret, &host_nonce, &guest_hello).unwrap();
    guest_hello.proof = Some(Proof {
        value: proof.to_vec(),
    });
    conn.send(&guest_hello).await.unwrap();

    let _host_reply: HostReply = conn.recv().await.unwrap();
    let result = HandshakeResult {
        outcome: Some(handshake_result::Outcome::Established(true)),
    };
    conn.send(&result).await.unwrap();
}

/// Reads one tagged request; asserts it matches `expected_tag` and decodes
/// it as `M`.
async fn recv_request<M: Message + Default>(
    conn: &mut FramedConnection<TcpStream>,
    expected_tag: u8,
) -> M {
    let (tag, raw) = framed::read_tagged_raw(conn.stream_mut(), T).await.unwrap();
    assert_eq!(tag, expected_tag, "unexpected request tag");
    M::decode(raw.as_slice()).unwrap()
}

fn session_config(addr: SocketAddr, sandbox_id: &str) -> HandshakeConfig {
    HandshakeConfig {
        sandbox_id: sandbox_id.into(),
        transport_addr: addr,
        timeout: T,
        ..Default::default()
    }
}

fn success_payload(exit_code: i32, duration_ms: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(12);
    p.extend_from_slice(&exit_code.to_be_bytes());
    p.extend_from_slice(&duration_ms.to_be_bytes());
    p
}

fn exec_outcome(status: operation_outcome::Status) -> ExecResponse {
    ExecResponse {
        frame: Some(exec_response::Frame::Outcome(OperationOutcome {
            status: Some(status),
        })),
    }
}

// ==================================================================
// Handshake
// ==================================================================

#[tokio::test]
async fn connect_establishes_session_and_carries_outcome_fields() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
    })
    .await;

    let session = GuestSession::connect_tcp(&session_config(addr, "sbx_connect"))
        .await
        .unwrap();

    assert_eq!(session.session_id().len(), 16);
    assert!(session.capabilities().contains(&"exec".to_string()));
    assert_eq!(session.guest_boot_id(), "boot-mock");
    assert_eq!(session.guest_agent_version(), "mock-agent/1.5");
    assert_eq!(session.protocol_version(), (1, 5));
    guest.await.unwrap();
}

#[tokio::test]
async fn connect_rejected_by_guest_is_guest_rejected_error() {
    let (addr, guest) = guest(|mut conn| async move {
        let host_hello: HostHello = conn.recv().await.unwrap();
        let shared_secret = crypto::derive_handshake_shared_secret(&host_hello.sandbox_id);
        let host_nonce = host_hello
            .host_nonce
            .as_ref()
            .map(|n| n.value.clone())
            .unwrap_or_default();
        let mut guest_hello = GuestHello {
            supported_versions: vec![VersionRange {
                min: Some(Version { major: 1, minor: 0 }),
                max: Some(Version { major: 1, minor: 5 }),
            }],
            guest_capabilities: Some(CapabilitySet {
                identifiers: vec!["exec".into()],
            }),
            guest_nonce: Some(Nonce {
                value: crypto::generate_nonce().to_vec(),
            }),
            image_id: host_hello.image_id.clone(),
            ..Default::default()
        };
        let proof = compute_guest_proof(&shared_secret, &host_nonce, &guest_hello).unwrap();
        guest_hello.proof = Some(Proof {
            value: proof.to_vec(),
        });
        conn.send(&guest_hello).await.unwrap();
        let _host_reply: HostReply = conn.recv().await.unwrap();
        let result = HandshakeResult {
            outcome: Some(handshake_result::Outcome::Error(
                pico_guest_protocol::bootstrap_v1::HandshakeError {
                    code: handshake_error::ErrorCode::AuthenticationFailed as i32,
                    message: "nope".into(),
                },
            )),
        };
        conn.send(&result).await.unwrap();
    })
    .await;

    let err = GuestSession::connect_tcp(&session_config(addr, "sbx_reject"))
        .await
        .map(|_| ())
        .expect_err("guest rejection must fail the handshake");
    assert!(matches!(
        err,
        SessionError::Handshake(HandshakeError::GuestRejected { ref message, .. })
            if message.contains("nope")
    ));
    guest.await.unwrap();
}

#[tokio::test]
async fn connect_refused_when_nothing_listens() {
    // Grab a free port then drop the listener so the port is dead.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = dead.local_addr().unwrap();
    drop(dead);

    let err = GuestSession::connect_tcp(&session_config(addr, "sbx_dead"))
        .await
        .map(|_| ())
        .expect_err("connecting to a dead port must fail");
    assert!(matches!(
        err,
        SessionError::Handshake(HandshakeError::ConnectionRefused(_))
    ));
}

#[tokio::test]
async fn connect_fails_when_guest_proof_is_tampered() {
    let (addr, guest) = guest(|mut conn| async move {
        let host_hello: HostHello = conn.recv().await.unwrap();
        let shared_secret = crypto::derive_handshake_shared_secret(&host_hello.sandbox_id);
        let host_nonce = host_hello
            .host_nonce
            .as_ref()
            .map(|n| n.value.clone())
            .unwrap_or_default();
        let mut guest_hello = GuestHello {
            supported_versions: vec![VersionRange {
                min: Some(Version { major: 1, minor: 0 }),
                max: Some(Version { major: 1, minor: 5 }),
            }],
            guest_capabilities: Some(CapabilitySet {
                identifiers: vec!["exec".into()],
            }),
            guest_nonce: Some(Nonce {
                value: crypto::generate_nonce().to_vec(),
            }),
            image_id: host_hello.image_id.clone(),
            ..Default::default()
        };
        let mut proof = compute_guest_proof(&shared_secret, &host_nonce, &guest_hello)
            .unwrap()
            .to_vec();
        proof[0] ^= 0xFF; // tamper
        guest_hello.proof = Some(Proof { value: proof });
        conn.send(&guest_hello).await.unwrap();
    })
    .await;

    let err = GuestSession::connect_tcp(&session_config(addr, "sbx_tamper"))
        .await
        .map(|_| ())
        .expect_err("tampered proof must fail validation");
    assert!(matches!(
        err,
        SessionError::Handshake(HandshakeError::ProofVerificationFailed { .. })
    ));
    guest.await.unwrap();
}

// ==================================================================
// exec
// ==================================================================

#[tokio::test]
async fn exec_collects_stream_frames_and_success_outcome() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let req: ExecRequest = recv_request(&mut conn, framed::TAG_EXEC_REQUEST).await;
        assert_eq!(req.command, "build");
        let ctx = req.context.unwrap();
        assert_eq!(ctx.sandbox_id, "sbx_exec");
        assert_eq!(ctx.session_id.len(), 16);
        assert_eq!(ctx.protocol_version, 0x0001_0005);

        conn.send_tagged(
            framed::TAG_EXEC_RESPONSE,
            &ExecResponse {
                frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                    frame: Some(StreamFrame {
                        sequence: 1,
                        payload: b"out-".to_vec(),
                        end_of_stream: false,
                    }),
                })),
            },
        )
        .await
        .unwrap();
        conn.send_tagged(
            framed::TAG_EXEC_RESPONSE,
            &ExecResponse {
                frame: Some(exec_response::Frame::Stderr(exec_response::StderrData {
                    frame: Some(StreamFrame {
                        sequence: 1,
                        payload: b"err!".to_vec(),
                        end_of_stream: false,
                    }),
                })),
            },
        )
        .await
        .unwrap();
        conn.send_tagged(
            framed::TAG_EXEC_RESPONSE,
            &exec_outcome(operation_outcome::Status::Success(
                operation_outcome::Success {
                    result_payload: success_payload(3, 42),
                },
            )),
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_exec"))
        .await
        .unwrap();
    let result = session
        .exec(
            "build",
            &["--release".into()],
            &hashbrown::HashMap::new(),
            "/",
            "op-1",
            None,
        )
        .await
        .unwrap();

    assert_eq!(result.exit_code, 3);
    assert_eq!(result.duration_ms, 42);
    assert_eq!(result.stdout, b"out-");
    assert_eq!(result.stderr, b"err!");
    assert_eq!(result.status, "success");
    guest.await.unwrap();
}

#[tokio::test]
async fn exec_failure_outcome_maps_exit_and_status() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let _req: ExecRequest = recv_request(&mut conn, framed::TAG_EXEC_REQUEST).await;
        conn.send_tagged(
            framed::TAG_EXEC_RESPONSE,
            &exec_outcome(operation_outcome::Status::Failure(
                operation_outcome::Failure {
                    code: "E_PERM".into(),
                    message: "permission denied".into(),
                    retryable: false,
                },
            )),
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_efail"))
        .await
        .unwrap();
    let result = session
        .exec("ls", &[], &hashbrown::HashMap::new(), "/", "op-2", None)
        .await
        .unwrap();
    assert_eq!(result.exit_code, -1);
    assert!(result.status.contains("E_PERM"));
    assert!(result.status.contains("permission denied"));
    guest.await.unwrap();
}

#[tokio::test]
async fn exec_canceled_and_timed_out_outcomes_map_status() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        // Request 1: canceled.
        let _req: ExecRequest = recv_request(&mut conn, framed::TAG_EXEC_REQUEST).await;
        conn.send_tagged(
            framed::TAG_EXEC_RESPONSE,
            &exec_outcome(operation_outcome::Status::Canceled(
                operation_outcome::Canceled {
                    reason: "user".into(),
                },
            )),
        )
        .await
        .unwrap();
        // Request 2: timed out.
        let _req: ExecRequest = recv_request(&mut conn, framed::TAG_EXEC_REQUEST).await;
        conn.send_tagged(
            framed::TAG_EXEC_RESPONSE,
            &exec_outcome(operation_outcome::Status::TimedOut(
                operation_outcome::TimedOut {
                    budget_remaining: None,
                },
            )),
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_cto"))
        .await
        .unwrap();
    let canceled = session
        .exec(
            "sleep",
            &["9".into()],
            &hashbrown::HashMap::new(),
            "/",
            "op-3",
            None,
        )
        .await
        .unwrap();
    assert_eq!(canceled.exit_code, -1);
    assert_eq!(canceled.status, "canceled: user");

    let timed_out = session
        .exec(
            "sleep",
            &["9".into()],
            &hashbrown::HashMap::new(),
            "/",
            "op-4",
            None,
        )
        .await
        .unwrap();
    assert_eq!(timed_out.exit_code, -1);
    assert_eq!(timed_out.status, "timed out");
    guest.await.unwrap();
}

#[tokio::test]
async fn exec_unexpected_response_tag_is_protocol_error() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let _req: ExecRequest = recv_request(&mut conn, framed::TAG_EXEC_REQUEST).await;
        // Respond with the wrong message type entirely.
        conn.send_tagged(
            framed::TAG_CANCEL_RESPONSE,
            &CancelResponse {
                result: Some(cancel_response::Result::Accepted(Ack {})),
            },
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_tag"))
        .await
        .unwrap();
    let err = session
        .exec("echo", &[], &hashbrown::HashMap::new(), "/", "op-5", None)
        .await
        .expect_err("wrong response tag must fail");
    assert!(matches!(
        err,
        SessionError::Protocol(ref m) if m.contains("unexpected response tag")
    ));
    guest.await.unwrap();
}

#[tokio::test]
async fn exec_empty_response_frame_is_protocol_error() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let _req: ExecRequest = recv_request(&mut conn, framed::TAG_EXEC_REQUEST).await;
        conn.send_tagged(framed::TAG_EXEC_RESPONSE, &ExecResponse { frame: None })
            .await
            .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_eframe"))
        .await
        .unwrap();
    let err = session
        .exec("echo", &[], &hashbrown::HashMap::new(), "/", "op-6", None)
        .await
        .expect_err("empty frame must fail");
    assert!(matches!(
        err,
        SessionError::Protocol(ref m) if m.contains("empty exec response frame")
    ));
    guest.await.unwrap();
}

// ==================================================================
// Simple request-response RPCs
// ==================================================================

#[tokio::test]
async fn cancel_forwards_operation_id() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let req: CancelRequest = recv_request(&mut conn, framed::TAG_CANCEL_REQUEST).await;
        assert_eq!(req.operation_id, "op-target");
        conn.send_tagged(
            framed::TAG_CANCEL_RESPONSE,
            &CancelResponse {
                result: Some(cancel_response::Result::Accepted(Ack {})),
            },
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_cancel"))
        .await
        .unwrap();
    let resp = session.cancel("op-target").await.unwrap();
    assert!(matches!(
        resp.result,
        Some(cancel_response::Result::Accepted(_))
    ));
    guest.await.unwrap();
}

#[tokio::test]
async fn signal_forwards_signal_number() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let req: SignalRequest = recv_request(&mut conn, framed::TAG_SIGNAL_REQUEST).await;
        assert_eq!(req.signal, 9);
        conn.send_tagged(
            framed::TAG_SIGNAL_RESPONSE,
            &SignalResponse {
                result: Some(signal_response::Result::Acknowledged(Ack {})),
            },
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_sig"))
        .await
        .unwrap();
    session.signal("op-kill", 9).await.unwrap();
    guest.await.unwrap();
}

#[tokio::test]
async fn health_round_trip_and_wrong_tag_rejected() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        // First request: correct response.
        let _req: HealthRequest = recv_request(&mut conn, framed::TAG_HEALTH_REQUEST).await;
        conn.send_tagged(
            framed::TAG_HEALTH_RESPONSE,
            &HealthResponse {
                status: health_response::HealthStatus::Ok as i32,
                message: "fine".into(),
            },
        )
        .await
        .unwrap();
        // Second request: wrong tag.
        let _req: HealthRequest = recv_request(&mut conn, framed::TAG_HEALTH_REQUEST).await;
        conn.send_tagged(framed::TAG_STATS_RESPONSE, &StatsResponse::default())
            .await
            .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_health"))
        .await
        .unwrap();
    let ok = session.health("op-h1").await.unwrap();
    assert_eq!(ok.status, health_response::HealthStatus::Ok as i32);

    let err = session
        .health("op-h2")
        .await
        .expect_err("wrong tag must fail");
    assert!(matches!(
        err,
        SessionError::Protocol(ref m) if m.contains("health")
    ));
    guest.await.unwrap();
}

#[tokio::test]
async fn quiesce_resume_shutdown_mount_stats_round_trips() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;

        let req: QuiesceRequest = recv_request(&mut conn, framed::TAG_QUIESCE_REQUEST).await;
        assert_eq!(req.drain_mode, quiesce_request::DrainMode::Force as i32);
        conn.send_tagged(
            framed::TAG_QUIESCE_RESPONSE,
            &QuiesceResponse {
                result: Some(quiesce_response::Result::Quiesced(true)),
            },
        )
        .await
        .unwrap();

        let req: ResumeNotifyRequest =
            recv_request(&mut conn, framed::TAG_RESUME_NOTIFY_REQUEST).await;
        assert_eq!(req.sandbox_id, "sbx_fresh");
        assert_eq!(req.policy_epoch, 9);
        assert_eq!(req.lineage_id, "snp_1");
        conn.send_tagged(
            framed::TAG_RESUME_NOTIFY_RESPONSE,
            &ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Accepted(true)),
            },
        )
        .await
        .unwrap();

        let req: ShutdownRequest = recv_request(&mut conn, framed::TAG_SHUTDOWN_REQUEST).await;
        assert_eq!(req.reason, "idle");
        assert!(req.force);
        conn.send_tagged(
            framed::TAG_SHUTDOWN_RESPONSE,
            &ShutdownResponse {
                result: Some(shutdown_response::Result::ShuttingDown(true)),
            },
        )
        .await
        .unwrap();

        let _req: MountWorkspaceRequest =
            recv_request(&mut conn, framed::TAG_MOUNT_WORKSPACE_REQUEST).await;
        conn.send_tagged(
            framed::TAG_MOUNT_WORKSPACE_RESPONSE,
            &MountWorkspaceResponse {
                result: Some(mount_workspace_response::Result::Mounted(true)),
            },
        )
        .await
        .unwrap();

        let _req: StatsRequest = recv_request(&mut conn, framed::TAG_STATS_REQUEST).await;
        conn.send_tagged(framed::TAG_STATS_RESPONSE, &StatsResponse::default())
            .await
            .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_life"))
        .await
        .unwrap();

    let q = session
        .quiesce(quiesce_request::DrainMode::Force as i32, None, "op-q")
        .await
        .unwrap();
    assert!(matches!(
        q.result,
        Some(quiesce_response::Result::Quiesced(true))
    ));

    let r = session
        .resume_notify("sbx_fresh", 9, "snp_1", None, "op-r")
        .await
        .unwrap();
    assert!(matches!(
        r.result,
        Some(resume_notify_response::Result::Accepted(true))
    ));

    let s = session.shutdown("idle", true, "op-s").await.unwrap();
    assert!(matches!(
        s.result,
        Some(shutdown_response::Result::ShuttingDown(true))
    ));

    let m = session
        .mount_workspace("/workspace", "tmpfs", &hashbrown::HashMap::new(), "op-m")
        .await
        .unwrap();
    assert!(matches!(
        m.result,
        Some(mount_workspace_response::Result::Mounted(true))
    ));

    session.stats("op-st").await.unwrap();
    guest.await.unwrap();
}

// ==================================================================
// File transfer
// ==================================================================

#[tokio::test]
async fn put_file_sends_metadata_then_single_end_of_stream_chunk() {
    let data = b"file contents".to_vec();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_g = Arc::clone(&captured);

    let (addr, guest) = guest(move |mut conn| {
        let captured = captured_g;
        async move {
            serve_handshake_ok(&mut conn).await;
            // Metadata frame.
            let raw = {
                let (tag, raw) = framed::read_tagged_raw(conn.stream_mut(), T).await.unwrap();
                assert_eq!(tag, framed::TAG_PUT_FILE_REQUEST);
                raw
            };
            captured.lock().push(raw);
            // Single data chunk.
            let raw = {
                let (tag, raw) = framed::read_tagged_raw(conn.stream_mut(), T).await.unwrap();
                assert_eq!(tag, framed::TAG_PUT_FILE_REQUEST);
                raw
            };
            captured.lock().push(raw);
            conn.send_tagged(
                framed::TAG_PUT_FILE_RESPONSE,
                &PutFileResponse {
                    result: Some(put_file_response::Result::BytesWritten(13)),
                    checksum: "beef".into(),
                },
            )
            .await
            .unwrap();
        }
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_put"))
        .await
        .unwrap();
    let resp = session
        .put_file("/tmp/f.txt", &data, 0o600, true, "op-p")
        .await
        .unwrap();
    assert!(matches!(
        resp.result,
        Some(put_file_response::Result::BytesWritten(13))
    ));
    assert_eq!(resp.checksum, "beef");
    guest.await.unwrap();

    let captured = captured.lock();
    assert_eq!(captured.len(), 2);
    let meta = PutFileRequest::decode(captured[0].as_slice()).unwrap();
    match meta.payload {
        Some(put_file_request::Payload::Metadata(m)) => {
            assert_eq!(m.path, "/tmp/f.txt");
            assert_eq!(m.mode, 0o600);
            assert_eq!(m.expected_size, 13);
            assert!(m.overwrite);
        }
        _ => panic!("first request must be metadata"),
    }
    let chunk = PutFileRequest::decode(captured[1].as_slice()).unwrap();
    match chunk.payload {
        Some(put_file_request::Payload::Chunk(f)) => {
            assert_eq!(f.sequence, 1);
            assert!(f.end_of_stream);
            assert_eq!(f.payload, data);
        }
        _ => panic!("second request must be a chunk"),
    }
}

#[tokio::test]
async fn put_file_empty_still_sends_end_of_stream_chunk() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_g = Arc::clone(&captured);

    let (addr, guest) = guest(move |mut conn| {
        let captured = captured_g;
        async move {
            serve_handshake_ok(&mut conn).await;
            for _ in 0..2 {
                let (tag, raw) = framed::read_tagged_raw(conn.stream_mut(), T).await.unwrap();
                assert_eq!(tag, framed::TAG_PUT_FILE_REQUEST);
                captured.lock().push(raw);
            }
            conn.send_tagged(
                framed::TAG_PUT_FILE_RESPONSE,
                &PutFileResponse {
                    result: Some(put_file_response::Result::BytesWritten(0)),
                    checksum: String::new(),
                },
            )
            .await
            .unwrap();
        }
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_pe"))
        .await
        .unwrap();
    session
        .put_file("/tmp/e.txt", &[], 0o644, false, "op-pe")
        .await
        .unwrap();
    guest.await.unwrap();

    let captured = captured.lock();
    assert_eq!(captured.len(), 2);
    let chunk = PutFileRequest::decode(captured[1].as_slice()).unwrap();
    match chunk.payload {
        Some(put_file_request::Payload::Chunk(f)) => {
            assert!(f.end_of_stream);
            assert!(f.payload.is_empty());
            assert_eq!(f.sequence, 1);
        }
        _ => panic!("expected chunk"),
    }
}

#[tokio::test]
async fn put_file_large_payload_is_chunked_in_sequence() {
    let data = vec![0xABu8; 150_000]; // spans 3 chunks at 64 KiB
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_g = Arc::clone(&captured);

    let (addr, guest) = guest(move |mut conn| {
        let captured = captured_g;
        async move {
            serve_handshake_ok(&mut conn).await;
            for _ in 0..4 {
                let (tag, raw) = framed::read_tagged_raw(conn.stream_mut(), T).await.unwrap();
                assert_eq!(tag, framed::TAG_PUT_FILE_REQUEST);
                captured.lock().push(raw);
            }
            conn.send_tagged(
                framed::TAG_PUT_FILE_RESPONSE,
                &PutFileResponse {
                    result: Some(put_file_response::Result::BytesWritten(150_000)),
                    checksum: String::new(),
                },
            )
            .await
            .unwrap();
        }
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_pl"))
        .await
        .unwrap();
    session
        .put_file("/tmp/big.bin", &data, 0o644, true, "op-pl")
        .await
        .unwrap();
    guest.await.unwrap();

    let captured = captured.lock();
    assert_eq!(captured.len(), 4, "meta + 3 chunks");
    let mut bytes = 0usize;
    let mut ends = 0;
    for (i, raw) in captured.iter().enumerate().skip(1) {
        let req = PutFileRequest::decode(raw.as_slice()).unwrap();
        match req.payload {
            Some(put_file_request::Payload::Chunk(f)) => {
                assert_eq!(f.sequence, i as u64);
                bytes += f.payload.len();
                ends += u32::from(f.end_of_stream);
            }
            _ => panic!("expected chunk"),
        }
    }
    assert_eq!(bytes, 150_000);
    assert_eq!(ends, 1, "only the final chunk is marked end_of_stream");
}

#[tokio::test]
async fn get_file_assembles_metadata_chunks_and_checksum() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let req: GetFileRequest = recv_request(&mut conn, framed::TAG_GET_FILE_REQUEST).await;
        assert_eq!(req.path, "/tmp/f.bin");
        conn.send_tagged(
            framed::TAG_GET_FILE_RESPONSE,
            &GetFileResponse {
                frame: Some(get_file_response::Frame::Metadata(
                    get_file_response::FileMetadata {
                        size: 10,
                        mode: 0o644,
                        modified_at: None,
                    },
                )),
            },
        )
        .await
        .unwrap();
        conn.send_tagged(
            framed::TAG_GET_FILE_RESPONSE,
            &GetFileResponse {
                frame: Some(get_file_response::Frame::Chunk(StreamFrame {
                    sequence: 1,
                    payload: b"hellofile!".to_vec(),
                    end_of_stream: true,
                })),
            },
        )
        .await
        .unwrap();
        conn.send_tagged(
            framed::TAG_GET_FILE_RESPONSE,
            &GetFileResponse {
                frame: Some(get_file_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: b"blake3hex".to_vec(),
                        },
                    )),
                })),
            },
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_get"))
        .await
        .unwrap();
    let result = session.get_file("/tmp/f.bin", "op-g").await.unwrap();
    assert_eq!(result.data, b"hellofile!");
    assert_eq!(result.size, 10);
    assert_eq!(result.mode, 0o644);
    assert_eq!(result.checksum, "blake3hex");
    guest.await.unwrap();
}

// ==================================================================
// Secrets
// ==================================================================

#[tokio::test]
async fn inject_secrets_injected_denied_and_guest_error() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        // Request 1: injected.
        let _req: InjectSecretsRequest =
            recv_request(&mut conn, framed::TAG_INJECT_SECRETS_REQUEST).await;
        conn.send_tagged(
            framed::TAG_INJECT_SECRETS_RESPONSE,
            &InjectSecretsResponse {
                result: Some(inject_secrets_response::Result::Injected(true)),
            },
        )
        .await
        .unwrap();
        // Request 2: denied.
        let _req: InjectSecretsRequest =
            recv_request(&mut conn, framed::TAG_INJECT_SECRETS_REQUEST).await;
        conn.send_tagged(
            framed::TAG_INJECT_SECRETS_RESPONSE,
            &InjectSecretsResponse {
                result: Some(inject_secrets_response::Result::Injected(false)),
            },
        )
        .await
        .unwrap();
        // Request 3: guest-side error outcome.
        let _req: InjectSecretsRequest =
            recv_request(&mut conn, framed::TAG_INJECT_SECRETS_REQUEST).await;
        conn.send_tagged(
            framed::TAG_INJECT_SECRETS_RESPONSE,
            &InjectSecretsResponse {
                result: Some(inject_secrets_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "E_LEASE".into(),
                            message: "lease revoked".into(),
                            retryable: false,
                        },
                    )),
                })),
            },
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_sec"))
        .await
        .unwrap();

    let injected = session.inject_secrets("l", "p", &[], "op").await.unwrap();
    assert!(injected.injected);

    let denied = session.inject_secrets("l", "p", &[], "op").await.unwrap();
    assert!(!denied.injected);

    let err = session
        .inject_secrets("l", "p", &[], "op")
        .await
        .expect_err("guest error outcome must fail");
    assert!(matches!(
        err,
        SessionError::Protocol(ref m) if m.contains("E_LEASE")
    ));
    guest.await.unwrap();
}

#[tokio::test]
async fn inject_secrets_missing_result_is_protocol_error() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let _req: InjectSecretsRequest =
            recv_request(&mut conn, framed::TAG_INJECT_SECRETS_REQUEST).await;
        conn.send_tagged(
            framed::TAG_INJECT_SECRETS_RESPONSE,
            &InjectSecretsResponse { result: None },
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_secnone"))
        .await
        .unwrap();
    let err = session
        .inject_secrets("l", "p", &[], "op")
        .await
        .expect_err("missing result must fail");
    assert!(matches!(
        err,
        SessionError::Protocol(ref m) if m.contains("missing result")
    ));
    guest.await.unwrap();
}

// ==================================================================
// Bounded buffering (framed-path guards)
// ==================================================================

#[tokio::test]
async fn exec_with_limits_rejects_stdout_overflow() {
    use pico_guest_protocol::DEFAULT_MAX_STDERR_BYTES;

    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let _req: ExecRequest = recv_request(&mut conn, framed::TAG_EXEC_REQUEST).await;
        // Two 1 KiB frames; limit is 1 KiB so the second overflows.
        for seq in 1..=2u64 {
            conn.send_tagged(
                framed::TAG_EXEC_RESPONSE,
                &ExecResponse {
                    frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                        frame: Some(StreamFrame {
                            sequence: seq,
                            payload: vec![0xABu8; 1024],
                            end_of_stream: false,
                        }),
                    })),
                },
            )
            .await
            .unwrap();
        }
        // Terminal outcome (never consumed after limit error, but keeps the
        // mock well-formed).
        conn.send_tagged(
            framed::TAG_EXEC_RESPONSE,
            &ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: b"done".to_vec(),
                        },
                    )),
                })),
            },
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_lim"))
        .await
        .unwrap();
    let err = session
        .exec_with_limits(
            "cmd",
            &[],
            &hashbrown::HashMap::new(),
            "/",
            "op-lim",
            None,
            1024,
            DEFAULT_MAX_STDERR_BYTES,
        )
        .await
        .expect_err("stdout over limit must fail");
    assert!(
        matches!(err, SessionError::OutputLimitExceeded(_)),
        "expected OutputLimitExceeded, got {err:?}"
    );
    assert_eq!(err.kind(), "session_output_limit");
    guest.await.unwrap();
}

#[tokio::test]
async fn exec_with_limits_rejects_oversized_frame() {
    use pico_guest_protocol::MAX_FRAME_PAYLOAD_BYTES;

    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let _req: ExecRequest = recv_request(&mut conn, framed::TAG_EXEC_REQUEST).await;
        conn.send_tagged(
            framed::TAG_EXEC_RESPONSE,
            &ExecResponse {
                frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                    frame: Some(StreamFrame {
                        sequence: 1,
                        payload: vec![0xABu8; MAX_FRAME_PAYLOAD_BYTES + 1],
                        end_of_stream: false,
                    }),
                })),
            },
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_frame"))
        .await
        .unwrap();
    let err = session
        .exec(
            "cmd",
            &[],
            &hashbrown::HashMap::new(),
            "/",
            "op-frame",
            None,
        )
        .await
        .expect_err("oversized frame must fail");
    assert!(matches!(
        err,
        SessionError::OutputLimitExceeded(ref m) if m.contains("per-frame limit")
    ));
    guest.await.unwrap();
}

#[tokio::test]
async fn get_file_with_limit_rejects_oversize_metadata_before_allocation() {
    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
        let _req: GetFileRequest = recv_request(&mut conn, framed::TAG_GET_FILE_REQUEST).await;
        conn.send_tagged(
            framed::TAG_GET_FILE_RESPONSE,
            &GetFileResponse {
                frame: Some(get_file_response::Frame::Metadata(
                    get_file_response::FileMetadata {
                        size: 1_000_000,
                        mode: 0o644,
                        modified_at: None,
                    },
                )),
            },
        )
        .await
        .unwrap();
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_flim"))
        .await
        .unwrap();
    let err = session
        .get_file_with_limit("/tmp/big.bin", "op-flim", 1024)
        .await
        .expect_err("metadata over limit must fail before allocation");
    assert!(matches!(err, SessionError::FileTooLarge(_)));
    assert_eq!(err.kind(), "session_file_too_large");
    guest.await.unwrap();
}

#[tokio::test]
async fn put_file_rejects_payload_over_default_limit_before_send() {
    use pico_guest_protocol::DEFAULT_MAX_FILE_BYTES;

    let (addr, guest) = guest(|mut conn| async move {
        serve_handshake_ok(&mut conn).await;
    })
    .await;

    let mut session = GuestSession::connect_tcp(&session_config(addr, "sbx_plim"))
        .await
        .unwrap();
    let big = vec![0u8; DEFAULT_MAX_FILE_BYTES + 1];
    let err = session
        .put_file("/tmp/huge.bin", &big, 0o644, true, "op-plim")
        .await
        .expect_err("put over limit must fail before send");
    assert!(matches!(err, SessionError::FileTooLarge(_)));
    guest.await.unwrap();
}
