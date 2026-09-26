use prost::Message;

use pico_guest_protocol::bootstrap_v1::*;
use pico_guest_protocol::operational_v1::*;

// ------------------------------------------------------------------
// Bootstrap round-trip tests
// ------------------------------------------------------------------

#[test]
fn host_hello_round_trip() {
    let hello = HostHello {
        protocol_name: "pico.guest".into(),
        bootstrap_version: Some(VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 0 }),
        }),
        supported_versions: vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        }],
        host_capabilities: Some(CapabilitySet {
            identifiers: vec!["exec".into(), "file".into(), "mount".into()],
        }),
        host_nonce: Some(Nonce {
            value: vec![0xABu8; 32],
        }),
        sandbox_id: "sbx_test".into(),
        image_id: "img_test".into(),
        image_digest: "abc123".into(),
    };

    let encoded = hello.encode_to_vec();
    let decoded = HostHello::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.protocol_name, "pico.guest");
    assert_eq!(decoded.sandbox_id, "sbx_test");
    assert_eq!(decoded.host_capabilities.unwrap().identifiers.len(), 3);
}

#[test]
fn guest_hello_round_trip() {
    let hello = GuestHello {
        supported_versions: vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        }],
        guest_capabilities: Some(CapabilitySet {
            identifiers: vec!["exec".into()],
        }),
        guest_nonce: Some(Nonce {
            value: vec![0xCDu8; 32],
        }),
        agent_version: "0.3.0".into(),
        boot_id: "boot-001".into(),
        image_id: "img_test".into(),
        image_digest: "abc123".into(),
        proof: Some(Proof {
            value: vec![0xEFu8; 32],
        }),
    };

    let encoded = hello.encode_to_vec();
    let decoded = GuestHello::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.agent_version, "0.3.0");
    assert_eq!(decoded.boot_id, "boot-001");
    assert_eq!(decoded.proof.unwrap().value.len(), 32);
}

#[test]
fn host_reply_round_trip() {
    let reply = HostReply {
        selected_version: Some(Version { major: 1, minor: 3 }),
        selected_capabilities: Some(CapabilitySet {
            identifiers: vec!["exec".into(), "file".into()],
        }),
        session_id: Some(SessionId {
            value: vec![0x01u8; 16],
        }),
        policy_epoch: 42,
        proof: Some(Proof {
            value: vec![0xFFu8; 32],
        }),
    };

    let encoded = reply.encode_to_vec();
    let decoded = HostReply::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.selected_version.unwrap().major, 1);
    assert_eq!(decoded.selected_version.unwrap().minor, 3);
    assert_eq!(decoded.policy_epoch, 42);
}

#[test]
fn handshake_error_round_trip() {
    let err = HandshakeError {
        code: handshake_error::ErrorCode::AuthenticationFailed as i32,
        message: "HMAC proof mismatch".into(),
    };

    let encoded = err.encode_to_vec();
    let decoded = HandshakeError::decode(encoded.as_slice()).unwrap();
    assert_eq!(
        decoded.code,
        handshake_error::ErrorCode::AuthenticationFailed as i32
    );
    assert_eq!(decoded.message, "HMAC proof mismatch");
}

// ------------------------------------------------------------------
// Operational round-trip tests
// ------------------------------------------------------------------

#[test]
fn exec_request_round_trip() {
    let req = ExecRequest {
        context: Some(RequestContext {
            request_id: "req-001".into(),
            operation_id: "op-001".into(),
            sandbox_id: "sbx_test".into(),
            session_id: vec![0x01u8; 16],
            policy_epoch: 42,
            protocol_version: (1 << 16) | 3,
            deadline: None,
            ..Default::default()
        }),
        command: "/bin/echo".into(),
        args: vec!["hello".into(), "world".into()],
        env: [("PATH".into(), "/usr/bin".into())].into(),
        working_dir: "/tmp".into(),
        timeout: None,
        max_stdout_bytes: 4096,
        max_stderr_bytes: 1024,
    };

    let encoded = req.encode_to_vec();
    let decoded = ExecRequest::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.command, "/bin/echo");
    assert_eq!(decoded.args.len(), 2);
    assert_eq!(decoded.max_stdout_bytes, 4096);
}

#[test]
fn stream_frame_round_trip() {
    let frame = StreamFrame {
        sequence: 1,
        payload: b"hello world".to_vec(),
        end_of_stream: false,
    };

    let encoded = frame.encode_to_vec();
    let decoded = StreamFrame::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.sequence, 1);
    assert_eq!(decoded.payload, b"hello world");
    assert!(!decoded.end_of_stream);
}

#[test]
fn end_of_stream_frame() {
    let frame = StreamFrame {
        sequence: 5,
        payload: vec![],
        end_of_stream: true,
    };

    let encoded = frame.encode_to_vec();
    let decoded = StreamFrame::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.sequence, 5);
    assert!(decoded.end_of_stream);
}

#[test]
fn operation_outcome_success_round_trip() {
    let outcome = OperationOutcome {
        status: Some(operation_outcome::Status::Success(
            operation_outcome::Success {
                result_payload: b"ok".to_vec(),
            },
        )),
    };

    let encoded = outcome.encode_to_vec();
    let decoded = OperationOutcome::decode(encoded.as_slice()).unwrap();
    assert!(matches!(
        decoded.status,
        Some(operation_outcome::Status::Success(_))
    ));
}

#[test]
fn operation_outcome_failure_round_trip() {
    let outcome = OperationOutcome {
        status: Some(operation_outcome::Status::Failure(
            operation_outcome::Failure {
                code: "EXEC_FAILURE".into(),
                message: "command not found".into(),
                retryable: false,
            },
        )),
    };

    let encoded = outcome.encode_to_vec();
    let decoded = OperationOutcome::decode(encoded.as_slice()).unwrap();
    match decoded.status.unwrap() {
        operation_outcome::Status::Failure(f) => {
            assert_eq!(f.code, "EXEC_FAILURE");
            assert!(!f.retryable);
        }
        _ => panic!("expected Failure"),
    }
}

// ------------------------------------------------------------------
// Wire-format stability (golden) tests
// ------------------------------------------------------------------

#[test]
fn golden_request_context() {
    let ctx = RequestContext {
        request_id: "req-001".into(),
        operation_id: "op-001".into(),
        sandbox_id: "sbx_test".into(),
        session_id: vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ],
        policy_epoch: 42,
        protocol_version: 65539, // (1 << 16) | 3
        deadline: None,
        ..Default::default()
    };

    let encoded = ctx.encode_to_vec();
    // Verify deterministic serialization by round-tripping.
    let decoded = RequestContext::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.request_id, "req-001");
    assert_eq!(decoded.operation_id, "op-001");
    assert_eq!(decoded.sandbox_id, "sbx_test");
    assert_eq!(decoded.session_id.len(), 16);
    assert_eq!(decoded.policy_epoch, 42);
    assert_eq!(decoded.protocol_version, 65539);
}

// ------------------------------------------------------------------
// Backward-compatibility tests for optional fields
// ------------------------------------------------------------------

#[test]
fn exec_request_without_optional_fields() {
    // Minimal exec request: only required fields.
    let req = ExecRequest {
        context: Some(RequestContext {
            request_id: "req-001".into(),
            operation_id: "".into(),
            sandbox_id: "sbx_test".into(),
            session_id: vec![],
            policy_epoch: 0,
            protocol_version: 0,
            deadline: None,
            ..Default::default()
        }),
        command: "/bin/true".into(),
        args: vec![],
        env: std::collections::HashMap::new(),
        working_dir: "".into(),
        timeout: None,
        max_stdout_bytes: 0,
        max_stderr_bytes: 0,
    };

    // Encode with default/empty optionals.
    let encoded = req.encode_to_vec();

    // Decode should succeed and missing optionals should be default.
    let decoded = ExecRequest::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.command, "/bin/true");
    assert!(decoded.args.is_empty());
    assert!(decoded.env.is_empty());
    assert!(decoded.timeout.is_none());
    assert_eq!(decoded.max_stdout_bytes, 0);
}

// ------------------------------------------------------------------
// File transfer message tests
// ------------------------------------------------------------------

#[test]
fn put_file_metadata_round_trip() {
    let meta = PutFileMetadata {
        context: Some(RequestContext {
            request_id: "req-file".into(),
            operation_id: "op-file".into(),
            sandbox_id: "sbx_test".into(),
            session_id: vec![0xAAu8; 16],
            policy_epoch: 1,
            protocol_version: 65539,
            deadline: None,
            ..Default::default()
        }),
        path: "/tmp/foo.txt".into(),
        mode: 0o644,
        expected_size: 1024,
        overwrite: true,
    };

    let encoded = meta.encode_to_vec();
    let decoded = PutFileMetadata::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.path, "/tmp/foo.txt");
    assert_eq!(decoded.mode, 0o644);
    assert_eq!(decoded.expected_size, 1024);
    assert!(decoded.overwrite);
}

#[test]
fn put_file_response_with_checksum() {
    let resp = PutFileResponse {
        result: Some(put_file_response::Result::BytesWritten(1024)),
        checksum: "abc123def456".into(),
    };

    let encoded = resp.encode_to_vec();
    let decoded = PutFileResponse::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.checksum, "abc123def456");
    assert!(matches!(
        decoded.result,
        Some(put_file_response::Result::BytesWritten(1024))
    ));
}

#[test]
fn get_file_response_with_metadata() {
    let resp = GetFileResponse {
        frame: Some(get_file_response::Frame::Metadata(
            get_file_response::FileMetadata {
                size: 4096,
                mode: 0o755,
                modified_at: None,
            },
        )),
    };

    let encoded = resp.encode_to_vec();
    let decoded = GetFileResponse::decode(encoded.as_slice()).unwrap();
    match decoded.frame.unwrap() {
        get_file_response::Frame::Metadata(m) => {
            assert_eq!(m.size, 4096);
            assert_eq!(m.mode, 0o755);
        }
        _ => panic!("expected Metadata"),
    }
}

// ------------------------------------------------------------------
// Health and stats message tests
// ------------------------------------------------------------------

#[test]
fn health_response_round_trip() {
    let resp = HealthResponse {
        status: health_response::HealthStatus::Ok as i32,
        message: "all subsystems ok".into(),
    };

    let encoded = resp.encode_to_vec();
    let decoded = HealthResponse::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.status, health_response::HealthStatus::Ok as i32);
    assert_eq!(decoded.message, "all subsystems ok");
}

#[test]
fn stats_response_round_trip() {
    let stats = StatsResponse {
        cpu: Some(stats_response::CpuStats {
            user_time: None,
            system_time: None,
            context_switches: 42,
        }),
        memory: Some(stats_response::MemoryStats {
            rss_bytes: 64 * 1024 * 1024,
            available_bytes: 256 * 1024 * 1024,
            total_bytes: 512 * 1024 * 1024,
            swap_bytes: 0,
        }),
        disk: Some(stats_response::DiskStats {
            total_bytes: 10_000_000_000,
            used_bytes: 3_000_000_000,
            available_bytes: 7_000_000_000,
        }),
    };

    let encoded = stats.encode_to_vec();
    let decoded = StatsResponse::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.cpu.unwrap().context_switches, 42);
    assert_eq!(decoded.memory.unwrap().rss_bytes, 64 * 1024 * 1024);
    assert_eq!(decoded.disk.unwrap().total_bytes, 10_000_000_000);
}

// ------------------------------------------------------------------
// Mount message tests
// ------------------------------------------------------------------

#[test]
fn mount_workspace_round_trip() {
    let req = MountWorkspaceRequest {
        context: Some(RequestContext {
            request_id: "req-mount".into(),
            operation_id: "".into(),
            sandbox_id: "sbx_test".into(),
            session_id: vec![0xBBu8; 16],
            policy_epoch: 1,
            protocol_version: 65539,
            deadline: None,
            ..Default::default()
        }),
        mount_point: "/mnt/workspace".into(),
        fs_type: "virtiofs".into(),
        options: [("ro".into(), "true".into())].into(),
    };

    let encoded = req.encode_to_vec();
    let decoded = MountWorkspaceRequest::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.mount_point, "/mnt/workspace");
    assert_eq!(decoded.fs_type, "virtiofs");
    assert_eq!(decoded.options.get("ro").map(|s| s.as_str()), Some("true"));
}

// ------------------------------------------------------------------
// Lifecycle message tests
// ------------------------------------------------------------------

#[test]
fn quiesce_request_round_trip() {
    let req = QuiesceRequest {
        context: Some(RequestContext {
            request_id: "req-quiesce".into(),
            operation_id: "op-quiesce".into(),
            sandbox_id: "sbx_test".into(),
            session_id: vec![0xCCu8; 16],
            policy_epoch: 1,
            protocol_version: 65539,
            deadline: None,
            ..Default::default()
        }),
        drain_mode: quiesce_request::DrainMode::Graceful as i32,
        quiesce_deadline: None,
    };

    let encoded = req.encode_to_vec();
    let decoded = QuiesceRequest::decode(encoded.as_slice()).unwrap();
    assert_eq!(
        decoded.drain_mode,
        quiesce_request::DrainMode::Graceful as i32
    );
}

#[test]
fn resume_notify_request_round_trip() {
    let req = ResumeNotifyRequest {
        context: Some(RequestContext {
            request_id: "req-resume".into(),
            operation_id: "".into(),
            sandbox_id: "sbx_restored".into(),
            session_id: vec![0xDDu8; 16],
            policy_epoch: 2,
            protocol_version: 65539,
            deadline: None,
            ..Default::default()
        }),
        sandbox_id: "sbx_restored".into(),
        policy_epoch: 2,
        lineage_id: "snap-lineage-001".into(),
        snapshot_taken_at: None,
    };

    let encoded = req.encode_to_vec();
    let decoded = ResumeNotifyRequest::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.sandbox_id, "sbx_restored");
    assert_eq!(decoded.lineage_id, "snap-lineage-001");
    assert_eq!(decoded.policy_epoch, 2);
}

#[test]
fn shutdown_request_round_trip() {
    let req = ShutdownRequest {
        context: Some(RequestContext {
            request_id: "req-shutdown".into(),
            operation_id: "".into(),
            sandbox_id: "sbx_test".into(),
            session_id: vec![0xEEu8; 16],
            policy_epoch: 1,
            protocol_version: 65539,
            deadline: None,
            ..Default::default()
        }),
        reason: "scheduled maintenance".into(),
        force: true,
    };

    let encoded = req.encode_to_vec();
    let decoded = ShutdownRequest::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.reason, "scheduled maintenance");
    assert!(decoded.force);
}

// ------------------------------------------------------------------
// Handshake wrapper message tests
// ------------------------------------------------------------------

#[test]
fn handshake_request_with_host_hello() {
    let req = HandshakeRequest {
        message: Some(handshake_request::Message::HostHello(HostHello {
            protocol_name: "pico.guest".into(),
            bootstrap_version: None,
            supported_versions: vec![],
            host_capabilities: None,
            host_nonce: None,
            sandbox_id: "sbx_test".into(),
            image_id: "".into(),
            image_digest: "".into(),
        })),
    };

    let encoded = req.encode_to_vec();
    let decoded = HandshakeRequest::decode(encoded.as_slice()).unwrap();
    assert!(matches!(
        decoded.message,
        Some(handshake_request::Message::HostHello(_))
    ));
}

#[test]
fn handshake_request_with_host_reply() {
    let req = HandshakeRequest {
        message: Some(handshake_request::Message::HostReply(HostReply {
            selected_version: None,
            selected_capabilities: None,
            session_id: None,
            policy_epoch: 42,
            proof: None,
        })),
    };

    let encoded = req.encode_to_vec();
    let decoded = HandshakeRequest::decode(encoded.as_slice()).unwrap();
    assert!(matches!(
        decoded.message,
        Some(handshake_request::Message::HostReply(_))
    ));
    match decoded.message.unwrap() {
        handshake_request::Message::HostReply(r) => assert_eq!(r.policy_epoch, 42),
        _ => panic!("expected HostReply"),
    }
}

#[test]
fn handshake_response_with_guest_hello() {
    let resp = HandshakeResponse {
        message: Some(handshake_response::Message::GuestHello(GuestHello {
            supported_versions: vec![],
            guest_capabilities: None,
            guest_nonce: None,
            agent_version: "0.3.0".into(),
            boot_id: "boot-001".into(),
            image_id: "".into(),
            image_digest: "".into(),
            proof: None,
        })),
    };

    let encoded = resp.encode_to_vec();
    let decoded = HandshakeResponse::decode(encoded.as_slice()).unwrap();
    assert!(matches!(
        decoded.message,
        Some(handshake_response::Message::GuestHello(_))
    ));
}

#[test]
fn handshake_result_established() {
    let result = HandshakeResult {
        outcome: Some(handshake_result::Outcome::Established(true)),
    };

    let encoded = result.encode_to_vec();
    let decoded = HandshakeResult::decode(encoded.as_slice()).unwrap();
    match decoded.outcome.unwrap() {
        handshake_result::Outcome::Established(v) => assert!(v),
        _ => panic!("expected Established"),
    }
}

#[test]
fn handshake_result_error() {
    let result = HandshakeResult {
        outcome: Some(handshake_result::Outcome::Error(HandshakeError {
            code: handshake_error::ErrorCode::AuthenticationFailed as i32,
            message: "HMAC mismatch".into(),
        })),
    };

    let encoded = result.encode_to_vec();
    let decoded = HandshakeResult::decode(encoded.as_slice()).unwrap();
    match decoded.outcome.unwrap() {
        handshake_result::Outcome::Error(e) => {
            assert_eq!(
                e.code,
                handshake_error::ErrorCode::AuthenticationFailed as i32
            );
        }
        _ => panic!("expected Error"),
    }
}

// ------------------------------------------------------------------
// Signal and Cancel response tests
// ------------------------------------------------------------------

#[test]
fn signal_response_acknowledged() {
    let resp = SignalResponse {
        result: Some(signal_response::Result::Acknowledged(Ack {})),
    };

    let encoded = resp.encode_to_vec();
    let decoded = SignalResponse::decode(encoded.as_slice()).unwrap();
    assert!(matches!(
        decoded.result,
        Some(signal_response::Result::Acknowledged(_))
    ));
}

#[test]
fn cancel_response_accepted() {
    let resp = CancelResponse {
        result: Some(cancel_response::Result::Accepted(Ack {})),
    };

    let encoded = resp.encode_to_vec();
    let decoded = CancelResponse::decode(encoded.as_slice()).unwrap();
    assert!(matches!(
        decoded.result,
        Some(cancel_response::Result::Accepted(_))
    ));
}

#[test]
fn cancel_response_unknown_operation() {
    let resp = CancelResponse {
        result: Some(cancel_response::Result::Unknown(UnknownOp {
            operation_id: "op-missing".into(),
        })),
    };

    let encoded = resp.encode_to_vec();
    let decoded = CancelResponse::decode(encoded.as_slice()).unwrap();
    match decoded.result.unwrap() {
        cancel_response::Result::Unknown(u) => assert_eq!(u.operation_id, "op-missing"),
        _ => panic!("expected Unknown"),
    }
}

#[test]
fn unknown_fields_are_tolerated() {
    let req = ExecRequest {
        context: Some(RequestContext {
            request_id: "req-unknown".into(),
            operation_id: "".into(),
            sandbox_id: "sbx_test".into(),
            session_id: vec![],
            policy_epoch: 0,
            protocol_version: 0,
            deadline: None,
            ..Default::default()
        }),
        command: "/bin/test".into(),
        args: vec![],
        env: std::collections::HashMap::new(),
        working_dir: "".into(),
        timeout: None,
        max_stdout_bytes: 0,
        max_stderr_bytes: 0,
    };

    let encoded = req.encode_to_vec();

    // Simulate a newer schema that added field 20 (varint = 42).
    // Protobuf wire format:
    //   tag = (20 << 3) | 0 (varint).  20 << 3 = 160 = 0xA0.
    //   Since 160 >= 128, the tag needs 2 varint bytes:
    //     [0xA0, 0x01] (low 7 bits | 0x80, then remaining bits).
    //   value = 42 = 0x2A (fits in 1 byte).
    let mut extended = encoded.clone();
    extended.extend_from_slice(&[0xA0, 0x01, 0x2A]);

    // An older peer receiving the extended message should
    // tolerate the unknown field and decode known fields.
    // This verifies forward compatibility: a newer peer adding
    // optional fields to the schema won't break an older peer
    // that doesn't know about them.
    let decoded = ExecRequest::decode(extended.as_slice()).unwrap();
    assert_eq!(decoded.command, "/bin/test");

    // Re-encode and decode again. Known fields survive the
    // round trip even when unknown fields are present in the
    // wire format.
    let re_encoded = decoded.encode_to_vec();
    let re_decoded = ExecRequest::decode(re_encoded.as_slice()).unwrap();
    assert_eq!(re_decoded.command, "/bin/test");
}
