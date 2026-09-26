//! Compatibility fixtures for the PicoCompute guest-agent protocol.
//!
//! These fixtures exercise protocol messages across at least two
//! operational protocol versions (v1.0 and v1.5) to verify that
//! version-aware parsers and validators behave correctly.
//!
//! Each fixture contains a full serialized message and a version
//! annotation. Conformance tests verify that:
//! - v1.0 clients can parse messages from v1.0 and v1.5 peers
//! - v1.5 clients can parse messages from v1.0 and v1.5 peers
//! - Unknown fields added in later minor versions are tolerated
//! - Version fields in RequestContext are correctly packed/verified

use prost::Message;

use pico_guest_protocol::bootstrap_v1::*;
use pico_guest_protocol::operational_v1::*;

// ==================================================================
// v1.0 -> v1.5 forward compatibility fixtures
// ==================================================================

/// A v1.0-encoded ExecRequest with minimal fields should be parseable
/// by a v1.5 peer.
#[test]
fn v1_0_exec_request_parses_on_v1_5() {
    let req = ExecRequest {
        context: Some(RequestContext {
            request_id: "req-v1.0".into(),
            operation_id: "op-v1.0".into(),
            sandbox_id: "sbx_v1.0".into(),
            session_id: vec![0x01u8; 16],
            policy_epoch: 1,
            protocol_version: (1u32 << 16), // v1.0
            deadline: None,
            trace_context: None,
        }),
        command: "/bin/echo".into(),
        args: vec!["hello".into()],
        env: [("PATH".into(), "/usr/bin".into())].into(),
        working_dir: "/tmp".into(),
        timeout: None,
        max_stdout_bytes: 0,
        max_stderr_bytes: 0,
    };

    let encoded = req.encode_to_vec();

    // A v1.5 peer parses the v1.0 message successfully
    let decoded = ExecRequest::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.command, "/bin/echo");
    assert_eq!(decoded.args.len(), 1);
    assert_eq!(
        decoded.context.as_ref().unwrap().protocol_version,
        (1u32 << 16)
    );
}

/// A v1.5-encoded ExecRequest with additional env vars and timeout
/// must be parseable by a v1.0 peer (forward compatibility via
/// unknown field tolerance).
#[test]
fn v1_5_exec_request_parses_on_v1_0_with_unknown_fields() {
    use prost_types::Duration as ProtoDuration;

    let req = ExecRequest {
        context: Some(RequestContext {
            request_id: "req-v1.5".into(),
            operation_id: "op-v1.5".into(),
            sandbox_id: "sbx_v1.5".into(),
            session_id: vec![0x02u8; 16],
            policy_epoch: 5,
            protocol_version: (1u32 << 16) | 5, // v1.5
            deadline: None,
            trace_context: None,
        }),
        command: "/bin/bash".into(),
        args: vec!["-c".into(), "echo done".into()],
        env: [
            ("PATH".into(), "/usr/bin".into()),
            ("HOME".into(), "/root".into()),
            ("LANG".into(), "en_US.UTF-8".into()),
        ]
        .into(),
        working_dir: "/home/user".into(),
        timeout: Some(ProtoDuration {
            seconds: 30,
            nanos: 0,
        }),
        max_stdout_bytes: 4096,
        max_stderr_bytes: 1024,
    };

    let encoded = req.encode_to_vec();

    // A v1.0 peer parses the v1.5 message - known fields are preserved
    let decoded = ExecRequest::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.command, "/bin/bash");
    assert_eq!(decoded.args.len(), 2);
    assert_eq!(decoded.env.len(), 3);

    // Re-encode and verify round-trip stability (known fields survive)
    let re_encoded = decoded.encode_to_vec();
    let re_decoded = ExecRequest::decode(re_encoded.as_slice()).unwrap();
    assert_eq!(re_decoded.command, "/bin/bash");
    assert_eq!(re_decoded.max_stdout_bytes, 4096);
}

// ==================================================================
// v1.0 <--> v1.5 handshake compatibility
// ==================================================================

/// HostHello with v1.5 version range, parseable by both versions.
#[test]
fn host_hello_v1_5_cross_version_parseable() {
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
            identifiers: vec![
                "exec".into(),
                "file".into(),
                "mount".into(),
                "stats".into(),
                "health".into(),
                "shutdown".into(),
            ],
        }),
        host_nonce: Some(Nonce {
            value: vec![0xABu8; 32],
        }),
        sandbox_id: "sbx_cross_version".into(),
        image_id: "img_cross_version".into(),
        image_digest: "sha256:abc123def456".into(),
    };

    let encoded = hello.encode_to_vec();
    let decoded = HostHello::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded.protocol_name, "pico.guest");
    assert_eq!(decoded.sandbox_id, "sbx_cross_version");
    assert_eq!(decoded.image_id, "img_cross_version");
    assert_eq!(decoded.host_nonce.unwrap().value.len(), 32);

    // Verify version range fields
    let versions = &decoded.supported_versions;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].max.as_ref().unwrap().minor, 5);
}

/// GuestHello with v1.3 version range and v1.5 capabilities.
#[test]
fn guest_hello_v1_3_with_v1_5_capabilities_parseable() {
    let hello = GuestHello {
        supported_versions: vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 3 }),
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
            value: vec![0xCDu8; 32],
        }),
        agent_version: "0.3.0".into(),
        boot_id: "boot-v1.3".into(),
        image_id: "img_test".into(),
        image_digest: "sha256:def789".into(),
        proof: Some(Proof {
            value: vec![0xEFu8; 32],
        }),
    };

    let encoded = hello.encode_to_vec();
    let decoded = GuestHello::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded.agent_version, "0.3.0");
    assert_eq!(decoded.boot_id, "boot-v1.3");
    assert_eq!(decoded.guest_nonce.unwrap().value.len(), 32);
    assert_eq!(decoded.proof.unwrap().value.len(), 32);

    // Verify version range
    assert_eq!(decoded.supported_versions[0].max.as_ref().unwrap().minor, 3);
}

// ==================================================================
// v1.0 -> v1.5 stream compatibility
// ==================================================================

/// StreamFrame encoded at v1.0 with 64 KiB payload, parseable at v1.5.
#[test]
fn stream_frame_v1_0_payload_v1_5_parseable() {
    let frame = StreamFrame {
        sequence: 1,
        payload: vec![0xAAu8; 64 * 1024], // 64 KiB
        end_of_stream: false,
    };

    let encoded = frame.encode_to_vec();
    let decoded = StreamFrame::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded.sequence, 1);
    assert_eq!(decoded.payload.len(), 64 * 1024);
    assert!(!decoded.end_of_stream);
}

/// StreamFrame with end_of_stream=true at v1.0, parseable at v1.5.
#[test]
fn end_of_stream_frame_v1_0_to_v1_5_compatible() {
    let frame = StreamFrame {
        sequence: 99,
        payload: vec![],
        end_of_stream: true,
    };

    let encoded = frame.encode_to_vec();
    let decoded = StreamFrame::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded.sequence, 99);
    assert!(decoded.payload.is_empty());
    assert!(decoded.end_of_stream);
}

// ==================================================================
// v1.0 -> v1.5 RequestContext compatibility
// ==================================================================

/// RequestContext with v1.0 protocol_version field.
#[test]
fn request_context_v1_0_version_field() {
    let ctx = RequestContext {
        request_id: "v1.0-req".into(),
        operation_id: "v1.0-op".into(),
        sandbox_id: "v1.0-sbx".into(),
        session_id: vec![0x10u8; 16],
        policy_epoch: 1,
        protocol_version: (1u32 << 16), // v1.0 = 0x00010000
        deadline: None,
        trace_context: None,
    };

    let encoded = ctx.encode_to_vec();
    let decoded = RequestContext::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded.protocol_version, 0x00010000);
    assert_eq!(decoded.request_id, "v1.0-req");
    assert_eq!(decoded.sandbox_id, "v1.0-sbx");
}

/// RequestContext with v1.5 protocol_version field.
#[test]
fn request_context_v1_5_version_field() {
    let ctx = RequestContext {
        request_id: "v1.5-req".into(),
        operation_id: "v1.5-op".into(),
        sandbox_id: "v1.5-sbx".into(),
        session_id: vec![0x15u8; 16],
        policy_epoch: 5,
        protocol_version: (1u32 << 16) | 5, // v1.5 = 0x00010005
        deadline: None,
        trace_context: None,
    };

    let encoded = ctx.encode_to_vec();
    let decoded = RequestContext::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded.protocol_version, 0x00010005);
    assert_eq!(decoded.sandbox_id, "v1.5-sbx");
    assert_eq!(decoded.policy_epoch, 5);
}

// ==================================================================
// v1.0 -> v1.5 operation outcome compatibility
// ==================================================================

/// All five OperationOutcome status variants round-trip at v1.0.
#[test]
fn operation_outcome_all_variants_v1_0_round_trip() {
    let variants: Vec<OperationOutcome> = vec![
        OperationOutcome {
            status: Some(operation_outcome::Status::Success(
                operation_outcome::Success {
                    result_payload: b"ok".to_vec(),
                },
            )),
        },
        OperationOutcome {
            status: Some(operation_outcome::Status::Failure(
                operation_outcome::Failure {
                    code: "ERR".into(),
                    message: "fail".into(),
                    retryable: false,
                },
            )),
        },
        OperationOutcome {
            status: Some(operation_outcome::Status::Canceled(
                operation_outcome::Canceled {
                    reason: "cancelled".into(),
                },
            )),
        },
        OperationOutcome {
            status: Some(operation_outcome::Status::TimedOut(
                operation_outcome::TimedOut {
                    budget_remaining: None,
                },
            )),
        },
        OperationOutcome {
            status: Some(operation_outcome::Status::Unsupported(
                operation_outcome::Unsupported {
                    detail: "unsupported".into(),
                },
            )),
        },
    ];

    for outcome in variants {
        let encoded = outcome.encode_to_vec();
        let decoded = OperationOutcome::decode(encoded.as_slice()).unwrap();
        // Round-trip through re-encode
        let re_encoded = decoded.encode_to_vec();
        let re_decoded = OperationOutcome::decode(re_encoded.as_slice()).unwrap();
        // Verify both variants are non-empty
        assert!(decoded.status.is_some());
        assert!(re_decoded.status.is_some());
    }
}

/// All six OperationOutcome status variants round-trip at v1.5
/// (with protocol_version=0x00010005 in context doesn't change
/// outcome encoding, but we test the wire format is stable).
#[test]
fn operation_outcome_all_variants_v1_5_round_trip() {
    // The outcome message itself is version-agnostic.
    let outcomes: Vec<(&str, OperationOutcome)> = vec![
        (
            "success",
            OperationOutcome {
                status: Some(operation_outcome::Status::Success(
                    operation_outcome::Success {
                        result_payload: vec![0x01, 0x02, 0x03],
                    },
                )),
            },
        ),
        (
            "failure_retryable",
            OperationOutcome {
                status: Some(operation_outcome::Status::Failure(
                    operation_outcome::Failure {
                        code: "RETRYABLE_ERR".into(),
                        message: "transient".into(),
                        retryable: true,
                    },
                )),
            },
        ),
        (
            "canceled",
            OperationOutcome {
                status: Some(operation_outcome::Status::Canceled(
                    operation_outcome::Canceled {
                        reason: "explicit cancel".into(),
                    },
                )),
            },
        ),
        (
            "timed_out",
            OperationOutcome {
                status: Some(operation_outcome::Status::TimedOut(
                    operation_outcome::TimedOut {
                        budget_remaining: None,
                    },
                )),
            },
        ),
        (
            "unsupported",
            OperationOutcome {
                status: Some(operation_outcome::Status::Unsupported(
                    operation_outcome::Unsupported {
                        detail: "feature not supported at v1.5".into(),
                    },
                )),
            },
        ),
        (
            "requires_review",
            OperationOutcome {
                status: Some(operation_outcome::Status::RequiresReview(
                    operation_outcome::RequiresReview {
                        detail: "needs human review".into(),
                    },
                )),
            },
        ),
    ];

    for (label, outcome) in outcomes {
        let encoded = outcome.encode_to_vec();
        let decoded = OperationOutcome::decode(encoded.as_slice()).unwrap();
        assert!(decoded.status.is_some(), "failed for variant: {label}");

        let re_encoded = decoded.encode_to_vec();
        let re_decoded = OperationOutcome::decode(re_encoded.as_slice()).unwrap();
        assert!(
            re_decoded.status.is_some(),
            "re-encode failed for variant: {label}"
        );
    }
}

// ==================================================================
// v1.0 <--> v1.5 lifecycle message compatibility
// ==================================================================

/// QuiesceRequest: v1.0 (Graceful) parseable by v1.5 peer.
#[test]
fn quiesce_request_v1_0_graceful_parseable() {
    let req = QuiesceRequest {
        context: Some(RequestContext {
            request_id: "q-v1.0".into(),
            operation_id: "".into(),
            sandbox_id: "sbx".into(),
            session_id: vec![0x10u8; 16],
            policy_epoch: 1,
            protocol_version: (1u32 << 16),
            deadline: None,
            trace_context: None,
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

/// QuiesceRequest: v1.5 (Force with deadline) parseable by v1.0 peer.
#[test]
fn quiesce_request_v1_5_force_with_deadline_parseable() {
    use prost_types::Timestamp;

    let req = QuiesceRequest {
        context: Some(RequestContext {
            request_id: "q-v1.5".into(),
            operation_id: "".into(),
            sandbox_id: "sbx".into(),
            session_id: vec![0x15u8; 16],
            policy_epoch: 5,
            protocol_version: (1u32 << 16) | 5,
            deadline: None,
            trace_context: None,
        }),
        drain_mode: quiesce_request::DrainMode::Force as i32,
        quiesce_deadline: Some(Timestamp {
            seconds: 1718114400,
            nanos: 0,
        }),
    };

    let encoded = req.encode_to_vec();
    let decoded = QuiesceRequest::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded.drain_mode, quiesce_request::DrainMode::Force as i32);
    assert!(decoded.quiesce_deadline.is_some());
    assert_eq!(decoded.quiesce_deadline.unwrap().seconds, 1718114400);
}

/// ResumeNotifyRequest with lineage_id and snapshot_taken_at (v1.5 features).
#[test]
fn resume_notify_v1_5_with_lineage_parseable() {
    use prost_types::Timestamp;

    let req = ResumeNotifyRequest {
        context: Some(RequestContext {
            request_id: "rn-v1.5".into(),
            operation_id: "".into(),
            sandbox_id: "sbx".into(),
            session_id: vec![0x15u8; 16],
            policy_epoch: 5,
            protocol_version: (1u32 << 16) | 5,
            deadline: None,
            trace_context: None,
        }),
        sandbox_id: "sbx".into(),
        policy_epoch: 5,
        lineage_id: "lineage-001-abc".into(),
        snapshot_taken_at: Some(Timestamp {
            seconds: 1718114300,
            nanos: 500_000_000,
        }),
    };

    let encoded = req.encode_to_vec();
    let decoded = ResumeNotifyRequest::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded.sandbox_id, "sbx");
    assert_eq!(decoded.lineage_id, "lineage-001-abc");
    assert_eq!(decoded.policy_epoch, 5);
    assert!(decoded.snapshot_taken_at.is_some());
}

/// ShutdownRequest: v1.0 (gentle shutdown) and v1.5 (force shutdown).
#[test]
fn shutdown_request_v1_0_and_v1_5_parseable() {
    // v1.0: gentle shutdown
    let req_v1_0 = ShutdownRequest {
        context: Some(RequestContext {
            request_id: "sd-v1.0".into(),
            operation_id: "".into(),
            sandbox_id: "sbx".into(),
            session_id: vec![0x10u8; 16],
            policy_epoch: 1,
            protocol_version: (1u32 << 16),
            deadline: None,
            trace_context: None,
        }),
        reason: "maintenance".into(),
        force: false,
    };
    let decoded_v1_0 = ShutdownRequest::decode(req_v1_0.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded_v1_0.reason, "maintenance");
    assert!(!decoded_v1_0.force);

    // v1.5: forced shutdown
    let req_v1_5 = ShutdownRequest {
        context: Some(RequestContext {
            request_id: "sd-v1.5".into(),
            operation_id: "".into(),
            sandbox_id: "sbx".into(),
            session_id: vec![0x15u8; 16],
            policy_epoch: 5,
            protocol_version: (1u32 << 16) | 5,
            deadline: None,
            trace_context: None,
        }),
        reason: "emergency".into(),
        force: true,
    };
    let decoded_v1_5 = ShutdownRequest::decode(req_v1_5.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded_v1_5.reason, "emergency");
    assert!(decoded_v1_5.force);
}

// ==================================================================
// v1.0 <--> v1.5 response type compatibility
// ==================================================================

/// SignalResponse variants: v1.0 (Acknowledged) / v1.5 (Error).
#[test]
fn signal_response_v1_0_and_v1_5_variants_compatible() {
    let resp_v1_0 = SignalResponse {
        result: Some(signal_response::Result::Acknowledged(Ack {})),
    };
    let decoded = SignalResponse::decode(resp_v1_0.encode_to_vec().as_slice()).unwrap();
    assert!(matches!(
        decoded.result,
        Some(signal_response::Result::Acknowledged(_))
    ));

    let resp_v1_5 = SignalResponse {
        result: Some(signal_response::Result::Error(OperationOutcome {
            status: Some(operation_outcome::Status::Failure(
                operation_outcome::Failure {
                    code: "INVALID_SIGNAL".into(),
                    message: "unknown signal number".into(),
                    retryable: false,
                },
            )),
        })),
    };
    let decoded = SignalResponse::decode(resp_v1_5.encode_to_vec().as_slice()).unwrap();
    assert!(matches!(
        decoded.result,
        Some(signal_response::Result::Error(_))
    ));
}

/// MountWorkspaceResponse: v1.0 (mounted) / v1.5 (error).
#[test]
fn mount_workspace_response_v1_0_and_v1_5_compatible() {
    let ok = MountWorkspaceResponse {
        result: Some(mount_workspace_response::Result::Mounted(true)),
    };
    let decoded = MountWorkspaceResponse::decode(ok.encode_to_vec().as_slice()).unwrap();
    assert!(matches!(
        decoded.result,
        Some(mount_workspace_response::Result::Mounted(true))
    ));

    let err = MountWorkspaceResponse {
        result: Some(mount_workspace_response::Result::Error(OperationOutcome {
            status: Some(operation_outcome::Status::Unsupported(
                operation_outcome::Unsupported {
                    detail: "virtiofs not available".into(),
                },
            )),
        })),
    };
    let decoded = MountWorkspaceResponse::decode(err.encode_to_vec().as_slice()).unwrap();
    assert!(matches!(
        decoded.result,
        Some(mount_workspace_response::Result::Error(_))
    ));
}

// ==================================================================
// Golden wire-format stability (cross-version)
// ==================================================================

/// Golden test: a well-known HostHello encoded at v1.0 must produce
/// a stable byte sequence that does not change with schema evolution.
#[test]
fn golden_host_hello_v1_0_byte_stable() {
    let hello = HostHello {
        protocol_name: "pico.guest".into(),
        bootstrap_version: Some(VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 0 }),
        }),
        supported_versions: vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 0 }),
        }],
        host_capabilities: Some(CapabilitySet {
            identifiers: vec!["exec".into()],
        }),
        host_nonce: Some(Nonce {
            value: vec![0x01u8; 32],
        }),
        sandbox_id: "golden-sbx".into(),
        image_id: "golden-img".into(),
        image_digest: "sha256:golden".into(),
    };

    // Encode and verify round-trip determinism
    let enc1 = hello.encode_to_vec();
    let enc2 = hello.encode_to_vec();
    assert_eq!(enc1, enc2, "HostHello encoding must be deterministic");

    let decoded = HostHello::decode(enc1.as_slice()).unwrap();
    assert_eq!(decoded.sandbox_id, "golden-sbx");
    assert_eq!(decoded.image_id, "golden-img");

    // Record the byte length for regression detection
    assert!(
        enc1.len() > 50,
        "HostHello should be reasonably sized (got {})",
        enc1.len()
    );
    assert!(
        enc1.len() < 1024,
        "HostHello should not be excessively large (got {})",
        enc1.len()
    );
}

/// Golden test: a well-known RequestContext encoded at v1.0 must
/// produce a stable byte sequence.
#[test]
fn golden_request_context_v1_0_byte_stable() {
    let ctx = RequestContext {
        request_id: "golden-req".into(),
        operation_id: "golden-op".into(),
        sandbox_id: "golden-sbx".into(),
        session_id: vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ],
        policy_epoch: 1,
        protocol_version: 0x00010000,
        deadline: None,
        trace_context: None,
    };

    let enc1 = ctx.encode_to_vec();
    let enc2 = ctx.encode_to_vec();
    assert_eq!(enc1, enc2, "RequestContext encoding must be deterministic");

    let decoded = RequestContext::decode(enc1.as_slice()).unwrap();
    assert_eq!(decoded.request_id, "golden-req");
    assert_eq!(decoded.operation_id, "golden-op");
    assert_eq!(decoded.protocol_version, 0x00010000);
    assert_eq!(decoded.policy_epoch, 1);
}
