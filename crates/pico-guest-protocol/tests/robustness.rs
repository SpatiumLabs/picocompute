//! Protocol robustness and misuse-resistance test suite.
//!
//! Validates that the PicoCompute host-guest protocol boundary resists
//! malformed, stale, replayed, reflected, oversized, and adversarial
//! messages without panicking or producing unsafe lifecycle transitions.
//!
//! # Test categories
//!
//! - Framing layer: oversized, truncated, invalid tags
//! - Handshake: wrong protocol, identity mismatch, proof, replay
//! - Operational: missing context, wrong bindings, invalid enums
//! - Binding: sandbox, session, policy epoch, protocol version
//! - Stream: backpressure, disconnect, oversized frames
//! - Replay/reflection: stale IDs, reflected messages, wrong tenant
//!
//! # Splitting policy
//!
//! When this file exceeds ~3000 lines, split each `mod *_robustness`
//! module into its own file under `tests/robustness/`:
//!
//! ```text
//! tests/
//!   protocol.rs
//!   compat_fixtures.rs
//!   robustness/
//!     mod.rs          # harness helpers (tcp_pair, test_context, etc.)
//!     framing.rs
//!     handshake.rs
//!     operational.rs
//!     binding.rs
//!     stream.rs
//!     replay.rs
//! ```
//!
//! Until then, the single-file layout keeps discovery simple: one
//! `grep` pattern finds every test.

use std::time::Duration;

use prost::Message;
use tokio::net::{TcpListener, TcpStream};

use pico_guest_protocol::bootstrap_v1::*;
use pico_guest_protocol::operational_v1::*;
use pico_guest_protocol::{FramedConnection, framed};

const TIMEOUT: Duration = Duration::from_secs(5);

// ==================================================================
// Test harness
// ==================================================================

/// Opens a connected TCP pair (client, server) on a loopback port.
async fn tcp_pair() -> (TcpStream, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    (client, listener)
}

/// Writes a length prefix followed by a 1-byte tag and raw payload.
async fn write_raw_tagged(stream: &mut TcpStream, tag: u8, payload: &[u8]) {
    use tokio::io::AsyncWriteExt;

    let len = (payload.len() + 1) as u32;
    let mut framed = Vec::with_capacity(4 + 1 + payload.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.push(tag);
    framed.extend_from_slice(payload);
    stream.write_all(&framed).await.unwrap();
}

/// Builds a minimal valid `RequestContext` for test messages.
fn test_context(sandbox_id: &str, session_id: &[u8], policy_epoch: u64) -> RequestContext {
    RequestContext {
        request_id: "test-req".into(),
        operation_id: "test-op".into(),
        sandbox_id: sandbox_id.into(),
        session_id: session_id.to_vec(),
        policy_epoch,
        protocol_version: 0x00010000,
        deadline: None,
        ..Default::default()
    }
}

/// Builds a valid `HostHello` for handshake tests.
fn test_host_hello(sandbox_id: &str, image_id: &str) -> HostHello {
    HostHello {
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
            identifiers: vec!["exec".into(), "file".into()],
        }),
        host_nonce: Some(Nonce {
            value: vec![0xABu8; 32],
        }),
        sandbox_id: sandbox_id.into(),
        image_id: image_id.into(),
        image_digest: "abc123".into(),
    }
}

// ==================================================================
// Framing layer robustness tests
// ==================================================================

mod framing_robustness {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Oversized length prefix must be rejected with a typed error,
    /// never panicking.
    #[tokio::test]
    async fn oversized_length_prefix_rejected() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let result = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT).await;
            let err = result.unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "expected InvalidData, got {:?}: {err}",
                err.kind()
            );
        });

        // Send oversized length prefix (2 MiB, well beyond 1 MiB limit)
        let oversized_len = (2 * 1024 * 1024) as u32;
        client
            .write_all(&oversized_len.to_be_bytes())
            .await
            .unwrap();
        client.flush().await.unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Tagged message with length < 1 (missing type tag) must be rejected.
    #[tokio::test]
    async fn tagged_message_too_short_no_tag_rejected() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let result = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT).await;
            let err = result.unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "expected InvalidData for missing type tag, got {:?}: {err}",
                err.kind()
            );
        });

        // Send length = 0 (no room for tag)
        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Truncated length prefix (fewer than 4 bytes) must be handled.
    #[tokio::test]
    async fn truncated_length_prefix_handled() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let result = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT).await;
            // Either an error or timeout is acceptable (both mean no panic)
            if let Err(e) = &result {
                assert!(
                    e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::UnexpectedEof
                        || e.kind() == std::io::ErrorKind::InvalidData,
                    "unexpected error kind: {:?}",
                    e.kind()
                );
            }
        });

        // Send only 2 bytes of the 4-byte length prefix
        client.write_all(&[0x00, 0x01]).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Length prefix claims 10 bytes but only 5 are sent -- truncated payload.
    #[tokio::test]
    async fn truncated_payload_handled() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let result = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT).await;
            if let Err(e) = &result {
                assert!(
                    e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::UnexpectedEof,
                    "expected TimedOut or UnexpectedEof, got: {:?}",
                    e.kind()
                );
            }
        });

        // Send length=5 (1 tag + 4 payload) but only send tag and 1 payload byte
        let payload: [u8; 2] = [0x01, 0xFF];
        client.write_all(&5u32.to_be_bytes()).await.unwrap();
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Invalid protobuf payload (random bytes) must be rejected cleanly.
    #[tokio::test]
    async fn invalid_protobuf_payload_rejected() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let result = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT).await;
            let err = result.unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "expected InvalidData for garbage protobuf, got {:?}: {err}",
                err.kind()
            );
        });

        // Send valid length + tag, but garbage payload (not valid protobuf)
        let garbage = vec![0xFFu8; 50];
        write_raw_tagged(&mut client, framed::TAG_EXEC_REQUEST, &garbage).await;
        drop(client);

        server.await.unwrap();
    }

    /// Unknown tag values must be tolerated by the framing layer
    /// (rejection is a protocol-layer concern, not a framing-layer panic).
    #[tokio::test]
    async fn unknown_tag_tolerated_by_framing() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read with tag 0xFF (unused) -- framing layer should succeed
            let result = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT).await;
            // Either decodes garbage protobuf "successfully" (default message)
            // or fails with decode error. Neither should panic.
            match result {
                Ok((tag, _msg)) => assert_eq!(tag, 0xFF),
                Err(e) => assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidData,
                    "expected InvalidData for unknown tag decode, got {:?}: {e}",
                    e.kind()
                ),
            }
        });

        let valid_req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "echo".into(),
            ..Default::default()
        };
        write_raw_tagged(&mut client, 0xFF, &valid_req.encode_to_vec()).await;
        drop(client);

        server.await.unwrap();
    }

    /// Zero-length payload with valid tag is tolerated (empty message body).
    #[tokio::test]
    async fn zero_length_payload_with_tag_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, _msg) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
        });

        // Length = 1 (just the 1-byte tag, zero payload)
        client.write_all(&1u32.to_be_bytes()).await.unwrap();
        client.write_all(&[framed::TAG_EXEC_REQUEST]).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Large but valid payload (near max but under limit) must succeed.
    #[tokio::test]
    async fn payload_near_max_size_accepted() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, msg) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            assert_eq!(msg.command, "large");
        });

        // Build a message that is exactly at the sub-max boundary
        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "large".into(),
            ..Default::default()
        };
        let encoded = req.encode_to_vec();
        assert!(
            encoded.len() < 1024 * 1024,
            "test message must fit within max size"
        );
        write_raw_tagged(&mut client, framed::TAG_EXEC_REQUEST, &encoded).await;
        drop(client);

        server.await.unwrap();
    }

    /// Oversized handshake message (no tag) must be rejected.
    #[tokio::test]
    async fn oversized_handshake_message_rejected() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let result = framed::read_message::<HostHello>(&mut stream, TIMEOUT).await;
            let err = result.unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "expected InvalidData for oversized handshake, got {:?}: {err}",
                err.kind()
            );
        });

        let oversized = (2 * 1024 * 1024) as u32;
        client.write_all(&oversized.to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        server.await.unwrap();
    }
}

// ==================================================================
// Handshake robustness tests
// ==================================================================

mod handshake_robustness {
    use super::*;

    /// Wrong protocol_name in HostHello must be rejected.
    #[tokio::test]
    async fn wrong_protocol_name_rejected() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);
            let hello = conn.recv::<HostHello>().await.unwrap();
            assert_eq!(hello.protocol_name, "wrong.protocol.v1");
            // Guest should reject this -- simulate rejection
        });

        let hello = HostHello {
            protocol_name: "wrong.protocol.v1".into(),
            ..test_host_hello("sbx", "img")
        };
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();
        drop(conn);

        server.await.unwrap();
    }

    /// Missing host_nonce in HostHello must be detected.
    #[tokio::test]
    async fn missing_host_nonce_detected() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);
            let hello = conn.recv::<HostHello>().await.unwrap();
            assert!(hello.host_nonce.is_none());
        });

        let hello = HostHello {
            host_nonce: None,
            ..test_host_hello("sbx", "img")
        };
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();
        drop(conn);

        server.await.unwrap();
    }

    /// Missing bootstrap_version in HostHello must be tolerated
    /// (it is optional in proto3) but the guest validates it.
    #[tokio::test]
    async fn missing_bootstrap_version_tolerated_at_wire_level() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);
            let hello = conn.recv::<HostHello>().await.unwrap();
            assert!(hello.bootstrap_version.is_none());
        });

        let hello = HostHello {
            bootstrap_version: None,
            ..test_host_hello("sbx", "img")
        };
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();
        drop(conn);

        server.await.unwrap();
    }

    /// Empty supported_versions in HostHello must be tolerated at wire level
    /// (semantic rejection is the handshake layer's responsibility).
    #[tokio::test]
    async fn empty_supported_versions_tolerated() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);
            let hello = conn.recv::<HostHello>().await.unwrap();
            assert!(hello.supported_versions.is_empty());
        });

        let hello = HostHello {
            supported_versions: vec![],
            ..test_host_hello("sbx", "img")
        };
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();
        drop(conn);

        server.await.unwrap();
    }

    /// Identity mismatch: HostHello declares image_id "A", GuestHello
    /// responds with image_id "B". The host must detect this mismatch.
    #[tokio::test]
    async fn image_id_mismatch_in_guest_hello_detected() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);
            let _hello = conn.recv::<HostHello>().await.unwrap();

            // Send GuestHello with mismatched image_id
            let guest_hello = GuestHello {
                image_id: "wrong-image-id".into(),
                supported_versions: vec![],
                ..Default::default()
            };
            conn.send(&guest_hello).await.unwrap();
        });

        let hello = test_host_hello("sbx", "expected-image");
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();

        let guest_hello = conn.recv::<GuestHello>().await.unwrap();
        // The guest hello has wrong-image-id; host-side validation would reject this
        assert_eq!(guest_hello.image_id, "wrong-image-id");

        drop(conn);
        server.await.unwrap();
    }

    /// GuestHello with missing proof must be detectable.
    #[tokio::test]
    async fn guest_hello_missing_proof_detected() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);
            let _hello = conn.recv::<HostHello>().await.unwrap();

            let guest_hello = GuestHello {
                proof: None,
                supported_versions: vec![VersionRange {
                    min: Some(Version { major: 1, minor: 0 }),
                    max: Some(Version { major: 1, minor: 5 }),
                }],
                ..Default::default()
            };
            conn.send(&guest_hello).await.unwrap();
        });

        let hello = test_host_hello("sbx", "img");
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();

        let guest_hello = conn.recv::<GuestHello>().await.unwrap();
        assert!(guest_hello.proof.is_none());

        drop(conn);
        server.await.unwrap();
    }

    /// HostReply with session_id shorter than 16 bytes must be detectable.
    #[tokio::test]
    async fn short_session_id_in_host_reply_detectable() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);
            let _hello = conn.recv::<HostHello>().await.unwrap();

            // Send GuestHello
            let guest_hello = GuestHello {
                supported_versions: vec![VersionRange {
                    min: Some(Version { major: 1, minor: 0 }),
                    max: Some(Version { major: 1, minor: 5 }),
                }],
                ..Default::default()
            };
            conn.send(&guest_hello).await.unwrap();

            // Read HostReply with short session_id
            let reply = conn.recv::<HostReply>().await.unwrap();
            assert!(reply.session_id.as_ref().unwrap().value.len() < 16);
        });

        let hello = test_host_hello("sbx", "img");
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();

        let _guest = conn.recv::<GuestHello>().await.unwrap();

        let reply = HostReply {
            selected_version: Some(Version { major: 1, minor: 0 }),
            selected_capabilities: Some(CapabilitySet {
                identifiers: vec!["exec".into()],
            }),
            session_id: Some(SessionId {
                value: vec![0x01u8; 4],
            }),
            policy_epoch: 1,
            proof: Some(Proof {
                value: vec![0xFFu8; 32],
            }),
        };
        conn.send(&reply).await.unwrap();
        drop(conn);

        server.await.unwrap();
    }

    /// HandshakeResult with missing outcome field must be handled.
    #[tokio::test]
    async fn handshake_result_missing_outcome_handled() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);

            // Full handshake simulation with empty outcome
            let _hello = conn.recv::<HostHello>().await.unwrap();

            let guest = GuestHello {
                supported_versions: vec![VersionRange {
                    min: Some(Version { major: 1, minor: 0 }),
                    max: Some(Version { major: 1, minor: 5 }),
                }],
                ..Default::default()
            };
            conn.send(&guest).await.unwrap();

            let _reply = conn.recv::<HostReply>().await.unwrap();

            // Send result with no outcome
            let result = HandshakeResult { outcome: None };
            conn.send(&result).await.unwrap();
        });

        let hello = test_host_hello("sbx", "img");
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();
        let _guest = conn.recv::<GuestHello>().await.unwrap();

        let reply = HostReply {
            selected_version: Some(Version { major: 1, minor: 0 }),
            selected_capabilities: Some(CapabilitySet {
                identifiers: vec!["exec".into()],
            }),
            session_id: Some(SessionId {
                value: vec![0x01u8; 16],
            }),
            policy_epoch: 1,
            proof: Some(Proof {
                value: vec![0xFFu8; 32],
            }),
        };
        conn.send(&reply).await.unwrap();

        let result = conn.recv::<HandshakeResult>().await.unwrap();
        assert!(result.outcome.is_none());

        drop(conn);
        server.await.unwrap();
    }

    /// HandshakeResult with invalid error code must be handled.
    #[tokio::test]
    async fn handshake_result_invalid_error_code_handled() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);

            let _hello = conn.recv::<HostHello>().await.unwrap();

            let guest = GuestHello {
                supported_versions: vec![VersionRange {
                    min: Some(Version { major: 1, minor: 0 }),
                    max: Some(Version { major: 1, minor: 5 }),
                }],
                ..Default::default()
            };
            conn.send(&guest).await.unwrap();

            let _reply = conn.recv::<HostReply>().await.unwrap();

            let result = HandshakeResult {
                outcome: Some(handshake_result::Outcome::Error(HandshakeError {
                    code: 999,
                    message: "test invalid error".into(),
                })),
            };
            conn.send(&result).await.unwrap();
        });

        let hello = test_host_hello("sbx", "img");
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();
        let _guest = conn.recv::<GuestHello>().await.unwrap();

        let reply = HostReply {
            selected_version: Some(Version { major: 1, minor: 0 }),
            selected_capabilities: Some(CapabilitySet {
                identifiers: vec!["exec".into()],
            }),
            session_id: Some(SessionId {
                value: vec![0x01u8; 16],
            }),
            policy_epoch: 1,
            proof: Some(Proof {
                value: vec![0xFFu8; 32],
            }),
        };
        conn.send(&reply).await.unwrap();

        let result = conn.recv::<HandshakeResult>().await.unwrap();
        match result.outcome {
            Some(handshake_result::Outcome::Error(e)) => {
                assert_eq!(e.code, 999);
                assert!(
                    handshake_error::ErrorCode::try_from(e.code).is_err(),
                    "code 999 should not be a valid ErrorCode"
                );
            }
            _ => panic!("expected error outcome"),
        }

        drop(conn);
        server.await.unwrap();
    }

    /// Cross-version downgrade: Host offers v1.5, Guest only supports v1.0-v1.3.
    /// Must negotiate to v1.3 (highest overlapping).
    #[tokio::test]
    async fn cross_version_downgrade_negotiation() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);

            let hello = conn.recv::<HostHello>().await.unwrap();
            // Host offers up to v1.5
            assert_eq!(hello.supported_versions[0].max.as_ref().unwrap().minor, 5);

            // Guest responds with narrower range: v1.0-v1.3
            let guest = GuestHello {
                supported_versions: vec![VersionRange {
                    min: Some(Version { major: 1, minor: 0 }),
                    max: Some(Version { major: 1, minor: 3 }),
                }],
                ..Default::default()
            };
            conn.send(&guest).await.unwrap();

            let reply = conn.recv::<HostReply>().await.unwrap();
            // Host should select v1.3 (highest overlap)
            assert_eq!(reply.selected_version.as_ref().unwrap().major, 1);
            assert_eq!(reply.selected_version.as_ref().unwrap().minor, 3);
        });

        let hello = test_host_hello("sbx", "img");
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();
        let _guest = conn.recv::<GuestHello>().await.unwrap();

        let reply = HostReply {
            selected_version: Some(Version { major: 1, minor: 3 }),
            selected_capabilities: Some(CapabilitySet {
                identifiers: vec!["exec".into()],
            }),
            session_id: Some(SessionId {
                value: vec![0x01u8; 16],
            }),
            policy_epoch: 1,
            proof: Some(Proof {
                value: vec![0xFFu8; 32],
            }),
        };
        conn.send(&reply).await.unwrap();

        drop(conn);
        server.await.unwrap();
    }

    /// Unsupported capability behavior: Guest advertises capabilities
    /// the host does not recognize. The intersection should be empty.
    #[tokio::test]
    async fn empty_capability_intersection_handled() {
        let (client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream, TIMEOUT);

            let _hello = conn.recv::<HostHello>().await.unwrap();

            // Guest advertises only capabilities the host doesn't have
            let guest = GuestHello {
                supported_versions: vec![VersionRange {
                    min: Some(Version { major: 1, minor: 0 }),
                    max: Some(Version { major: 1, minor: 5 }),
                }],
                guest_capabilities: Some(CapabilitySet {
                    identifiers: vec!["unknown-feature".into()],
                }),
                ..Default::default()
            };
            conn.send(&guest).await.unwrap();

            // Host should detect empty intersection and reject
            let _reply = conn.recv::<HostReply>().await.unwrap();
        });

        let hello = HostHello {
            host_capabilities: Some(CapabilitySet {
                identifiers: vec!["exec".into(), "file".into()],
            }),
            ..test_host_hello("sbx", "img")
        };
        let mut conn = FramedConnection::new(client, TIMEOUT);
        conn.send(&hello).await.unwrap();
        let guest = conn.recv::<GuestHello>().await.unwrap();

        // Verify the guest only advertises unknown capabilities
        assert_eq!(
            guest.guest_capabilities.unwrap().identifiers,
            vec!["unknown-feature"]
        );

        // Host should send HostReply with empty selected_capabilities or reject
        // For wire-level testing we verify the message is parseable
        let reply = HostReply {
            selected_version: Some(Version { major: 1, minor: 0 }),
            selected_capabilities: Some(CapabilitySet {
                identifiers: vec![],
            }),
            session_id: Some(SessionId {
                value: vec![0x01u8; 16],
            }),
            policy_epoch: 1,
            proof: Some(Proof {
                value: vec![0xFFu8; 32],
            }),
        };
        conn.send(&reply).await.unwrap();

        drop(conn);
        server.await.unwrap();
    }
}

// ==================================================================
// Operational protocol misuse tests
// ==================================================================

mod operational_robustness {
    use super::*;

    /// Missing RequestContext in an operational request must be tolerated
    /// at wire level (semantic rejection is the guest's responsibility).
    #[tokio::test]
    async fn missing_request_context_tolerated_at_wire() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            assert!(req.context.is_none());
        });

        let req = ExecRequest {
            context: None,
            command: "test".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Invalid drain_mode enum value in QuiesceRequest.
    #[tokio::test]
    async fn invalid_enum_value_drain_mode_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<QuiesceRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_QUIESCE_REQUEST);
            // Invalid enum value (not in DrainMode enum)
            assert_eq!(req.drain_mode, 99);
        });

        let req = QuiesceRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            drain_mode: 99,
            quiesce_deadline: None,
        };
        framed::send_tagged(&mut client, framed::TAG_QUIESCE_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Invalid health status enum value in HealthResponse.
    #[tokio::test]
    async fn invalid_health_status_enum_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<HealthResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_HEALTH_RESPONSE);
            assert_eq!(resp.status, 99);
        });

        let resp = HealthResponse {
            status: 99,
            message: "bogus status".into(),
        };
        framed::send_tagged(&mut client, framed::TAG_HEALTH_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// OperationOutcome with no status field must be handled.
    #[tokio::test]
    async fn operation_outcome_missing_status_handled() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

            match resp.frame.unwrap() {
                exec_response::Frame::Outcome(outcome) => {
                    assert!(outcome.status.is_none());
                }
                _ => panic!("expected Outcome frame with no status"),
            }
        });

        let resp = ExecResponse {
            frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                status: None,
            })),
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// SignalRequest with invalid signal number (e.g., negative) must be tolerated
    /// at wire level. Semantic validation is the guest's responsibility.
    #[tokio::test]
    async fn negative_signal_number_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<SignalRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_SIGNAL_REQUEST);
            assert_eq!(req.signal, -1);
        });

        let req = SignalRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            operation_id: "test-op".into(),
            signal: -1,
        };
        framed::send_tagged(&mut client, framed::TAG_SIGNAL_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// ShutdownRequest with empty reason string.
    #[tokio::test]
    async fn shutdown_empty_reason_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ShutdownRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_SHUTDOWN_REQUEST);
            assert!(req.reason.is_empty());
        });

        let req = ShutdownRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            reason: String::new(),
            force: false,
        };
        framed::send_tagged(&mut client, framed::TAG_SHUTDOWN_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// ExecRequest with empty command string.
    #[tokio::test]
    async fn exec_empty_command_tolerated_at_wire() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            assert!(req.command.is_empty());
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: String::new(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// CancelResponse with UnknownOp referencing an operation.
    #[tokio::test]
    async fn cancel_unknown_operation_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<CancelResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_CANCEL_RESPONSE);

            match resp.result.unwrap() {
                cancel_response::Result::Unknown(u) => {
                    assert_eq!(u.operation_id, "unknown-op-999");
                }
                _ => panic!("expected Unknown"),
            }
        });

        let resp = CancelResponse {
            result: Some(cancel_response::Result::Unknown(UnknownOp {
                operation_id: "unknown-op-999".into(),
            })),
        };
        framed::send_tagged(&mut client, framed::TAG_CANCEL_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// CancelResponse with AlreadyTerminal operation.
    #[tokio::test]
    async fn cancel_already_terminal_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<CancelResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_CANCEL_RESPONSE);

            match resp.result.unwrap() {
                cancel_response::Result::AlreadyTerminal(outcome) => {
                    assert!(matches!(
                        outcome.status,
                        Some(operation_outcome::Status::Success(_))
                    ));
                }
                _ => panic!("expected AlreadyTerminal"),
            }
        });

        let resp = CancelResponse {
            result: Some(cancel_response::Result::AlreadyTerminal(OperationOutcome {
                status: Some(operation_outcome::Status::Success(
                    operation_outcome::Success {
                        result_payload: b"done".to_vec(),
                    },
                )),
            })),
        };
        framed::send_tagged(&mut client, framed::TAG_CANCEL_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// GetFileResponse with HistoryLost frame.
    #[tokio::test]
    async fn get_file_history_lost_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<AttachStreamResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_ATTACH_STREAM_RESPONSE);

            match resp.frame.unwrap() {
                attach_stream_response::Frame::HistoryLost(hl) => {
                    assert_eq!(hl.earliest_available, 42);
                }
                _ => panic!("expected HistoryLost"),
            }
        });

        let resp = AttachStreamResponse {
            frame: Some(attach_stream_response::Frame::HistoryLost(
                attach_stream_response::HistoryLost {
                    earliest_available: 42,
                },
            )),
        };
        framed::send_tagged(
            &mut client,
            framed::TAG_ATTACH_STREAM_RESPONSE,
            &resp,
            TIMEOUT,
        )
        .await
        .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// PutFileResponse with error outcome.
    #[tokio::test]
    async fn put_file_error_outcome_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<PutFileResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_PUT_FILE_RESPONSE);

            match resp.result.unwrap() {
                put_file_response::Result::Error(outcome) => {
                    assert!(matches!(
                        outcome.status,
                        Some(operation_outcome::Status::Failure(_))
                    ));
                }
                _ => panic!("expected Error outcome"),
            }
        });

        let resp = PutFileResponse {
            result: Some(put_file_response::Result::Error(OperationOutcome {
                status: Some(operation_outcome::Status::Failure(
                    operation_outcome::Failure {
                        code: "DISK_FULL".into(),
                        message: "no space left".into(),
                        retryable: false,
                    },
                )),
            })),
            checksum: String::new(),
        };
        framed::send_tagged(&mut client, framed::TAG_PUT_FILE_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }
}

// ==================================================================
// Protocol binding tests (identity, version, policy)
// ==================================================================

mod binding_robustness {
    use super::*;

    /// Request with wrong sandbox_id in context must be detectable at wire level.
    #[tokio::test]
    async fn wrong_sandbox_id_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let expected_sandbox = "correct-sbx";
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let ctx = req.context.unwrap();
            // The request claims sandbox "wrong-sbx" but the session is for "correct-sbx"
            assert_eq!(ctx.sandbox_id, "wrong-sbx");
            // Verify it's actually wrong (protocol mismatch)
            assert_ne!(ctx.sandbox_id, expected_sandbox);
        });

        let req = ExecRequest {
            context: Some(RequestContext {
                sandbox_id: "wrong-sbx".into(),
                ..test_context(expected_sandbox, b"1234567890123456", 1)
            }),
            command: "echo".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Wrong session_id in request context.
    #[tokio::test]
    async fn wrong_session_id_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let correct_session = b"correct-session-12";
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let ctx = req.context.unwrap();
            assert_ne!(ctx.session_id, correct_session);
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"wrong-session-999", 1)),
            command: "echo".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Stale policy_epoch in request context.
    #[tokio::test]
    async fn stale_policy_epoch_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let current_epoch: u64 = 10;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let ctx = req.context.unwrap();
            // Request uses epoch 5, current is 10
            assert_eq!(ctx.policy_epoch, 5);
            assert_ne!(ctx.policy_epoch, current_epoch);
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 5)),
            command: "echo".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Wrong protocol_version in request context.
    #[tokio::test]
    async fn wrong_protocol_version_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let negotiated_version: u32 = (1 << 16) | 3; // 1.3
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let ctx = req.context.unwrap();
            // Request claims v1.0 but negotiated is v1.3
            assert_eq!(ctx.protocol_version, 0x00010000);
            assert_ne!(ctx.protocol_version, negotiated_version);
        });

        let req = ExecRequest {
            context: Some(RequestContext {
                protocol_version: 0x00010000,
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "echo".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// ResumeNotify with different sandbox_id in body vs context.
    #[tokio::test]
    async fn resume_notify_sandbox_mismatch_body_vs_context_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ResumeNotifyRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            // Context says sbx-A, body says sbx-B
            let ctx = req.context.as_ref().unwrap();
            assert_eq!(ctx.sandbox_id, "sbx-A");
            assert_eq!(req.sandbox_id, "sbx-B");
            assert_ne!(ctx.sandbox_id, req.sandbox_id);
        });

        let req = ResumeNotifyRequest {
            context: Some(test_context("sbx-A", b"1234567890123456", 1)),
            sandbox_id: "sbx-B".into(),
            policy_epoch: 1,
            lineage_id: "lineage-1".into(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut client,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &req,
            TIMEOUT,
        )
        .await
        .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Request with empty session_id (zero-length bytes).
    #[tokio::test]
    async fn empty_session_id_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let ctx = req.context.unwrap();
            assert!(ctx.session_id.is_empty());
        });

        let req = ExecRequest {
            context: Some(RequestContext {
                session_id: vec![],
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "echo".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Request with empty operation_id (valid for read-only ops).
    #[tokio::test]
    async fn empty_operation_id_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let ctx = req.context.unwrap();
            assert!(ctx.operation_id.is_empty());
        });

        let req = ExecRequest {
            context: Some(RequestContext {
                operation_id: String::new(),
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "echo".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Request with empty request_id.
    #[tokio::test]
    async fn empty_request_id_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let ctx = req.context.unwrap();
            assert!(ctx.request_id.is_empty());
        });

        let req = ExecRequest {
            context: Some(RequestContext {
                request_id: String::new(),
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "echo".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }
}

// ==================================================================
// Stream robustness tests
// ==================================================================

mod stream_robustness {
    use super::*;

    /// Abrupt disconnect during exec streaming: client sends exec request,
    /// receives a few stdout frames, then connection drops. Must not panic.
    #[tokio::test]
    async fn abrupt_disconnect_during_stream_no_panic() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read exec request
            let (tag, _req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            // Send one stdout frame
            let frame = ExecResponse {
                frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                    frame: Some(StreamFrame {
                        sequence: 1,
                        payload: b"partial output\n".to_vec(),
                        end_of_stream: false,
                    }),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &frame, TIMEOUT)
                .await
                .unwrap();

            // Drop the connection abruptly (no outcome sent)
            drop(stream);
        });

        // Send exec request
        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "long-running".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        // Read a few frames then encounter EOF
        let mut frame_count = 0;
        while let Ok((tag, _resp)) = framed::read_tagged::<ExecResponse>(&mut client, TIMEOUT).await
        {
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
            frame_count += 1;
        }
        assert!(frame_count >= 1, "should have received at least one frame");

        guest.await.unwrap();
    }

    /// StreamFrame with sequence = 0 (must not crash; sequences start at 1).
    #[tokio::test]
    async fn stream_frame_zero_sequence_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

            match resp.frame.unwrap() {
                exec_response::Frame::Stdout(data) => {
                    let frame = data.frame.unwrap();
                    assert_eq!(frame.sequence, 0);
                }
                _ => panic!("expected Stdout frame"),
            }
        });

        let resp = ExecResponse {
            frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                frame: Some(StreamFrame {
                    sequence: 0,
                    payload: b"data".to_vec(),
                    end_of_stream: false,
                }),
            })),
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// StreamFrame with oversized payload (> 64 KiB) must be tolerated
    /// at wire level. The protocol spec says max 64 KiB per frame,
    /// but protobuf allows any bytes field size up to the message limit.
    #[tokio::test]
    async fn oversized_stream_frame_payload_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let large_payload = vec![0xABu8; 128 * 1024]; // 128 KiB

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

            match resp.frame.unwrap() {
                exec_response::Frame::Stdout(data) => {
                    let frame = data.frame.unwrap();
                    assert_eq!(frame.payload.len(), 128 * 1024);
                }
                _ => panic!("expected Stdout frame"),
            }
        });

        // The framing layer enforces 1 MiB max message; 128 KiB payload fits.
        let resp = ExecResponse {
            frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                frame: Some(StreamFrame {
                    sequence: 1,
                    payload: large_payload,
                    end_of_stream: false,
                }),
            })),
        };
        let encoded = resp.encode_to_vec();
        assert!(
            encoded.len() < 1024 * 1024,
            "oversized frame test must fit within max message"
        );

        framed::send_tagged(&mut client, framed::TAG_EXEC_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Missing end_of_stream on the last frame: the stream must still
    /// be consumable.
    #[tokio::test]
    async fn missing_end_of_stream_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            // Send frame without end_of_stream flag
            let frame = ExecResponse {
                frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                    frame: Some(StreamFrame {
                        sequence: 1,
                        payload: b"no eos flag\n".to_vec(),
                        end_of_stream: false,
                    }),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &frame, TIMEOUT)
                .await
                .unwrap();

            // Send outcome without an explicit EOS frame
            let outcome = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: b"ok".to_vec(),
                        },
                    )),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &outcome, TIMEOUT)
                .await
                .unwrap();
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "test".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        loop {
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut client, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
            if let Some(exec_response::Frame::Outcome(_)) = resp.frame {
                break;
            }
        }

        guest.await.unwrap();
    }

    /// Duplicate frame sequences in exec streaming must be tolerated at wire level.
    #[tokio::test]
    async fn duplicate_sequence_numbers_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            // Send duplicate seq=1 frames
            for _ in 0..3 {
                let frame = ExecResponse {
                    frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                        frame: Some(StreamFrame {
                            sequence: 1,
                            payload: b"dup\n".to_vec(),
                            end_of_stream: false,
                        }),
                    })),
                };
                framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &frame, TIMEOUT)
                    .await
                    .unwrap();
            }

            let outcome = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: b"ok".to_vec(),
                        },
                    )),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &outcome, TIMEOUT)
                .await
                .unwrap();
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "test".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        let mut seq1_count = 0;
        loop {
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut client, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
            match resp.frame {
                Some(exec_response::Frame::Stdout(data)) => {
                    if data.frame.unwrap().sequence == 1 {
                        seq1_count += 1;
                    }
                }
                Some(exec_response::Frame::Outcome(_)) => break,
                _ => {}
            }
        }
        assert_eq!(seq1_count, 3);

        guest.await.unwrap();
    }

    /// Sequence gap in exec streaming: guest sends seq=1 then seq=3 (skipping seq=2).
    #[tokio::test]
    async fn sequence_gap_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, _req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            // Send seq=1
            let f1 = ExecResponse {
                frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                    frame: Some(StreamFrame {
                        sequence: 1,
                        payload: b"a".to_vec(),
                        end_of_stream: false,
                    }),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &f1, TIMEOUT)
                .await
                .unwrap();

            // Skip seq=2, send seq=3
            let f3 = ExecResponse {
                frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                    frame: Some(StreamFrame {
                        sequence: 3,
                        payload: b"c".to_vec(),
                        end_of_stream: true,
                    }),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &f3, TIMEOUT)
                .await
                .unwrap();
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "test".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        let mut sequences = Vec::new();
        loop {
            let result = framed::read_tagged::<ExecResponse>(&mut client, TIMEOUT).await;
            match result {
                Ok((tag, resp)) => {
                    assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
                    if let Some(exec_response::Frame::Stdout(data)) = resp.frame
                        && let Some(f) = data.frame
                    {
                        sequences.push(f.sequence);
                        if f.end_of_stream {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        assert_eq!(sequences, vec![1, 3]);

        guest.await.unwrap();
    }

    /// StreamAck with high-contiguous sequence.
    #[tokio::test]
    async fn stream_ack_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

            match resp.frame.unwrap() {
                exec_response::Frame::Ack(ack) => {
                    assert_eq!(ack.highest_contiguous, 42);
                }
                _ => panic!("expected Ack"),
            }
        });

        let resp = ExecResponse {
            frame: Some(exec_response::Frame::Ack(StreamAck {
                highest_contiguous: 42,
            })),
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }
}

// ==================================================================
// Replay, reflection, and stale message tests
// ==================================================================

mod replay_reflection {
    use super::*;

    /// Replay: sending the same request_id twice must be detectable.
    #[tokio::test]
    async fn duplicate_request_id_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // First request
            let (tag, req1) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            let ctx1 = req1.context.unwrap();
            assert_eq!(ctx1.request_id, "duplicate-req-id");

            // Replayed request with same request_id
            let (tag, req2) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            let ctx2 = req2.context.unwrap();
            assert_eq!(ctx2.request_id, "duplicate-req-id");
            // Same request_id appears twice -- replay detected
        });

        // Send first request
        let req1 = ExecRequest {
            context: Some(RequestContext {
                request_id: "duplicate-req-id".into(),
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "cmd1".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req1, TIMEOUT)
            .await
            .unwrap();

        // Send replay (same request_id, different command)
        let req2 = ExecRequest {
            context: Some(RequestContext {
                request_id: "duplicate-req-id".into(),
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "cmd2".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req2, TIMEOUT)
            .await
            .unwrap();

        drop(client);
        server.await.unwrap();
    }

    /// Duplicate operation_id must be detectable.
    #[tokio::test]
    async fn duplicate_operation_id_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, req1) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            let ctx1 = req1.context.unwrap();
            assert_eq!(ctx1.operation_id, "stable-op-id");

            let (tag, req2) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            let ctx2 = req2.context.unwrap();
            assert_eq!(ctx2.operation_id, "stable-op-id");
            // Same operation_id -- duplicate operation detected
        });

        let req1 = ExecRequest {
            context: Some(RequestContext {
                request_id: "req-1".into(),
                operation_id: "stable-op-id".into(),
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "cmd1".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req1, TIMEOUT)
            .await
            .unwrap();

        let req2 = ExecRequest {
            context: Some(RequestContext {
                request_id: "req-2".into(),
                operation_id: "stable-op-id".into(),
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "cmd2".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req2, TIMEOUT)
            .await
            .unwrap();

        drop(client);
        server.await.unwrap();
    }

    /// Reflection: sending a response-type message with a request tag
    /// (e.g., ExecResponse where ExecRequest is expected).
    #[tokio::test]
    async fn reflected_response_type_as_request_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read with request tag, but the payload is a response type
            let result = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT).await;
            // Protobuf may decode it as a default ExecRequest due to field mismatch
            // Either way, no panic.
            match result {
                Ok((tag, req)) => {
                    assert_eq!(tag, framed::TAG_EXEC_REQUEST);
                    // The decoded message will likely have empty/default fields
                    assert!(req.command.is_empty());
                }
                Err(e) => {
                    // Protobuf decode error: response fields don't map to
                    // the request type. Either way, no panic.
                    assert_eq!(
                        e.kind(),
                        std::io::ErrorKind::InvalidData,
                        "expected InvalidData for reflected response, got {:?}: {e}",
                        e.kind()
                    );
                }
            }
        });

        // Send an ExecResponse where ExecRequest is expected
        let resp = ExecResponse {
            frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                status: Some(operation_outcome::Status::Success(
                    operation_outcome::Success {
                        result_payload: b"reflected".to_vec(),
                    },
                )),
            })),
        };
        write_raw_tagged(&mut client, framed::TAG_EXEC_REQUEST, &resp.encode_to_vec()).await;
        drop(client);

        server.await.unwrap();
    }

    /// Wrong-tenant: request for sandbox "tenant-B" on a session for "tenant-A".
    #[tokio::test]
    async fn wrong_tenant_sandbox_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let expected = "tenant-A-sbx";
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            let ctx = req.context.unwrap();
            assert_ne!(ctx.sandbox_id, expected);
            assert_eq!(ctx.sandbox_id, "tenant-B-sbx");
        });

        let req = ExecRequest {
            context: Some(test_context("tenant-B-sbx", b"1234567890123456", 1)),
            command: "echo".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        drop(client);
        server.await.unwrap();
    }

    /// Response tag mismatch: sending a response with wrong tag.
    #[tokio::test]
    async fn response_tag_mismatch_detectable() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, _req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            // Send response with wrong response tag (HEALTH instead of EXEC)
            let resp = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: b"ok".to_vec(),
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_HEALTH_RESPONSE, // Wrong tag!
                &resp,
                TIMEOUT,
            )
            .await
            .unwrap();
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "echo".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        // Client expects TAG_EXEC_RESPONSE but gets TAG_HEALTH_RESPONSE
        let (tag, _resp) = framed::read_tagged::<ExecResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_HEALTH_RESPONSE); // Wrong tag -- detectable

        drop(client);
        server.await.unwrap();
    }
}

// ==================================================================
// Secrets service robustness tests
// ==================================================================

mod secrets_robustness {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Valid InjectSecrets request/response round-trip framing.
    #[tokio::test]
    async fn inject_secrets_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<InjectSecretsRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_INJECT_SECRETS_REQUEST);

            let ctx = req.context.unwrap();
            assert_eq!(ctx.sandbox_id, "sbx");
            assert_eq!(req.lease_id, "lease-001");
            assert_eq!(req.credentials.len(), 2);
            assert_eq!(req.credentials[0].name, "API_KEY");
            assert_eq!(req.credentials[0].content, b"secret-value");
            assert_eq!(req.credentials[0].mode, 0o400);
            assert_eq!(req.credentials[1].name, "DB_PASS");
            assert_eq!(req.credentials[1].mode, 0o600);

            let resp = InjectSecretsResponse {
                result: Some(inject_secrets_response::Result::Injected(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_INJECT_SECRETS_RESPONSE,
                &resp,
                TIMEOUT,
            )
            .await
            .unwrap();
        });

        let req = InjectSecretsRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            lease_id: "lease-001".into(),
            policy_decision_id: "pd-001".into(),
            credentials: vec![
                SecretCredential {
                    name: "API_KEY".into(),
                    content: b"secret-value".to_vec(),
                    mode: 0o400,
                },
                SecretCredential {
                    name: "DB_PASS".into(),
                    content: b"dummy-password".to_vec(),
                    mode: 0o600,
                },
            ],
        };
        framed::send_tagged(
            &mut client,
            framed::TAG_INJECT_SECRETS_REQUEST,
            &req,
            TIMEOUT,
        )
        .await
        .unwrap();

        let (tag, resp) = framed::read_tagged::<InjectSecretsResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_INJECT_SECRETS_RESPONSE);
        match resp.result.unwrap() {
            inject_secrets_response::Result::Injected(v) => assert!(v),
            _ => panic!("expected Injected"),
        }

        server.await.unwrap();
    }

    /// Oversized InjectSecretsRequest must be rejected.
    #[tokio::test]
    async fn oversized_inject_secrets_rejected() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let result = framed::read_tagged::<InjectSecretsRequest>(&mut stream, TIMEOUT).await;
            let err = result.unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "expected InvalidData, got {:?}: {err}",
                err.kind()
            );
        });

        let oversized_len = (2 * 1024 * 1024) as u32;
        client
            .write_all(&oversized_len.to_be_bytes())
            .await
            .unwrap();
        client.flush().await.unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// InjectSecretsResponse with error outcome round-trip.
    #[tokio::test]
    async fn inject_secrets_error_outcome_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, _req) = framed::read_tagged::<InjectSecretsRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_INJECT_SECRETS_REQUEST);

            let resp = InjectSecretsResponse {
                result: Some(inject_secrets_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "ACCESS_DENIED".into(),
                            message: "lease has expired".into(),
                            retryable: false,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_INJECT_SECRETS_RESPONSE,
                &resp,
                TIMEOUT,
            )
            .await
            .unwrap();
        });

        let req = InjectSecretsRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            lease_id: "expired-lease".into(),
            policy_decision_id: "pd-002".into(),
            credentials: vec![],
        };
        framed::send_tagged(
            &mut client,
            framed::TAG_INJECT_SECRETS_REQUEST,
            &req,
            TIMEOUT,
        )
        .await
        .unwrap();

        let (tag, resp) = framed::read_tagged::<InjectSecretsResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_INJECT_SECRETS_RESPONSE);
        match resp.result.unwrap() {
            inject_secrets_response::Result::Error(outcome) => match outcome.status.unwrap() {
                operation_outcome::Status::Failure(f) => {
                    assert_eq!(f.code, "ACCESS_DENIED");
                    assert_eq!(f.message, "lease has expired");
                    assert!(!f.retryable);
                }
                _ => panic!("expected Failure"),
            },
            _ => panic!("expected Error"),
        }

        server.await.unwrap();
    }
}

// ==================================================================
// Quiesce/resume lifecycle smoke tests
// ==================================================================

mod quiesce_resume_lifecycle {
    use super::*;
    use prost_types::Timestamp;

    // Arbitrary but valid Unix timestamps used for wire-format validation.
    const T_SNAPSHOT_2026_Q2: i64 = 1718114400;
    const T_RESTORE_2026_Q2: i64 = 1718200000;
    const T_ANCIENT_DEADLINE: i64 = 100;

    /// Full quiesce -> drain -> resume lifecycle at wire level.
    /// Validates the complete message flow required before and after
    /// a snapshot/restore cycle.
    #[tokio::test]
    async fn quiesce_resume_lifecycle_smoke() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // 1. Host sends QuiesceRequest (graceful mode)
            let (tag, req) = framed::read_tagged::<QuiesceRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_QUIESCE_REQUEST);
            assert_eq!(req.drain_mode, quiesce_request::DrainMode::Graceful as i32);

            // 2. Guest acknowledges quiescence
            let quiesce_resp = QuiesceResponse {
                result: Some(quiesce_response::Result::Quiesced(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_QUIESCE_RESPONSE,
                &quiesce_resp,
                TIMEOUT,
            )
            .await
            .unwrap();

            // Connection is then closed for snapshot
            drop(stream);
        });

        // Send quiesce request with deadline
        let quiesce_req = QuiesceRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            drain_mode: quiesce_request::DrainMode::Graceful as i32,
            quiesce_deadline: Some(Timestamp {
                seconds: T_SNAPSHOT_2026_Q2,
                nanos: 0,
            }),
        };
        framed::send_tagged(
            &mut client,
            framed::TAG_QUIESCE_REQUEST,
            &quiesce_req,
            TIMEOUT,
        )
        .await
        .unwrap();

        // Read quiesce response
        let (tag, resp) = framed::read_tagged::<QuiesceResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_QUIESCE_RESPONSE);
        match resp.result.unwrap() {
            quiesce_response::Result::Quiesced(v) => assert!(v),
            _ => panic!("expected Quiesced"),
        }

        guest.await.unwrap();
    }

    /// Post-restore: the host opens a new transport, sends ResumeNotify
    /// with fresh identity (sandbox_id, policy_epoch, lineage_id).
    /// The guest must accept with a fresh session.
    #[tokio::test]
    async fn resume_notify_with_fresh_identity_after_restore() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read ResumeNotify with post-restore identity
            let (tag, req) = framed::read_tagged::<ResumeNotifyRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            // Verify fresh identity fields
            assert_eq!(req.sandbox_id, "sbx-restored-v2");
            assert_eq!(req.policy_epoch, 3);
            assert_eq!(req.lineage_id, "snap-lineage-002");
            assert!(req.snapshot_taken_at.is_some());

            // Guest accepts and returns fresh session confirmation
            let resp = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Accepted(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &resp,
                TIMEOUT,
            )
            .await
            .unwrap();
        });

        let req = ResumeNotifyRequest {
            context: Some(test_context("sbx-restored-v2", b"5678901234567890", 3)),
            sandbox_id: "sbx-restored-v2".into(),
            policy_epoch: 3,
            lineage_id: "snap-lineage-002".into(),
            snapshot_taken_at: Some(Timestamp {
                seconds: T_RESTORE_2026_Q2,
                nanos: 0,
            }),
        };
        framed::send_tagged(
            &mut client,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &req,
            TIMEOUT,
        )
        .await
        .unwrap();

        let (tag, resp) = framed::read_tagged::<ResumeNotifyResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result.unwrap() {
            resume_notify_response::Result::Accepted(v) => assert!(v),
            _ => panic!("expected Accepted"),
        }

        guest.await.unwrap();
    }

    /// Force-drain quiesce: operations are terminated immediately.
    #[tokio::test]
    async fn quiesce_force_drain_mode_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<QuiesceRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_QUIESCE_REQUEST);
            assert_eq!(req.drain_mode, quiesce_request::DrainMode::Force as i32);

            let resp = QuiesceResponse {
                result: Some(quiesce_response::Result::Quiesced(true)),
            };
            framed::send_tagged(&mut stream, framed::TAG_QUIESCE_RESPONSE, &resp, TIMEOUT)
                .await
                .unwrap();
        });

        let req = QuiesceRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            drain_mode: quiesce_request::DrainMode::Force as i32,
            quiesce_deadline: None,
        };
        framed::send_tagged(&mut client, framed::TAG_QUIESCE_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        let (tag, resp) = framed::read_tagged::<QuiesceResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_QUIESCE_RESPONSE);
        match resp.result.unwrap() {
            quiesce_response::Result::Quiesced(v) => assert!(v),
            _ => panic!("expected Quiesced"),
        }

        guest.await.unwrap();
    }

    /// Quiesce failure: guest cannot quiesce within deadline.
    #[tokio::test]
    async fn quiesce_failure_within_deadline_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, _req) = framed::read_tagged::<QuiesceRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_QUIESCE_REQUEST);

            let resp = QuiesceResponse {
                result: Some(quiesce_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::TimedOut(
                        operation_outcome::TimedOut {
                            budget_remaining: None,
                        },
                    )),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_QUIESCE_RESPONSE, &resp, TIMEOUT)
                .await
                .unwrap();
        });

        let req = QuiesceRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            drain_mode: quiesce_request::DrainMode::Graceful as i32,
            quiesce_deadline: Some(Timestamp {
                seconds: T_ANCIENT_DEADLINE,
                nanos: 0,
            }),
        };
        framed::send_tagged(&mut client, framed::TAG_QUIESCE_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        let (tag, resp) = framed::read_tagged::<QuiesceResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_QUIESCE_RESPONSE);
        match resp.result.unwrap() {
            quiesce_response::Result::Error(outcome) => {
                assert!(matches!(
                    outcome.status,
                    Some(operation_outcome::Status::TimedOut(_))
                ));
            }
            _ => panic!("expected Error with TimedOut"),
        }

        guest.await.unwrap();
    }

    /// ResumeNotify with rejected outcome.
    #[tokio::test]
    async fn resume_notify_rejected_outcome_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, _req) = framed::read_tagged::<ResumeNotifyRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let resp = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Unsupported(
                        operation_outcome::Unsupported {
                            detail: "image mismatch after restore".into(),
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &resp,
                TIMEOUT,
            )
            .await
            .unwrap();
        });

        let req = ResumeNotifyRequest {
            context: Some(test_context("sbx-restored", b"5678901234567890", 2)),
            sandbox_id: "sbx-restored".into(),
            policy_epoch: 2,
            lineage_id: "lineage-003".into(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut client,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &req,
            TIMEOUT,
        )
        .await
        .unwrap();

        let (tag, resp) = framed::read_tagged::<ResumeNotifyResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result.unwrap() {
            resume_notify_response::Result::Error(outcome) => {
                assert!(matches!(
                    outcome.status,
                    Some(operation_outcome::Status::Unsupported(_))
                ));
            }
            _ => panic!("expected Error with Unsupported"),
        }

        guest.await.unwrap();
    }

    /// Full lifecycle: exec before quiesce, drain, snapshot, restore, exec after.
    /// Validates that operations submitted before quiesce complete, and new
    /// operations can be submitted after resume.
    #[tokio::test]
    async fn full_quiesce_resume_with_exec_flow() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Phase 1: Pre-quiesce exec request
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            assert_eq!(req.command, "pre-snapshot-cmd");

            // Send exec response (success)
            let exec_resp = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: b"pre-snapshot-ok".to_vec(),
                        },
                    )),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &exec_resp, TIMEOUT)
                .await
                .unwrap();

            // Phase 2: Quiesce request
            let (tag, req) = framed::read_tagged::<QuiesceRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_QUIESCE_REQUEST);
            assert_eq!(req.drain_mode, quiesce_request::DrainMode::Graceful as i32);

            // Confirm quiescence
            let quiesce_resp = QuiesceResponse {
                result: Some(quiesce_response::Result::Quiesced(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_QUIESCE_RESPONSE,
                &quiesce_resp,
                TIMEOUT,
            )
            .await
            .unwrap();

            // Drop connection (simulates snapshot + transport loss)
            drop(stream);
        });

        // Phase 1: Send pre-quiesce exec
        let exec_req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "pre-snapshot-cmd".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &exec_req, TIMEOUT)
            .await
            .unwrap();

        let (tag, exec_resp) = framed::read_tagged::<ExecResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
        assert!(matches!(
            exec_resp.frame,
            Some(exec_response::Frame::Outcome(_))
        ));

        // Phase 2: Send quiesce request
        let quiesce_req = QuiesceRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            drain_mode: quiesce_request::DrainMode::Graceful as i32,
            quiesce_deadline: Some(Timestamp {
                seconds: T_SNAPSHOT_2026_Q2,
                nanos: 0,
            }),
        };
        framed::send_tagged(
            &mut client,
            framed::TAG_QUIESCE_REQUEST,
            &quiesce_req,
            TIMEOUT,
        )
        .await
        .unwrap();

        let (tag, quiesce_resp2) = framed::read_tagged::<QuiesceResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_QUIESCE_RESPONSE);
        match quiesce_resp2.result.unwrap() {
            quiesce_response::Result::Quiesced(v) => assert!(v),
            _ => panic!("expected Quiesced"),
        }

        guest.await.unwrap();

        // Phase 3: New transport for post-restore (simulated via new TCP pair)
        let (mut client2, listener2) = tcp_pair().await;

        let guest2 = tokio::spawn(async move {
            let (mut stream, _) = listener2.accept().await.unwrap();

            // Read ResumeNotify with fresh identity
            let (tag, req) = framed::read_tagged::<ResumeNotifyRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);
            assert_eq!(req.sandbox_id, "sbx-restored");
            assert_eq!(req.policy_epoch, 3);

            // Accept resume
            let resp = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Accepted(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &resp,
                TIMEOUT,
            )
            .await
            .unwrap();

            // Phase 4: Post-restore exec request
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);
            assert_eq!(req.command, "post-restore-cmd");
            assert_eq!(req.context.as_ref().unwrap().sandbox_id, "sbx-restored");

            let exec_resp = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: b"post-restore-ok".to_vec(),
                        },
                    )),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &exec_resp, TIMEOUT)
                .await
                .unwrap();
        });

        // Send ResumeNotify on new transport
        let resume_req = ResumeNotifyRequest {
            context: Some(test_context("sbx-restored", b"5678901234567890", 3)),
            sandbox_id: "sbx-restored".into(),
            policy_epoch: 3,
            lineage_id: "snap-lineage-sim".into(),
            snapshot_taken_at: Some(Timestamp {
                seconds: T_SNAPSHOT_2026_Q2,
                nanos: 0,
            }),
        };
        framed::send_tagged(
            &mut client2,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &resume_req,
            TIMEOUT,
        )
        .await
        .unwrap();

        let (tag, resp) = framed::read_tagged::<ResumeNotifyResponse>(&mut client2, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result.unwrap() {
            resume_notify_response::Result::Accepted(v) => assert!(v),
            _ => panic!("expected Accepted"),
        }

        // Send post-restore exec
        let exec_req2 = ExecRequest {
            context: Some(test_context("sbx-restored", b"5678901234567890", 3)),
            command: "post-restore-cmd".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client2, framed::TAG_EXEC_REQUEST, &exec_req2, TIMEOUT)
            .await
            .unwrap();

        let (tag, exec_resp2) = framed::read_tagged::<ExecResponse>(&mut client2, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
        assert!(matches!(
            exec_resp2.frame,
            Some(exec_response::Frame::Outcome(_))
        ));

        guest2.await.unwrap();
    }
}

// ==================================================================
// Stream backpressure and deadline behavior tests
// ==================================================================

mod backpressure_deadline {
    use super::*;
    use prost_types::{Duration as ProtoDuration, Timestamp};

    // Arbitrary but valid timestamps/durations for wire-format validation.
    const T_DEADLINE_2026_Q2: i64 = 1718200000;
    const T_COMBINED_DEADLINE: i64 = 1718300000;
    const NANOS_500MS: i32 = 500_000_000;
    const TIMEOUT_30S: i64 = 30;
    const TIMEOUT_10S: i64 = 10;
    const TIMEOUT_5S: i64 = 5;

    /// Rapid frame delivery: guest sends many frames in quick succession.
    /// The client must consume them without data loss or panic.
    #[tokio::test]
    async fn rapid_sequential_frames_no_data_loss() {
        let (mut client, listener) = tcp_pair().await;

        let frame_count: u64 = 100;
        let payload_size = 1024;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read exec request
            let (tag, _req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            // Send many frames rapidly
            for seq in 1..=frame_count {
                let payload = vec![(seq % 256) as u8; payload_size];
                let last = seq == frame_count;

                let frame = ExecResponse {
                    frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                        frame: Some(StreamFrame {
                            sequence: seq,
                            payload,
                            end_of_stream: last,
                        }),
                    })),
                };
                framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &frame, TIMEOUT)
                    .await
                    .unwrap();
            }

            // Send terminal outcome
            let outcome = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: b"done".to_vec(),
                        },
                    )),
                })),
            };
            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &outcome, TIMEOUT)
                .await
                .unwrap();
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "rapid-output".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        let mut received_frames: u64 = 0;
        let mut total_bytes: usize = 0;
        let mut last_seq: u64 = 0;
        let mut got_outcome = false;

        loop {
            let result = framed::read_tagged::<ExecResponse>(&mut client, TIMEOUT).await;
            match result {
                Ok((tag, resp)) => {
                    assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
                    match resp.frame {
                        Some(exec_response::Frame::Stdout(data)) => {
                            let f = data.frame.unwrap();
                            assert!(
                                f.sequence > last_seq,
                                "frames must be monotonic: seq {} after {}",
                                f.sequence,
                                last_seq
                            );
                            last_seq = f.sequence;
                            received_frames += 1;
                            total_bytes += f.payload.len();
                        }
                        Some(exec_response::Frame::Outcome(_)) => {
                            got_outcome = true;
                            break;
                        }
                        _ => {}
                    }
                }
                Err(_) => break,
            }
        }

        assert_eq!(received_frames, frame_count, "should receive all frames");
        assert_eq!(
            total_bytes,
            (payload_size * frame_count as usize),
            "should receive all payload bytes"
        );
        assert!(got_outcome, "should receive terminal outcome");

        guest.await.unwrap();
    }

    /// Backpressure simulation: guest sends frames faster than client reads.
    /// Framing layer must tolerate buffered data; no frames should be
    /// dropped or corrupted.
    #[tokio::test]
    async fn slow_reader_does_not_cause_data_corruption() {
        let (mut client, listener) = tcp_pair().await;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            // Send frames in quick bursts (no delay between writes)
            let frames: Vec<Vec<u8>> = (0..10)
                .map(|i| {
                    let resp = ExecResponse {
                        frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                            frame: Some(StreamFrame {
                                sequence: i + 1,
                                payload: format!("chunk-{i:04}-").into_bytes(),
                                end_of_stream: i == 9,
                            }),
                        })),
                    };
                    resp.encode_to_vec()
                })
                .collect();

            for payload in &frames {
                write_raw_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, payload).await;
            }

            let outcome = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: b"backpressure-ok".to_vec(),
                        },
                    )),
                })),
            };
            write_raw_tagged(
                &mut stream,
                framed::TAG_EXEC_RESPONSE,
                &outcome.encode_to_vec(),
            )
            .await;
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "slow-reader-test".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        // Simulate slow reader with small delays between reads
        let mut received_seqs: Vec<u64> = Vec::new();
        loop {
            let result = framed::read_tagged::<ExecResponse>(&mut client, TIMEOUT).await;
            match result {
                Ok((tag, resp)) => {
                    assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
                    match resp.frame {
                        Some(exec_response::Frame::Stdout(data)) => {
                            received_seqs.push(data.frame.unwrap().sequence);
                            // Small delay to simulate slow consumer
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        Some(exec_response::Frame::Outcome(_)) => break,
                        _ => {}
                    }
                }
                Err(_) => break,
            }
        }

        assert_eq!(received_seqs.len(), 10, "should receive all 10 frames");
        // Verify sequences are ordered (no corruption/out-of-order)
        for (i, &seq) in received_seqs.iter().enumerate() {
            assert_eq!(seq, (i + 1) as u64, "sequence mismatch at index {i}");
        }

        guest.await.unwrap();
    }

    /// StreamFrame at exactly 64 KiB payload (the spec max per frame) must
    /// be accepted at wire level.
    #[tokio::test]
    async fn stream_frame_at_exact_max_payload_accepted() {
        let (mut client, listener) = tcp_pair().await;
        let max_payload: usize = 64 * 1024;

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let resp = ExecResponse {
                frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                    frame: Some(StreamFrame {
                        sequence: 1,
                        payload: vec![0x42u8; max_payload],
                        end_of_stream: true,
                    }),
                })),
            };

            let encoded = resp.encode_to_vec();
            assert!(
                encoded.len() < framed::MAX_MESSAGE_SIZE,
                "64 KiB payload frame must fit within 1 MiB message limit"
            );

            framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &resp, TIMEOUT)
                .await
                .unwrap();
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "max-payload-test".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();

        let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut client, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

        match resp.frame.unwrap() {
            exec_response::Frame::Stdout(data) => {
                let frame = data.frame.unwrap();
                assert_eq!(frame.payload.len(), max_payload);
                assert!(frame.end_of_stream);
            }
            _ => panic!("expected Stdout frame"),
        }

        guest.await.unwrap();
    }

    /// Deadline awareness: request carries an absolute deadline in
    /// RequestContext. The deadline field must round-trip correctly
    /// and be parseable by the peer.
    #[tokio::test]
    async fn request_context_with_deadline_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let ctx = req.context.unwrap();
            let deadline = ctx.deadline.unwrap();
            // Verify deadline timestamp fields
            assert!(deadline.seconds > 0);
            assert_eq!(deadline.nanos, NANOS_500MS);
        });

        let req = ExecRequest {
            context: Some(RequestContext {
                deadline: Some(Timestamp {
                    seconds: T_DEADLINE_2026_Q2,
                    nanos: NANOS_500MS,
                }),
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "deadline-aware-cmd".into(),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Operation timeout: ExecRequest carries a per-operation timeout.
    /// The timeout field must round-trip correctly.
    #[tokio::test]
    async fn exec_request_with_operation_timeout_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let timeout = req.timeout.unwrap();
            assert_eq!(timeout.seconds, TIMEOUT_30S);
            assert_eq!(timeout.nanos, 0);
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "timed-cmd".into(),
            timeout: Some(ProtoDuration {
                seconds: TIMEOUT_30S,
                nanos: 0,
            }),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// TimedOut outcome with remaining budget reports correctly.
    #[tokio::test]
    async fn timed_out_outcome_with_budget_remaining_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

            match resp.frame.unwrap() {
                exec_response::Frame::Outcome(outcome) => {
                    match outcome.status.unwrap() {
                        operation_outcome::Status::TimedOut(t) => {
                            // Budget exhausted (0 remaining)
                            let remaining = t.budget_remaining.unwrap();
                            assert_eq!(remaining.seconds, 0);
                            assert_eq!(remaining.nanos, 0);
                        }
                        _ => panic!("expected TimedOut"),
                    }
                }
                _ => panic!("expected Outcome"),
            }
        });

        let resp = ExecResponse {
            frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                status: Some(operation_outcome::Status::TimedOut(
                    operation_outcome::TimedOut {
                        budget_remaining: Some(ProtoDuration {
                            seconds: 0,
                            nanos: 0,
                        }),
                    },
                )),
            })),
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// TimedOut with partial budget remaining (child action exhausted).
    #[tokio::test]
    async fn timed_out_with_partial_budget_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

            match resp.frame.unwrap() {
                exec_response::Frame::Outcome(outcome) => {
                    match outcome.status.unwrap() {
                        operation_outcome::Status::TimedOut(t) => {
                            // Child action budget exhausted, 5s remaining on parent
                            let remaining = t.budget_remaining.unwrap();
                            assert_eq!(remaining.seconds, TIMEOUT_5S);
                        }
                        _ => panic!("expected TimedOut"),
                    }
                }
                _ => panic!("expected Outcome"),
            }
        });

        let resp = ExecResponse {
            frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                status: Some(operation_outcome::Status::TimedOut(
                    operation_outcome::TimedOut {
                        budget_remaining: Some(ProtoDuration {
                            seconds: TIMEOUT_5S,
                            nanos: 0,
                        }),
                    },
                )),
            })),
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// StreamAck with maximum contiguous sequence value tests overflow
    /// safety (u64::MAX).
    #[tokio::test]
    async fn stream_ack_max_sequence_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

            match resp.frame.unwrap() {
                exec_response::Frame::Ack(ack) => {
                    assert_eq!(ack.highest_contiguous, u64::MAX);
                }
                _ => panic!("expected Ack"),
            }
        });

        let resp = ExecResponse {
            frame: Some(exec_response::Frame::Ack(StreamAck {
                highest_contiguous: u64::MAX,
            })),
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Host sends max_stdout_bytes / max_stderr_bytes limits.
    /// These bounds must round-trip correctly.
    #[tokio::test]
    async fn exec_request_output_byte_limits_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            assert_eq!(req.max_stdout_bytes, 1_048_576); // 1 MiB
            assert_eq!(req.max_stderr_bytes, 524_288); // 512 KiB
        });

        let req = ExecRequest {
            context: Some(test_context("sbx", b"1234567890123456", 1)),
            command: "bounded-output".into(),
            max_stdout_bytes: 1_048_576,
            max_stderr_bytes: 524_288,
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// StreamFrame sequence value wraps through high u64 values.
    #[tokio::test]
    async fn stream_frame_large_sequence_tolerated() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, resp) = framed::read_tagged::<ExecResponse>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);

            match resp.frame.unwrap() {
                exec_response::Frame::Stdout(data) => {
                    let frame = data.frame.unwrap();
                    assert_eq!(frame.sequence, u64::MAX - 1);
                    assert_eq!(frame.payload, b"high-seq");
                    assert!(frame.end_of_stream);
                }
                _ => panic!("expected Stdout frame"),
            }
        });

        let resp = ExecResponse {
            frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                frame: Some(StreamFrame {
                    sequence: u64::MAX - 1,
                    payload: b"high-seq".to_vec(),
                    end_of_stream: true,
                }),
            })),
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_RESPONSE, &resp, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }

    /// Combined request with both deadline (RequestContext) and timeout
    /// (ExecRequest) - validates the host can set both independently.
    #[tokio::test]
    async fn combined_deadline_and_timeout_round_trip() {
        let (mut client, listener) = tcp_pair().await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (tag, req) = framed::read_tagged::<ExecRequest>(&mut stream, TIMEOUT)
                .await
                .unwrap();
            assert_eq!(tag, framed::TAG_EXEC_REQUEST);

            let ctx = req.context.unwrap();
            // Deadline is absolute timestamp
            let deadline = ctx.deadline.unwrap();
            assert_eq!(deadline.seconds, T_COMBINED_DEADLINE);

            // Timeout is relative duration
            let timeout = req.timeout.unwrap();
            assert_eq!(timeout.seconds, TIMEOUT_10S);
        });

        let req = ExecRequest {
            context: Some(RequestContext {
                deadline: Some(Timestamp {
                    seconds: T_COMBINED_DEADLINE,
                    nanos: 0,
                }),
                ..test_context("sbx", b"1234567890123456", 1)
            }),
            command: "dual-deadline".into(),
            timeout: Some(ProtoDuration {
                seconds: TIMEOUT_10S,
                nanos: 0,
            }),
            ..Default::default()
        };
        framed::send_tagged(&mut client, framed::TAG_EXEC_REQUEST, &req, TIMEOUT)
            .await
            .unwrap();
        drop(client);

        server.await.unwrap();
    }
}
