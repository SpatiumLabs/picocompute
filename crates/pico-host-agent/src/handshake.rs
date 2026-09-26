//! Guest-agent handshake protocol implementation.
//!
//! Implements the PicoCompute bootstrap handshake as defined in
//! `pico.guest.bootstrap.v1.Bootstrap/Handshake`. The host-agent
//! opens a TCP connection to the guest, exchanges identity claims and
//! capability sets, validates HMAC proofs, and negotiates the
//! operational protocol session.
//!
//! A sandbox must not be marked Running until this handshake
//! succeeds.

use std::net::SocketAddr;
use std::time::Duration;

use heapless::Vec as HVec;

use pico_core::Result;
use pico_core::SandboxError;
use pico_core::crypto;
use pico_guest_protocol::FramedConnection;
use pico_guest_protocol::bootstrap_v1::*;

const HANDSHAKE_TIMEOUT_SECS: u64 = 30;
const PROTOCOL_NAME: &str = "pico.guest";
const BOOTSTRAP_VERSION_MAJOR: u32 = 1;
const BOOTSTRAP_VERSION_MINOR: u32 = 0;
const OPERATIONAL_VERSION_MAJOR: u32 = 1;
const OPERATIONAL_VERSION_MINOR_MIN: u32 = 0;
const OPERATIONAL_VERSION_MINOR_MAX: u32 = 5;

#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    pub sandbox_id: String,
    pub image_id: String,
    pub image_digest: String,
    pub host_agent_version: String,
    pub host_capabilities: Vec<String>,
    pub transport_addr: SocketAddr,
    pub timeout: Duration,
    pub policy_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct HandshakeOutcome {
    pub session_id: HVec<u8, 16>,
    pub negotiated_version: (u32, u32),
    pub negotiated_capabilities: Vec<String>,
    pub guest_agent_version: String,
    pub guest_boot_id: String,
    pub guest_image_id: String,
    pub guest_image_digest: String,
    pub policy_epoch: u64,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            sandbox_id: String::new(),
            image_id: String::new(),
            image_digest: String::new(),
            host_agent_version: env!("CARGO_PKG_VERSION").into(),
            host_capabilities: vec![
                "exec".into(),
                "file".into(),
                "mount".into(),
                "stats".into(),
                "health".into(),
                "shutdown".into(),
            ],
            transport_addr: "127.0.0.1:9999".parse().unwrap(),
            timeout: Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            policy_epoch: 1,
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HandshakeError {
    #[error("handshake timed out after {0:?}")]
    Timeout(Duration),

    #[error("connection refused: {0}")]
    ConnectionRefused(String),

    #[error("protocol mismatch: expected '{expected}', got '{received}'")]
    ProtocolMismatch { expected: String, received: String },

    #[error(
        "version negotiation failed: host supports {host_versions:?}, guest supports {guest_versions:?}"
    )]
    VersionMismatch {
        host_versions: String,
        guest_versions: String,
    },

    #[error("identity mismatch: field '{field}', expected '{expected}', got '{received}'")]
    IdentityMismatch {
        field: String,
        expected: String,
        received: String,
    },

    #[error(
        "capability negotiation failed: host declares {host:?}, guest declares {guest:?}, intersection is empty"
    )]
    CapabilityMismatch {
        host: Vec<String>,
        guest: Vec<String>,
    },

    #[error("HMAC proof verification failed for role '{role}'")]
    ProofVerificationFailed { role: String },

    #[error("guest rejected handshake: code={code:?}, message='{message}'")]
    GuestRejected { code: i32, message: String },

    #[error("unexpected message from guest: expected {expected}, got {received}")]
    UnexpectedMessage { expected: String, received: String },

    #[error("message encoding/decoding error: {0}")]
    Protocol(String),

    #[error("I/O error: {0}")]
    Io(String),
}

impl From<HandshakeError> for SandboxError {
    fn from(err: HandshakeError) -> Self {
        let msg = err.to_string();
        match &err {
            HandshakeError::Timeout(_) => SandboxError::NotReady(msg),
            HandshakeError::ConnectionRefused(_) => SandboxError::NotReady(msg),
            _ => SandboxError::Unprocessable(msg),
        }
    }
}

pub async fn perform_handshake(config: &HandshakeConfig) -> Result<HandshakeOutcome> {
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

    let mut conn = FramedConnection::new(stream, config.timeout);
    perform_handshake_exchange(&mut conn, config)
        .await
        .map_err(Into::into)
}

/// Performs the handshake protocol exchange on an already-connected stream.
pub(crate) async fn perform_handshake_exchange(
    conn: &mut FramedConnection,
    config: &HandshakeConfig,
) -> std::result::Result<HandshakeOutcome, HandshakeError> {
    let shared_secret = crypto::derive_handshake_shared_secret(&config.sandbox_id);

    let host_nonce = crypto::generate_nonce();
    let host_hello = build_host_hello(config, &host_nonce);

    tracing::info!(
        sandbox_id = %config.sandbox_id,
        image_id = %config.image_id,
        "sending HostHello to guest agent"
    );

    conn.send(&host_hello)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("failed to send HostHello: {e}")))?;

    let guest_hello = conn
        .recv::<GuestHello>()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("failed to read GuestHello: {e}")))?;

    validate_guest_hello(config, &guest_hello, &shared_secret, &host_nonce)
        .map_err(|e| HandshakeError::Protocol(e.to_string()))?;

    tracing::info!(
        sandbox_id = %config.sandbox_id,
        guest_boot_id = %guest_hello.boot_id,
        guest_agent_version = %guest_hello.agent_version,
        "received GuestHello, negotiating protocol"
    );

    let negotiated = negotiate_version_and_capabilities(
        config,
        &guest_hello.supported_versions,
        guest_hello.guest_capabilities.as_ref(),
    )
    .map_err(|e| HandshakeError::Protocol(e.to_string()))?;

    let session_id = crypto::generate_session_id();
    let host_reply = build_host_reply(
        &negotiated,
        &session_id,
        config.policy_epoch,
        &shared_secret,
        &host_nonce,
        &guest_hello,
    );

    tracing::info!(
        sandbox_id = %config.sandbox_id,
        session_id_len = session_id.len(),
        selected_version = ?negotiated.version,
        selected_capabilities_len = negotiated.capabilities.len(),
        "sending HostReply to guest agent"
    );

    conn.send(&host_reply)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("failed to send HostReply: {e}")))?;

    let result = conn
        .recv::<HandshakeResult>()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("failed to read HandshakeResult: {e}")))?;

    match result.outcome {
        Some(handshake_result::Outcome::Established(true)) => {
            tracing::info!(
                sandbox_id = %config.sandbox_id,
                "handshake established"
            );
        }
        Some(handshake_result::Outcome::Error(ref err)) => {
            let code_str = handshake_error::ErrorCode::try_from(err.code)
                .map(|c| format!("{c:?}"))
                .unwrap_or_else(|_| format!("UNKNOWN({})", err.code));
            return Err(HandshakeError::GuestRejected {
                code: err.code,
                message: format!("{code_str}: {}", err.message),
            });
        }
        _ => {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "Established or Error".into(),
                received: "missing outcome".into(),
            });
        }
    }

    Ok(HandshakeOutcome {
        session_id,
        negotiated_version: negotiated.version,
        negotiated_capabilities: negotiated.capabilities,
        guest_agent_version: guest_hello.agent_version,
        guest_boot_id: guest_hello.boot_id,
        guest_image_id: guest_hello.image_id,
        guest_image_digest: guest_hello.image_digest,
        policy_epoch: config.policy_epoch,
    })
}

pub(crate) fn build_host_hello(config: &HandshakeConfig, host_nonce: &[u8]) -> HostHello {
    HostHello {
        protocol_name: PROTOCOL_NAME.into(),
        bootstrap_version: Some(VersionRange {
            min: Some(Version {
                major: BOOTSTRAP_VERSION_MAJOR,
                minor: BOOTSTRAP_VERSION_MINOR,
            }),
            max: Some(Version {
                major: BOOTSTRAP_VERSION_MAJOR,
                minor: BOOTSTRAP_VERSION_MINOR,
            }),
        }),
        supported_versions: vec![VersionRange {
            min: Some(Version {
                major: OPERATIONAL_VERSION_MAJOR,
                minor: OPERATIONAL_VERSION_MINOR_MIN,
            }),
            max: Some(Version {
                major: OPERATIONAL_VERSION_MAJOR,
                minor: OPERATIONAL_VERSION_MINOR_MAX,
            }),
        }],
        host_capabilities: Some(CapabilitySet {
            identifiers: config.host_capabilities.clone(),
        }),
        host_nonce: Some(Nonce {
            value: host_nonce.to_vec(),
        }),
        sandbox_id: config.sandbox_id.clone(),
        image_id: config.image_id.clone(),
        image_digest: config.image_digest.clone(),
    }
}

pub(crate) fn validate_guest_hello(
    config: &HandshakeConfig,
    guest_hello: &GuestHello,
    shared_secret: &[u8],
    host_nonce: &[u8],
) -> Result<()> {
    if guest_hello.image_id != config.image_id {
        return Err(HandshakeError::IdentityMismatch {
            field: "image_id".into(),
            expected: config.image_id.clone(),
            received: guest_hello.image_id.clone(),
        }
        .into());
    }

    if guest_hello.supported_versions.is_empty() {
        return Err(HandshakeError::VersionMismatch {
            host_versions: format!(
                "[{OPERATIONAL_VERSION_MAJOR}.{OPERATIONAL_VERSION_MINOR_MIN}-{OPERATIONAL_VERSION_MAJOR}.{OPERATIONAL_VERSION_MINOR_MAX}]"
            ),
            guest_versions: "none".into(),
        }
        .into());
    }

    let proof_bytes = guest_hello
        .proof
        .as_ref()
        .map(|p| p.value.as_slice())
        .unwrap_or(&[]);
    let expected_proof = compute_guest_proof(shared_secret, host_nonce, guest_hello);
    if !crypto::constant_time_eq(proof_bytes, &expected_proof) {
        return Err(HandshakeError::ProofVerificationFailed {
            role: "guest".into(),
        }
        .into());
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) struct NegotiatedParams {
    pub(crate) version: (u32, u32),
    pub(crate) capabilities: Vec<String>,
}

pub(crate) fn negotiate_version_and_capabilities(
    config: &HandshakeConfig,
    guest_version_ranges: &[VersionRange],
    guest_capabilities: Option<&CapabilitySet>,
) -> Result<NegotiatedParams> {
    let host_range = VersionRange {
        min: Some(Version {
            major: OPERATIONAL_VERSION_MAJOR,
            minor: OPERATIONAL_VERSION_MINOR_MIN,
        }),
        max: Some(Version {
            major: OPERATIONAL_VERSION_MAJOR,
            minor: OPERATIONAL_VERSION_MINOR_MAX,
        }),
    };

    let intersection = find_version_intersection(&host_range, guest_version_ranges)
        .ok_or_else(|| HandshakeError::VersionMismatch {
            host_versions: format!(
                "[{OPERATIONAL_VERSION_MAJOR}.{OPERATIONAL_VERSION_MINOR_MIN}-{OPERATIONAL_VERSION_MAJOR}.{OPERATIONAL_VERSION_MINOR_MAX}]"
            ),
            guest_versions: guest_version_ranges
                .iter()
                .map(|r| format!(
                    "[{}.{}-{}.{}]",
                    r.min.as_ref().map_or(0, |v| v.major),
                    r.min.as_ref().map_or(0, |v| v.minor),
                    r.max.as_ref().map_or(0, |v| v.major),
                    r.max.as_ref().map_or(0, |v| v.minor),
                ))
                .collect::<Vec<_>>()
                .join(", "),
        })?;

    let host_set: hashbrown::HashSet<&str> = config
        .host_capabilities
        .iter()
        .map(|s| s.as_str())
        .collect();
    let guest_set: hashbrown::HashSet<&str> = guest_capabilities
        .map(|c| c.identifiers.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let negotiated: Vec<String> = host_set
        .intersection(&guest_set)
        .map(|s| s.to_string())
        .collect();
    if negotiated.is_empty() {
        return Err(HandshakeError::CapabilityMismatch {
            host: config.host_capabilities.clone(),
            guest: guest_set.iter().map(|s| s.to_string()).collect(),
        }
        .into());
    }

    Ok(NegotiatedParams {
        version: intersection,
        capabilities: negotiated,
    })
}

pub(crate) fn build_host_reply(
    negotiated: &NegotiatedParams,
    session_id: &[u8],
    policy_epoch: u64,
    shared_secret: &[u8],
    host_nonce: &[u8],
    guest_hello: &GuestHello,
) -> HostReply {
    let selected_version = Some(Version {
        major: negotiated.version.0,
        minor: negotiated.version.1,
    });
    let selected_capabilities = Some(CapabilitySet {
        identifiers: negotiated.capabilities.clone(),
    });
    let session = Some(SessionId {
        value: session_id.to_vec(),
    });

    let proof = compute_host_proof(
        shared_secret,
        host_nonce,
        guest_hello,
        session_id,
        policy_epoch,
        negotiated.version,
        &negotiated.capabilities,
    );

    HostReply {
        selected_version,
        selected_capabilities,
        session_id: session,
        policy_epoch,
        proof: Some(Proof {
            value: proof.to_vec(),
        }),
    }
}

fn find_version_intersection(
    host_range: &VersionRange,
    guest_ranges: &[VersionRange],
) -> Option<(u32, u32)> {
    for guest_range in guest_ranges {
        let h_min = version_to_tuple(host_range.min.as_ref());
        let h_max = version_to_tuple(host_range.max.as_ref());
        let g_min = version_to_tuple(guest_range.min.as_ref());
        let g_max = version_to_tuple(guest_range.max.as_ref());

        let overlap_min = (h_min.0.max(g_min.0), h_min.1.max(g_min.1));
        let overlap_max = (h_max.0.min(g_max.0), h_max.1.min(g_max.1));

        if compare_versions(overlap_min, overlap_max) != std::cmp::Ordering::Greater {
            // Pick the highest overlapping version (prefer host's max)
            return Some(overlap_max);
        }
    }
    None
}

fn version_to_tuple(v: Option<&Version>) -> (u32, u32) {
    v.map(|v| (v.major, v.minor)).unwrap_or((0, 0))
}

fn compare_versions(a: (u32, u32), b: (u32, u32)) -> std::cmp::Ordering {
    a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1))
}

pub(crate) fn compute_guest_proof(
    shared_secret: &[u8],
    host_nonce: &[u8],
    guest_hello: &GuestHello,
) -> HVec<u8, 32> {
    let guest_nonce = guest_hello
        .guest_nonce
        .as_ref()
        .map(|n| n.value.as_slice())
        .unwrap_or(&[]);

    // Transcript bound: 31B(label) + 32Bx2(nonces) + ~128B(identity fields) < 400B < 512
    let mut transcript: HVec<u8, 512> = HVec::new();
    transcript
        .extend_from_slice(b"pico.guest.bootstrap.v1|guest")
        .ok();
    transcript.extend_from_slice(host_nonce).ok();
    transcript.extend_from_slice(guest_nonce).ok();
    transcript
        .extend_from_slice(guest_hello.agent_version.as_bytes())
        .ok();
    transcript
        .extend_from_slice(guest_hello.boot_id.as_bytes())
        .ok();
    transcript
        .extend_from_slice(guest_hello.image_id.as_bytes())
        .ok();
    transcript
        .extend_from_slice(guest_hello.image_digest.as_bytes())
        .ok();

    crypto::blake3_mac(shared_secret, &transcript)
}

fn compute_host_proof(
    shared_secret: &[u8],
    host_nonce: &[u8],
    guest_hello: &GuestHello,
    session_id: &[u8],
    policy_epoch: u64,
    selected_version: (u32, u32),
    selected_capabilities: &[String],
) -> HVec<u8, 32> {
    let guest_nonce = guest_hello
        .guest_nonce
        .as_ref()
        .map(|n| n.value.as_slice())
        .unwrap_or(&[]);

    // Transcript bound: 31B(label) + 32Bx2(nonces) + 16B(session_id) + 12B(epoch+versions) + ~128B(identity) + capabilities < 400B < 512
    let mut transcript: HVec<u8, 512> = HVec::new();
    transcript
        .extend_from_slice(b"pico.guest.bootstrap.v1|host")
        .ok();
    transcript.extend_from_slice(host_nonce).ok();
    transcript.extend_from_slice(guest_nonce).ok();
    transcript
        .extend_from_slice(guest_hello.agent_version.as_bytes())
        .ok();
    transcript
        .extend_from_slice(guest_hello.boot_id.as_bytes())
        .ok();
    transcript.extend_from_slice(session_id).ok();
    transcript
        .extend_from_slice(&policy_epoch.to_be_bytes())
        .ok();
    transcript
        .extend_from_slice(&selected_version.0.to_be_bytes())
        .ok();
    transcript
        .extend_from_slice(&selected_version.1.to_be_bytes())
        .ok();
    for cap in selected_capabilities {
        transcript.extend_from_slice(cap.as_bytes()).ok();
        transcript.push(0u8).ok();
    }

    crypto::blake3_mac(shared_secret, &transcript)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_intersection_exact_match() {
        let host = VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        };
        let guest = vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        }];
        let result = find_version_intersection(&host, &guest);
        assert_eq!(result, Some((1, 5)));
    }

    #[test]
    fn version_intersection_overlap() {
        let host = VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        };
        let guest = vec![VersionRange {
            min: Some(Version { major: 1, minor: 3 }),
            max: Some(Version { major: 1, minor: 7 }),
        }];
        let result = find_version_intersection(&host, &guest);
        assert_eq!(result, Some((1, 5)));
    }

    #[test]
    fn version_intersection_no_overlap_different_major() {
        let host = VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        };
        let guest = vec![VersionRange {
            min: Some(Version { major: 2, minor: 0 }),
            max: Some(Version { major: 2, minor: 3 }),
        }];
        let result = find_version_intersection(&host, &guest);
        assert_eq!(result, None);
    }

    #[test]
    fn version_intersection_no_overlap_minor() {
        let host = VersionRange {
            min: Some(Version { major: 1, minor: 5 }),
            max: Some(Version {
                major: 1,
                minor: 10,
            }),
        };
        let guest = vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 4 }),
        }];
        let result = find_version_intersection(&host, &guest);
        assert_eq!(result, None);
    }

    #[test]
    fn version_intersection_multiple_ranges_picks_best() {
        let host = VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version {
                major: 1,
                minor: 10,
            }),
        };
        let guest = vec![
            VersionRange {
                min: Some(Version { major: 1, minor: 0 }),
                max: Some(Version { major: 1, minor: 3 }),
            },
            VersionRange {
                min: Some(Version { major: 1, minor: 5 }),
                max: Some(Version { major: 1, minor: 8 }),
            },
        ];
        let result = find_version_intersection(&host, &guest);
        assert_eq!(result, Some((1, 3)));
    }

    #[test]
    fn derive_shared_secret_is_stable() {
        let s1 = crypto::derive_handshake_shared_secret("sbx_test");
        let s2 = crypto::derive_handshake_shared_secret("sbx_test");
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 32);
    }

    #[test]
    fn derive_shared_secret_varies_with_sandbox_id() {
        let s1 = crypto::derive_handshake_shared_secret("sbx_alpha");
        let s2 = crypto::derive_handshake_shared_secret("sbx_beta");
        assert_ne!(s1, s2);
    }

    #[test]
    fn generate_nonce_is_32_bytes() {
        let nonce = crypto::generate_nonce();
        assert_eq!(nonce.len(), 32);
    }

    #[test]
    fn generate_session_id_is_16_bytes() {
        let id = crypto::generate_session_id();
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(crypto::constant_time_eq(b"hello", b"hello"));
        assert!(!crypto::constant_time_eq(b"hello", b"world"));
        assert!(!crypto::constant_time_eq(b"hello", b"hell"));
        assert!(!crypto::constant_time_eq(b"", b"a"));
    }

    #[test]
    fn validate_identity_mismatch_rejects_wrong_image_id() {
        let config = HandshakeConfig {
            sandbox_id: "sbx_test".into(),
            image_id: "expected-image".into(),
            image_digest: "abc123".into(),
            ..Default::default()
        };
        let guest_hello = GuestHello {
            image_id: "wrong-image".into(),
            supported_versions: vec![],
            ..Default::default()
        };
        let shared_secret = crypto::derive_handshake_shared_secret("sbx_test");
        let host_nonce = crypto::generate_nonce();

        let result = validate_guest_hello(&config, &guest_hello, &shared_secret, &host_nonce);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("image_id"));
    }

    #[test]
    fn validate_empty_supported_versions_is_rejected() {
        let config = HandshakeConfig {
            sandbox_id: "sbx_test".into(),
            image_id: "test-image".into(),
            image_digest: "abc123".into(),
            ..Default::default()
        };
        let guest_hello = GuestHello {
            image_id: "test-image".into(),
            supported_versions: vec![],
            ..Default::default()
        };
        let shared_secret = crypto::derive_handshake_shared_secret("sbx_test");
        let host_nonce = crypto::generate_nonce();

        let result = validate_guest_hello(&config, &guest_hello, &shared_secret, &host_nonce);
        assert!(result.is_err());
    }

    #[test]
    fn capability_negotiation_intersection() {
        let config = HandshakeConfig {
            host_capabilities: vec!["exec".into(), "file".into(), "mount".into()],
            ..Default::default()
        };
        let guest_ranges = vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        }];
        let guest_caps = Some(CapabilitySet {
            identifiers: vec!["exec".into(), "stats".into()],
        });

        let result =
            negotiate_version_and_capabilities(&config, &guest_ranges, guest_caps.as_ref());
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert_eq!(outcome.version, (1, 5));
        assert_eq!(outcome.capabilities, vec!["exec"]);
    }

    #[test]
    fn capability_negotiation_empty_intersection_is_rejected() {
        let config = HandshakeConfig {
            host_capabilities: vec!["exec".into(), "file".into()],
            ..Default::default()
        };
        let guest_ranges = vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        }];
        let guest_caps = Some(CapabilitySet {
            identifiers: vec!["stats".into(), "health".into()],
        });

        let result =
            negotiate_version_and_capabilities(&config, &guest_ranges, guest_caps.as_ref());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("capability"),
            "expected capability mismatch, got: {err}"
        );
    }
}
