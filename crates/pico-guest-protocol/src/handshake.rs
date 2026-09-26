//! Guest-agent bootstrap handshake (host side).
//!
//! Implements the PicoCompute bootstrap handshake defined by
//! `pico.guest.bootstrap.v1`. The host opens a transport to the guest
//! agent, exchanges identity claims and capability sets, validates BLAKE3
//! keyed-MAC proofs, and negotiates the operational protocol session.
//!
//! A sandbox must not be marked Running until this handshake succeeds.
//! This is the single, fail-closed readiness gate: there is no soft-skip
//! path that reports Ready without a completed handshake.
//!
//! The exchange is transport-agnostic and runs over any
//! [`crate::framed::TransportStream`] (TCP for tests, vsock for production).

use std::net::SocketAddr;
use std::time::Duration;

use heapless::Vec as HVec;

use pico_core::crypto;

use crate::bootstrap_v1::*;
use crate::framed::{FramedConnection, TransportStream};

const HANDSHAKE_TIMEOUT_SECS: u64 = 30;
const PROTOCOL_NAME: &str = "pico.guest";
const BOOTSTRAP_VERSION_MAJOR: u32 = 1;
const BOOTSTRAP_VERSION_MINOR: u32 = 0;
const OPERATIONAL_VERSION_MAJOR: u32 = 1;
const OPERATIONAL_VERSION_MINOR_MIN: u32 = 0;
const OPERATIONAL_VERSION_MINOR_MAX: u32 = 5;

/// Host parameters for the guest bootstrap handshake.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Sandbox identity shared with the guest.
    pub sandbox_id: String,
    /// Expected guest image id. When empty, image identity validation is
    /// skipped (test/restore transports where the identity is not pinned).
    /// Production paths MUST populate this so the check is enforced.
    pub image_id: String,
    /// Expected guest image digest. Same skip-if-empty semantics as
    /// [`Self::image_id`].
    pub image_digest: String,
    /// Host-side agent version claim.
    pub host_agent_version: String,
    /// Capabilities offered by the host.
    pub host_capabilities: Vec<String>,
    /// Guest agent TCP address (used by the TCP convenience connector).
    pub transport_addr: SocketAddr,
    /// Overall handshake timeout.
    pub timeout: Duration,
    /// Policy epoch bound into the session.
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
            transport_addr: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                9999,
            ),
            timeout: Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            policy_epoch: 1,
        }
    }
}

/// Successful handshake result used to open the operational session.
#[derive(Debug, Clone)]
pub struct HandshakeOutcome {
    /// Negotiated session identifier.
    pub session_id: HVec<u8, 16>,
    /// Selected operational protocol version.
    pub negotiated_version: (u32, u32),
    /// Capability intersection.
    pub negotiated_capabilities: Vec<String>,
    /// Guest agent version string.
    pub guest_agent_version: String,
    /// Guest boot identifier.
    pub guest_boot_id: String,
    /// Guest-reported image id.
    pub guest_image_id: String,
    /// Guest-reported image digest.
    pub guest_image_digest: String,
    /// Policy epoch accepted for the session.
    pub policy_epoch: u64,
}

/// Failures during guest bootstrap handshake.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HandshakeError {
    /// Handshake exceeded the configured timeout.
    #[error("handshake timed out after {0:?}")]
    Timeout(Duration),

    /// Transport connect failed or was refused.
    #[error("connection refused: {0}")]
    ConnectionRefused(String),

    /// Protocol name did not match.
    #[error("protocol mismatch: expected '{expected}', got '{received}'")]
    ProtocolMismatch {
        /// Expected protocol name.
        expected: String,
        /// Received protocol name.
        received: String,
    },

    /// No overlapping operational protocol version.
    #[error(
        "version negotiation failed: host supports {host_versions:?}, guest supports {guest_versions:?}"
    )]
    VersionMismatch {
        /// Host version ranges.
        host_versions: String,
        /// Guest version ranges.
        guest_versions: String,
    },

    /// Guest identity claim did not match host expectation.
    #[error("identity mismatch: field '{field}', expected '{expected}', got '{received}'")]
    IdentityMismatch {
        /// Field name that mismatched.
        field: String,
        /// Expected value.
        expected: String,
        /// Received value.
        received: String,
    },

    /// Capability intersection was empty.
    #[error(
        "capability negotiation failed: host declares {host:?}, guest declares {guest:?}, intersection is empty"
    )]
    CapabilityMismatch {
        /// Host capabilities.
        host: Vec<String>,
        /// Guest capabilities.
        guest: Vec<String>,
    },

    /// MAC proof verification failed.
    #[error("proof verification failed for role '{role}'")]
    ProofVerificationFailed {
        /// Role whose proof failed (`host` or `guest`).
        role: String,
    },

    /// Guest returned a handshake error.
    #[error("guest rejected handshake: code={code:?}, message='{message}'")]
    GuestRejected {
        /// Guest error code.
        code: i32,
        /// Guest error message.
        message: String,
    },

    /// Unexpected message type in the exchange.
    #[error("unexpected message from guest: expected {expected}, got {received}")]
    UnexpectedMessage {
        /// Expected message description.
        expected: String,
        /// Received message description.
        received: String,
    },

    /// Framing or protobuf encode/decode failure.
    #[error("message encoding/decoding error: {0}")]
    Protocol(String),

    /// Handshake transcript exceeded its fixed capacity.
    #[error("handshake transcript overflow: {0}")]
    TranscriptOverflow(String),

    /// Underlying transport I/O failure.
    #[error("I/O error: {0}")]
    Io(String),
}

impl HandshakeError {
    /// Stable machine-readable label for metrics and alert routing.
    ///
    /// Maps each variant to a snake_case string that survives being folded
    /// into stringly-typed outer errors (e.g., `BackendError::Failed`).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Timeout(_) => "handshake_timeout",
            Self::ConnectionRefused(_) => "connection_refused",
            Self::ProtocolMismatch { .. } => "protocol_mismatch",
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::IdentityMismatch { .. } => "identity_mismatch",
            Self::CapabilityMismatch { .. } => "capability_mismatch",
            Self::ProofVerificationFailed { .. } => "proof_verification_failed",
            Self::GuestRejected { .. } => "guest_rejected",
            Self::UnexpectedMessage { .. } => "unexpected_message",
            Self::Protocol(_) => "handshake_protocol",
            Self::TranscriptOverflow(_) => "transcript_overflow",
            Self::Io(_) => "handshake_io",
        }
    }

    /// Whether retrying the same handshake could plausibly succeed.
    ///
    /// Transient transport failures (unreachable guest, slow boot) are
    /// retryable; terminal assumption violations (proof, version,
    /// identity, rejection) are not.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout(_) | Self::ConnectionRefused(_) | Self::Io(_)
        )
    }
}

/// Performs the handshake protocol exchange on an already-connected stream.
///
/// This is the fail-closed readiness gate. It returns `Ok` only after the
/// guest has authenticated, negotiated a version and capability set, and
/// confirmed the session is established.
pub async fn perform_handshake_exchange<S: TransportStream>(
    conn: &mut FramedConnection<S>,
    config: &HandshakeConfig,
) -> Result<HandshakeOutcome, HandshakeError> {
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

    validate_guest_hello(config, &guest_hello, &shared_secret, &host_nonce)?;

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
    )?;

    let session_id = crypto::generate_session_id();
    let host_reply = build_host_reply(
        &negotiated,
        &session_id,
        config.policy_epoch,
        &shared_secret,
        &host_nonce,
        &guest_hello,
    )?;

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

/// Builds the host hello message.
pub fn build_host_hello(config: &HandshakeConfig, host_nonce: &[u8]) -> HostHello {
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

/// Validates guest identity and proof.
///
/// Identity checks are conditional on the expected value being non-empty:
/// when [`HandshakeConfig::image_id`]/[`HandshakeConfig::image_digest`] are
/// set (production), the guest's claim must match exactly. An empty
/// expectation skips the check so tests and restore flows can connect
/// without pinning image identity.
pub fn validate_guest_hello(
    config: &HandshakeConfig,
    guest_hello: &GuestHello,
    shared_secret: &[u8],
    host_nonce: &[u8],
) -> Result<(), HandshakeError> {
    if !config.image_id.is_empty() && guest_hello.image_id != config.image_id {
        return Err(HandshakeError::IdentityMismatch {
            field: "image_id".into(),
            expected: config.image_id.clone(),
            received: guest_hello.image_id.clone(),
        });
    }

    if !config.image_digest.is_empty() && guest_hello.image_digest != config.image_digest {
        return Err(HandshakeError::IdentityMismatch {
            field: "image_digest".into(),
            expected: config.image_digest.clone(),
            received: guest_hello.image_digest.clone(),
        });
    }

    if guest_hello.supported_versions.is_empty() {
        return Err(HandshakeError::VersionMismatch {
            host_versions: format!(
                "[{OPERATIONAL_VERSION_MAJOR}.{OPERATIONAL_VERSION_MINOR_MIN}-{OPERATIONAL_VERSION_MAJOR}.{OPERATIONAL_VERSION_MINOR_MAX}]"
            ),
            guest_versions: "none".into(),
        });
    }

    let proof_bytes = guest_hello
        .proof
        .as_ref()
        .map(|p| p.value.as_slice())
        .unwrap_or(&[]);
    let expected_proof = compute_guest_proof(shared_secret, host_nonce, guest_hello)?;
    if !crypto::constant_time_eq(proof_bytes, &expected_proof) {
        return Err(HandshakeError::ProofVerificationFailed {
            role: "guest".into(),
        });
    }

    Ok(())
}

/// Selected version and capability set after negotiation.
#[derive(Debug)]
pub struct NegotiatedParams {
    /// Selected protocol version.
    pub version: (u32, u32),
    /// Selected capabilities.
    pub capabilities: Vec<String>,
}

/// Negotiates the operational version and capability intersection.
pub fn negotiate_version_and_capabilities(
    config: &HandshakeConfig,
    guest_version_ranges: &[VersionRange],
    guest_capabilities: Option<&CapabilitySet>,
) -> Result<NegotiatedParams, HandshakeError> {
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
        });
    }

    Ok(NegotiatedParams {
        version: intersection,
        capabilities: negotiated,
    })
}

/// Builds the host reply that establishes the session.
///
/// Fails with [`HandshakeError::TranscriptOverflow`] if the proof
/// transcript could not be built within bounds.
pub fn build_host_reply(
    negotiated: &NegotiatedParams,
    session_id: &[u8],
    policy_epoch: u64,
    shared_secret: &[u8],
    host_nonce: &[u8],
    guest_hello: &GuestHello,
) -> Result<HostReply, HandshakeError> {
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
    )?;

    Ok(HostReply {
        selected_version,
        selected_capabilities,
        session_id: session,
        policy_epoch,
        proof: Some(Proof {
            value: proof.to_vec(),
        }),
    })
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
            // Pick the highest overlapping version (prefer host's max).
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

/// Computes the expected guest proof MAC.
///
/// Fails with [`HandshakeError::TranscriptOverflow`] when the transcript
/// would exceed its 512-byte capacity rather than silently truncating.
pub fn compute_guest_proof(
    shared_secret: &[u8],
    host_nonce: &[u8],
    guest_hello: &GuestHello,
) -> Result<HVec<u8, 32>, HandshakeError> {
    let guest_nonce = guest_hello
        .guest_nonce
        .as_ref()
        .map(|n| n.value.as_slice())
        .unwrap_or(&[]);

    // Transcript bound: label + 2 nonces + identity fields < 400B < 512.
    // Overflow is a hard error, not truncation.
    let mut transcript: HVec<u8, 512> = HVec::new();
    let mut push = |bytes: &[u8]| -> Result<(), HandshakeError> {
        transcript.extend_from_slice(bytes).map_err(|_| {
            HandshakeError::TranscriptOverflow(
                "guest proof transcript exceeds 512-byte capacity".into(),
            )
        })
    };
    push(b"pico.guest.bootstrap.v1|guest")?;
    push(host_nonce)?;
    push(guest_nonce)?;
    push(guest_hello.agent_version.as_bytes())?;
    push(guest_hello.boot_id.as_bytes())?;
    push(guest_hello.image_id.as_bytes())?;
    push(guest_hello.image_digest.as_bytes())?;

    Ok(crypto::blake3_mac(shared_secret, &transcript))
}

/// Computes the host proof MAC bound into the HostReply.
///
/// Fails with [`HandshakeError::TranscriptOverflow`] when the transcript
/// would exceed its 512-byte capacity rather than silently truncating.
pub fn compute_host_proof(
    shared_secret: &[u8],
    host_nonce: &[u8],
    guest_hello: &GuestHello,
    session_id: &[u8],
    policy_epoch: u64,
    selected_version: (u32, u32),
    selected_capabilities: &[String],
) -> Result<HVec<u8, 32>, HandshakeError> {
    let guest_nonce = guest_hello
        .guest_nonce
        .as_ref()
        .map(|n| n.value.as_slice())
        .unwrap_or(&[]);

    // Transcript bound: label + 2 nonces + session id + epoch + versions
    // + identity + capabilities < 400B < 512.
    // Overflow is a hard error, not truncation.
    let mut transcript: HVec<u8, 512> = HVec::new();
    let mut push = |bytes: &[u8]| -> Result<(), HandshakeError> {
        transcript.extend_from_slice(bytes).map_err(|_| {
            HandshakeError::TranscriptOverflow(
                "host proof transcript exceeds 512-byte capacity".into(),
            )
        })
    };
    push(b"pico.guest.bootstrap.v1|host")?;
    push(host_nonce)?;
    push(guest_nonce)?;
    push(guest_hello.agent_version.as_bytes())?;
    push(guest_hello.boot_id.as_bytes())?;
    push(session_id)?;
    push(&policy_epoch.to_be_bytes())?;
    push(&selected_version.0.to_be_bytes())?;
    push(&selected_version.1.to_be_bytes())?;
    for cap in selected_capabilities {
        push(cap.as_bytes())?;
        push(&[0u8])?;
    }

    Ok(crypto::blake3_mac(shared_secret, &transcript))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HandshakeConfig {
        HandshakeConfig {
            sandbox_id: "sbx_test".into(),
            image_id: "img_test".into(),
            image_digest: "digest".into(),
            host_capabilities: vec!["exec".into(), "file".into(), "stats".into()],
            ..Default::default()
        }
    }

    fn version_range(maj_lo: u32, min_lo: u32, maj_hi: u32, min_hi: u32) -> VersionRange {
        VersionRange {
            min: Some(Version {
                major: maj_lo,
                minor: min_lo,
            }),
            max: Some(Version {
                major: maj_hi,
                minor: min_hi,
            }),
        }
    }

    fn valid_guest_hello(sandbox_id: &str, host_nonce: &[u8]) -> GuestHello {
        let shared_secret = crypto::derive_handshake_shared_secret(sandbox_id);
        let mut hello = GuestHello {
            supported_versions: vec![version_range(1, 0, 1, 5)],
            guest_capabilities: Some(CapabilitySet {
                identifiers: vec!["exec".into(), "file".into()],
            }),
            guest_nonce: Some(Nonce {
                value: crypto::generate_nonce().to_vec(),
            }),
            agent_version: "test-agent".into(),
            boot_id: "boot-1".into(),
            image_id: "img_test".into(),
            image_digest: "digest".into(),
            proof: None,
        };
        let proof =
            compute_guest_proof(&shared_secret, host_nonce, &hello).expect("transcript fits");
        hello.proof = Some(Proof {
            value: proof.to_vec(),
        });
        hello
    }

    // ── Version negotiation ─────────────────────────────────────────

    #[test]
    fn version_intersection_exact_match() {
        let result =
            find_version_intersection(&version_range(1, 0, 1, 5), &[version_range(1, 0, 1, 5)]);
        assert_eq!(result, Some((1, 5)));
    }

    #[test]
    fn version_intersection_overlap_prefers_highest_common() {
        let result =
            find_version_intersection(&version_range(1, 0, 1, 5), &[version_range(1, 3, 1, 9)]);
        assert_eq!(result, Some((1, 5)));
    }

    #[test]
    fn version_intersection_no_overlap_major() {
        assert_eq!(
            find_version_intersection(&version_range(1, 0, 1, 5), &[version_range(2, 0, 2, 3)]),
            None
        );
        assert_eq!(
            find_version_intersection(&version_range(1, 5, 1, 10), &[version_range(1, 0, 1, 4)]),
            None
        );
    }

    #[test]
    fn negotiate_picks_best_of_multiple_guest_ranges() {
        let config = test_config();
        // Guest offers two disjoint ranges; host max is 1.5, so the lower
        // range's ceiling wins.
        let guest_ranges = vec![version_range(1, 0, 1, 3), version_range(1, 6, 1, 9)];
        let negotiated = negotiate_version_and_capabilities(
            &config,
            &guest_ranges,
            Some(&CapabilitySet {
                identifiers: vec!["exec".into()],
            }),
        )
        .expect("negotiation succeeds");
        assert_eq!(negotiated.version.0, 1);
        assert!(negotiated.version.1 <= 5);
    }

    #[test]
    fn negotiate_no_common_version_errors() {
        let config = test_config();
        let err = negotiate_version_and_capabilities(&config, &[version_range(2, 0, 2, 3)], None)
            .expect_err("no common version must fail");
        assert!(matches!(err, HandshakeError::VersionMismatch { .. }));
    }

    // ── Capability negotiation ──────────────────────────────────────

    #[test]
    fn capability_intersection_computed() {
        let config = HandshakeConfig {
            host_capabilities: vec!["exec".into(), "file".into()],
            ..test_config()
        };
        let negotiated = negotiate_version_and_capabilities(
            &config,
            &[version_range(1, 0, 1, 5)],
            Some(&CapabilitySet {
                identifiers: vec!["exec".into(), "stats".into()],
            }),
        )
        .expect("negotiation succeeds");
        assert_eq!(negotiated.capabilities, vec!["exec"]);
    }

    #[test]
    fn capability_empty_intersection_rejected() {
        let config = test_config();
        let err = negotiate_version_and_capabilities(
            &config,
            &[version_range(1, 0, 1, 5)],
            Some(&CapabilitySet {
                identifiers: vec!["nonexistent".into()],
            }),
        )
        .expect_err("empty capability intersection must fail");
        assert!(matches!(err, HandshakeError::CapabilityMismatch { .. }));
    }

    #[test]
    fn capability_missing_guest_set_rejected() {
        let config = test_config();
        let err = negotiate_version_and_capabilities(&config, &[version_range(1, 0, 1, 5)], None)
            .expect_err("missing guest capabilities must fail");
        assert!(matches!(err, HandshakeError::CapabilityMismatch { .. }));
    }

    // ── Identity & proof validation ─────────────────────────────────

    #[test]
    fn validate_accepts_well_formed_guest_hello() {
        let config = test_config();
        let host_nonce = crypto::generate_nonce();
        let hello = valid_guest_hello(&config.sandbox_id, &host_nonce);
        let shared_secret = crypto::derive_handshake_shared_secret(&config.sandbox_id);
        validate_guest_hello(&config, &hello, &shared_secret, &host_nonce)
            .expect("valid guest hello accepted");
    }

    #[test]
    fn validate_rejects_wrong_image_id() {
        let config = test_config();
        let host_nonce = crypto::generate_nonce();
        let mut hello = valid_guest_hello(&config.sandbox_id, &host_nonce);
        hello.image_id = "img_other".into();
        let shared_secret = crypto::derive_handshake_shared_secret(&config.sandbox_id);
        let err = validate_guest_hello(&config, &hello, &shared_secret, &host_nonce)
            .expect_err("image_id mismatch must fail");
        assert!(matches!(
            err,
            HandshakeError::IdentityMismatch { ref field, .. } if field == "image_id"
        ));
    }

    #[test]
    fn validate_rejects_wrong_image_digest_when_pinned() {
        let config = test_config();
        let host_nonce = crypto::generate_nonce();
        let mut hello = valid_guest_hello(&config.sandbox_id, &host_nonce);
        hello.image_digest = "other-digest".into();
        let shared_secret = crypto::derive_handshake_shared_secret(&config.sandbox_id);
        let err = validate_guest_hello(&config, &hello, &shared_secret, &host_nonce)
            .expect_err("image_digest mismatch must fail");
        assert!(matches!(
            err,
            HandshakeError::IdentityMismatch { ref field, .. } if field == "image_digest"
        ));
    }

    #[test]
    fn validate_skips_identity_when_expectations_empty() {
        // Test/restore transports may not pin image identity; the check
        // must be skipped rather than fail against an arbitrary guest claim.
        let config = HandshakeConfig {
            image_id: String::new(),
            image_digest: String::new(),
            sandbox_id: "sbx_test".into(),
            host_capabilities: vec!["exec".into()],
            ..Default::default()
        };
        let host_nonce = crypto::generate_nonce();
        let mut hello = valid_guest_hello(&config.sandbox_id, &host_nonce);
        hello.image_id = "git-image-id-the-host-never-pinned".into();
        hello.image_digest = "sha256:unpinned".into();
        // Recompute the proof over the mutated identity: the transcript
        // binds image_id/digest, so the guest must re-sign here regardless
        // of the host's (unpinned) expectation.
        let shared_secret = crypto::derive_handshake_shared_secret(&config.sandbox_id);
        let proof =
            compute_guest_proof(&shared_secret, &host_nonce, &hello).expect("transcript fits");
        hello.proof = Some(Proof {
            value: proof.to_vec(),
        });
        validate_guest_hello(&config, &hello, &shared_secret, &host_nonce)
            .expect("empty expectations skip identity validation");
    }

    #[test]
    fn validate_rejects_empty_supported_versions() {
        let config = test_config();
        let host_nonce = crypto::generate_nonce();
        let mut hello = valid_guest_hello(&config.sandbox_id, &host_nonce);
        hello.supported_versions = vec![];
        let shared_secret = crypto::derive_handshake_shared_secret(&config.sandbox_id);
        let err = validate_guest_hello(&config, &hello, &shared_secret, &host_nonce)
            .expect_err("empty supported_versions must fail");
        assert!(matches!(err, HandshakeError::VersionMismatch { .. }));
    }

    #[test]
    fn validate_rejects_tampered_proof() {
        let config = test_config();
        let host_nonce = crypto::generate_nonce();
        let mut hello = valid_guest_hello(&config.sandbox_id, &host_nonce);
        if let Some(proof) = hello.proof.as_mut() {
            // Flip a bit in the proof without touching the transcript fields.
            proof.value[0] ^= 0xFF;
        }
        let shared_secret = crypto::derive_handshake_shared_secret(&config.sandbox_id);
        let err = validate_guest_hello(&config, &hello, &shared_secret, &host_nonce)
            .expect_err("tampered proof must fail");
        assert!(matches!(
            err,
            HandshakeError::ProofVerificationFailed { ref role } if role == "guest"
        ));
    }

    #[test]
    fn validate_rejects_proof_for_wrong_sandbox_secret() {
        let config = test_config();
        let host_nonce = crypto::generate_nonce();
        // Proof computed with a different sandbox's secret.
        let wrong_secret = crypto::derive_handshake_shared_secret("sbx_other");
        let mut hello = GuestHello {
            supported_versions: vec![version_range(1, 0, 1, 5)],
            image_id: config.image_id.clone(),
            image_digest: config.image_digest.clone(),
            ..Default::default()
        };
        let proof =
            compute_guest_proof(&wrong_secret, &host_nonce, &hello).expect("transcript fits");
        hello.proof = Some(Proof {
            value: proof.to_vec(),
        });
        let shared_secret = crypto::derive_handshake_shared_secret(&config.sandbox_id);
        let err = validate_guest_hello(&config, &hello, &shared_secret, &host_nonce)
            .expect_err("proof under wrong secret must fail");
        assert!(matches!(
            err,
            HandshakeError::ProofVerificationFailed { .. }
        ));
    }

    // ── Message construction ────────────────────────────────────────

    #[test]
    fn host_hello_declares_protocol_and_versions() {
        let config = test_config();
        let hello = build_host_hello(&config, &crypto::generate_nonce());
        assert_eq!(hello.protocol_name, "pico.guest");
        assert_eq!(hello.supported_versions.len(), 1);
        assert_eq!(hello.sandbox_id, config.sandbox_id);
        assert!(hello.host_nonce.is_some());
    }

    #[test]
    fn host_and_guest_proofs_are_deterministic_and_role_distinct() {
        let shared_secret = crypto::derive_handshake_shared_secret("sbx_test");
        let host_nonce = crypto::generate_nonce();
        let hello = valid_guest_hello("sbx_test", &host_nonce);
        let session_id = crypto::generate_session_id();

        let g1 = compute_guest_proof(&shared_secret, &host_nonce, &hello).expect("transcript fits");
        let g2 = compute_guest_proof(&shared_secret, &host_nonce, &hello).expect("transcript fits");
        assert_eq!(g1, g2, "guest proof must be deterministic");

        let h1 = compute_host_proof(
            &shared_secret,
            &host_nonce,
            &hello,
            &session_id,
            1,
            (1, 5),
            &["exec".into()],
        )
        .expect("transcript fits");
        let h2 = compute_host_proof(
            &shared_secret,
            &host_nonce,
            &hello,
            &session_id,
            1,
            (1, 5),
            &["exec".into()],
        )
        .expect("transcript fits");
        assert_eq!(h1, h2, "host proof must be deterministic");
        assert_ne!(g1, h1, "role separators must yield distinct proofs");
    }

    #[test]
    fn guest_proof_overflow_fails_closed() {
        // A guest hello with absurdly large identity fields must not be
        // silently truncated into a valid-looking transcript.
        let shared_secret = crypto::derive_handshake_shared_secret("sbx_test");
        let host_nonce = crypto::generate_nonce();
        let hello = GuestHello {
            agent_version: "x".repeat(600),
            ..valid_guest_hello("sbx_test", &host_nonce)
        };

        let err = compute_guest_proof(&shared_secret, &host_nonce, &hello)
            .expect_err("oversized transcript must fail");
        assert!(matches!(err, HandshakeError::TranscriptOverflow(_)));
    }

    #[test]
    fn host_proof_overflow_fails_closed() {
        let shared_secret = crypto::derive_handshake_shared_secret("sbx_test");
        let host_nonce = crypto::generate_nonce();
        let hello = valid_guest_hello("sbx_test", &host_nonce);
        let session_id = crypto::generate_session_id();
        let many_caps: Vec<String> = (0..200).map(|i| format!("capability-{i}")).collect();

        let err = compute_host_proof(
            &shared_secret,
            &host_nonce,
            &hello,
            &session_id,
            1,
            (1, 5),
            &many_caps,
        )
        .expect_err("oversized transcript must fail");
        assert!(matches!(err, HandshakeError::TranscriptOverflow(_)));
    }
}
