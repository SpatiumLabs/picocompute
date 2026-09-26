//! Guest-side handshake protocol implementation.
//!
//! Implements the PicoCompute bootstrap handshake from the guest's
//! perspective. The guest agent listens for a HostHello, responds
//! with a GuestHello, validates the HostReply, and returns a
//! HandshakeResult. Operations after a successful handshake are
//! scoped to the established session.

use heapless::Vec as HVec;

use pico_core::crypto;
use pico_guest_protocol::bootstrap_v1::*;

const PROTOCOL_NAME: &str = "pico.guest";
const BOOTSTRAP_VERSION_MAJOR: u32 = 1;
const BOOTSTRAP_VERSION_MINOR: u32 = 0;
const OPERATIONAL_VERSION_MAJOR: u32 = 1;
const OPERATIONAL_VERSION_MINOR_MIN: u32 = 0;
const OPERATIONAL_VERSION_MINOR_MAX: u32 = 5;
const HANDSHAKE_READ_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub(crate) struct GuestIdentity {
    pub image_id: String,
    pub image_digest: String,
    pub agent_version: String,
    pub boot_id: String,
    pub capabilities: Vec<String>,
}

impl GuestIdentity {
    pub(crate) fn validated_image_id(&self) -> Option<&str> {
        if self.image_id.is_empty() {
            None
        } else {
            Some(&self.image_id)
        }
    }
}

impl Default for GuestIdentity {
    fn default() -> Self {
        Self {
            image_id: String::new(),
            image_digest: String::new(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
            boot_id: uuid::Uuid::new_v4().to_string(),
            capabilities: vec!["exec".into(), "stats".into(), "health".into()],
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct HandshakeOutcome {
    pub session_id: HVec<u8, 16>,
    pub policy_epoch: u64,
    pub selected_version: (u32, u32),
    pub selected_capabilities: Vec<String>,
}

pub(crate) async fn serve_handshake(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send),
    identity: &GuestIdentity,
    shared_secret: HVec<u8, 32>,
) -> std::io::Result<Option<HandshakeOutcome>> {
    let host_hello = read_message::<HostHello>(stream).await?;

    validate_host_hello(&host_hello)?;
    if let Some(id) = identity.validated_image_id()
        && host_hello.image_id != id
        && !host_hello.image_id.is_empty()
    {
        tracing::warn!(
            host_image_id = %host_hello.image_id,
            guest_image_id = %id,
            "host image_id mismatch with guest identity"
        );
    }

    let nonce = crypto::generate_nonce();
    let guest_hello = build_guest_hello(identity, &nonce, &shared_secret, &host_hello);

    tracing::info!(
        image_id = %identity.image_id,
        boot_id = %identity.boot_id,
        "received HostHello, sending GuestHello"
    );

    send_message(stream, &guest_hello).await?;

    let host_reply = read_message::<HostReply>(stream).await?;

    match validate_host_reply(&host_reply, &shared_secret, &host_hello, &guest_hello) {
        Ok(session_id) => {
            tracing::info!(
                session_id_len = session_id.len(),
                selected_version = ?host_reply.selected_version.as_ref().map(|v| (v.major, v.minor)),
                "handshake established from guest side"
            );

            let result = HandshakeResult {
                outcome: Some(handshake_result::Outcome::Established(true)),
            };
            send_message(stream, &result).await?;

            let selected_version = host_reply
                .selected_version
                .as_ref()
                .map(|v| (v.major, v.minor))
                .unwrap_or((1, 0));
            let selected_capabilities = host_reply
                .selected_capabilities
                .as_ref()
                .map(|c| c.identifiers.clone())
                .unwrap_or_default();

            Ok(Some(HandshakeOutcome {
                session_id,
                policy_epoch: host_reply.policy_epoch,
                selected_version,
                selected_capabilities,
            }))
        }
        Err(err) => {
            tracing::warn!("host reply validation failed: {err}");

            let result = HandshakeResult {
                outcome: Some(handshake_result::Outcome::Error(HandshakeError {
                    code: handshake_error::ErrorCode::AuthenticationFailed as i32,
                    message: err.to_string(),
                })),
            };
            let _ = send_message(stream, &result).await;
            Ok(None)
        }
    }
}

pub(crate) fn parse_sandbox_id_from_cmdline(cmdline: &str) -> Option<String> {
    for part in cmdline.split_whitespace() {
        if let Some(val) = part.strip_prefix("pico_sandbox_id=") {
            return Some(val.to_string());
        }
    }
    None
}

pub(crate) fn parse_manifest_json(json_str: &str) -> Option<GuestIdentity> {
    let parsed: serde_json::Value = serde_json::from_str(json_str).ok()?;
    Some(GuestIdentity {
        image_id: parsed.get("image_id")?.as_str()?.to_string(),
        image_digest: parsed
            .get("artifacts")?
            .get("guest_agent")?
            .get("digest")?
            .as_str()?
            .to_string(),
        agent_version: parsed
            .get("artifacts")?
            .get("guest_agent")?
            .get("version")?
            .as_str()
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
        boot_id: uuid::Uuid::new_v4().to_string(),
        capabilities: parsed
            .get("protocol")?
            .get("capabilities")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
    })
}

fn validate_host_hello(host_hello: &HostHello) -> std::io::Result<()> {
    if host_hello.protocol_name != PROTOCOL_NAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "protocol mismatch: expected {PROTOCOL_NAME}, got {}",
                host_hello.protocol_name
            ),
        ));
    }

    if let Some(ref range) = host_hello.bootstrap_version {
        let min_major = range.min.as_ref().map_or(0, |v| v.major);
        if min_major != BOOTSTRAP_VERSION_MAJOR {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "bootstrap version incompatible: host={min_major}.x, guest={BOOTSTRAP_VERSION_MAJOR}.{BOOTSTRAP_VERSION_MINOR}"
                ),
            ));
        }
    }

    Ok(())
}

fn build_guest_hello(
    identity: &GuestIdentity,
    nonce: &[u8],
    shared_secret: &[u8],
    host_hello: &HostHello,
) -> GuestHello {
    let host_nonce = host_hello
        .host_nonce
        .as_ref()
        .map(|n| n.value.as_slice())
        .unwrap_or(&[]);

    GuestHello {
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
        guest_capabilities: Some(CapabilitySet {
            identifiers: identity.capabilities.clone(),
        }),
        guest_nonce: Some(Nonce {
            value: nonce.to_vec(),
        }),
        agent_version: identity.agent_version.clone(),
        boot_id: identity.boot_id.clone(),
        image_id: identity.image_id.clone(),
        image_digest: identity.image_digest.clone(),
        proof: Some(Proof {
            value: compute_guest_proof(shared_secret, host_nonce, nonce, identity).to_vec(),
        }),
    }
}

fn validate_host_reply(
    host_reply: &HostReply,
    shared_secret: &[u8],
    host_hello: &HostHello,
    guest_hello: &GuestHello,
) -> std::io::Result<HVec<u8, 16>> {
    let session_id_raw = host_reply
        .session_id
        .as_ref()
        .map(|s| s.value.clone())
        .unwrap_or_default();

    let session_id = HVec::from_slice(&session_id_raw)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "session ID too long"))?;

    if session_id.len() < 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "session ID too short",
        ));
    }

    let selected_version = host_reply
        .selected_version
        .as_ref()
        .map(|v| (v.major, v.minor))
        .unwrap_or((1, 0));
    let selected_capabilities = host_reply
        .selected_capabilities
        .as_ref()
        .map(|c| c.identifiers.clone())
        .unwrap_or_default();

    let expected_proof = compute_host_proof(
        shared_secret,
        host_hello,
        guest_hello,
        &session_id,
        host_reply.policy_epoch,
        selected_version,
        &selected_capabilities,
    );

    let proof_bytes = host_reply
        .proof
        .as_ref()
        .map(|p| p.value.as_slice())
        .unwrap_or(&[]);

    if !crypto::constant_time_eq(proof_bytes, &expected_proof) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HMAC proof verification failed for host role",
        ));
    }

    Ok(session_id)
}

fn compute_guest_proof(
    shared_secret: &[u8],
    host_nonce: &[u8],
    guest_nonce: &[u8],
    identity: &GuestIdentity,
) -> HVec<u8, 32> {
    // Transcript bound: 31B(label) + 32Bx2(nonces) + ~128B(identity fields) < 400B < 512
    let mut transcript: HVec<u8, 512> = HVec::new();
    transcript
        .extend_from_slice(b"pico.guest.bootstrap.v1|guest")
        .ok();
    transcript.extend_from_slice(host_nonce).ok();
    transcript.extend_from_slice(guest_nonce).ok();
    transcript
        .extend_from_slice(identity.agent_version.as_bytes())
        .ok();
    transcript
        .extend_from_slice(identity.boot_id.as_bytes())
        .ok();
    transcript
        .extend_from_slice(identity.image_id.as_bytes())
        .ok();
    transcript
        .extend_from_slice(identity.image_digest.as_bytes())
        .ok();

    crypto::blake3_mac(shared_secret, &transcript)
}

fn compute_host_proof(
    shared_secret: &[u8],
    host_hello: &HostHello,
    guest_hello: &GuestHello,
    session_id: &[u8],
    policy_epoch: u64,
    selected_version: (u32, u32),
    selected_capabilities: &[String],
) -> HVec<u8, 32> {
    let host_nonce = host_hello
        .host_nonce
        .as_ref()
        .map(|n| n.value.as_slice())
        .unwrap_or(&[]);
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

async fn send_message(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin + Send),
    message: &impl prost::Message,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let encoded = message.encode_to_vec();
    let len = encoded.len() as u32;
    let mut framed = Vec::with_capacity(4 + encoded.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&encoded);

    stream.write_all(&framed).await
}

async fn read_message<T: prost::Message + Default>(
    stream: &mut (impl tokio::io::AsyncRead + Unpin + Send),
) -> std::io::Result<T> {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    let timeout = Duration::from_secs(HANDSHAKE_READ_TIMEOUT_SECS);

    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "read length timed out")
        })??;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes"),
        ));
    }

    let mut payload = vec![0u8; len];
    tokio::time::timeout(timeout, stream.read_exact(&mut payload))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "read payload timed out")
        })??;

    T::decode(payload.as_slice())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_shared_secret_is_stable() {
        let s1 = crypto::derive_handshake_shared_secret("sbx_test");
        let s2 = crypto::derive_handshake_shared_secret("sbx_test");
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 32);
    }

    #[test]
    fn parse_sandbox_id_from_cmdline_finds_value() {
        let cmdline = "console=ttyS0 pico_sandbox_id=sbx_01JXYZ root=/dev/vda";
        assert_eq!(
            parse_sandbox_id_from_cmdline(cmdline),
            Some("sbx_01JXYZ".into())
        );
    }

    #[test]
    fn parse_sandbox_id_from_cmdline_returns_none() {
        let cmdline = "console=ttyS0 root=/dev/vda";
        assert_eq!(parse_sandbox_id_from_cmdline(cmdline), None);
    }

    #[test]
    fn validate_host_hello_accepts_correct_protocol() {
        let hello = HostHello {
            protocol_name: "pico.guest".into(),
            bootstrap_version: Some(VersionRange {
                min: Some(Version { major: 1, minor: 0 }),
                max: Some(Version { major: 1, minor: 0 }),
            }),
            ..Default::default()
        };
        assert!(validate_host_hello(&hello).is_ok());
    }

    #[test]
    fn validate_host_hello_rejects_wrong_protocol() {
        let hello = HostHello {
            protocol_name: "wrong.protocol".into(),
            ..Default::default()
        };
        assert!(validate_host_hello(&hello).is_err());
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(crypto::constant_time_eq(b"hello", b"hello"));
        assert!(!crypto::constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn parse_manifest_json_extracts_correct_fields() {
        let json = r#"{
            "schema_version": "1",
            "image_id": "test-image-abc123",
            "artifacts": {
                "guest_agent": {
                    "digest": "sha256:def456",
                    "version": "0.3.0"
                }
            },
            "protocol": {
                "bootstrap": "pico.guest.bootstrap.v1",
                "supported": [{"major":1,"min_minor":0,"max_minor":5}],
                "capabilities": ["exec", "stats", "health"]
            }
        }"#;
        let identity = parse_manifest_json(json).unwrap();
        assert_eq!(identity.image_id, "test-image-abc123");
        assert_eq!(identity.image_digest, "sha256:def456");
        assert_eq!(identity.agent_version, "0.3.0");
        assert_eq!(identity.capabilities, vec!["exec", "stats", "health"]);
    }
}
