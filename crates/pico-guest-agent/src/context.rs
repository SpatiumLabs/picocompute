//! Single `RequestContext` validator for the guest agent.
//!
//! Every operational handler validates the request context through this
//! module so binding semantics cannot drift between handlers. The strict
//! validator rejects any sandbox/session/epoch/version mismatch before side
//! effects. The resume validator shares the same field comparators but
//! allows a zero `policy_epoch` (proto3 default for peers that do not carry
//! an epoch claim) and leaves body-carried identity updates to the caller.
//!
//! Resume keeps different semantics from strict validation because after
//! snapshot restore or fork the host may authorize a sandbox/policy update
//! via the `ResumeNotifyRequest` body, whereas strict validation rejects any
//! mismatch. Only `session_id` and `protocol_version` are immutable
//! connection bindings in both modes.

use std::sync::atomic::Ordering;

use pico_guest_protocol::operational_v1::RequestContext;
use thiserror::Error;

use crate::exec::OperationalSession;

/// Typed context validation failure.
///
/// Messages preserve the `sandbox_id`/`session_id`/`policy_epoch`/
/// `protocol_version` substrings asserted by existing session tests.
#[expect(
    clippy::enum_variant_names,
    reason = "Mismatch suffix is domain language for binding checks"
)]
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub(crate) enum ContextError {
    #[error("sandbox_id mismatch: expected '{expected}', got '{got}'")]
    SandboxMismatch { expected: String, got: String },

    #[error("session_id mismatch")]
    SessionMismatch,

    #[error("policy_epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    #[error("protocol_version mismatch: expected {expected:?}, got {got:?}")]
    VersionMismatch {
        expected: (u32, u32),
        got: (u32, u32),
    },
}

/// Unpack the protobuf `protocol_version` (`(major << 16) | minor`).
pub(crate) fn unpack_version(packed: u32) -> (u32, u32) {
    (packed >> 16, packed & 0xFFFF)
}

fn check_sandbox_id(expected: &str, got: &str) -> Result<(), ContextError> {
    if expected != got {
        return Err(ContextError::SandboxMismatch {
            expected: expected.to_string(),
            got: got.to_string(),
        });
    }
    Ok(())
}

fn check_session_id(expected: &[u8], got: &[u8]) -> Result<(), ContextError> {
    if expected != got {
        return Err(ContextError::SessionMismatch);
    }
    Ok(())
}

fn check_policy_epoch(expected: u64, got: u64) -> Result<(), ContextError> {
    if expected != got {
        return Err(ContextError::EpochMismatch { expected, got });
    }
    Ok(())
}

fn check_protocol_version(expected: (u32, u32), got_packed: u32) -> Result<(), ContextError> {
    let got = unpack_version(got_packed);
    if expected != got {
        return Err(ContextError::VersionMismatch { expected, got });
    }
    Ok(())
}

/// Strict validation: every binding must match the authenticated session.
///
/// Used by all operational handlers before side effects.
pub(crate) fn validate_strict(
    session: &OperationalSession,
    ctx: &RequestContext,
) -> Result<(), ContextError> {
    check_sandbox_id(&session.sandbox_id.lock(), &ctx.sandbox_id)?;
    check_session_id(session.session_id.as_slice(), &ctx.session_id)?;
    check_policy_epoch(
        session.policy_epoch.load(Ordering::Acquire),
        ctx.policy_epoch,
    )?;
    check_protocol_version(session.protocol_version, ctx.protocol_version)?;
    Ok(())
}

/// Resume-context validation: immutable bindings plus current identity.
///
/// Shares the field comparators above so strict and resume checks cannot
/// drift. Differences from [`validate_strict`] are intentional and limited:
/// - `policy_epoch == 0` means "no epoch claim" and skips the epoch check
///   (proto3 default for older peers); any non-zero epoch must match.
/// - body-carried updates (`request.sandbox_id`, `request.policy_epoch`)
///   are applied by the caller after this check passes.
pub(crate) fn validate_resume_context(
    session: &OperationalSession,
    ctx: &RequestContext,
) -> Result<(), ContextError> {
    check_session_id(session.session_id.as_slice(), &ctx.session_id)?;
    check_protocol_version(session.protocol_version, ctx.protocol_version)?;
    check_sandbox_id(&session.sandbox_id.lock(), &ctx.sandbox_id)?;
    if ctx.policy_epoch != 0 {
        check_policy_epoch(
            session.policy_epoch.load(Ordering::Acquire),
            ctx.policy_epoch,
        )?;
    }
    Ok(())
}

/// Map a [`ContextError`] to the resume-notify failure code used on the wire.
///
/// Keeps the per-field codes (`SessionMismatch`, `ProtocolVersionMismatch`,
/// `SandboxIdMismatch`, `PolicyEpochMismatch`) in one place next to the
/// single validator.
pub(crate) fn resume_error_code(err: &ContextError) -> &'static str {
    match err {
        ContextError::SessionMismatch => "SessionMismatch",
        ContextError::VersionMismatch { .. } => "ProtocolVersionMismatch",
        ContextError::SandboxMismatch { .. } => "SandboxIdMismatch",
        ContextError::EpochMismatch { .. } => "PolicyEpochMismatch",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::OperationalSession;
    use crate::handshake::HandshakeOutcome;
    use heapless::Vec as HVec;

    fn make_session() -> OperationalSession {
        let outcome = HandshakeOutcome {
            session_id: HVec::from_slice(b"test-session").unwrap(),
            policy_epoch: 1,
            selected_version: (1, 0),
            selected_capabilities: vec!["exec".into()],
        };
        OperationalSession::new(&outcome, "sbx-a".into())
    }

    fn valid_ctx() -> RequestContext {
        RequestContext {
            sandbox_id: "sbx-a".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0001_0000,
            ..Default::default()
        }
    }

    #[test]
    fn strict_accepts_matching_context() {
        let session = make_session();
        assert!(validate_strict(&session, &valid_ctx()).is_ok());
    }

    #[test]
    fn strict_rejects_each_binding() {
        let session = make_session();

        let mut ctx = valid_ctx();
        ctx.sandbox_id = "sbx-b".into();
        let err = validate_strict(&session, &ctx).unwrap_err();
        assert!(err.to_string().contains("sandbox_id"));

        let mut ctx = valid_ctx();
        ctx.session_id = b"wrong".to_vec();
        let err = validate_strict(&session, &ctx).unwrap_err();
        assert!(err.to_string().contains("session_id"));

        let mut ctx = valid_ctx();
        ctx.policy_epoch = 99;
        let err = validate_strict(&session, &ctx).unwrap_err();
        assert!(err.to_string().contains("policy_epoch"));

        let mut ctx = valid_ctx();
        ctx.protocol_version = 0x0002_0000;
        let err = validate_strict(&session, &ctx).unwrap_err();
        assert!(err.to_string().contains("protocol_version"));
    }

    #[test]
    fn resume_shares_comparators_but_tolerates_zero_epoch() {
        let session = make_session();

        // Matching context passes both validators.
        assert!(validate_resume_context(&session, &valid_ctx()).is_ok());

        // Zero epoch skips the epoch check (resume-only policy).
        let mut ctx = valid_ctx();
        ctx.policy_epoch = 0;
        assert!(validate_resume_context(&session, &ctx).is_ok());
        assert!(validate_strict(&session, &ctx).is_err());

        // Non-zero mismatch still rejected with the same typed variant.
        let mut ctx = valid_ctx();
        ctx.policy_epoch = 99;
        let err = validate_resume_context(&session, &ctx).unwrap_err();
        assert_eq!(
            err,
            ContextError::EpochMismatch {
                expected: 1,
                got: 99
            }
        );
        assert_eq!(resume_error_code(&err), "PolicyEpochMismatch");
    }

    #[test]
    fn resume_error_codes_cover_all_variants() {
        assert_eq!(
            resume_error_code(&ContextError::SessionMismatch),
            "SessionMismatch"
        );
        assert_eq!(
            resume_error_code(&ContextError::SandboxMismatch {
                expected: "a".into(),
                got: "b".into()
            }),
            "SandboxIdMismatch"
        );
        assert_eq!(
            resume_error_code(&ContextError::VersionMismatch {
                expected: (1, 0),
                got: (2, 0)
            }),
            "ProtocolVersionMismatch"
        );
    }

    #[test]
    fn unpack_version_matches_wire_packing() {
        assert_eq!(unpack_version(0x0001_0000), (1, 0));
        assert_eq!(unpack_version((1 << 16) | 3), (1, 3));
    }
}
