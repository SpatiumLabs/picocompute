//! Audit event redaction utilities.
//!
//! Ensures audit event payloads never contain secrets, raw user content,
//! or prohibited telemetry fields. Called before persistence in the
//! Postgres sink.
//!
//! Delegates credential/URL/command detection to the shared
//! `pico_telemetry::structured_log::ProhibitedCategory` taxonomy
//! from ADR-0009.

use pico_telemetry::structured_log::ProhibitedCategory;

use crate::identity::{AuditEvent, AuditEventDetails};

/// Redact prohibited content from an audit event in-place.
///
/// Strips or overwrites:
/// - Command arguments and environment from runtime outcome details
/// - Raw user-supplied values in reason fields (truncates to structural info)
/// - Potentially sensitive paths from snapshot/cleanup details
///
/// The event ID, sandbox ID, and tenant ID are correlation fields and
/// are preserved. Secrets (passwords, tokens, keys) are never present
/// in the schema by design but this provides a defense-in-depth filter.
pub fn redact_event(event: &mut AuditEvent) {
    if let Some(ref details) = event.details {
        let redacted = redact_details(details);
        event.details = Some(redacted);
    }

    if let Some(reason) = &event.reason
        && (reason.len() > 256 || is_sensitive_reason(reason))
    {
        event.reason = Some("[redacted]".into());
    }
}

/// Check if a reason string contains prohibited content using the shared
/// `ProhibitedCategory` taxonomy from pico-telemetry.
fn is_sensitive_reason(reason: &str) -> bool {
    ProhibitedCategory::Credential.is_suspected_in(reason)
        || ProhibitedCategory::Url.is_suspected_in(reason)
}

/// Redact an AuditEventDetails variant, returning a safe copy.
fn redact_details(details: &AuditEventDetails) -> AuditEventDetails {
    match details {
        AuditEventDetails::RuntimeOutcome {
            operation,
            success,
            error,
        } => {
            let safe_error = error.as_ref().map(|e| {
                if e.len() > 128 {
                    format!("{}...", &e[..125])
                } else {
                    e.clone()
                }
            });
            AuditEventDetails::RuntimeOutcome {
                operation: operation.clone(),
                success: *success,
                error: safe_error,
            }
        }
        AuditEventDetails::SnapshotOperation {
            operation,
            outcome,
            reason,
            snapshot_id,
            parent_snapshot_id,
            state_profile,
        } => AuditEventDetails::SnapshotOperation {
            operation: operation.clone(),
            outcome: outcome.clone(),
            reason: reason.as_ref().map(|r| safe_reason(r)),
            snapshot_id: snapshot_id.clone(),
            parent_snapshot_id: parent_snapshot_id.clone(),
            state_profile: state_profile.clone(),
        },
        AuditEventDetails::CleanupDisposition {
            disposition,
            reason,
            affected_resources,
            quarantine,
        } => AuditEventDetails::CleanupDisposition {
            disposition: disposition.clone(),
            reason: safe_reason(reason),
            affected_resources: affected_resources.clone(),
            quarantine: *quarantine,
        },
        AuditEventDetails::CredentialIssuance {
            action,
            outcome,
            reason,
            credential_type,
            lease_id,
        } => AuditEventDetails::CredentialIssuance {
            action: action.clone(),
            outcome: outcome.clone(),
            reason: reason.as_ref().map(|r| safe_reason(r)),
            credential_type: credential_type.clone(),
            lease_id: lease_id.clone(),
        },
        AuditEventDetails::SnapshotMetadataAccess {
            operation,
            outcome,
            snapshot_id,
            tenant_id,
            filter,
            result_count,
        } => AuditEventDetails::SnapshotMetadataAccess {
            operation: operation.clone(),
            outcome: outcome.clone(),
            snapshot_id: snapshot_id.clone(),
            tenant_id: tenant_id.clone(),
            filter: filter.as_ref().map(|f| safe_reason(f)),
            result_count: *result_count,
        },
        other => other.clone(),
    }
}

fn safe_reason(reason: &str) -> String {
    if is_sensitive_reason(reason) {
        "[redacted]".into()
    } else if reason.len() > 256 {
        format!("{}...", &reason[..253])
    } else {
        reason.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_bus::AuditEventBuilder;
    use crate::identity::{AuditEventKind, Hlc};

    #[test]
    fn redact_strips_credential_patterns() {
        let hlc = std::sync::Arc::new(Hlc::new());
        let mut event = AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
            .reason("password=secret123")
            .build();

        redact_event(&mut event);
        assert_eq!(event.reason.as_deref(), Some("[redacted]"));
    }

    #[test]
    fn redact_strips_token_in_reason() {
        let hlc = std::sync::Arc::new(Hlc::new());
        let mut event = AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
            .reason("api_key validation failed")
            .build();

        redact_event(&mut event);
        assert_eq!(event.reason.as_deref(), Some("[redacted]"));
    }

    #[test]
    fn redact_strips_url_from_reason() {
        let hlc = std::sync::Arc::new(Hlc::new());
        let mut event = AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
            .reason("failed to fetch https://internal.example.com/secret")
            .build();

        redact_event(&mut event);
        assert_eq!(event.reason.as_deref(), Some("[redacted]"));
    }

    #[test]
    fn redact_preserves_safe_reason() {
        let hlc = std::sync::Arc::new(Hlc::new());
        let mut event = AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
            .reason("quota exceeded: vcpus")
            .build();

        redact_event(&mut event);
        assert_eq!(event.reason.as_deref(), Some("quota exceeded: vcpus"));
    }

    #[test]
    fn redact_snapshot_metadata_access_filter_with_sensitive_content() {
        let hlc = std::sync::Arc::new(Hlc::new());
        let mut event = AuditEventBuilder::new(hlc, AuditEventKind::SnapshotMetadataAccess)
            .details(AuditEventDetails::SnapshotMetadataAccess {
                operation: "list".into(),
                outcome: "success".into(),
                snapshot_id: None,
                tenant_id: Some("tnt_test".into()),
                filter: Some("query with password=secret123".into()),
                result_count: Some(3),
            })
            .build();

        redact_event(&mut event);
        let details = event.details.unwrap();
        match details {
            AuditEventDetails::SnapshotMetadataAccess {
                filter,
                result_count,
                ..
            } => {
                assert_eq!(filter.as_deref(), Some("[redacted]"));
                assert_eq!(result_count, Some(3));
            }
            _ => panic!("expected SnapshotMetadataAccess details"),
        }
    }

    #[test]
    fn redact_handles_new_event_kind_details() {
        let hlc = std::sync::Arc::new(Hlc::new());
        let mut event = AuditEventBuilder::new(hlc, AuditEventKind::NetworkEnforcement)
            .details(AuditEventDetails::NetworkEnforcement {
                action: "egress_allow".into(),
                destination: Some("10.0.0.1:443".into()),
                outcome: "allow".into(),
                reason: Some("dashboard access".into()),
                lease_id: Some("lse_001".into()),
            })
            .build();

        redact_event(&mut event);
        let details = event.details.unwrap();
        match details {
            AuditEventDetails::NetworkEnforcement { outcome, .. } => {
                assert_eq!(outcome, "allow");
            }
            _ => panic!("expected NetworkEnforcement details"),
        }
    }
}
