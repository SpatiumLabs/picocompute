//! Audit event ordering utilities.

use crate::identity::AuditEvent;

/// Compares two audit events for chronological ordering.
///
/// Primary ordering is by HLC timestamp. If HLC timestamps are
/// equal (concurrent events from the same source), falls back to
/// the event id for deterministic tie-breaking.
pub fn compare_events(a: &AuditEvent, b: &AuditEvent) -> std::cmp::Ordering {
    match a.hlc_ts.compare(&b.hlc_ts) {
        std::cmp::Ordering::Equal => a.id.as_str().cmp(b.id.as_str()),
        ord => ord,
    }
}

/// Returns true if the events in a slice are in chronological order
/// (each event has an HLC timestamp >= the previous).
pub fn is_ordered_chronologically(events: &[AuditEvent]) -> bool {
    events.windows(2).all(|w| w[0].hlc_ts <= w[1].hlc_ts)
}

/// Validates that events for a given sandbox form a valid causal
/// chain: each event's HLC timestamp must be >= the previous
/// event's, and fencing tokens (if present) must be monotonic.
pub fn validate_causal_chain(events: &[AuditEvent]) -> Result<(), String> {
    for window in events.windows(2) {
        let prev = &window[0];
        let next = &window[1];

        if prev.sandbox_id != next.sandbox_id {
            return Err(format!(
                "sandbox id mismatch: {:?} vs {:?}",
                prev.sandbox_id, next.sandbox_id
            ));
        }

        if next.hlc_ts < prev.hlc_ts {
            return Err(format!(
                "hlc regression: {} -> {}",
                prev.hlc_ts, next.hlc_ts
            ));
        }

        if let (Some(pt), Some(nt)) = (prev.fencing_token, next.fencing_token)
            && nt < pt
        {
            return Err(format!("fencing token regression: {} -> {}", pt, nt));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AuditEventId, AuditEventKind, FencingToken, HlcTimestamp, SandboxId};

    fn make_event(id: &str, ms: i64, counter: u32) -> AuditEvent {
        AuditEvent {
            schema_version: crate::identity::AUDIT_SCHEMA_VERSION,
            id: AuditEventId::from_string(id),
            hlc_ts: HlcTimestamp {
                wall_time_ms: ms,
                logical_counter: counter,
            },
            kind: AuditEventKind::LifecycleTransition,
            sandbox_id: Some(SandboxId::from_string("sbx_test")),
            tenant_id: None,
            from_state: None,
            to_state: None,
            principal: None,
            service: None,
            operation_id: None,
            trace_id: None,
            idempotency_key: None,
            failure: None,
            details: None,
            recorded_at: "2026-01-01T00:00:00Z".into(),
            epoch: None,
            fencing_token: None,
            producer: None,
            request_id: None,
            action: None,
            outcome: None,
            reason: None,
            policy_decision_id: None,
            lease_id: None,
        }
    }

    fn make_event_with_fencing(id: &str, ms: i64, counter: u32, ft: FencingToken) -> AuditEvent {
        AuditEvent {
            schema_version: crate::identity::AUDIT_SCHEMA_VERSION,
            id: AuditEventId::from_string(id),
            hlc_ts: HlcTimestamp {
                wall_time_ms: ms,
                logical_counter: counter,
            },
            kind: AuditEventKind::LifecycleTransition,
            sandbox_id: Some(SandboxId::from_string("sbx_test")),
            tenant_id: None,
            from_state: None,
            to_state: None,
            principal: None,
            service: None,
            operation_id: None,
            trace_id: None,
            idempotency_key: None,
            failure: None,
            details: None,
            recorded_at: "2026-01-01T00:00:00Z".into(),
            epoch: None,
            fencing_token: Some(ft),
            producer: None,
            request_id: None,
            action: None,
            outcome: None,
            reason: None,
            policy_decision_id: None,
            lease_id: None,
        }
    }

    #[test]
    fn compare_events_orders_by_hlc() {
        let a = make_event("a", 1000, 0);
        let b = make_event("b", 1000, 1);
        let c = make_event("c", 2000, 0);

        assert!(compare_events(&a, &b) == std::cmp::Ordering::Less);
        assert!(compare_events(&b, &c) == std::cmp::Ordering::Less);
    }

    #[test]
    fn is_ordered_chronologically_detects_order() {
        let ordered = vec![
            make_event("a", 1000, 0),
            make_event("b", 1000, 1),
            make_event("c", 2000, 0),
        ];
        assert!(is_ordered_chronologically(&ordered));

        let unordered = vec![make_event("a", 2000, 0), make_event("b", 1000, 0)];
        assert!(!is_ordered_chronologically(&unordered));
    }

    #[test]
    fn validate_causal_chain_rejects_regression() {
        let valid = vec![
            make_event_with_fencing(
                "a",
                1000,
                0,
                FencingToken {
                    epoch: 1,
                    sequence: 0,
                },
            ),
            make_event_with_fencing(
                "b",
                1000,
                1,
                FencingToken {
                    epoch: 1,
                    sequence: 1,
                },
            ),
        ];
        assert!(validate_causal_chain(&valid).is_ok());

        let fencing_regression = vec![
            make_event_with_fencing(
                "a",
                1000,
                0,
                FencingToken {
                    epoch: 1,
                    sequence: 5,
                },
            ),
            make_event_with_fencing(
                "b",
                2000,
                0,
                FencingToken {
                    epoch: 1,
                    sequence: 3,
                },
            ),
        ];
        assert!(validate_causal_chain(&fencing_regression).is_err());

        let hlc_regression = vec![
            make_event_with_fencing(
                "a",
                2000,
                0,
                FencingToken {
                    epoch: 1,
                    sequence: 0,
                },
            ),
            make_event_with_fencing(
                "b",
                1000,
                0,
                FencingToken {
                    epoch: 1,
                    sequence: 1,
                },
            ),
        ];
        assert!(validate_causal_chain(&hlc_regression).is_err());
    }
}
