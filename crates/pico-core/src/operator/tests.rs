use super::*;
use crate::identity::FencingToken;

#[test]
fn ticket_accepts_incident_ids() {
    for ticket in ["INC-123", "INC-154", "SRE-2026-09-21#1", "incident 42"] {
        assert!(
            validate_ticket(ticket).is_ok(),
            "ticket {ticket:?} should pass"
        );
    }
}

#[test]
fn ticket_rejects_blank_and_placeholders() {
    assert_eq!(validate_ticket(""), Err(OperatorError::MissingTicket));
    assert_eq!(validate_ticket("   "), Err(OperatorError::MissingTicket));
    for placeholder in ["tbd", "TODO", "xxx", "none", "null", "test"] {
        assert!(
            validate_ticket(placeholder).is_err(),
            "placeholder {placeholder:?} should fail"
        );
    }
}

#[test]
fn ticket_rejects_bad_charset_and_length() {
    assert!(validate_ticket("ab").is_err());
    assert!(validate_ticket("INC-123; rm -rf").is_err());
    assert!(validate_ticket("INC-123$").is_err());
    let long = "x".repeat(129);
    assert!(validate_ticket(&long).is_err());
}

#[test]
fn parse_condition_accepts_all_five() {
    assert_eq!(
        parse_condition("repeated_runtime_outcomes"),
        Ok(AlertCondition::RepeatedRuntimeOutcomes)
    );
    assert_eq!(
        parse_condition("cleanup_or_reconciliation_issue"),
        Ok(AlertCondition::CleanupOrReconciliationIssue)
    );
    assert_eq!(
        parse_condition("stale_resources"),
        Ok(AlertCondition::StaleResources)
    );
    assert_eq!(
        parse_condition("capacity_reporting_staleness"),
        Ok(AlertCondition::CapacityReportingStaleness)
    );
    assert_eq!(
        parse_condition("resource_pressure"),
        Ok(AlertCondition::ResourcePressure)
    );
}

#[test]
fn parse_condition_rejects_unknown() {
    let err = parse_condition("runtime_failed").unwrap_err();
    assert!(matches!(err, OperatorError::UnknownCondition { .. }));
}

#[test]
fn acknowledge_needs_ticket_and_owner() {
    assert!(validate_acknowledge("INC-1", "sre-picocompute").is_ok());
    assert_eq!(
        validate_acknowledge("", "sre-picocompute").unwrap_err(),
        OperatorError::MissingTicket
    );
    assert_eq!(
        validate_acknowledge("INC-1", "").unwrap_err(),
        OperatorError::MissingOwner
    );
    assert_eq!(
        validate_acknowledge("INC-1", " ").unwrap_err(),
        OperatorError::MissingOwner
    );
    assert_eq!(
        validate_acknowledge("INC-1", "sre; rm").unwrap_err(),
        OperatorError::MissingOwner
    );
}

#[test]
fn resolve_needs_cleared_condition() {
    assert!(validate_resolve("INC-1", true).is_ok());
    assert_eq!(
        validate_resolve("INC-1", false).unwrap_err(),
        OperatorError::ConditionNotCleared
    );
    assert_eq!(
        validate_resolve("", true).unwrap_err(),
        OperatorError::MissingTicket
    );
}

#[test]
fn fenced_cleanup_needs_tokens() {
    let tokens = vec![FencingToken::new(42).next_sequence()];
    let evidence = validate_fenced_cleanup("INC-9", &tokens).expect("valid cleanup");
    assert_eq!(evidence.tokens.len(), 1);
    assert_eq!(
        validate_fenced_cleanup("INC-9", &[]).unwrap_err(),
        OperatorError::MissingFencingTokens
    );
    assert_eq!(
        validate_fenced_cleanup("", &tokens).unwrap_err(),
        OperatorError::MissingTicket
    );
}

#[test]
fn ledger_inspect_allows_read_only_queries() {
    for query in [
        "sandbox-status",
        "list-sandboxes",
        "list-receipts",
        "gc-stats",
        "findings",
    ] {
        let evidence = validate_ledger_inspect("INC-4", query).expect("read query passes");
        assert_eq!(evidence.query.as_str(), query);
    }
}

#[test]
fn ledger_inspect_rejects_writes() {
    for query in ["edit", "delete", "write", "rm", "gc --force-stale", ""] {
        let err = validate_ledger_inspect("INC-4", query).unwrap_err();
        assert!(
            matches!(err, OperatorError::ProhibitedLedgerQuery { .. }),
            "query {query:?} should be rejected"
        );
    }
}

#[test]
fn drain_needs_ticket() {
    assert!(validate_drain("INC-7").is_ok());
    assert_eq!(
        validate_drain("").unwrap_err(),
        OperatorError::MissingTicket
    );
}

fn passing_checks() -> ReadmitChecks {
    ReadmitChecks {
        quarantine_gauge_zero: true,
        capacity_age_secs: 12,
        health_admitting: true,
        reconciliation_clean: true,
        five_minute_watch_clean: true,
    }
}

#[test]
fn readmit_passes_when_all_gates_hold() {
    assert!(validate_readmit(&passing_checks()).is_ok());
}

#[test]
fn readmit_blocks_each_failing_gate() {
    let mut checks = passing_checks();
    checks.quarantine_gauge_zero = false;
    assert!(validate_readmit(&checks).is_err());

    let mut checks = passing_checks();
    checks.capacity_age_secs = 60;
    assert!(validate_readmit(&checks).is_err());

    let mut checks = passing_checks();
    checks.health_admitting = false;
    assert!(validate_readmit(&checks).is_err());

    let mut checks = passing_checks();
    checks.reconciliation_clean = false;
    assert!(validate_readmit(&checks).is_err());

    let mut checks = passing_checks();
    checks.five_minute_watch_clean = false;
    assert!(validate_readmit(&checks).is_err());
}

#[test]
fn fencing_token_parse_feeds_cleanup_evidence() {
    let token: FencingToken = "42.7".parse().expect("token parses");
    let evidence = validate_fenced_cleanup("INC-11", &[token]).expect("valid");
    assert_eq!(format!("{}", evidence.tokens[0]), "42.7");
    assert!("not-a-token".parse::<FencingToken>().is_err());
}

#[test]
fn parse_condition_round_trips_all_as_str_values() {
    use crate::host_quarantine::AlertCondition;
    let all = [
        AlertCondition::RepeatedRuntimeOutcomes,
        AlertCondition::CleanupOrReconciliationIssue,
        AlertCondition::StaleResources,
        AlertCondition::CapacityReportingStaleness,
        AlertCondition::ResourcePressure,
    ];
    for condition in all {
        assert_eq!(parse_condition(condition.as_str()), Ok(condition));
    }
}
