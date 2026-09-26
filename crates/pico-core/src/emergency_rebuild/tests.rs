use super::*;
use crate::operator::ReadmitChecks;

fn passing_checks() -> ReadmitChecks {
    ReadmitChecks {
        quarantine_gauge_zero: true,
        capacity_age_secs: 12,
        health_admitting: true,
        reconciliation_clean: true,
        five_minute_watch_clean: true,
    }
}

fn audit(kind: &str) -> Vec<String> {
    vec![format!("{kind}:evt-1")]
}

fn full_exercise() -> EmergencyExercise {
    let mut exercise = EmergencyExercise::begin(
        "INC-2026-09-22-01",
        "hst_01",
        "cel_east",
        "region_test",
        "SYNTH-ADV-01",
    )
    .expect("begin");
    exercise
        .record_cordon(2, audit("host_disabled"))
        .expect("cordon");
    exercise
        .record_drain(12, audit("host_disabled"))
        .expect("drain");
    exercise.retire("sbx_21");
    exercise.retire("10.0.0.21");
    exercise
        .record_revoke(17, audit("LeaseRevoked"))
        .expect("revoke");
    exercise.prove_absence("sbx_21");
    exercise.prove_absence("10.0.0.21");
    exercise
        .freeze_evidence(19, audit("cleanup_disposition"))
        .expect("freeze");
    exercise
        .record_rebuild(
            49,
            "build-2026-09-22",
            "sha256:good",
            audit("placement_outcome"),
        )
        .expect("rebuild");
    exercise
        .record_verify(
            59,
            "firecracker-linux-kvm-2026-09-22",
            true,
            audit("runtime_outcome"),
        )
        .expect("verify");
    exercise
        .record_readmit(64, &passing_checks(), audit("lifecycle_transition"))
        .expect("readmit");
    exercise
}

#[test]
fn begin_validates_scope() {
    assert!(EmergencyExercise::begin("", "h", "c", "r", "a").is_err());
    assert!(EmergencyExercise::begin("INC-1", "", "c", "r", "a").is_err());
    assert!(EmergencyExercise::begin("INC-1", "h", "c", "r", "").is_err());
    let exercise =
        EmergencyExercise::begin("INC-1", "hst_01", "cel_east", "region_test", "SYNTH-ADV-01")
            .expect("valid scope");
    assert_eq!(exercise.stage(), EmergencyStage::AdvisoryTriaged);
    assert_eq!(
        exercise.timestamp_for(EmergencyStage::AdvisoryTriaged),
        Some(0)
    );
}

#[test]
fn stages_reject_skips() {
    let mut exercise = EmergencyExercise::begin("INC-1", "h", "c", "r", "a").expect("begin");
    let err = exercise
        .record_drain(5, audit("host_disabled"))
        .unwrap_err();
    assert!(
        matches!(err, EmergencyError::OutOfOrder { .. }),
        "drain before cordon must fail, got {err:?}"
    );
}

#[test]
fn stages_reject_stale_timestamps() {
    let mut exercise = EmergencyExercise::begin("INC-1", "h", "c", "r", "a").expect("begin");
    exercise
        .record_cordon(10, audit("host_disabled"))
        .expect("cordon");
    let err = exercise
        .record_drain(9, audit("host_disabled"))
        .unwrap_err();
    assert!(
        matches!(err, EmergencyError::StaleTimestamp { .. }),
        "backwards clock must fail, got {err:?}"
    );
}

#[test]
fn stages_need_audit_ids() {
    let mut exercise = EmergencyExercise::begin("INC-1", "h", "c", "r", "a").expect("begin");
    let err = exercise.record_cordon(2, Vec::new()).unwrap_err();
    assert!(
        matches!(err, EmergencyError::MissingAudit { .. }),
        "cordon without audit must fail, got {err:?}"
    );
}

#[test]
fn rebuild_needs_build_and_digest() {
    let mut exercise = EmergencyExercise::begin("INC-1", "h", "c", "r", "a").expect("begin");
    exercise
        .record_cordon(2, audit("host_disabled"))
        .expect("cordon");
    exercise
        .record_drain(5, audit("host_disabled"))
        .expect("drain");
    exercise
        .record_revoke(6, audit("LeaseRevoked"))
        .expect("revoke");
    exercise
        .freeze_evidence(7, audit("cleanup_disposition"))
        .expect("freeze");
    assert_eq!(
        exercise
            .record_rebuild(9, "", "sha256:x", audit("placement_outcome"))
            .unwrap_err(),
        EmergencyError::MissingBuild
    );
    assert_eq!(
        exercise
            .record_rebuild(9, "build", "", audit("placement_outcome"))
            .unwrap_err(),
        EmergencyError::MissingBuild
    );
}

#[test]
fn verify_needs_passing_suite_for_exact_profile() {
    let mut exercise = EmergencyExercise::begin("INC-1", "h", "c", "r", "a").expect("begin");
    exercise
        .record_cordon(2, audit("host_disabled"))
        .expect("cordon");
    exercise
        .record_drain(5, audit("host_disabled"))
        .expect("drain");
    exercise
        .record_revoke(6, audit("LeaseRevoked"))
        .expect("revoke");
    exercise
        .freeze_evidence(7, audit("cleanup_disposition"))
        .expect("freeze");
    exercise
        .record_rebuild(9, "build", "sha256:x", audit("placement_outcome"))
        .expect("rebuild");
    assert_eq!(
        exercise
            .record_verify(10, "profile", false, audit("runtime_outcome"))
            .unwrap_err(),
        EmergencyError::BoundarySuiteFailed
    );
    assert_eq!(
        exercise
            .record_verify(10, "", true, audit("runtime_outcome"))
            .unwrap_err(),
        EmergencyError::BoundarySuiteFailed
    );
}

#[test]
fn readmit_reuses_shared_gates() {
    let exercise = full_exercise();
    // Full exercise already readmitted; a fresh run with failing gates blocks.
    let mut blocked = EmergencyExercise::begin("INC-2", "h", "c", "r", "a").expect("begin");
    blocked
        .record_cordon(2, audit("host_disabled"))
        .expect("cordon");
    blocked
        .record_drain(5, audit("host_disabled"))
        .expect("drain");
    blocked
        .record_revoke(6, audit("LeaseRevoked"))
        .expect("revoke");
    blocked
        .freeze_evidence(7, audit("cleanup_disposition"))
        .expect("freeze");
    blocked
        .record_rebuild(9, "build", "sha256:x", audit("placement_outcome"))
        .expect("rebuild");
    blocked
        .record_verify(10, "profile", true, audit("runtime_outcome"))
        .expect("verify");
    let mut checks = passing_checks();
    checks.five_minute_watch_clean = false;
    let err = blocked
        .record_readmit(11, &checks, audit("lifecycle_transition"))
        .unwrap_err();
    assert!(
        matches!(err, EmergencyError::ReadmitBlocked { .. }),
        "failing watch must block, got {err:?}"
    );
    assert_eq!(exercise.stage(), EmergencyStage::Readmitted);
}

#[test]
fn reuse_fails_before_absence_proof() {
    let mut exercise = EmergencyExercise::begin("INC-1", "h", "c", "r", "a").expect("begin");
    exercise.retire("sbx_21");
    assert_eq!(
        exercise.check_reuse("sbx_21").unwrap_err(),
        EmergencyError::ReuseBeforeAbsence {
            value: "sbx_21".to_string()
        }
    );
    exercise.prove_absence("sbx_21");
    assert!(exercise.check_reuse("sbx_21").is_ok());
    assert!(exercise.check_reuse("never-retired").is_ok());
}

#[test]
fn timings_measure_drain_and_rebuild() {
    let exercise = full_exercise();
    assert_eq!(exercise.time_to_drain_secs(), Some(10));
    assert_eq!(exercise.time_to_rebuild_secs(), Some(37));
}

#[test]
fn close_needs_complete_evidence() {
    let mut exercise = full_exercise();
    assert!(exercise.missing_evidence().is_empty());
    exercise
        .close(70, audit("lifecycle_transition"))
        .expect("close");
    assert_eq!(exercise.stage(), EmergencyStage::Closed);
}

#[test]
fn close_blocks_on_missing_revoke() {
    let mut exercise = EmergencyExercise::begin("INC-1", "h", "c", "r", "a").expect("begin");
    exercise
        .record_cordon(2, audit("host_disabled"))
        .expect("cordon");
    exercise
        .record_drain(5, audit("host_disabled"))
        .expect("drain");
    // Skip the LeaseRevoked kind on purpose with a different kind string.
    exercise
        .record_revoke(6, audit("cleanup_disposition"))
        .expect("revoke");
    exercise
        .freeze_evidence(7, audit("cleanup_disposition"))
        .expect("freeze");
    exercise
        .record_rebuild(9, "build", "sha256:x", audit("placement_outcome"))
        .expect("rebuild");
    exercise
        .record_verify(10, "profile", true, audit("runtime_outcome"))
        .expect("verify");
    exercise
        .record_readmit(11, &passing_checks(), audit("lifecycle_transition"))
        .expect("readmit");
    let missing = exercise.missing_evidence();
    assert!(missing.contains(&REQUIRED_REVOKE_AUDIT_KIND.to_string()));
    assert!(matches!(
        exercise
            .close(12, audit("lifecycle_transition"))
            .unwrap_err(),
        EmergencyError::IncompleteEvidence { .. }
    ));
}

#[test]
fn summary_names_ticket_stage_and_timings() {
    let exercise = full_exercise();
    let summary = exercise.summary();
    assert!(summary.contains("ticket=INC-2026-09-22-01"));
    assert!(summary.contains("stage=readmitted"));
    assert!(summary.contains("drain=Some(10)"));
    assert!(summary.contains("rebuild=Some(37)"));
}

#[test]
fn stage_names_and_order_are_stable() {
    assert_eq!(EmergencyStage::AdvisoryTriaged.as_str(), "advisory-triaged");
    assert_eq!(EmergencyStage::Cordoned.as_str(), "cordoned");
    assert_eq!(EmergencyStage::Closed.as_str(), "closed");
    assert_eq!(
        EmergencyStage::AdvisoryTriaged.next(),
        Some(EmergencyStage::Cordoned)
    );
    assert_eq!(EmergencyStage::Closed.next(), None);
}
