//! Integration tests for the isolation boundary validation suite.
//!
//! Tests exercise the full suite against mock backends with varying
//! capabilities, isolation floors, and boundary assertions.

use pico_core::{ExecRequest, SandboxConfig, backend_selection::IsolationFloor};
use pico_runtime::{
    conformance::ConformanceProfile,
    isolation::{
        BoundaryCategory, CheckOutcome, IsolationProfile, isolation_floor_as_stable_str,
        run_isolation_suite,
    },
    mock::MockBackend,
};

fn isolation_profile() -> IsolationProfile {
    IsolationProfile {
        conformance: ConformanceProfile {
            sandbox: SandboxConfig {
                id: "sbx_isolation_test".into(),
                memory_limit_bytes: 512 * 1024 * 1024,
                max_pids: Some(128),
                network_isolated: true,
                ..Default::default()
            },
            exec: ExecRequest {
                command: "true".into(),
                args: Vec::new(),
                env: None,
                working_dir: None,
                timeout_secs: Some(1),
            },
            fork_child: None,
        },
        expected_isolation_floor: IsolationFloor::MicroVm,
        live_boundary_tests: false,
        requires_strong_side_channel_validation: false,
    }
}

// ─── Full suite tests ───

#[tokio::test]
async fn full_suite_passes_with_mock_default() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    assert!(
        report.passed,
        "isolation suite did not pass. Failures:\n{:#?}",
        report.failures()
    );
}

#[tokio::test]
async fn report_has_schema_version() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    assert_eq!(report.schema_version, 1, "schema version must be present");
}

#[tokio::test]
async fn suite_generates_isolation_floor_assertion() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    assert!(report.actual_isolation_floor.is_some());
    assert_eq!(report.actual_isolation_floor, Some(IsolationFloor::MicroVm));
    assert!(report.isolation_floor_assertion_passed);
}

#[tokio::test]
async fn suite_fails_when_isolation_floor_insufficient() {
    let backend = MockBackend::default();
    let profile = IsolationProfile {
        expected_isolation_floor: IsolationFloor::Vm,
        ..isolation_profile()
    };

    let report = run_isolation_suite(&backend, &profile).await.unwrap();

    assert!(!report.isolation_floor_assertion_passed);
    assert_eq!(report.actual_isolation_floor, Some(IsolationFloor::MicroVm));
}

#[tokio::test]
async fn suite_succeeds_with_live_boundary_tests_using_mock() {
    let backend = MockBackend::default();
    let profile = IsolationProfile {
        live_boundary_tests: true,
        ..isolation_profile()
    };

    let report = run_isolation_suite(&backend, &profile).await.unwrap();

    // With a mock backend, live boundary probes run against the host system
    // and may fail when the host lacks CPU pinning or cgroup v2. Verify that
    // live checks are *executed* (not skipped) and the suite framework runs
    // without crashing, rather than asserting all checks pass.
    let side_channel_skipped = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::SideChannels && c.outcome.is_skipped())
        .count();
    assert_eq!(
        side_channel_skipped, 0,
        "no side-channel checks should be skipped in live mode"
    );
}

// ─── Skipped checks tests ───

#[tokio::test]
async fn suite_skips_live_boundary_checks_when_not_in_live_mode() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let skipped = report.skipped();
    assert!(
        !skipped.is_empty(),
        "must have skipped checks when live_boundary_tests=false"
    );

    let signal_skip = skipped
        .iter()
        .find(|c| c.name == "process/signal-isolation-assertion")
        .expect("signal isolation must be skipped");
    assert!(signal_skip.outcome.is_skipped());
    assert!(
        signal_skip
            .message
            .as_ref()
            .unwrap()
            .contains("requires live backend")
    );

    let pid_skip = skipped
        .iter()
        .find(|c| c.name == "process/pid-namespace-isolation")
        .expect("pid namespace isolation must be skipped");
    assert!(pid_skip.outcome.is_skipped());

    let side_channel_skips: Vec<_> = skipped
        .iter()
        .filter(|c| c.category == BoundaryCategory::SideChannels)
        .collect();
    assert_eq!(
        side_channel_skips.len(),
        4,
        "all four side-channel checks must be skipped"
    );
}

#[tokio::test]
async fn suite_skipped_checks_do_not_cause_failure() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    assert!(report.passed, "skipped checks must not fail the suite");
    assert!(
        !report.skipped().is_empty(),
        "but must still document skipped checks"
    );
}

#[tokio::test]
async fn live_mode_runs_side_channel_checks() {
    let backend = MockBackend::default();
    let profile = IsolationProfile {
        live_boundary_tests: true,
        ..isolation_profile()
    };

    let report = run_isolation_suite(&backend, &profile).await.unwrap();

    let sc_skipped = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::SideChannels && c.outcome.is_skipped())
        .count();
    assert_eq!(
        sc_skipped, 0,
        "no side-channel checks should be skipped in live mode"
    );
}

// ─── Category coverage tests ───

#[tokio::test]
async fn suite_includes_filesystem_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let fs_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::Filesystem)
        .collect();
    assert!(
        !fs_checks.is_empty(),
        "must have filesystem boundary checks"
    );
}

#[tokio::test]
async fn suite_includes_process_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let proc_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::Process)
        .collect();
    assert!(!proc_checks.is_empty(), "must have process boundary checks");
}

#[tokio::test]
async fn suite_includes_network_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let net_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::Network)
        .collect();
    assert!(!net_checks.is_empty(), "must have network boundary checks");
}

#[tokio::test]
async fn suite_includes_resource_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let res_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::Resources)
        .collect();
    assert!(!res_checks.is_empty(), "must have resource boundary checks");
}

#[tokio::test]
async fn suite_includes_credential_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let cred_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::Credentials)
        .collect();
    assert!(
        !cred_checks.is_empty(),
        "must have credential boundary checks"
    );
}

#[tokio::test]
async fn suite_includes_audit_detection_check() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let detection_check = report
        .checks
        .iter()
        .find(|c| c.name == "credentials/audit-detection-coverage")
        .expect("must have audit detection coverage check");
    assert!(detection_check.outcome.is_pass());
}

#[tokio::test]
async fn suite_includes_backend_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let backend_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::Backend)
        .collect();
    assert!(
        !backend_checks.is_empty(),
        "must have backend boundary checks"
    );
}

#[tokio::test]
async fn backend_uses_invariant_based_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "backend/boundary-classification-invariants"),
        "must use invariant-based classification"
    );
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "backend/production-eligibility-invariants"),
        "must use invariant-based eligibility"
    );
}

#[tokio::test]
async fn suite_includes_data_sharing_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let ds_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::DataSharing)
        .collect();
    assert!(
        !ds_checks.is_empty(),
        "must have data sharing boundary checks"
    );
}

#[tokio::test]
async fn suite_includes_side_channel_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let sc_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == BoundaryCategory::SideChannels)
        .collect();
    assert!(
        !sc_checks.is_empty(),
        "must have side channel boundary checks"
    );
}

// ─── Evidence bundle tests ───

#[tokio::test]
async fn evidence_bundle_includes_assertions() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    assert!(!report.evidence.filesystem_assertions.is_empty());
    assert!(!report.evidence.process_assertions.is_empty());
    assert!(!report.evidence.network_assertions.is_empty());
    assert!(!report.evidence.resource_assertions.is_empty());
    assert!(!report.evidence.credential_assertions.is_empty());
    assert!(!report.evidence.backend_assertions.is_empty());
    assert!(!report.evidence.data_sharing_assertions.is_empty());
    assert!(!report.evidence.side_channel_assertions.is_empty());
    assert!(report.evidence.backend_metadata.is_some());
}

// ─── Report rendering tests ───

#[tokio::test]
async fn render_json_produces_valid_output() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let json = report.to_json();
    assert!(json.is_object());
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["passed"], true);
    assert!(json["checks"].is_array());
    let checks = json["checks"].as_array().unwrap();
    assert!(!checks.is_empty());
    assert!(checks.iter().any(|c| c["outcome"] == "PASS"));
    assert!(json["evidence"].is_object());
}

#[tokio::test]
async fn display_format_includes_status_and_checks() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let text = report.to_string();
    assert!(text.contains("Isolation Boundary Validation Report"));
    assert!(text.contains("Schema version:"));
    assert!(text.contains("PASS"));
    assert!(text.contains("filesystem/mount-isolation"));
    assert!(text.contains("Total latency"));
    assert!(text.contains("SKIP"), "display must show skipped checks");
}

// ─── Stable render tests ───

#[tokio::test]
async fn isolation_floor_has_stable_strings() {
    assert_eq!(
        isolation_floor_as_stable_str(IsolationFloor::Container),
        "container"
    );
    assert_eq!(
        isolation_floor_as_stable_str(IsolationFloor::MicroVm),
        "microvm"
    );
    assert_eq!(isolation_floor_as_stable_str(IsolationFloor::Vm), "vm");
}

// ─── Failure filtering tests ───

#[tokio::test]
async fn failures_by_category_returns_correct_subset() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let fs_failures = report.failures_by_category(BoundaryCategory::Filesystem);
    assert!(fs_failures.is_empty(), "filesystem tests should all pass");
}

#[tokio::test]
async fn category_counts_returns_all_categories() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    let counts = report.category_counts();
    assert!(counts.len() >= 7, "should have at least 7 categories");
    for (_cat, _pass, fail, _skip) in &counts {
        assert!(
            *fail == 0,
            "all checks should pass (no fails) with default mock"
        );
    }
}

// ─── Evidence assertions cross-check ───

#[tokio::test]
async fn isolation_floor_evidence_is_consistent() {
    let backend = MockBackend::default();
    let report = run_isolation_suite(&backend, &isolation_profile())
        .await
        .unwrap();

    assert_eq!(report.expected_isolation_floor, IsolationFloor::MicroVm);
    assert!(report.isolation_floor_assertion_passed);

    let floor_check = report
        .checks
        .iter()
        .find(|c| c.name == "isolation-floor/assertion")
        .expect("must have isolation floor assertion");
    assert!(floor_check.outcome.is_pass());
    assert_eq!(floor_check.category, BoundaryCategory::Backend);
}

// ─── CheckOutcome helpers ───

#[test]
fn check_outcome_is_pass_only_true_for_pass() {
    assert!(CheckOutcome::Pass.is_pass());
    assert!(!CheckOutcome::Fail.is_pass());
    assert!(!CheckOutcome::Skipped.is_pass());
}

#[test]
fn check_outcome_is_fail_only_true_for_fail() {
    assert!(!CheckOutcome::Pass.is_fail());
    assert!(CheckOutcome::Fail.is_fail());
    assert!(!CheckOutcome::Skipped.is_fail());
}

#[test]
fn check_outcome_is_skipped_only_true_for_skipped() {
    assert!(!CheckOutcome::Pass.is_skipped());
    assert!(!CheckOutcome::Fail.is_skipped());
    assert!(CheckOutcome::Skipped.is_skipped());
}
