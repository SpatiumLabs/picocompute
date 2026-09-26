use pico_core::{
    BackendCapabilities, BackendCapability, BackendOperation, ExecRequest, RuntimeBackend,
    RuntimeType, SandboxConfig, WorkloadClass,
};
use pico_runtime::conformance::{
    ConformanceProfile, required_capabilities_for_workload_class, run_backend_conformance,
    run_backend_conformance_for_workload_class, run_lifecycle_suite,
    run_lifecycle_suite_for_workload_class,
};
use pico_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};

fn profile() -> ConformanceProfile {
    ConformanceProfile {
        sandbox: SandboxConfig {
            id: "sbx_conformance_test".into(),
            memory_limit_bytes: 512 * 1024 * 1024,
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
        fork_child: Some(SandboxConfig {
            id: "sbx_conformance_test-child".into(),
            memory_limit_bytes: 512 * 1024 * 1024,
            network_isolated: true,
            ..Default::default()
        }),
    }
}

#[tokio::test]
async fn full_suite_passes_with_mock_default() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(
        report.passed,
        "conformance suite did not pass. Failures:\n{:#?}",
        report.failures()
    );
    assert!(
        report.missing_capabilities.is_empty(),
        "missing capabilities: {:?}",
        report.missing_capabilities
    );
}

#[tokio::test]
async fn suite_reports_missing_capabilities() {
    let backend = MockBackend::new(MockBackendConfig {
        capabilities: BackendCapabilities::from([BackendCapability::Boot]),
        ..Default::default()
    });

    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(!report.passed);
    assert!(!report.missing_capabilities.is_empty());
    assert!(
        report
            .missing_capabilities
            .contains(&BackendCapability::GuestTransport)
    );
}

#[tokio::test]
async fn suite_reports_unsupported_capabilities() {
    let backend = MockBackend::new(MockBackendConfig {
        capabilities: BackendCapabilities::from([
            BackendCapability::Boot,
            BackendCapability::GuestTransport,
            BackendCapability::GuestReadiness,
            BackendCapability::Exec,
            BackendCapability::Stats,
            BackendCapability::Health,
            BackendCapability::Diagnostics,
        ]),
        ..Default::default()
    });

    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::Suspend)
    );
    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::Resume)
    );
    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::Fork)
    );
    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::BackendManagedPortForwarding)
    );
    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::SnapshotRestore)
    );
    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::EbpFNetworking)
    );
}

#[tokio::test]
async fn suite_records_checks_with_latency() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(!report.checks.is_empty());
    for check in &report.checks {
        assert!(!check.name.is_empty());
    }
}

#[tokio::test]
async fn suite_reports_failures_as_struct() {
    let backend = MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::Timeout {
            operation: BackendOperation::Boot,
        }),
        ..Default::default()
    });

    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(!report.passed);
    let failures = report.failures();
    assert!(!failures.is_empty(), "expected failures, got: {report:#?}");
}

#[tokio::test]
async fn backward_compat_runner_still_works() {
    let backend = MockBackend::default();
    let profile = profile();

    let ops = run_backend_conformance(&backend, &profile).await.unwrap();

    assert_eq!(ops.first(), Some(&BackendOperation::Prepare));
    assert_eq!(ops.last(), Some(&BackendOperation::Cleanup));
}

#[tokio::test]
async fn destroy_idempotency_succeeds_with_mock() {
    let backend = MockBackend::default();
    let _ = backend.prepare(&profile().sandbox).await;
    let _ = backend.boot().await;
    assert!(backend.destroy().await.is_ok());
    assert!(backend.destroy().await.is_ok());
}

#[tokio::test]
async fn cleanup_idempotency_succeeds_with_mock() {
    let backend = MockBackend::default();
    let _ = backend.prepare(&profile().sandbox).await;
    let _ = backend.boot().await;
    let _ = backend.destroy().await;
    assert!(backend.cleanup().await.is_ok());
    assert!(backend.cleanup().await.is_ok());
}

#[tokio::test]
async fn resource_accounting_tracks_prepare_resources() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(!report.resource_accounting.resource_classes.is_empty());
    assert!(report.resource_accounting.total_receipts > 0);
}

#[tokio::test]
async fn observability_latency_bounds_pass_for_mock() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let latency_check = report
        .checks
        .iter()
        .find(|c| c.name == "observability/latency-bounds")
        .expect("latency-bounds check should exist");
    assert!(latency_check.passed);
}

#[tokio::test]
async fn observability_resource_classes_present() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let resource_check = report
        .checks
        .iter()
        .find(|c| c.name == "observability/resource-classes-present")
        .expect("resource-classes-present check should exist");
    assert!(resource_check.passed);
}

#[tokio::test]
async fn observability_stats_memory_nonzero() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let memory_check = report
        .checks
        .iter()
        .find(|c| c.name == "observability/stats-memory-nonzero")
        .expect("stats-memory-nonzero check should exist");
    assert!(memory_check.passed);
}

#[tokio::test]
async fn observability_diagnostics_has_summary() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let diag_check = report
        .checks
        .iter()
        .find(|c| c.name == "observability/diagnostics-has-summary")
        .expect("diagnostics-has-summary check should exist");
    assert!(diag_check.passed);
}

#[tokio::test]
async fn render_json_produces_valid_output() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let json = report.to_json();
    assert!(json.is_object());
    assert_eq!(json["passed"], true);
    assert!(json["checks"].is_array());
    assert!(!json["checks"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn display_format_includes_status_and_checks() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let text = report.to_string();
    assert!(text.contains("PASS"));
    assert!(text.contains("lifecycle/prepare"));
    assert!(text.contains("Total latency"));
}

// ================================================================
// Profile-aware required sets
// ================================================================

fn gvisor_like_backend() -> MockBackend {
    // GuestReadiness-less backend for trusted-profile tests. Suspend/Resume/
    // Fork are included (unlike real gVisor) because MockBackend returns
    // InvalidState rather than Unsupported for undeclared ops, which would
    // fail the capabilities/unsupported-* probes unrelated to the GuestReadiness
    // omission under test. The exact gVisor capability set is pinned separately by
    // gvisor::tests::trusted_fast_path_required_set_satisfied_by_gvisor.
    MockBackend::new(MockBackendConfig {
        runtime: RuntimeType::GVisor,
        capabilities: BackendCapabilities::from([
            BackendCapability::Boot,
            BackendCapability::GuestTransport,
            BackendCapability::Exec,
            BackendCapability::Suspend,
            BackendCapability::Resume,
            BackendCapability::Fork,
            BackendCapability::Stats,
            BackendCapability::Health,
            BackendCapability::Diagnostics,
        ]),
        ..Default::default()
    })
}

#[test]
fn required_sets_differ_only_by_guest_readiness() {
    let trusted = required_capabilities_for_workload_class(WorkloadClass::TrustedFastPath);
    let public = required_capabilities_for_workload_class(WorkloadClass::PublicUntrusted);
    let compat = required_capabilities_for_workload_class(WorkloadClass::CompatibilityVm);
    let k8s = required_capabilities_for_workload_class(WorkloadClass::KubernetesIntegrated);

    assert!(!trusted.contains(BackendCapability::GuestReadiness));
    assert!(public.contains(BackendCapability::GuestReadiness));
    // Compatibility and Kubernetes classes keep the strict public set.
    assert_eq!(compat, public);
    assert_eq!(k8s, public);

    for cap in [
        BackendCapability::Boot,
        BackendCapability::GuestTransport,
        BackendCapability::Exec,
        BackendCapability::Stats,
        BackendCapability::Health,
        BackendCapability::Diagnostics,
    ] {
        assert!(trusted.contains(cap), "trusted set missing {cap:?}");
        assert!(public.contains(cap), "public set missing {cap:?}");
    }
}

#[tokio::test]
async fn trusted_fast_path_suite_passes_without_guest_readiness() {
    let backend = gvisor_like_backend();
    let report = run_lifecycle_suite_for_workload_class(
        &backend,
        &profile(),
        WorkloadClass::TrustedFastPath,
    )
    .await
    .unwrap();

    assert!(
        report.passed,
        "trusted-fast-path suite did not pass. Failures:\n{:#?}",
        report.failures()
    );
    assert!(report.missing_capabilities.is_empty());
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "lifecycle/wait_ready-skipped" && c.passed),
        "expected a passing wait_ready-skipped check, got: {:#?}",
        report.checks
    );
}

#[tokio::test]
async fn public_untrusted_suite_rejects_missing_guest_readiness() {
    let backend = gvisor_like_backend();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(!report.passed);
    assert!(
        report
            .missing_capabilities
            .contains(&BackendCapability::GuestReadiness)
    );
}

#[tokio::test]
async fn trusted_fast_path_suite_passes_with_full_capabilities() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite_for_workload_class(
        &backend,
        &profile(),
        WorkloadClass::TrustedFastPath,
    )
    .await
    .unwrap();

    assert!(
        report.passed,
        "trusted suite with full caps did not pass. Failures:\n{:#?}",
        report.failures()
    );
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "lifecycle/wait_ready" && c.passed),
        "expected a real wait_ready check for GuestReadiness backends"
    );
}

#[tokio::test]
async fn legacy_runner_skips_wait_ready_without_guest_readiness() {
    let backend = gvisor_like_backend();
    let ops = run_backend_conformance_for_workload_class(
        &backend,
        &profile(),
        WorkloadClass::TrustedFastPath,
    )
    .await
    .unwrap();

    assert!(!ops.contains(&BackendOperation::WaitReady));
    assert_eq!(ops.first(), Some(&BackendOperation::Prepare));
    assert_eq!(ops.last(), Some(&BackendOperation::Cleanup));
}

#[tokio::test]
async fn legacy_runner_still_requires_guest_readiness_for_public() {
    let backend = gvisor_like_backend();
    let err = run_backend_conformance(&backend, &profile())
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        pico_core::BackendError::Unsupported { capability }
            if capability == BackendCapability::GuestReadiness
    ));
}
