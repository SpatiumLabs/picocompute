use super::*;
use crate::identity::TenantId;
use crate::overcommit::ServiceClass;
use crate::runtime::BackendCapabilities;
use crate::tenant::{Tenant, TenantStatus};

fn make_tenant(allowed_runtimes: Vec<RuntimeType>, allowed_classes: Vec<WorkloadClass>) -> Tenant {
    Tenant {
        id: TenantId::generate(),
        name: "test-tenant".into(),
        status: TenantStatus::Active,
        allowed_runtimes,
        allowed_workload_classes: allowed_classes,
        default_service_class: ServiceClass::LatencySensitive,
        policy_epoch: Some(1),
    }
}

fn make_capabilities(
    runtimes: &[(RuntimeType, Vec<crate::runtime::BackendCapability>)],
) -> HashMap<RuntimeType, BackendCapabilities> {
    runtimes
        .iter()
        .map(|(rt, caps)| (*rt, BackendCapabilities::new(caps.iter().copied())))
        .collect()
}

fn default_required_capabilities() -> BackendCapabilities {
    use crate::runtime::BackendCapability;
    BackendCapabilities::from([
        BackendCapability::Boot,
        BackendCapability::GuestTransport,
        BackendCapability::Exec,
        BackendCapability::Health,
    ])
}

fn ready_health(runtimes: &[RuntimeType]) -> HashMap<RuntimeType, BackendHealth> {
    runtimes
        .iter()
        .copied()
        .map(|runtime| (runtime, BackendHealth::ready()))
        .collect()
}

fn passing_conformance(runtimes: &[RuntimeType]) -> HashMap<RuntimeType, ConformanceStatus> {
    runtimes
        .iter()
        .copied()
        .map(|runtime| {
            (
                runtime,
                ConformanceStatus {
                    passing: true,
                    profile: None,
                },
            )
        })
        .collect()
}

fn default_health() -> &'static HashMap<RuntimeType, BackendHealth> {
    static HEALTH: std::sync::LazyLock<HashMap<RuntimeType, BackendHealth>> =
        std::sync::LazyLock::new(|| {
            ready_health(&[
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
                RuntimeType::GVisor,
            ])
        });
    &HEALTH
}

fn default_conformance() -> &'static HashMap<RuntimeType, ConformanceStatus> {
    static CONFORMANCE: std::sync::LazyLock<HashMap<RuntimeType, ConformanceStatus>> =
        std::sync::LazyLock::new(|| {
            passing_conformance(&[
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
                RuntimeType::GVisor,
            ])
        });
    &CONFORMANCE
}

fn compatible_image(runtimes: &[RuntimeType]) -> HashMap<RuntimeType, ImageCompatibility> {
    runtimes
        .iter()
        .copied()
        .map(|runtime| (runtime, ImageCompatibility { compatible: true }))
        .collect()
}

fn compatible_snapshot(runtimes: &[RuntimeType]) -> HashMap<RuntimeType, SnapshotCompatibility> {
    runtimes
        .iter()
        .copied()
        .map(|runtime| (runtime, SnapshotCompatibility { compatible: true }))
        .collect()
}

fn compatible_protocol(runtimes: &[RuntimeType]) -> HashMap<RuntimeType, ProtocolCompatibility> {
    runtimes
        .iter()
        .copied()
        .map(|runtime| (runtime, ProtocolCompatibility { compatible: true }))
        .collect()
}

fn default_image() -> &'static HashMap<RuntimeType, ImageCompatibility> {
    static IMAGE: std::sync::LazyLock<HashMap<RuntimeType, ImageCompatibility>> =
        std::sync::LazyLock::new(|| {
            compatible_image(&[
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
                RuntimeType::GVisor,
            ])
        });
    &IMAGE
}

fn default_snapshot() -> &'static HashMap<RuntimeType, SnapshotCompatibility> {
    static SNAPSHOT: std::sync::LazyLock<HashMap<RuntimeType, SnapshotCompatibility>> =
        std::sync::LazyLock::new(|| {
            compatible_snapshot(&[
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
                RuntimeType::GVisor,
            ])
        });
    &SNAPSHOT
}

fn default_protocol() -> &'static HashMap<RuntimeType, ProtocolCompatibility> {
    static PROTOCOL: std::sync::LazyLock<HashMap<RuntimeType, ProtocolCompatibility>> =
        std::sync::LazyLock::new(|| {
            compatible_protocol(&[
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
                RuntimeType::GVisor,
            ])
        });
    &PROTOCOL
}

// ================================================================
// WorkloadClass -> Backend mappings
// ================================================================

#[test]
fn public_untrusted_prefers_firecracker_then_qemu() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[
        (
            RuntimeType::Firecracker,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
        (
            RuntimeType::Qemu,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
    ]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker, RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Firecracker));
    assert_eq!(result.fallback_rank, 0);
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::PreferredBackendPassed
    );
    assert!(result.rejected_candidates.is_empty());
}

#[test]
fn public_untrusted_falls_back_to_qemu_when_firecracker_unavailable() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Qemu,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Qemu));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::FallbackBackendSelected
    );
    assert_eq!(result.fallback_rank, 1);
    assert_eq!(result.rejected_candidates.len(), 1);
    assert_eq!(
        result.rejected_candidates[0].runtime,
        RuntimeType::Firecracker
    );
}

#[test]
fn public_untrusted_rejects_gvisor_output() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::GVisor],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::GVisor,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::GVisor],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            // For PublicUntrusted, ordered candidates are [Firecracker, Qemu].
            // Neither is in tenant's allowed_runtimes (only gVisor), so both
            // fail TenantPolicy. gVisor is never a candidate for this class.
            assert!(!rejected.is_empty());
            assert!(
                rejected
                    .iter()
                    .all(|r| r.gate == BackendSelectionGate::TenantPolicy)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn trusted_fast_path_prefers_gvisor_then_firecracker_then_qemu() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![
            RuntimeType::GVisor,
            RuntimeType::Firecracker,
            RuntimeType::Qemu,
        ],
        vec![WorkloadClass::TrustedFastPath],
    );
    let caps = make_capabilities(&[
        (
            RuntimeType::GVisor,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
        (
            RuntimeType::Firecracker,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
        (
            RuntimeType::Qemu,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
    ]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::TrustedFastPath,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[
                RuntimeType::GVisor,
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
            ],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::GVisor));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::PreferredBackendPassed
    );
}

#[test]
fn trusted_fast_path_falls_back_to_firecracker_when_gvisor_not_available() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::GVisor, RuntimeType::Firecracker],
        vec![WorkloadClass::TrustedFastPath],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::TrustedFastPath,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Firecracker));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::FallbackBackendSelected
    );
}

#[test]
fn compatibility_vm_selects_qemu_only() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Qemu],
        vec![WorkloadClass::CompatibilityVm],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Qemu,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::CompatibilityVm,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Qemu));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::PreferredBackendPassed
    );
}

#[test]
fn compatibility_vm_rejects_without_qemu() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::CompatibilityVm],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::CompatibilityVm,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::TenantPolicy)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// KubernetesIntegrated behavior: VM-only, never lowered by grants
// ================================================================

// Minimal capability set shared by the Kubernetes fixtures below.
fn k8s_minimal_caps() -> Vec<crate::runtime::BackendCapability> {
    vec![
        crate::runtime::BackendCapability::Boot,
        crate::runtime::BackendCapability::GuestTransport,
        crate::runtime::BackendCapability::Exec,
        crate::runtime::BackendCapability::Health,
    ]
}

#[test]
fn kubernetes_integrated_with_trusted_grant_stays_on_vm_floor() {
    let policy = BackendSelectionPolicy::new();
    // Even with a trusted-fast-path grant, a KubernetesIntegrated request
    // must not silently drop to Container isolation. The grant authorizes
    // TrustedFastPath requests; it must not change the floor of another
    // class. Tenants that want gVisor on a Kubernetes cell request
    // TrustedFastPath explicitly.
    let tenant = make_tenant(
        vec![
            RuntimeType::GVisor,
            RuntimeType::Firecracker,
            RuntimeType::Qemu,
        ],
        vec![
            WorkloadClass::KubernetesIntegrated,
            WorkloadClass::TrustedFastPath,
        ],
    );
    let caps = make_capabilities(&[
        (RuntimeType::GVisor, k8s_minimal_caps()),
        (RuntimeType::Firecracker, k8s_minimal_caps()),
        (RuntimeType::Qemu, k8s_minimal_caps()),
    ]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::KubernetesIntegrated,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[
                RuntimeType::GVisor,
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
            ],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Firecracker));
    assert_eq!(result.isolation_floor, IsolationFloor::MicroVm);
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::PreferredBackendPassed
    );
    // gVisor is never a candidate for this class, so no gVisor path is
    // advertised and none is rejected by the floor gate.
    assert!(result.rejected_candidates.is_empty());
}

#[test]
fn kubernetes_integrated_without_trusted_grant_excludes_gvisor() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![
            RuntimeType::GVisor,
            RuntimeType::Firecracker,
            RuntimeType::Qemu,
        ],
        vec![WorkloadClass::KubernetesIntegrated],
    );
    let caps = make_capabilities(&[
        (RuntimeType::GVisor, k8s_minimal_caps()),
        (RuntimeType::Firecracker, k8s_minimal_caps()),
        (RuntimeType::Qemu, k8s_minimal_caps()),
    ]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::KubernetesIntegrated,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[
                RuntimeType::GVisor,
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
            ],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    // The order is Firecracker-first and the floor stays MicroVm regardless
    // of grants. gVisor is never a candidate, so selection must not
    // record an isolation-floor rejection for an advertised gVisor path.
    assert_eq!(result.selected, Some(RuntimeType::Firecracker));
    assert_eq!(result.isolation_floor, IsolationFloor::MicroVm);
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::PreferredBackendPassed
    );
    assert!(result.rejected_candidates.is_empty());
    assert!(!result.rejected_candidates.iter().any(
        |r| r.runtime == RuntimeType::GVisor && r.gate == BackendSelectionGate::IsolationFloor
    ));
}

#[test]
fn kubernetes_integrated_with_only_gvisor_allowed_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    // A tenant that allows only gVisor cannot place a KubernetesIntegrated
    // workload anywhere: gVisor is not a candidate for this class, so both
    // VM candidates fail tenant policy. This must be an explicit error, never
    // a silent isolation downgrade.
    let tenant = make_tenant(
        vec![RuntimeType::GVisor],
        vec![
            WorkloadClass::KubernetesIntegrated,
            WorkloadClass::TrustedFastPath,
        ],
    );
    let caps = make_capabilities(&[(RuntimeType::GVisor, k8s_minimal_caps())]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::KubernetesIntegrated,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::GVisor],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert_eq!(rejected.len(), 2);
            assert!(
                rejected
                    .iter()
                    .all(|r| r.gate == BackendSelectionGate::TenantPolicy)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn kubernetes_integrated_with_kubernetes_required_set_selects_firecracker() {
    use crate::runtime::BackendCapability;

    let policy = BackendSelectionPolicy::new();
    // Composition pin (review finding 3): the Kubernetes conformance required
    // set (with GuestReadiness) must compose with Kubernetes selection. VM
    // backends declare the full set, so the strict set still selects
    // Firecracker instead of vetoing every candidate.
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        vec![WorkloadClass::KubernetesIntegrated],
    );
    let full_caps = vec![
        BackendCapability::Boot,
        BackendCapability::GuestTransport,
        BackendCapability::GuestReadiness,
        BackendCapability::Exec,
        BackendCapability::Stats,
        BackendCapability::Health,
        BackendCapability::Diagnostics,
    ];
    let caps = make_capabilities(&[
        (RuntimeType::Firecracker, full_caps.clone()),
        (RuntimeType::Qemu, full_caps),
    ]);
    let required = BackendCapabilities::from([
        BackendCapability::Boot,
        BackendCapability::GuestTransport,
        BackendCapability::GuestReadiness,
        BackendCapability::Exec,
        BackendCapability::Stats,
        BackendCapability::Health,
        BackendCapability::Diagnostics,
    ]);

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::KubernetesIntegrated,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker, RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Firecracker));
    assert_eq!(result.isolation_floor, IsolationFloor::MicroVm);
}

// ================================================================
// Tenant policy enforcement
// ================================================================

#[test]
fn tenant_policy_rejects_backend_not_in_allowed_runtimes() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Qemu,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(!rejected.is_empty());
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::TenantPolicy
                        && r.runtime == RuntimeType::Qemu)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn tenant_unauthorized_for_workload_class() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::GVisor],
        vec![], // no classes authorized
    );
    let caps = make_capabilities(&[]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::TrustedFastPath,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    assert!(matches!(
        err,
        BackendSelectionError::UnauthorizedClass { .. }
    ));
}

// ================================================================
// Capability rejection
// ================================================================

#[test]
fn missing_capability_rejects_backend() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[
        (
            RuntimeType::Firecracker,
            vec![crate::runtime::BackendCapability::Boot],
        ),
        (
            RuntimeType::Qemu,
            vec![crate::runtime::BackendCapability::Boot],
        ),
    ]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker, RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert_eq!(rejected.len(), 2);
            for r in &rejected {
                assert_eq!(r.gate, BackendSelectionGate::Capabilities);
            }
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// Isolation floor enforcement
// ================================================================

#[test]
fn isolation_floor_from_workload_class() {
    assert_eq!(
        IsolationFloor::from(WorkloadClass::PublicUntrusted),
        IsolationFloor::MicroVm
    );
    assert_eq!(
        IsolationFloor::from(WorkloadClass::TrustedFastPath),
        IsolationFloor::Container
    );
    assert_eq!(
        IsolationFloor::from(WorkloadClass::CompatibilityVm),
        IsolationFloor::MicroVm
    );
    // Kubernetes never lowers the floor: the mapping is authoritative and
    // selection uses it directly (see kubernetes_integrated_* fixtures).
    assert_eq!(
        IsolationFloor::from(WorkloadClass::KubernetesIntegrated),
        IsolationFloor::MicroVm
    );
}

#[test]
fn runtime_isolation_floor_values() {
    assert_eq!(
        RuntimeType::Firecracker.isolation_floor(),
        IsolationFloor::MicroVm
    );
    assert_eq!(RuntimeType::Qemu.isolation_floor(), IsolationFloor::Vm);
    assert_eq!(
        RuntimeType::GVisor.isolation_floor(),
        IsolationFloor::Container
    );
}

#[test]
fn isolation_floor_ordering() {
    assert!(IsolationFloor::MicroVm > IsolationFloor::Container);
    assert!(IsolationFloor::Vm > IsolationFloor::MicroVm);
    assert!(IsolationFloor::Vm > IsolationFloor::Container);
}

// ================================================================
// Health gate
// ================================================================

#[test]
fn health_gate_rejects_unhealthy_backend() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let mut health: HashMap<RuntimeType, BackendHealth> = HashMap::new();
    health.insert(
        RuntimeType::Firecracker,
        BackendHealth {
            status: crate::runtime::BackendHealthStatus::Unavailable,
            checked_at: crate::types::now_iso(),
            message: Some("firecracker process crashed".into()),
        },
    );

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(&health),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(!rejected.is_empty());
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::HealthCapacity)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// Conformance status gate
// ================================================================

#[test]
fn conformance_gate_rejects_non_passing_backend() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let mut conformance: HashMap<RuntimeType, ConformanceStatus> = HashMap::new();
    conformance.insert(
        RuntimeType::Firecracker,
        ConformanceStatus {
            passing: false,
            profile: Some(WorkloadClass::PublicUntrusted),
        },
    );

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(&conformance),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(!rejected.is_empty());
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::ConformanceStatus)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// Selection result metadata
// ================================================================

#[test]
fn selection_records_metadata_on_success() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.workload_class, WorkloadClass::PublicUntrusted);
    assert_eq!(result.isolation_floor, IsolationFloor::MicroVm);
    assert!(result.tenant_id.is_some());
    assert_eq!(result.policy_epoch, Some(1));
    assert!(!result.decided_at.is_empty());
    assert!(result.required_capabilities.supports_all(&required));
}

// ================================================================
// Evaluation-only backends
// ================================================================

#[test]
fn production_eligibility() {
    assert!(RuntimeType::Firecracker.is_production_eligible());
    assert!(RuntimeType::Qemu.is_production_eligible());
    assert!(RuntimeType::GVisor.is_production_eligible());
    assert!(!RuntimeType::RemoteFirecracker.is_production_eligible());
}

#[test]
fn vm_boundary_classification() {
    assert!(RuntimeType::Firecracker.is_vm_boundary());
    assert!(RuntimeType::Qemu.is_vm_boundary());
    assert!(!RuntimeType::GVisor.is_vm_boundary());
}

#[test]
fn stranded_tenant_with_no_allowed_runtimes() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(vec![], vec![WorkloadClass::PublicUntrusted]);
    let caps = make_capabilities(&[]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    assert!(matches!(
        err,
        BackendSelectionError::NoBackendAvailable { .. }
    ));
}

// ================================================================
// Fail-closed gates
// ================================================================

#[test]
fn omitted_health_map_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: None,
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::HealthCapacity)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn omitted_conformance_map_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: None,
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::ConformanceStatus)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn omitted_image_map_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: None,
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::ImageCompatibility)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn omitted_snapshot_map_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: None,
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::SnapshotCompatibility)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn omitted_protocol_map_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: None,
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::ProtocolCompatibility)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn incompatible_image_rejects_backend() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();
    let mut image = compatible_image(&[RuntimeType::Firecracker]);
    image.insert(
        RuntimeType::Firecracker,
        ImageCompatibility { compatible: false },
    );

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(&image),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::ImageCompatibility)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn incompatible_snapshot_rejects_backend() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();
    let mut snapshot = compatible_snapshot(&[RuntimeType::Firecracker]);
    snapshot.insert(
        RuntimeType::Firecracker,
        SnapshotCompatibility { compatible: false },
    );

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(&snapshot),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::SnapshotCompatibility)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn incompatible_protocol_rejects_backend() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();
    let mut protocol = compatible_protocol(&[RuntimeType::Firecracker]);
    protocol.insert(
        RuntimeType::Firecracker,
        ProtocolCompatibility { compatible: false },
    );

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(&protocol),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::ProtocolCompatibility)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn available_backends_rejects_missing_host_support() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[
        (
            RuntimeType::Firecracker,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
        (
            RuntimeType::Qemu,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
    ]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Qemu));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::FallbackBackendSelected
    );
    assert_eq!(
        result.rejected_candidates[0].runtime,
        RuntimeType::Firecracker
    );
    assert_eq!(
        result.rejected_candidates[0].gate,
        BackendSelectionGate::HostSupport
    );
}

#[test]
fn cross_tenant_without_cpu_policy_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            image_compatibility: Some(default_image()),
            snapshot_compatibility: Some(default_snapshot()),
            protocol_compatibility: Some(default_protocol()),
            cpu_isolation_policy: None,
            cross_tenant_host: true,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::CpuIsolation)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// WorkloadClass serde
// ================================================================

#[test]
fn workload_class_serde_kebab_case() {
    assert_eq!(
        serde_json::to_string(&WorkloadClass::PublicUntrusted).unwrap(),
        r#""public-untrusted""#
    );
    assert_eq!(
        serde_json::to_string(&WorkloadClass::TrustedFastPath).unwrap(),
        r#""trusted-fast-path""#
    );
    assert_eq!(
        serde_json::to_string(&WorkloadClass::CompatibilityVm).unwrap(),
        r#""compatibility-vm""#
    );

    let deser: WorkloadClass = serde_json::from_str(r#""public-untrusted""#).unwrap();
    assert_eq!(deser, WorkloadClass::PublicUntrusted);
}

#[test]
fn runtime_type_serde_kebab_case() {
    assert_eq!(
        serde_json::to_string(&RuntimeType::GVisor).unwrap(),
        r#""gvisor""#
    );
}
