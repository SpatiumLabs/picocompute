//! Backend selection property tests.
//!
//! Covers deterministic selection invariants over randomized inputs: workload
//! order is fixed, isolation floors never weaken, fail-closed gates reject on
//! missing evidence, and public classes never select a container backend.
//!
//! Run with:
//! ```bash
//! cargo nextest run -p pico-core --test backend_selection_property
//! ```

use hashbrown::HashMap;
use pico_core::backend_selection::{
    BackendSelectionGate, BackendSelectionPolicy, ConformanceStatus, ImageCompatibility,
    IsolationFloor, ProtocolCompatibility, SelectionInputs, SnapshotCompatibility, WorkloadClass,
};
use pico_core::identity::TenantId;
use pico_core::runtime::{BackendCapabilities, BackendCapability, BackendHealth, RuntimeType};
use pico_core::tenant::{Tenant, TenantStatus};
use proptest::prelude::*;

fn arb_workload() -> impl Strategy<Value = WorkloadClass> {
    prop_oneof![
        Just(WorkloadClass::PublicUntrusted),
        Just(WorkloadClass::TrustedFastPath),
        Just(WorkloadClass::CompatibilityVm),
        Just(WorkloadClass::KubernetesIntegrated),
    ]
}

fn arb_runtime() -> impl Strategy<Value = RuntimeType> {
    prop_oneof![
        Just(RuntimeType::Firecracker),
        Just(RuntimeType::Qemu),
        Just(RuntimeType::GVisor),
    ]
}

fn test_tenant() -> Tenant {
    Tenant {
        id: TenantId::generate(),
        name: "prop-tenant".into(),
        status: TenantStatus::Active,
        allowed_runtimes: vec![
            RuntimeType::Firecracker,
            RuntimeType::Qemu,
            RuntimeType::GVisor,
        ],
        allowed_workload_classes: vec![
            WorkloadClass::PublicUntrusted,
            WorkloadClass::TrustedFastPath,
            WorkloadClass::CompatibilityVm,
            WorkloadClass::KubernetesIntegrated,
        ],
        policy_epoch: Some(1),
    }
}

fn full_caps() -> HashMap<RuntimeType, BackendCapabilities> {
    let all = [
        BackendCapability::Boot,
        BackendCapability::GuestTransport,
        BackendCapability::Exec,
        BackendCapability::Health,
    ];
    [
        RuntimeType::Firecracker,
        RuntimeType::Qemu,
        RuntimeType::GVisor,
    ]
    .into_iter()
    .map(|rt| (rt, BackendCapabilities::new(all.iter().copied())))
    .collect()
}

type EvidenceMaps = (
    HashMap<RuntimeType, ConformanceStatus>,
    HashMap<RuntimeType, BackendHealth>,
    HashMap<RuntimeType, ImageCompatibility>,
    HashMap<RuntimeType, SnapshotCompatibility>,
    HashMap<RuntimeType, ProtocolCompatibility>,
);

fn passing_maps() -> EvidenceMaps {
    let conf = [
        RuntimeType::Firecracker,
        RuntimeType::Qemu,
        RuntimeType::GVisor,
    ]
    .into_iter()
    .map(|rt| {
        (
            rt,
            ConformanceStatus {
                passing: true,
                profile: None,
            },
        )
    })
    .collect();
    let health = [
        RuntimeType::Firecracker,
        RuntimeType::Qemu,
        RuntimeType::GVisor,
    ]
    .into_iter()
    .map(|rt| (rt, BackendHealth::ready()))
    .collect();
    let image = [
        RuntimeType::Firecracker,
        RuntimeType::Qemu,
        RuntimeType::GVisor,
    ]
    .into_iter()
    .map(|rt| (rt, ImageCompatibility { compatible: true }))
    .collect();
    let snapshot = [
        RuntimeType::Firecracker,
        RuntimeType::Qemu,
        RuntimeType::GVisor,
    ]
    .into_iter()
    .map(|rt| (rt, SnapshotCompatibility { compatible: true }))
    .collect();
    let protocol = [
        RuntimeType::Firecracker,
        RuntimeType::Qemu,
        RuntimeType::GVisor,
    ]
    .into_iter()
    .map(|rt| (rt, ProtocolCompatibility { compatible: true }))
    .collect();
    (conf, health, image, snapshot, protocol)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Isolation floor mapping never weakens below MicroVm except for the
    /// explicit trusted fast path.
    #[test]
    fn floor_never_weakens(class in arb_workload()) {
        let floor = IsolationFloor::from(class);
        match class {
            WorkloadClass::TrustedFastPath => prop_assert_eq!(floor, IsolationFloor::Container),
            _ => prop_assert!(floor >= IsolationFloor::MicroVm),
        }
    }

    /// Public and Kubernetes classes never select a container backend even
    /// when every gate passes for all backends.
    #[test]
    fn public_classes_never_select_container(class in prop_oneof![
        Just(WorkloadClass::PublicUntrusted),
        Just(WorkloadClass::KubernetesIntegrated),
    ]) {
        let policy = BackendSelectionPolicy::new();
        let tenant = test_tenant();
        let caps = full_caps();
        let required = BackendCapabilities::new([BackendCapability::Boot].into_iter());
        let (conf, health, image, snapshot, protocol) = passing_maps();
        let available = vec![RuntimeType::Firecracker, RuntimeType::Qemu, RuntimeType::GVisor];
        let result = policy.evaluate(&SelectionInputs {
            workload_class: class,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &available,
            backend_capabilities: &caps,
            conformance: Some(&conf),
            host_health: Some(&health),
            image_compatibility: Some(&image),
            snapshot_compatibility: Some(&snapshot),
            protocol_compatibility: Some(&protocol),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        });
        if let Ok(selection) = result {
            let selected = selection.selected.unwrap();
            prop_assert!(selected != RuntimeType::GVisor);
        }
    }

    /// Missing evidence maps always fail closed with the matching gate.
    #[test]
    fn missing_evidence_fails_closed(
        omit in prop_oneof![
            Just(BackendSelectionGate::HealthCapacity),
            Just(BackendSelectionGate::ConformanceStatus),
            Just(BackendSelectionGate::ImageCompatibility),
            Just(BackendSelectionGate::SnapshotCompatibility),
            Just(BackendSelectionGate::ProtocolCompatibility),
        ]
    ) {
        let policy = BackendSelectionPolicy::new();
        let tenant = test_tenant();
        let caps = full_caps();
        let required = BackendCapabilities::new([BackendCapability::Boot].into_iter());
        let (conf, health, image, snapshot, protocol) = passing_maps();
        let available = vec![RuntimeType::Firecracker];
        let result = policy.evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &available,
            backend_capabilities: &caps,
            conformance: if omit == BackendSelectionGate::ConformanceStatus { None } else { Some(&conf) },
            host_health: if omit == BackendSelectionGate::HealthCapacity { None } else { Some(&health) },
            image_compatibility: if omit == BackendSelectionGate::ImageCompatibility { None } else { Some(&image) },
            snapshot_compatibility: if omit == BackendSelectionGate::SnapshotCompatibility { None } else { Some(&snapshot) },
            protocol_compatibility: if omit == BackendSelectionGate::ProtocolCompatibility { None } else { Some(&protocol) },
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        });
        prop_assert!(result.is_err(), "omitted {omit} must fail closed");
        if let Err(pico_core::backend_selection::BackendSelectionError::NoBackendAvailable { rejected, .. }) = result {
            prop_assert!(rejected.iter().any(|r| r.gate == omit), "missing {omit} must record its gate");
        }
    }

    /// Selection is deterministic: same inputs always give the same outcome.
    #[test]
    fn selection_is_deterministic(class in arb_workload(), runtime in arb_runtime()) {
        let policy = BackendSelectionPolicy::new();
        let tenant = test_tenant();
        let caps = full_caps();
        let required = BackendCapabilities::new([BackendCapability::Boot].into_iter());
        let (conf, health, image, snapshot, protocol) = passing_maps();
        let available = vec![runtime];
        let inputs = SelectionInputs {
            workload_class: class,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &available,
            backend_capabilities: &caps,
            conformance: Some(&conf),
            host_health: Some(&health),
            image_compatibility: Some(&image),
            snapshot_compatibility: Some(&snapshot),
            protocol_compatibility: Some(&protocol),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        };
        let first = policy.evaluate(&inputs).map(|s| s.selected);
        let second = policy.evaluate(&inputs).map(|s| s.selected);
        prop_assert_eq!(first.is_ok(), second.is_ok());
        if let (Ok(a), Ok(b)) = (first, second) {
            prop_assert_eq!(a, b);
        }
    }

    /// Cross-tenant hosts require CPU isolation evidence; without a policy
    /// every VM candidate is rejected at the CpuIsolation gate.
    #[test]
    fn cross_tenant_without_policy_fails_at_cpu_gate(_in in Just(())) {
        let policy = BackendSelectionPolicy::new();
        let tenant = test_tenant();
        let caps = full_caps();
        let required = BackendCapabilities::new([BackendCapability::Boot].into_iter());
        let (conf, health, image, snapshot, protocol) = passing_maps();
        let available = vec![RuntimeType::Firecracker, RuntimeType::Qemu];
        let result = policy.evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &available,
            backend_capabilities: &caps,
            conformance: Some(&conf),
            host_health: Some(&health),
            image_compatibility: Some(&image),
            snapshot_compatibility: Some(&snapshot),
            protocol_compatibility: Some(&protocol),
            cpu_isolation_policy: None,
            cross_tenant_host: true,
        });
        prop_assert!(result.is_err());
        if let Err(pico_core::backend_selection::BackendSelectionError::NoBackendAvailable { rejected, .. }) = result {
            prop_assert!(rejected.iter().any(|r| r.gate == BackendSelectionGate::CpuIsolation));
        }
    }
}
