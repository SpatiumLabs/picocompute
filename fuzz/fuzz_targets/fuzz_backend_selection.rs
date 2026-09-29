//! Fuzz target for backend selection inputs.
//!
//! Parses workload class and runtime strings from arbitrary bytes and
//! evaluates the selection policy with bit-derived evidence maps. Selection
//! must be deterministic and fail closed on missing evidence.

#![no_main]

use pico_core::backend_selection::{
    BackendSelectionPolicy, ConformanceStatus, ImageCompatibility, ProtocolCompatibility,
    SelectionInputs, SnapshotCompatibility, WorkloadClass,
};
use pico_core::runtime::{BackendCapabilities, BackendCapability, BackendHealth, RuntimeType};
use pico_core::tenant::{Tenant, TenantStatus};
use pico_core::ServiceClass;
use pico_core::identity::TenantId;
use hashbrown::HashMap;
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

fn workload_from_byte(b: u8) -> WorkloadClass {
    match b % 4 {
        0 => WorkloadClass::PublicUntrusted,
        1 => WorkloadClass::TrustedFastPath,
        2 => WorkloadClass::CompatibilityVm,
        _ => WorkloadClass::KubernetesIntegrated,
    }
}

fn runtime_from_byte(b: u8) -> RuntimeType {
    match b % 3 {
        0 => RuntimeType::Firecracker,
        1 => RuntimeType::Qemu,
        _ => RuntimeType::GVisor,
    }
}

fn fuzz_one(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    // String parsers must never panic on arbitrary UTF8.
    if let Ok(text) = std::str::from_utf8(data) {
        let head: String = text.chars().take(32).collect();
        let _ = WorkloadClass::from_str(&head);
        let _ = RuntimeType::from_str(&head);
    }
    let class = workload_from_byte(data[0]);
    let hint = data.get(1).copied().unwrap_or(0);
    let tenant = Tenant {
        id: TenantId::generate(),
        name: "fuzz".into(),
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
        default_service_class: ServiceClass::LatencySensitive,
        policy_epoch: Some(1),
    };
    let caps = BackendCapabilities::new(
        [
            BackendCapability::Boot,
            BackendCapability::GuestTransport,
            BackendCapability::Exec,
        ]
        .into_iter(),
    );
    let required = BackendCapabilities::new([BackendCapability::Boot].into_iter());
    let mut backend_caps = HashMap::new();
    backend_caps.insert(RuntimeType::Firecracker, caps.clone());
    backend_caps.insert(RuntimeType::Qemu, caps.clone());
    backend_caps.insert(RuntimeType::GVisor, caps);
    // Evidence presence is derived from input bits so fuzz explores both
    // the pass and fail-closed paths.
    let present = |bit: u8| hint & (1 << (bit % 8)) != 0;
    let conf: HashMap<RuntimeType, ConformanceStatus> = [RuntimeType::Firecracker]
        .into_iter()
        .map(|rt| {
            (
                rt,
                ConformanceStatus {
                    passing: present(0),
                    profile: None,
                },
            )
        })
        .collect();
    let health: HashMap<RuntimeType, BackendHealth> = [RuntimeType::Firecracker]
        .into_iter()
        .map(|rt| (rt, BackendHealth::ready()))
        .collect();
    let image: HashMap<RuntimeType, ImageCompatibility> = [RuntimeType::Firecracker]
        .into_iter()
        .map(|rt| {
            (
                rt,
                ImageCompatibility {
                    compatible: present(1),
                },
            )
        })
        .collect();
    let snapshot: HashMap<RuntimeType, SnapshotCompatibility> = [RuntimeType::Firecracker]
        .into_iter()
        .map(|rt| {
            (
                rt,
                SnapshotCompatibility {
                    compatible: present(2),
                },
            )
        })
        .collect();
    let protocol: HashMap<RuntimeType, ProtocolCompatibility> = [RuntimeType::Firecracker]
        .into_iter()
        .map(|rt| {
            (
                rt,
                ProtocolCompatibility {
                    compatible: present(3),
                },
            )
        })
        .collect();
    let available = vec![runtime_from_byte(hint)];
    let policy = BackendSelectionPolicy::new();
    let first = policy.evaluate(&SelectionInputs {
        workload_class: class,
        tenant: &tenant,
        required_capabilities: &required,
        available_backends: &available,
        backend_capabilities: &backend_caps,
        conformance: if present(4) { Some(&conf) } else { None },
        host_health: if present(5) { Some(&health) } else { None },
        image_compatibility: if present(6) { Some(&image) } else { None },
        snapshot_compatibility: if present(0) { Some(&snapshot) } else { None },
        protocol_compatibility: if present(1) { Some(&protocol) } else { None },
        cpu_isolation_policy: None,
        cross_tenant_host: false,
    });
    // Determinism: same inputs give the same outcome.
    let second = policy.evaluate(&SelectionInputs {
        workload_class: class,
        tenant: &tenant,
        required_capabilities: &required,
        available_backends: &available,
        backend_capabilities: &backend_caps,
        conformance: if present(4) { Some(&conf) } else { None },
        host_health: if present(5) { Some(&health) } else { None },
        image_compatibility: if present(6) { Some(&image) } else { None },
        snapshot_compatibility: if present(0) { Some(&snapshot) } else { None },
        protocol_compatibility: if present(1) { Some(&protocol) } else { None },
        cpu_isolation_policy: None,
        cross_tenant_host: false,
    });
    assert_eq!(first.is_ok(), second.is_ok());
}

fuzz_target!(|data: &[u8]| {
    fuzz_one(data);
});
