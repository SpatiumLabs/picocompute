use std::time::Instant;

use pico_core::{BackendCapabilities, BackendCapability, RuntimeBackend, RuntimeType};

use super::{BoundaryCategory, BoundaryCheck, IsolationProfile, IsolationReport};

pub(super) async fn validate_backend_boundaries(
    backend: &dyn RuntimeBackend,
    _profile: &IsolationProfile,
    report: &mut IsolationReport,
) {
    let metadata = backend.metadata();

    report.evidence
        .backend_assertions
        .push("backend boundary assertion: each backend must declare its VM/microVM/container boundary type".into());

    let t0 = Instant::now();
    let classification = check_boundary_classification_invariants(&metadata.runtime);
    if classification {
        report.add_check(BoundaryCheck::pass(
            "backend/boundary-classification-invariants",
            BoundaryCategory::Backend,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "backend/boundary-classification-invariants",
            BoundaryCategory::Backend,
            "runtime type boundary classification violates invariants",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let eligibility = check_production_eligibility_invariants(&metadata.runtime);
    report.evidence
        .backend_assertions
        .push("backend boundary assertion: only production-eligible backends may be selected for production workloads".into());

    if eligibility {
        report.add_check(BoundaryCheck::pass(
            "backend/production-eligibility-invariants",
            BoundaryCategory::Backend,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "backend/production-eligibility-invariants",
            BoundaryCategory::Backend,
            "production eligibility invariants violated",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let capabilities_check = check_capability_declarations(&metadata.capabilities);
    report.evidence.backend_assertions.push(
        "backend boundary assertion: each backend must declare its actual capability set".into(),
    );

    if capabilities_check {
        report.add_check(BoundaryCheck::pass(
            "backend/capability-declarations",
            BoundaryCategory::Backend,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "backend/capability-declarations",
            BoundaryCategory::Backend,
            "capability declarations incomplete for isolation boundary",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let selection_policy = check_selection_policy_boundaries();
    report.evidence
        .backend_assertions
        .push("backend boundary assertion: backend selection must enforce isolation floor per workload class".into());

    if selection_policy {
        report.add_check(BoundaryCheck::pass(
            "backend/selection-policy-boundaries",
            BoundaryCategory::Backend,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "backend/selection-policy-boundaries",
            BoundaryCategory::Backend,
            "backend selection policy does not enforce isolation floor",
            t0.elapsed().as_millis() as u64,
        ));
    }
}

fn check_boundary_classification_invariants(runtime: &RuntimeType) -> bool {
    if runtime.is_microvm_boundary() && !runtime.is_vm_boundary() {
        return false;
    }
    true
}

fn check_production_eligibility_invariants(runtime: &RuntimeType) -> bool {
    if runtime.is_production_eligible()
        && (!runtime.is_vm_boundary() && *runtime != RuntimeType::GVisor)
    {
        return false;
    }
    true
}

fn check_capability_declarations(caps: &BackendCapabilities) -> bool {
    let required = BackendCapabilities::from([BackendCapability::Boot]);
    caps.first_missing(&required).is_none()
}

fn check_selection_policy_boundaries() -> bool {
    use pico_core::backend_selection::{IsolationFloor, WorkloadClass};

    let untrusted_floor: IsolationFloor = WorkloadClass::PublicUntrusted.into();
    let fast_path_floor: IsolationFloor = WorkloadClass::TrustedFastPath.into();
    let compat_floor: IsolationFloor = WorkloadClass::CompatibilityVm.into();

    untrusted_floor >= IsolationFloor::MicroVm
        && fast_path_floor >= IsolationFloor::Container
        && compat_floor >= IsolationFloor::MicroVm
}
