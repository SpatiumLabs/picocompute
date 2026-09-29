//! Sandbox runtime backends for Firecracker, QEMU, and gVisor.

pub mod base;
pub mod conformance;
pub mod firecracker;
pub mod guest_agent;
pub mod gvisor;
pub mod isolation;
pub mod mock;
pub mod qemu;
pub mod reclaim;
pub mod remote_firecracker;
pub mod snapshot_optimizer;
pub mod validation;

pub use base::RuntimeHardening;
pub use reclaim::{
    ContainerReclaimHandle, MicroVmReclaimHandle, ReclaimError, estimate_reclaimed_bytes,
};

use pico_core::runtime::BackendCapabilities;

/// Declared capability set for a runtime family.
///
/// `AdapterRegistry` in `pico-sandboxd` builds one adapter per prepare call,
/// and `RuntimeBackend::metadata` is a pure function of the adapter type. This
/// exposes the same set to processes that must gate on capabilities without
/// owning an adapter instance, such as the host agent's image admission path
/// (which must know whether a backend can present a composable layer stack
/// before it admits the image).
///
/// Delegating rather than repeating the lists keeps a single source of truth:
/// an adapter that gains a capability cannot drift from what the host believes
/// it supports.
#[must_use]
pub fn declared_capabilities(runtime_type: pico_core::RuntimeType) -> BackendCapabilities {
    use pico_core::RuntimeType;
    use pico_core::runtime::RuntimeBackend as _;

    match runtime_type {
        RuntimeType::Firecracker => {
            firecracker::FirecrackerAdapter::new()
                .metadata()
                .capabilities
        }
        RuntimeType::RemoteFirecracker => {
            remote_firecracker::RemoteFirecrackerAdapter::new()
                .metadata()
                .capabilities
        }
        RuntimeType::Qemu => qemu::QemuAdapter::new().metadata().capabilities,
        RuntimeType::GVisor => gvisor::GVisorAdapter::new().metadata().capabilities,
    }
}

/// Initialize seccomp profile and capability minimization for a runtime backend.
///
/// Maps each `RuntimeType` variant to its dedicated seccomp profile and applies
/// the shared `runtime_backend()` capability set. Failure is non-fatal (warning
/// only) since some environments (e.g., CI, macOS) may not support seccomp.
pub fn init_seccomp(runtime_type: pico_core::RuntimeType) {
    use pico_core::RuntimeType;
    use pico_seccomp::{CapabilitySet, ComponentProfile};

    let profile = match runtime_type {
        RuntimeType::Firecracker | RuntimeType::RemoteFirecracker => {
            ComponentProfile::RuntimeFirecracker
        }
        RuntimeType::Qemu => ComponentProfile::RuntimeQemu,
        RuntimeType::GVisor => ComponentProfile::RuntimeGvisor,
    };

    let _ = pico_seccomp::init_profile_for_component_with_strictness(
        profile,
        &CapabilitySet::runtime_backend(),
        true,
        false,
    );
}
