//! Sandbox runtime backends for Firecracker, QEMU, and gVisor.

pub mod base;
pub mod conformance;
pub mod firecracker;
pub mod guest_agent;
pub mod gvisor;
pub mod isolation;
pub mod mock;
pub mod qemu;
pub mod remote_firecracker;
pub mod snapshot_optimizer;
pub mod validation;

pub use base::RuntimeHardening;

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
