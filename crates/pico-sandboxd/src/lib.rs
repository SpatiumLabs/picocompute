//! Durable local supervision for sandbox runtimes and host processes.
//!
//! `pico-sandboxd` owns per-sandbox operation serialization, cancellation,
//! deadlines, runtime handles, process handles, and the host-local observed
//! state ledger. The regional control plane remains authoritative for desired
//! lifecycle state.

#![deny(missing_docs)]

pub mod config;
pub mod dns;
mod gc;
pub mod grpc;
pub mod guest;
mod ledger;
pub mod network;
mod process;
pub mod registry;
mod resources;
pub mod secrets;
mod supervisor;

pub use dns::{DnsAttachConfig, DnsAttachManager};
pub use gc::{GarbageCollector, GcStats, OrphanFinding, ResourceClass, has_unsafe_findings};
pub use network::{NetworkAttachManager, NetworkProvisioner};
pub use process::{ProcessOutput, ProcessRequest};
pub use resources::{HostResourceConfig, HostResourceSpec};
pub use secrets::{SecretsCoordinationError, SecretsCoordinator};
pub use supervisor::{
    CommandContext, ForkCommand, GuestSessionError, ObservationWatchEvent, OperationKind,
    OperationOutcome, OutcomeReason, OutcomeStatus, PortTargetObservation, ResolvedPortTarget,
    ResourceReceiptStatus, RestoreCommand, SandboxObservationSnapshot, SandboxStatus,
    SandboxSupervisor, SnapshotRestoreStores, SupervisorError, SupervisorHealth,
};

/// Initialize seccomp filter and drop Linux capabilities for the sandboxd supervisor.
///
/// Loads the embedded sandboxd seccomp profile, enables `no_new_privs`,
/// drops all capabilities not required by the supervisor, and installs
/// the BPF filter. On non-Linux platforms this is a no-op.
pub fn init_seccomp() {
    use pico_seccomp::{CapabilitySet, ComponentProfile};
    use tracing::{error, info};

    info!("initializing seccomp and capability minimization for sandboxd");

    if let Err(e) = pico_seccomp::init_profile_for_component_with_strictness(
        ComponentProfile::Sandboxd,
        &CapabilitySet::sandboxd(),
        true,
        false,
    ) {
        error!("seccomp initialization failed: {e}");
    }
}
