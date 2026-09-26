//! Host-side observation cache and coherence policy.
//!
//! This module is the only host-agent boundary that merges supervisor
//! observations into a local mirror. It owns generation ordering, host-boot
//! resets, and preservation of non-empty SSH identity fields. It never mutates
//! desired lifecycle state.

use pico_core::{
    ObservationEpoch, RuntimeType, SandboxState, SshObservation, merge_ssh_observation,
};
use pico_sandboxd_proto::v1::{
    RuntimeType as ProtoRuntime, SandboxObservation, SandboxState as ProtoState,
};

/// Local mirror of the latest accepted supervisor observation.
#[derive(Debug, Clone)]
pub struct ObservationSnapshot {
    /// Monotonic generation for cache invalidation.
    pub generation: u64,
    /// Last observed sandbox state.
    pub observed_state: SandboxState,
    /// Backend or runtime label.
    pub backend: String,
    /// Host boot id reported by sandboxd.
    pub host_boot_id: String,
    /// Guest boot id when known.
    pub guest_boot_id: String,
    /// Port targets from the latest accepted observation.
    pub ports: Vec<pico_sandboxd_proto::v1::PortTarget>,
    /// Host-authoritative SSH username.
    pub ssh_username: String,
    /// Optional host SSH port from observation.
    pub ssh_host_port: Option<u16>,
    /// Optional SSH public key reported by sandboxd.
    pub ssh_public_key: Option<String>,
    /// Last update timestamp from sandboxd.
    pub updated_at: String,
}

impl Default for ObservationSnapshot {
    fn default() -> Self {
        Self {
            generation: 0,
            observed_state: SandboxState::Pending,
            backend: String::new(),
            host_boot_id: String::new(),
            guest_boot_id: String::new(),
            ports: Vec::new(),
            ssh_username: "root".into(),
            ssh_host_port: None,
            ssh_public_key: None,
            updated_at: String::new(),
        }
    }
}

impl ObservationSnapshot {
    /// Returns the snapshot's ordering epoch.
    #[must_use]
    pub fn epoch(&self) -> ObservationEpoch {
        ObservationEpoch::new(self.generation, self.host_boot_id.clone())
    }
}

/// Applies one observation to a local snapshot if it is not stale.
///
/// Empty SSH fields are intentionally ignored. Older supervisors omit those
/// fields on some events, and treating omission as deletion would make a
/// reconnect lose usable connection metadata.
pub fn apply_observation(cache: &mut ObservationSnapshot, observation: &SandboxObservation) {
    let incoming = ObservationEpoch::new(observation.generation, observation.host_boot_id.clone());
    if !cache.epoch().accepts(&incoming) {
        return;
    }

    cache.generation = incoming.generation;
    cache.host_boot_id = incoming.host_boot_id;
    if let Some(state) = proto_state_to_core(observation.observed_state) {
        cache.observed_state = state;
    }
    if let Some(backend) = proto_runtime_to_core(observation.backend) {
        cache.backend = backend.to_string();
    }
    cache.guest_boot_id = observation.guest_boot_id.clone();
    cache.ports = observation.ports.clone();
    if let Some(ssh) = &observation.ssh {
        let incoming = SshObservation {
            username: ssh.username.clone(),
            host_port: ssh.host_port.and_then(|port| u16::try_from(port).ok()),
            public_key: ssh.public_key.clone(),
        };
        merge_ssh_observation(
            &mut cache.ssh_username,
            &mut cache.ssh_host_port,
            &mut cache.ssh_public_key,
            &incoming,
        );
    }
    cache.updated_at = observation.updated_at.clone();
}

/// Maps the wire state enum into the core lifecycle contract.
pub(crate) fn proto_state_to_core(value: i32) -> Option<SandboxState> {
    let proto = ProtoState::try_from(value).ok()?;
    match proto {
        ProtoState::Unspecified => None,
        ProtoState::Pending => Some(SandboxState::Pending),
        ProtoState::Scheduled => Some(SandboxState::Scheduled),
        ProtoState::Preparing => Some(SandboxState::Preparing),
        ProtoState::Booting => Some(SandboxState::Booting),
        ProtoState::Running => Some(SandboxState::Running),
        ProtoState::Suspending => Some(SandboxState::Suspending),
        ProtoState::Suspended => Some(SandboxState::Suspended),
        ProtoState::Resuming => Some(SandboxState::Resuming),
        ProtoState::Stopped => Some(SandboxState::Stopped),
        ProtoState::Destroying => Some(SandboxState::Destroying),
        ProtoState::Destroyed => Some(SandboxState::Destroyed),
        ProtoState::Failed => Some(SandboxState::Failed),
    }
}

/// Maps the wire runtime enum into the core runtime contract.
pub(crate) fn proto_runtime_to_core(value: i32) -> Option<RuntimeType> {
    let proto = ProtoRuntime::try_from(value).ok()?;
    match proto {
        ProtoRuntime::Unspecified => None,
        ProtoRuntime::Firecracker => Some(RuntimeType::Firecracker),
        ProtoRuntime::Qemu => Some(RuntimeType::Qemu),
        ProtoRuntime::Gvisor => Some(RuntimeType::GVisor),
        ProtoRuntime::RemoteFirecracker => Some(RuntimeType::RemoteFirecracker),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(generation: u64, host_boot_id: &str) -> SandboxObservation {
        SandboxObservation {
            sandbox_id: "sbx_obs".into(),
            observed_state: ProtoState::Running as i32,
            generation,
            host_boot_id: host_boot_id.into(),
            guest_boot_id: String::new(),
            backend: ProtoRuntime::Firecracker as i32,
            ports: Vec::new(),
            ssh: None,
            policy_epoch: 1,
            assignment_fencing_token: "1.1".into(),
            updated_at: "t".into(),
        }
    }

    #[test]
    fn stale_observation_does_not_regress_fields() {
        let mut cache = ObservationSnapshot::default();
        apply_observation(&mut cache, &observation(7, "boot-a"));
        let mut stale = observation(3, "boot-a");
        stale.observed_state = ProtoState::Stopped as i32;
        apply_observation(&mut cache, &stale);
        assert_eq!(cache.generation, 7);
        assert_eq!(cache.observed_state, SandboxState::Running);
    }

    #[test]
    fn new_boot_accepts_lower_generation() {
        let mut cache = ObservationSnapshot::default();
        apply_observation(&mut cache, &observation(9, "boot-a"));
        apply_observation(&mut cache, &observation(1, "boot-b"));
        assert_eq!(cache.generation, 1);
        assert_eq!(cache.host_boot_id, "boot-b");
    }

    #[test]
    fn empty_ssh_fields_preserve_existing_identity() {
        let mut cache = ObservationSnapshot::default();
        let mut first = observation(1, "boot-a");
        first.ssh = Some(pico_sandboxd_proto::v1::SshObservation {
            host_port: Some(22022),
            username: "root".into(),
            public_key: Some("key-a".into()),
        });
        apply_observation(&mut cache, &first);
        let mut second = observation(2, "boot-a");
        second.ssh = Some(pico_sandboxd_proto::v1::SshObservation {
            host_port: Some(22023),
            username: String::new(),
            public_key: None,
        });
        apply_observation(&mut cache, &second);
        assert_eq!(cache.ssh_host_port, Some(22023));
        assert_eq!(cache.ssh_username, "root");
        assert_eq!(cache.ssh_public_key.as_deref(), Some("key-a"));
    }
}
