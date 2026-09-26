//! Deterministic per-sandbox network identity derived from the sandbox ID.
//!
//! Uses fnv1a64 hashing to produce stable TAP/veth names, MAC addresses,
//! IPv4 addresses, and namespace paths without storing state.

use std::net::Ipv4Addr;

/// Backend class determining which network objects to provision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendClass {
    /// MicroVM backends (Firecracker, QEMU) -- TAP device + namespace.
    MicroVm,
    /// Container-backed backends (gVisor, container) -- veth pair + namespace.
    Container,
}

impl BackendClass {
    /// Returns the kebab-case string for metric labels.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MicroVm => "microvm",
            Self::Container => "container",
        }
    }
}

/// Logical network identity for a single sandbox.
///
/// All fields are deterministically derived from `sandbox_id` via fnv1a64,
/// ensuring the same ID always produces the same interface names, addresses,
/// and namespace paths across hosts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SandboxNetworkIdentity {
    /// The original sandbox identifier.
    pub sandbox_id: String,
    /// Backend class for provisioning strategy.
    pub backend_class: BackendClass,
    /// Deterministic TAP or veth interface name (<= 15 chars, Linux IFNAMSIZ).
    pub if_name: String,
    /// Host-side veth name for container backends, or host uplink peer for microVMs.
    pub host_if_name: String,
    /// Guest-side IP address (assigned to sandbox interface).
    pub guest_ip: Ipv4Addr,
    /// Host-side IP address (gateway for guest).
    pub host_ip: Ipv4Addr,
    /// MAC address for the sandbox-side interface.
    pub guest_mac: String,
    /// Prefix length for the point-to-point link.
    pub prefix_len: u8,
    /// Network namespace path (e.g. `/var/run/netns/cvx-{hash}`).
    pub ns_path: String,
}

impl SandboxNetworkIdentity {
    /// Derive a network identity deterministically from a sandbox ID.
    #[must_use]
    pub fn for_sandbox(sandbox_id: &str, backend_class: BackendClass) -> Self {
        let hash = fnv1a64(sandbox_id.as_bytes());
        let subnet = hash % (16 * 256 * 64);
        let second_octet = 16 + (subnet / (256 * 64)) as u8;
        let third_octet = ((subnet / 64) % 256) as u8;
        let fourth_octet = ((subnet % 64) * 4) as u8;
        let mac_bytes = hash.to_be_bytes();

        let (if_name, host_if_name, ns_path) = match backend_class {
            BackendClass::MicroVm => {
                let tap = format!("cvx{:010x}", hash & 0xffffffffff);
                // `hp-{tap}` is 16 characters and exceeds IFNAMSIZ (15), so
                // link creation and bandwidth shaping reject it. Keep the
                // `hp-` prefix and the same 10 hex digits without repeating
                // `cvx`.
                let host = format!("hp-{:010x}", hash & 0xffffffffff);
                let ns = format!("/var/run/netns/{tap}");
                (tap, host, ns)
            }
            BackendClass::Container => {
                let sandbox = format!("cvx{:010x}", hash & 0xffffffffff);
                let host = format!("hpc{:010x}", hash & 0xffffffffff);
                let ns = format!("/var/run/netns/cnt-{sandbox}");
                (sandbox, host, ns)
            }
        };

        Self {
            sandbox_id: sandbox_id.to_string(),
            backend_class,
            if_name,
            host_if_name,
            guest_ip: Ipv4Addr::new(172, second_octet, third_octet, fourth_octet + 2),
            host_ip: Ipv4Addr::new(172, second_octet, third_octet, fourth_octet + 1),
            guest_mac: format!(
                "02:fc:{:02x}:{:02x}:{:02x}:{:02x}",
                mac_bytes[4], mac_bytes[5], mac_bytes[6], mac_bytes[7]
            ),
            prefix_len: 30,
            ns_path,
        }
    }

    /// Returns the sandbox-side interface name.
    #[must_use]
    pub fn sandbox_if_name(&self) -> &str {
        &self.if_name
    }

    /// Returns the host-side interface name.
    #[must_use]
    pub fn host_if_name(&self) -> &str {
        &self.host_if_name
    }

    /// Returns the interface name to use for stats collection.
    ///
    /// For microVM backends, returns the TAP device name (host-side).
    /// For container backends, returns the host-side veth peer name.
    #[must_use]
    pub fn if_name_for_stats(&self) -> &str {
        match self.backend_class {
            BackendClass::MicroVm => &self.if_name,
            BackendClass::Container => &self.host_if_name,
        }
    }

    /// Network namespace base name: the last component of [`Self::ns_path`].
    #[must_use]
    pub fn ns_name(&self) -> &str {
        Self::namespace_base_name(&self.ns_path)
    }

    /// Last path component of a namespace path.
    ///
    /// `/var/run/netns/cvx0123456789` yields `cvx0123456789`. A path with no
    /// slash is returned unchanged.
    #[must_use]
    pub fn namespace_base_name(ns_path: &str) -> &str {
        ns_path.rsplit_once('/').map_or(ns_path, |(_, base)| base)
    }

    /// Returns true when both identities would claim the same host resource.
    ///
    /// A shared interface name, address, MAC, or namespace path is a conflict.
    /// Sandbox id and backend class are not resources.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.if_name == other.if_name
            || self.host_if_name == other.host_if_name
            || self.guest_ip == other.guest_ip
            || self.host_ip == other.host_ip
            || self.guest_mac == other.guest_mac
            || self.ns_path == other.ns_path
    }
}

/// Well-known internal platform networks that must be denied by default.
///
/// These RFC 1918, CGNAT, and link-local ranges require an explicit
/// lease-granted egress exception to permit traffic.
pub const INTERNAL_NETWORKS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "224.0.0.0/4",
];

/// Computes the deterministic guest IP address for a sandbox.
///
/// The address does not depend on backend class. This delegates to
/// [`SandboxNetworkIdentity::for_sandbox`] so the subnet formula lives
/// in one place.
#[must_use]
pub fn sandbox_guest_ip(sandbox_id: &str) -> Ipv4Addr {
    SandboxNetworkIdentity::for_sandbox(sandbox_id, BackendClass::MicroVm).guest_ip
}

/// FNV-1a 64-bit hash for deterministic resource naming.
#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable() {
        let id1 = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::MicroVm);
        let id2 = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::MicroVm);
        assert_eq!(id1, id2);
    }

    #[test]
    fn pinned_vector_for_external_tap_provisioning() {
        // Pinned for scripts/live-boot-tap-watch.sh, which reimplements this
        // derivation in Python. If this vector changes, update the script's
        // formula comment and vice versa. Values cross-checked against a live
        // run (sbx-live-fc-42781 provisioned cvx11b8572062 on 172.28.129.137/30).
        let id = SandboxNetworkIdentity::for_sandbox("sbx-live-fc-42781", BackendClass::MicroVm);
        assert_eq!(id.if_name, "cvx11b8572062");
        assert_eq!(id.guest_ip, Ipv4Addr::new(172, 28, 129, 138));
        assert_eq!(id.host_ip, Ipv4Addr::new(172, 28, 129, 137));
        assert_eq!(id.guest_mac, "02:fc:b8:57:20:62");
        assert_eq!(id.prefix_len, 30);
    }

    #[test]
    fn different_sandboxes_have_different_identities() {
        let id1 = SandboxNetworkIdentity::for_sandbox("sbx_a", BackendClass::MicroVm);
        let id2 = SandboxNetworkIdentity::for_sandbox("sbx_b", BackendClass::MicroVm);
        assert_ne!(id1.if_name, id2.if_name);
        assert_ne!(id1.guest_ip, id2.guest_ip);
        assert_ne!(id1.guest_mac, id2.guest_mac);
    }

    #[test]
    fn microvm_uses_tap_naming() {
        let id = SandboxNetworkIdentity::for_sandbox("test_sbx_123", BackendClass::MicroVm);
        assert!(
            id.if_name.starts_with("cvx"),
            "TAP name should start with cvx"
        );
        assert!(
            id.host_if_name.starts_with("hp-"),
            "Host peer should start with hp-"
        );
        assert!(id.ns_path.starts_with("/var/run/netns/"));
        assert!(id.if_name.len() <= 15, "IFNAMSIZ <= 15");
        assert!(
            id.host_if_name.len() <= 15,
            "host IFNAMSIZ <= 15, got {} ({})",
            id.host_if_name.len(),
            id.host_if_name
        );
    }

    #[test]
    fn container_uses_veth_naming() {
        let id = SandboxNetworkIdentity::for_sandbox("test_sbx_123", BackendClass::Container);
        assert!(
            id.if_name.starts_with("cvx"),
            "Container iface should start with cvx"
        );
        assert!(
            id.host_if_name.starts_with("hpc"),
            "Host peer should start with hpc"
        );
        assert!(id.ns_path.starts_with("/var/run/netns/"));
        assert!(id.if_name.len() <= 15, "IFNAMSIZ <= 15");
        assert!(id.host_if_name.len() <= 15, "host IFNAMSIZ <= 15");
    }

    #[test]
    fn prefix_len_is_30_for_ptp() {
        let id = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::MicroVm);
        assert_eq!(id.prefix_len, 30);
    }

    #[test]
    fn guest_mac_is_locally_administered_unicast() {
        let id = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::MicroVm);
        let parts: Vec<&str> = id.guest_mac.split(':').collect();
        assert_eq!(parts.len(), 6);
        let first_byte = u8::from_str_radix(parts[0], 16).unwrap();
        assert_eq!(
            first_byte & 0b0000_0010,
            0b0000_0010,
            "locally administered bit"
        );
        assert_eq!(first_byte & 0b0000_0001, 0, "unicast bit");
    }

    #[test]
    fn sandbox_id_is_not_leaked_in_resource_names() {
        let id = SandboxNetworkIdentity::for_sandbox("tenant-abc_task-xyz", BackendClass::MicroVm);
        assert!(!id.if_name.contains("tenant"));
        assert!(!id.if_name.contains("task"));
        assert!(!id.host_if_name.contains("tenant"));
        assert!(!id.ns_path.contains("tenant"));
    }

    #[test]
    fn microvm_and_container_produce_different_host_if_names() {
        let vm = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::MicroVm);
        let ct = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::Container);
        assert_ne!(vm.host_if_name, ct.host_if_name);
        assert_ne!(vm.ns_path, ct.ns_path);
    }

    #[test]
    fn serde_roundtrip() {
        let id = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::MicroVm);
        let json = serde_json::to_string(&id).unwrap();
        let parsed: SandboxNetworkIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn backend_class_as_str() {
        assert_eq!(BackendClass::MicroVm.as_str(), "microvm");
        assert_eq!(BackendClass::Container.as_str(), "container");
    }

    #[test]
    fn if_name_for_stats_microvm_uses_tap() {
        let id = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::MicroVm);
        assert_eq!(id.if_name_for_stats(), id.if_name);
        assert!(!id.if_name_for_stats().starts_with("hp-"));
    }

    #[test]
    fn if_name_for_stats_container_uses_host_peer() {
        let id = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::Container);
        assert_eq!(id.if_name_for_stats(), id.host_if_name);
        assert!(id.if_name_for_stats().starts_with("hpc"));
    }

    #[test]
    fn ns_name_is_the_path_base() {
        let vm = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::MicroVm);
        assert_eq!(vm.ns_name(), vm.if_name);
        assert_eq!(vm.ns_path, format!("/var/run/netns/{}", vm.ns_name()));
        let ct = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::Container);
        assert!(ct.ns_name().starts_with("cnt-"));
        assert_eq!(ct.ns_path, format!("/var/run/netns/{}", ct.ns_name()));
    }

    #[test]
    fn conflicts_with_matches_any_resource_field() {
        let left = SandboxNetworkIdentity::for_sandbox("sbx_a", BackendClass::MicroVm);
        let right = SandboxNetworkIdentity::for_sandbox("sbx_b", BackendClass::MicroVm);
        assert!(!left.conflicts_with(&right));
        assert!(left.conflicts_with(&left));

        let mut host_peer = right.clone();
        host_peer.host_if_name.clone_from(&left.host_if_name);
        assert!(left.conflicts_with(&host_peer));

        let mut mac = right.clone();
        mac.guest_mac.clone_from(&left.guest_mac);
        assert!(left.conflicts_with(&mac));
    }
}
