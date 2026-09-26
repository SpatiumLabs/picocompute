//! Pre-computed expected resource names for known sandboxes.
//!
//! Link, namespace, and address names come from
//! [`crate::identity::SandboxNetworkIdentity`].
//! The prefix constants classify observed objects that are not in that set.

use std::collections::BTreeSet;

use crate::identity::{BackendClass, SandboxNetworkIdentity};

use super::KnownSandboxIds;

// Naming prefix constants
pub(super) const PREFIX_SANDBOX_IF: &str = "cvx";
pub(super) const PREFIX_HOST_PEER_VM: &str = "hp-";
pub(super) const PREFIX_HOST_PEER_CT: &str = "hpc";
pub(super) const PREFIX_NS_CT: &str = "cnt-";
pub(super) const PREFIX_NFT_TABLE: &str = "pico-sbx-";

/// Returns true if the link name matches PicoCompute naming conventions.
pub(super) fn is_pico_link(name: &str) -> bool {
    name.starts_with(PREFIX_SANDBOX_IF)
        || name.starts_with(PREFIX_HOST_PEER_VM)
        || name.starts_with(PREFIX_HOST_PEER_CT)
}

/// Returns true if the network namespace name matches PicoCompute conventions.
pub(super) fn is_pico_ns(name: &str) -> bool {
    name.starts_with(PREFIX_SANDBOX_IF) || name.starts_with(PREFIX_NS_CT)
}

/// Split `sandbox-id` from a trailing interface name.
///
/// The interface marker is one of the naming prefixes (`-cvx`, `-hpc`, `-hp-`).
/// Returns `(sandbox_id, if_name)` when a marker is present.
pub(super) fn split_resource_suffix(suffix: &str) -> Option<(&str, &str)> {
    for prefix in [PREFIX_SANDBOX_IF, PREFIX_HOST_PEER_CT, PREFIX_HOST_PEER_VM] {
        let marker = format!("-{prefix}");
        if let Some(pos) = suffix.rfind(&marker) {
            return Some((&suffix[..pos], &suffix[pos + 1..]));
        }
    }
    None
}

/// Returns the resource class for a link name.
pub(super) fn link_kind_to_class(name: &str) -> super::ResourceClass {
    if name.starts_with(PREFIX_SANDBOX_IF) {
        super::ResourceClass::TapOrVeth
    } else if name.starts_with(PREFIX_HOST_PEER_VM) || name.starts_with(PREFIX_HOST_PEER_CT) {
        super::ResourceClass::HostPeer
    } else {
        super::ResourceClass::Unknown
    }
}

/// Pre-computed set of expected network resource names.
#[derive(Debug, Clone)]
pub(super) struct ExpectedResources {
    /// Interface names expected for known sandboxes.
    pub link_names: BTreeSet<String>,
    /// Namespace base names expected (without `/var/run/netns/` prefix).
    pub ns_names: BTreeSet<String>,
    /// Guest IPs expected for known sandboxes (for DNS/route matching).
    pub guest_ips: BTreeSet<String>,
}

impl ExpectedResources {
    /// Build expected resource names for every known sandbox.
    ///
    /// For each sandbox ID, derives MicroVM and Container identities
    /// through [`SandboxNetworkIdentity::for_sandbox`]. This is
    /// intentionally over-inclusive: a sandbox uses only one backend.
    pub(super) fn from_known_sandbox_ids(known_ids: &KnownSandboxIds) -> Self {
        let mut link_names = BTreeSet::new();
        let mut ns_names = BTreeSet::new();
        let mut guest_ips = BTreeSet::new();

        for sandbox_id in known_ids {
            for backend in [BackendClass::MicroVm, BackendClass::Container] {
                let identity = SandboxNetworkIdentity::for_sandbox(sandbox_id, backend);
                let ns_name = identity.ns_name().to_string();
                let guest_ip = identity.guest_ip.to_string();
                link_names.insert(identity.if_name);
                link_names.insert(identity.host_if_name);
                ns_names.insert(ns_name);
                guest_ips.insert(guest_ip);
            }
        }

        Self {
            link_names,
            ns_names,
            guest_ips,
        }
    }

    /// Returns true if the given link name matches any expected sandbox.
    pub(super) fn owns_link(&self, name: &str) -> bool {
        self.link_names.contains(name)
    }

    /// Returns true if the given namespace base name matches any expected sandbox.
    pub(super) fn owns_ns(&self, name: &str) -> bool {
        self.ns_names.contains(name)
    }

    /// Returns true if the given guest IP matches any expected sandbox.
    pub(super) fn owns_guest_ip(&self, ip: &str) -> bool {
        self.guest_ips.contains(ip)
    }
}
