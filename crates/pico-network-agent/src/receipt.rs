//! Resource receipts returned by provisioning for durable reconciliation.
//!
//! Receipts are serde-serializable so they can be persisted by sandboxd
//! and used by the reconciliation loop to detect stale or orphaned objects.

use std::time::Duration;

use crate::identity::BackendClass;

/// A receipt proving a network resource was created.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResourceReceipt {
    /// The sandbox this resource belongs to.
    pub sandbox_id: String,
    /// The interface or namespace name.
    pub resource_name: String,
    /// The type of resource created.
    pub kind: ResourceKind,
    /// Whether this resource was successfully created.
    pub created: bool,
    /// Time taken to provision this resource.
    #[serde(with = "duration_serde")]
    pub provision_latency: Duration,
}

impl ResourceReceipt {
    /// Maps this receipt into the sandboxd ledger shape.
    #[must_use]
    pub fn to_ledger(&self) -> pico_core::ResourceReceipt {
        pico_core::ResourceReceipt {
            class: self.kind.as_ledger_class().to_string(),
            name: self.resource_name.clone(),
            external_id: Some(self.sandbox_id.clone()),
        }
    }
}

/// Types of network resources that can be provisioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    /// A TAP device.
    Tap,
    /// A veth pair (sandbox-side and host-side peers).
    Veth,
    /// A network namespace.
    Namespace,
    /// A route entry.
    Route,
    /// An IP address assignment.
    Address,
    /// A link state change (up/down).
    Link,
    /// An nftables egress policy ruleset.
    Egress,
    /// A NAT/masquerade configuration.
    Nat,
    /// A DNS proxy attachment (prerouting redirect rules).
    DnsAttachment,
    /// A bandwidth shaping configuration (tc qdisc).
    Bandwidth,
    /// An eBPF XDP/TC network policy attachment.
    EbpF,
}

impl ResourceKind {
    /// Ledger class string recorded by sandboxd for this resource kind.
    #[must_use]
    pub fn as_ledger_class(self) -> &'static str {
        match self {
            Self::Tap => "tap",
            Self::Veth => "veth",
            Self::Namespace => "namespace",
            Self::Route => "route",
            Self::Address => "address",
            Self::Link => "link",
            Self::Egress => "egress",
            Self::Nat => "nat",
            Self::DnsAttachment => "dns_attachment",
            Self::Bandwidth => "bandwidth",
            Self::EbpF => "ebpf",
        }
    }
}

/// Set of receipts from a provisioning or cleanup operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvisionReceipt {
    pub sandbox_id: String,
    pub backend_class: BackendClass,
    pub resources: Vec<ResourceReceipt>,
    /// The total number of resources that were attempted.
    pub total_attempted: usize,
    /// Whether all resources were provisioned successfully.
    pub completed: bool,
    /// Total time for the entire provisioning operation.
    #[serde(with = "duration_serde")]
    pub total_latency: Duration,
}

/// A receipt proving network resources were cleaned up.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CleanupReceipt {
    pub sandbox_id: String,
    pub resources_removed: Vec<ResourceReceipt>,
    /// Resources that were not found (already cleaned up).
    pub resources_absent: Vec<String>,
    /// Whether cleanup completed without error.
    pub completed: bool,
    #[serde(with = "duration_serde")]
    pub total_latency: Duration,
}

impl ProvisionReceipt {
    #[must_use]
    pub fn new(sandbox_id: String, backend_class: BackendClass, total_attempted: usize) -> Self {
        Self {
            sandbox_id,
            backend_class,
            resources: Vec::with_capacity(total_attempted),
            total_attempted,
            completed: false,
            total_latency: Duration::ZERO,
        }
    }

    /// Add a resource receipt and update total latency.
    pub fn push(&mut self, receipt: ResourceReceipt) {
        self.resources.push(receipt);
    }

    /// Mark provisioning as complete and record total latency.
    pub fn finalize(&mut self, total_latency: Duration) {
        self.total_latency = total_latency;
        self.completed =
            self.resources.iter().filter(|r| r.created).count() == self.total_attempted;
    }
}

impl CleanupReceipt {
    #[must_use]
    pub fn new(sandbox_id: String) -> Self {
        Self {
            sandbox_id,
            resources_removed: Vec::new(),
            resources_absent: Vec::new(),
            completed: false,
            total_latency: Duration::ZERO,
        }
    }

    pub fn push_removed(&mut self, receipt: ResourceReceipt) {
        self.resources_removed.push(receipt);
    }

    pub fn push_absent(&mut self, name: String) {
        self.resources_absent.push(name);
    }

    pub fn finalize(&mut self, total_latency: Duration) {
        self.total_latency = total_latency;
        self.completed = true;
    }
}

mod duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_millis() as u64)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let ms = u64::deserialize(d)?;
        Ok(Duration::from_millis(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn provision_receipt_tracks_completion() {
        let mut receipt = ProvisionReceipt::new("sbx_test".into(), BackendClass::MicroVm, 3);
        assert!(!receipt.completed);

        receipt.push(ResourceReceipt {
            sandbox_id: "sbx_test".into(),
            resource_name: "tap0".into(),
            kind: ResourceKind::Tap,
            created: true,
            provision_latency: Duration::from_millis(10),
        });
        receipt.push(ResourceReceipt {
            sandbox_id: "sbx_test".into(),
            resource_name: "ns0".into(),
            kind: ResourceKind::Namespace,
            created: true,
            provision_latency: Duration::from_millis(5),
        });
        receipt.push(ResourceReceipt {
            sandbox_id: "sbx_test".into(),
            resource_name: "route0".into(),
            kind: ResourceKind::Route,
            created: false,
            provision_latency: Duration::from_millis(1),
        });

        receipt.finalize(Duration::from_millis(50));
        // 2 of 3 succeeded -> not complete
        assert!(!receipt.completed);
        assert_eq!(receipt.total_latency, Duration::from_millis(50));
    }

    #[test]
    fn cleanup_receipt_tracks_absent_resources() {
        let mut receipt = CleanupReceipt::new("sbx_test".into());
        receipt.push_absent("tap0".into());
        receipt.push_absent("ns0".into());
        receipt.finalize(Duration::from_millis(20));

        assert!(receipt.completed);
        assert_eq!(receipt.resources_absent.len(), 2);
        assert_eq!(receipt.resources_removed.len(), 0);
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let mut receipt = ProvisionReceipt::new("sbx_test".into(), BackendClass::MicroVm, 1);
        receipt.push(ResourceReceipt {
            sandbox_id: "sbx_test".into(),
            resource_name: "cvx001".into(),
            kind: ResourceKind::Tap,
            created: true,
            provision_latency: Duration::from_millis(15),
        });
        receipt.finalize(Duration::from_millis(20));

        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: ProvisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.total_attempted, parsed.total_attempted);
        assert_eq!(receipt.completed, parsed.completed);
        assert_eq!(receipt.total_latency, parsed.total_latency);
    }

    #[test]
    fn to_ledger_uses_snake_class_and_resource_name() {
        let receipt = ResourceReceipt {
            sandbox_id: "sbx_test".into(),
            resource_name: "cvx001".into(),
            kind: ResourceKind::DnsAttachment,
            created: true,
            provision_latency: Duration::from_millis(1),
        };
        let ledger = receipt.to_ledger();
        assert_eq!(ledger.class, "dns_attachment");
        assert_eq!(ledger.name, "cvx001");
        assert_eq!(ledger.external_id.as_deref(), Some("sbx_test"));
    }
}
