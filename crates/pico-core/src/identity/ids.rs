//! Canonical identifier types for PicoCompute resources.
//!
//! Each identifier type uses a ULID-based format with a domain-specific prefix
//! (e.g., `tnt_` for tenants, `sbx_` for sandboxes).

use heapless::String as HString;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Capacity for identifier strings (ULID: prefix + 1 + 26 = max ~31 chars).
const ID_CAPACITY: usize = 128;

macro_rules! define_id {
    (
        $(#[$doc:meta])*
        $name:ident,
        $prefix:literal,
        $stability:literal,
        $is_principal:literal
    ) => {
        $(#[$doc])*
        ///
        /// Stability: {stability}. Security principal: {is_principal}.
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(HString<ID_CAPACITY>);

        impl $name {
            /// Creates a new identifier with the required prefix and ULID-format suffix.
            ///
            /// Delegates to [`crate::types::new_ulid`] for generation.
            pub fn generate() -> Self {
                let raw = crate::types::new_ulid($prefix);
                Self(HString::try_from(raw.as_str()).expect("ULID fits in 128 bytes"))
            }

            /// Wraps an existing string as this identifier.
            ///
            /// Callers are responsible for ensuring the value is valid.
            pub fn from_string(value: impl AsRef<str>) -> Self {
                Self(
                    HString::try_from(value.as_ref())
                        .expect("identifier string exceeds 128-byte capacity"),
                )
            }

            /// Returns the underlying string reference.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the identifier and returns the inner string.
            pub fn into_inner(self) -> HString<ID_CAPACITY> {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

define_id!(
    /// A stable identifier for a PicoCompute tenant.
    TenantId,
    "tnt",
    "stable",
    "no"
);

define_id!(
    /// A stable identifier for a PicoCompute sandbox.
    SandboxId,
    "sbx",
    "stable",
    "no"
);

define_id!(
    /// A stable identifier for a physical or virtual host within a cell.
    HostId,
    "hst",
    "stable",
    "no"
);

define_id!(
    /// A stable identifier for a cell (group of hosts) within a region.
    CellId,
    "cel",
    "stable",
    "no"
);

define_id!(
    /// A stable identifier for a geographic region.
    RegionId,
    "rgn",
    "stable",
    "no"
);

define_id!(
    /// A stable identifier for a container image or rootfs.
    ImageId,
    "img",
    "stable",
    "no"
);

define_id!(
    /// A stable identifier for a point-in-time sandbox snapshot.
    SnapshotId,
    "snp",
    "stable",
    "no"
);

define_id!(
    /// An ephemeral identifier for an access lease.
    LeaseId,
    "lse",
    "ephemeral",
    "no"
);

define_id!(
    /// An ephemeral identifier for a single lifecycle or exec operation.
    OperationId,
    "opr",
    "ephemeral",
    "no"
);

define_id!(
    /// An ephemeral identifier for a policy engine decision.
    PolicyDecisionId,
    "pdc",
    "ephemeral",
    "no"
);

define_id!(
    /// A stable identifier for an immutable audit event record.
    AuditEventId,
    "aev",
    "stable",
    "no"
);

define_id!(
    /// A stable identifier for a COW workspace.
    ///
    /// Workspaces track the filesystem layer stack for a sandbox.
    /// Each fork creates a new workspace that shares immutable base
    /// layers with its parent.
    WorkspaceId,
    "wsp",
    "stable",
    "no"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_generates_with_prefix() {
        let id = TenantId::generate();
        assert!(id.as_str().starts_with("tnt_"));
    }

    #[test]
    fn sandbox_id_generates_with_prefix() {
        let id = SandboxId::generate();
        assert!(id.as_str().starts_with("sbx_"));
    }

    #[test]
    fn identifiers_from_string() {
        let id = HostId::from_string("hst_01JXYZ");
        assert_eq!(id.as_str(), "hst_01JXYZ");
    }

    #[test]
    fn identifier_display_and_as_str_agree() {
        let id = CellId::generate();
        assert_eq!(format!("{id}"), id.as_str().to_string());
    }

    #[test]
    fn identifier_into_inner() {
        let id = RegionId::from_string("rgn_us-east-1");
        assert_eq!(id.into_inner().as_str(), "rgn_us-east-1");
    }

    #[test]
    fn identifiers_are_serializable() {
        let id = SandboxId::generate();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: SandboxId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }

    #[test]
    fn operation_id_prefix() {
        assert!(OperationId::generate().as_str().starts_with("opr_"));
    }

    #[test]
    fn audit_event_id_prefix() {
        assert!(AuditEventId::generate().as_str().starts_with("aev_"));
    }

    #[test]
    fn lease_id_prefix() {
        assert!(LeaseId::generate().as_str().starts_with("lse_"));
    }

    #[test]
    fn policy_decision_id_prefix() {
        assert!(PolicyDecisionId::generate().as_str().starts_with("pdc_"));
    }

    #[test]
    fn workspace_id_prefix() {
        assert!(WorkspaceId::generate().as_str().starts_with("wsp_"));
    }
}
