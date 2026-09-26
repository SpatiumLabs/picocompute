//! Network resource reconciliation after host-agent restart.
//!
//! Reconciliation detects stale network resources left behind by
//! interrupted setup or destroy operations. It compares current host
//! state against expected resource names derived from known sandbox
//! identities (via deterministic fnv1a64 hashing) and produces a health
//! assessment, metrics, and audit evidence.
//!
//! # Covered resource classes
//!
//! - **Links** — TAP/veth interfaces and host-side peer interfaces.
//! - **Namespaces** — network namespaces under `/var/run/netns`.
//! - **nftables tables** — per-sandbox policy tables (`pico-sbx-...`).
//! - **Routes** — IPv4 routes on PicoCompute interfaces.
//! - **Addresses** — IPv4 addresses on PicoCompute interfaces.
//! - **Policy rules** — ip-rule entries referencing PicoCompute interfaces.
//! - **NAT chains** — SNAT/masquerade postrouting chains in nftables tables.
//! - **tc qdiscs** — traffic-control qdisc entries on PicoCompute interfaces.
//! - **DNS registrations** — per-sandbox DNS proxy registrations (via trait).
//! - **Port-forwarding** — per-sandbox port-forward endpoints (via trait).
//!
//! # Architecture
//!
//! - Phase 0: compute expected resource names for every known sandbox.
//! - Phase 1-3: enumerate all PicoCompute-owned resources across all classes.
//! - Phase 4: classify each discovered resource against the expected set:
//!   * **ConfirmedOwned** — belongs to a known sandbox.
//!   * **SafeToRemove** — PicoCompute naming, no known owner; safe to delete.
//!   * **RequiresReview** — ambiguous ownership; requires operator review.
//! - Phase 5: attempt safe cleanup of proven-stale resources.
//! - Phase 6: produce a [`ReconciliationReport`] with health assessment.
//!
//! # Conservatism rule
//!
//! Ambiguous or incomplete ownership **never** triggers automatic deletion.
//! The host is marked unsafe so the scheduler can avoid new placement
//! until an operator or fenced re-play resolves the conflict.
//!
//! # Platform support
//!
//! All enumeration is `#[cfg(target_os = "linux")]` gated. Non-Linux
//! platforms return an empty report with `HealthStatus::Ready`.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::metrics;
use crate::netlink::Handle;

mod classification;
mod cleanup;
mod derive_id;
mod enumeration;
mod expected;
pub mod inspectors;
mod nft_json;

use expected::ExpectedResources;
use inspectors::{DnsInspector, NoopDnsInspector, NoopPortForwardInspector, PortForwardInspector};

// ── Public types ────────────────────────────────────────────────────────

/// Overall network health status reported after reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthStatus {
    /// All expected resources are present; no stale objects found.
    Ready,
    /// Minor stale objects were found and cleaned; host can still serve.
    Degraded,
    /// Ambiguous objects remain that could not be safely resolved.
    Unsafe,
}

impl HealthStatus {
    /// Returns true when the host should accept new placements.
    #[must_use]
    pub fn is_serviceable(self) -> bool {
        matches!(self, Self::Ready | Self::Degraded)
    }

    /// Returns the lowercase kebab string for metrics and audit.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Unsafe => "unsafe",
        }
    }
}

/// Whether a stale object can be safely removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafetyAssessment {
    /// No known sandbox matches; deterministic naming proves no owner.
    SafeToRemove,
    /// Partial match or identity conflict; requires operator review.
    RequiresReview,
    /// Resource matches and belongs to an active sandbox (not stale).
    ConfirmedOwned,
}

/// Classification of a stale network resource for cleanup routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceClass {
    /// A TAP or veth sandbox-side interface (cvx prefix).
    TapOrVeth,
    /// A host-side peer interface (hp- or hpc prefix).
    HostPeer,
    /// A network namespace.
    Namespace,
    /// An nftables policy table.
    Nftables,
    /// An IPv4 route entry.
    Route,
    /// An IPv4 address assignment.
    Address,
    /// An ip-rule policy routing entry.
    PolicyRule,
    /// An nftables NAT/masquerade chain.
    NatChain,
    /// A tc traffic-control qdisc entry.
    TcQdisc,
    /// A DNS proxy per-sandbox registration.
    DnsRegistration,
    /// A port-forwarding endpoint per-sandbox registration.
    PortForward,
    /// A resource that does not match any PicoCompute naming convention.
    Unknown,
}

impl ResourceClass {
    /// Returns the stable kebab-case string for tracing and audit.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TapOrVeth => "tap-or-veth",
            Self::HostPeer => "host-peer",
            Self::Namespace => "namespace",
            Self::Nftables => "nftables",
            Self::Route => "route",
            Self::Address => "address",
            Self::PolicyRule => "policy-rule",
            Self::NatChain => "nat-chain",
            Self::TcQdisc => "tc-qdisc",
            Self::DnsRegistration => "dns-registration",
            Self::PortForward => "port-forward",
            Self::Unknown => "unknown",
        }
    }
}

/// A single stale or orphaned network object found during reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaleObject {
    /// What was found (link name, ns path, nftables table name, etc.).
    pub resource_name: String,
    /// Resource class for cleanup routing.
    pub resource_class: ResourceClass,
    /// Sandbox ID derived from the resource name, if any.
    pub derived_sandbox_id: Option<String>,
    /// Whether this object is safe to remove automatically.
    pub safety: SafetyAssessment,
    /// Human-readable evidence for the classification.
    pub evidence: String,
    /// Whether the object was successfully cleaned up.
    pub cleaned_up: bool,
    /// Error message if cleanup was attempted but failed.
    pub cleanup_error: Option<String>,
}

/// The outcome of one reconciliation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationReport {
    /// Overall health assessment after this pass.
    pub health: HealthStatus,
    /// Number of stale (non-owned) objects detected.
    pub stale_count: u64,
    /// Number of stale objects successfully cleaned.
    pub cleaned_count: u64,
    /// Number of ambiguous objects requiring review.
    pub review_required: u64,
    /// Number of objects where cleanup failed.
    pub cleanup_failed: u64,
    /// Number of objects confirmed as owned by known sandboxes.
    pub confirmed_owned: u64,
    /// Detailed findings for audit and operator review.
    pub findings: Vec<StaleObject>,
}

/// Set of known sandbox identifiers for reconciliation.
pub type KnownSandboxIds = BTreeSet<String>;

// ── Reconciler ──────────────────────────────────────────────────────────

/// Network resource reconciler.
///
/// Enumerates the host network stack and classifies every PicoCompute-owned
/// resource against known sandbox identities. Proven-stale resources
/// are cleaned; ambiguous resources degrade the host.
#[derive(Clone)]
pub struct NetworkReconciler {
    dns_inspector: Arc<dyn DnsInspector>,
    port_forward_inspector: Arc<dyn PortForwardInspector>,
}

impl NetworkReconciler {
    /// Create a reconciler that inspects all resource classes.
    ///
    /// Pass [`NoopDnsInspector`] and [`NoopPortForwardInspector`] if
    /// those subsystems are not wired in.
    #[must_use]
    pub fn new(
        dns_inspector: Arc<dyn DnsInspector>,
        port_forward_inspector: Arc<dyn PortForwardInspector>,
    ) -> Self {
        Self {
            dns_inspector,
            port_forward_inspector,
        }
    }

    /// Create a reconciler with no-op inspectors for all cross-crate types.
    #[must_use]
    pub fn with_noop_inspectors() -> Self {
        Self {
            dns_inspector: Arc::new(NoopDnsInspector),
            port_forward_inspector: Arc::new(NoopPortForwardInspector),
        }
    }

    /// Run a full reconciliation pass.
    #[tracing::instrument(skip(self, handle), fields(
        known_sandbox_count = known_ids.len()
    ))]
    pub async fn reconcile(
        &self,
        handle: &Handle,
        known_ids: &KnownSandboxIds,
    ) -> ReconciliationReport {
        let start = Instant::now();
        let mut report = ReconciliationReport::default();

        info!("network reconciliation pass starting");

        // Phase 0: pre-compute expected resource names
        let expected = ExpectedResources::from_known_sandbox_ids(known_ids);

        // Phase 1: links
        for finding in enumeration::enumerate_links(handle, &expected).await {
            report.findings.push(finding);
        }

        // Phase 2: namespaces
        #[cfg(target_os = "linux")]
        for finding in enumeration::enumerate_namespaces(&expected) {
            report.findings.push(finding);
        }

        // Phase 3: nftables tables
        #[cfg(target_os = "linux")]
        for finding in enumeration::enumerate_nftables(known_ids, &expected).await {
            report.findings.push(finding);
        }

        // Phase 4: routes
        #[cfg(target_os = "linux")]
        for finding in enumeration::enumerate_routes(&expected).await {
            report.findings.push(finding);
        }

        // Phase 5: addresses
        #[cfg(target_os = "linux")]
        for finding in enumeration::enumerate_addresses(handle, &expected).await {
            report.findings.push(finding);
        }

        // Phase 6: policy rules
        #[cfg(target_os = "linux")]
        for finding in enumeration::enumerate_policy_rules(&expected).await {
            report.findings.push(finding);
        }

        // Phase 7: NAT chains
        #[cfg(target_os = "linux")]
        for finding in enumeration::enumerate_nat_chains(known_ids, &expected).await {
            report.findings.push(finding);
        }

        // Phase 8: tc qdiscs
        #[cfg(target_os = "linux")]
        for finding in enumeration::enumerate_tc_qdiscs(&expected).await {
            report.findings.push(finding);
        }

        // Phase 9: DNS registrations (cross-crate)
        for finding in
            enumeration::enumerate_dns_registrations(&*self.dns_inspector, known_ids, &expected)
        {
            report.findings.push(finding);
        }

        // Phase 10: port-forwarding (cross-crate)
        for finding in
            enumeration::enumerate_port_forwards(&*self.port_forward_inspector, known_ids)
        {
            report.findings.push(finding);
        }

        // Phase 11: attempt safe cleanup
        #[cfg(target_os = "linux")]
        {
            for finding in &mut report.findings {
                if finding.safety == SafetyAssessment::SafeToRemove && !finding.cleaned_up {
                    match cleanup::cleanup_stale_resource(handle, finding).await {
                        Ok(()) => {
                            finding.cleaned_up = true;
                        }
                        Err(error) => {
                            finding.cleanup_error = Some(error);
                            finding.safety = SafetyAssessment::RequiresReview;
                        }
                    }
                }
            }
        }

        // Phase 12: compute final counts and health
        report.stale_count = report
            .findings
            .iter()
            .filter(|f| f.safety == SafetyAssessment::SafeToRemove)
            .count() as u64;
        report.cleaned_count = report.findings.iter().filter(|f| f.cleaned_up).count() as u64;
        report.cleanup_failed = report
            .findings
            .iter()
            .filter(|f| f.cleanup_error.is_some())
            .count() as u64;
        report.review_required = report
            .findings
            .iter()
            .filter(|f| f.safety == SafetyAssessment::RequiresReview)
            .count() as u64;
        report.confirmed_owned = report
            .findings
            .iter()
            .filter(|f| f.safety == SafetyAssessment::ConfirmedOwned)
            .count() as u64;

        report.health = if report.review_required > 0 {
            HealthStatus::Unsafe
        } else if report.stale_count > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Ready
        };

        let elapsed = start.elapsed();
        emit_reconciliation_metrics(&report, elapsed);

        info!(
            health = %report.health.as_str(),
            stale = report.stale_count,
            cleaned = report.cleaned_count,
            review_required = report.review_required,
            confirmed = report.confirmed_owned,
            cleanup_failed = report.cleanup_failed,
            duration_ms = elapsed.as_millis(),
            "network reconciliation pass completed"
        );

        report
    }
}

// ── Default impl ────────────────────────────────────────────────────────

impl Default for NetworkReconciler {
    fn default() -> Self {
        Self::with_noop_inspectors()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Publishes a reconciliation pass to the network metrics module.
///
/// The module owns the label set, the zero-increment guard, and the health
/// mapping, so this stays a single call at the end of each pass.
fn emit_reconciliation_metrics(report: &ReconciliationReport, duration: Duration) {
    metrics::record_reconciliation_pass(
        duration.as_secs_f64(),
        &metrics::ReconciliationReport {
            stale_count: report.stale_count,
            cleaned_count: report.cleaned_count,
            review_required: report.review_required,
            cleanup_failed: report.cleanup_failed,
            health: match report.health {
                HealthStatus::Ready => metrics::NetworkHealth::Ready,
                HealthStatus::Degraded => metrics::NetworkHealth::Degraded,
                HealthStatus::Unsafe => metrics::NetworkHealth::Unsafe,
            },
        },
    );
}

impl Default for ReconciliationReport {
    fn default() -> Self {
        Self {
            health: HealthStatus::Ready,
            stale_count: 0,
            cleaned_count: 0,
            review_required: 0,
            cleanup_failed: 0,
            confirmed_owned: 0,
            findings: Vec::new(),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_serviceable() {
        assert!(HealthStatus::Ready.is_serviceable());
        assert!(HealthStatus::Degraded.is_serviceable());
        assert!(!HealthStatus::Unsafe.is_serviceable());
    }

    #[test]
    fn health_status_strings() {
        assert_eq!(HealthStatus::Ready.as_str(), "ready");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        assert_eq!(HealthStatus::Unsafe.as_str(), "unsafe");
    }

    #[test]
    fn report_default_is_ready() {
        let report = ReconciliationReport::default();
        assert_eq!(report.health, HealthStatus::Ready);
        assert_eq!(report.stale_count, 0);
    }

    #[test]
    fn resource_class_as_str_all_variants() {
        let classes = [
            (ResourceClass::TapOrVeth, "tap-or-veth"),
            (ResourceClass::HostPeer, "host-peer"),
            (ResourceClass::Namespace, "namespace"),
            (ResourceClass::Nftables, "nftables"),
            (ResourceClass::Route, "route"),
            (ResourceClass::Address, "address"),
            (ResourceClass::PolicyRule, "policy-rule"),
            (ResourceClass::NatChain, "nat-chain"),
            (ResourceClass::TcQdisc, "tc-qdisc"),
            (ResourceClass::DnsRegistration, "dns-registration"),
            (ResourceClass::PortForward, "port-forward"),
            (ResourceClass::Unknown, "unknown"),
        ];
        for (class, expected) in &classes {
            assert_eq!(class.as_str(), *expected, "mismatch for {class:?}");
        }
    }

    #[test]
    fn resource_class_serialization_roundtrip() {
        let classes = [
            ResourceClass::TapOrVeth,
            ResourceClass::HostPeer,
            ResourceClass::Namespace,
            ResourceClass::Nftables,
            ResourceClass::Route,
            ResourceClass::Address,
            ResourceClass::PolicyRule,
            ResourceClass::NatChain,
            ResourceClass::TcQdisc,
            ResourceClass::DnsRegistration,
            ResourceClass::PortForward,
            ResourceClass::Unknown,
        ];
        for class in &classes {
            let json = serde_json::to_string(class).unwrap();
            let parsed: ResourceClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*class, parsed);
        }
    }

    #[test]
    fn reconciler_default_is_noop_inspectors() {
        let r = NetworkReconciler::default();
        // Verify construction doesn't panic
        let _ = r;
    }

    #[test]
    fn reconciler_with_noop_inspectors_constructs() {
        let _ = NetworkReconciler::with_noop_inspectors();
    }

    // ── ExpectedResources ────────────────────────────────────────

    #[test]
    fn expected_resources_owns_its_own_links() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);

        let hash = crate::identity::fnv1a64(b"sbx_test");
        let hex = format!("{:010x}", hash & 0xffffffffff);
        let own_link = format!("cvx{hex}");

        assert!(
            expected.owns_link(&own_link),
            "expected resources should own its own sandbox link"
        );
    }

    #[test]
    fn expected_resources_does_not_own_unknown_link() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        assert!(!expected.owns_link("cvxdeadbeef0"));
    }

    #[test]
    fn expected_resources_owns_both_microvm_and_container_peers() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let hash = crate::identity::fnv1a64(b"sbx_test");
        let hex = format!("{:010x}", hash & 0xffffffffff);
        assert!(expected.owns_link(&format!("cvx{hex}")));
        assert!(expected.owns_link(&format!("hp-{hex}")));
        assert!(expected.owns_link(&format!("hpc{hex}")));
    }

    #[test]
    fn expected_resources_owns_namespaces() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let hash = crate::identity::fnv1a64(b"sbx_test");
        let hex = format!("{:010x}", hash & 0xffffffffff);
        assert!(expected.owns_ns(&format!("cvx{hex}")));
        assert!(expected.owns_ns(&format!("cnt-cvx{hex}")));
    }

    #[test]
    fn expected_resources_computes_guest_ips() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        assert!(!expected.guest_ips.is_empty(), "should compute guest IPs");
    }

    // ── Classification ──────────────────────────────────────────

    #[test]
    fn classify_link_confirmed_owned() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let hash = crate::identity::fnv1a64(b"sbx_test");
        let hex = format!("{:010x}", hash & 0xffffffffff);
        let link = format!("cvx{hex}");
        let (safety, _) = classification::classify_link(&link, &expected);
        assert_eq!(safety, SafetyAssessment::ConfirmedOwned);
    }

    #[test]
    fn classify_link_safe_to_remove() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let (safety, _) = classification::classify_link("cvxdeadbeef0", &expected);
        assert_eq!(safety, SafetyAssessment::SafeToRemove);
    }

    #[test]
    fn classify_route_confirmed_owned() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let hash = crate::identity::fnv1a64(b"sbx_test");
        let hex = format!("{:010x}", hash & 0xffffffffff);
        let if_name = format!("cvx{hex}");
        let (safety, _) = classification::classify_route(
            "default via 172.16.0.1 dev cvx...",
            &if_name,
            &expected,
        );
        assert_eq!(safety, SafetyAssessment::ConfirmedOwned);
    }

    #[test]
    fn classify_route_safe_to_remove() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let (safety, _) = classification::classify_route(
            "default via 10.0.0.1 dev cvxdeadbeef0",
            "cvxdeadbeef0",
            &expected,
        );
        assert_eq!(safety, SafetyAssessment::SafeToRemove);
    }

    #[test]
    fn classify_address_confirmed_owned() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let hash = crate::identity::fnv1a64(b"sbx_test");
        let hex = format!("{:010x}", hash & 0xffffffffff);
        let if_name = format!("cvx{hex}");
        let (safety, _) = classification::classify_address("172.16.0.2", &if_name, &expected);
        assert_eq!(safety, SafetyAssessment::ConfirmedOwned);
    }

    #[test]
    fn classify_nft_table_confirmed_owned() {
        let mut known = BTreeSet::new();
        known.insert("sandbox123".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let hash = crate::identity::fnv1a64(b"sandbox123");
        let hex = format!("{:010x}", hash & 0xffffffffff);
        let table = format!("pico-sbx-sandbox123-cvx{hex}");
        let (safety, _) = classification::classify_nft_table(&table, &known, &expected);
        assert_eq!(safety, SafetyAssessment::ConfirmedOwned);
    }

    #[test]
    fn classify_dns_registration_confirmed_owned() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let (safety, _) = classification::classify_dns_registration("sbx_test", &known, &expected);
        assert_eq!(safety, SafetyAssessment::ConfirmedOwned);
    }

    #[test]
    fn classify_port_forward_confirmed_owned() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let (safety, _) = classification::classify_port_forward("sbx_test", &known);
        assert_eq!(safety, SafetyAssessment::ConfirmedOwned);
    }

    #[test]
    fn classify_port_forward_safe_to_remove() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let (safety, _) = classification::classify_port_forward("unknown_sbx", &known);
        assert_eq!(safety, SafetyAssessment::SafeToRemove);
    }

    #[test]
    fn classify_tc_qdisc_confirmed_owned() {
        let mut known = BTreeSet::new();
        known.insert("sbx_test".to_string());
        let expected = ExpectedResources::from_known_sandbox_ids(&known);
        let hash = crate::identity::fnv1a64(b"sbx_test");
        let hex = format!("{:010x}", hash & 0xffffffffff);
        let if_name = format!("cvx{hex}");
        let (safety, _) = classification::classify_tc_qdisc(
            "qdisc fq_codel 0: dev cvx... root",
            &if_name,
            &expected,
        );
        assert_eq!(safety, SafetyAssessment::ConfirmedOwned);
    }

    // ── FNV hash matches identity module ────────────────────────

    #[test]
    fn fnv1a64_matches_identity_module() {
        use crate::identity::{BackendClass, SandboxNetworkIdentity};

        let identity = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::MicroVm);
        assert!(identity.if_name.starts_with("cvx"));
        let hash = crate::identity::fnv1a64(b"sbx_test");
        let hex = format!("{:010x}", hash & 0xffffffffff);
        assert_eq!(identity.if_name, format!("cvx{hex}"));
    }

    // ── Name derivation ─────────────────────────────────────────

    #[test]
    fn derive_sandbox_id_from_link_parses() {
        assert_eq!(
            derive_id::derive_sandbox_id_from_link("cvx0000000001"),
            Some("anon-cvx-0000000001".to_string())
        );
        assert_eq!(
            derive_id::derive_sandbox_id_from_link("hp-0000000001"),
            Some("anon-cvx-0000000001".to_string())
        );
        assert_eq!(derive_id::derive_sandbox_id_from_link("eth0"), None);
    }

    #[test]
    fn derive_sandbox_id_from_nft_table_parses() {
        assert_eq!(
            derive_id::derive_sandbox_id_from_nft_table("pico-sbx-sandbox123-cvx0000000001"),
            Some("sandbox123".to_string())
        );
        assert_eq!(
            derive_id::derive_sandbox_id_from_nft_table("my-table"),
            None
        );
    }

    // ── Inspector no-ops ────────────────────────────────────────

    #[test]
    fn noop_dns_inspector_returns_empty() {
        let inspector = inspectors::NoopDnsInspector;
        assert!(inspector.registered_sandbox_ids().is_empty());
        assert_eq!(inspector.sandbox_cache_entry_count("any"), 0);
        assert_eq!(inspector.total_cache_sandbox_count(), 0);
    }

    #[test]
    fn noop_port_forward_inspector_returns_empty() {
        let inspector = inspectors::NoopPortForwardInspector;
        assert!(inspector.registered_sandbox_ids().is_empty());
    }
}
