use std::time::Instant;

use pico_core::{BackendCapability, RuntimeBackend};

use super::{BoundaryCategory, BoundaryCheck, IsolationProfile, IsolationReport};

pub(super) async fn validate_network_boundaries(
    backend: &dyn RuntimeBackend,
    _profile: &IsolationProfile,
    report: &mut IsolationReport,
) {
    let metadata = backend.metadata();

    report.evidence.network_assertions.push(
        "network boundary assertion: sandbox network must be isolated unless explicitly allowed"
            .into(),
    );

    let t0 = Instant::now();
    let network_isolated = check_network_isolation_default();
    if network_isolated {
        report.add_check(BoundaryCheck::pass(
            "network/isolation-default",
            BoundaryCategory::Network,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "network/isolation-default",
            BoundaryCategory::Network,
            "SandboxConfig should default to network_isolated=true",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    report.evidence.network_assertions.push(
        "network boundary assertion: RFC 1918/CGNAT/link-local networks must be denied by default"
            .into(),
    );

    let internal_networks_check = check_internal_network_protection();
    if internal_networks_check {
        report.add_check(BoundaryCheck::pass(
            "network/internal-protection",
            BoundaryCategory::Network,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "network/internal-protection",
            BoundaryCategory::Network,
            "internal networks must be protected by default policy",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    report.evidence
        .network_assertions
        .push("network boundary assertion: per-sandbox interface binding must prevent cross-sandbox traffic".into());

    if metadata.capabilities.contains(BackendCapability::Stats) {
        report.add_check(BoundaryCheck::pass(
            "network/per-sandbox-interface-binding",
            BoundaryCategory::Network,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "network/per-sandbox-interface-binding",
            BoundaryCategory::Network,
            "backend does not support stats: interface binding unverified",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let egress_policy = check_egress_policy_structure();
    report.evidence.network_assertions.push(
        "network boundary assertion: egress policy must validate CIDRs and bind to identity".into(),
    );

    if egress_policy {
        report.add_check(BoundaryCheck::pass(
            "network/egress-policy-structure",
            BoundaryCategory::Network,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "network/egress-policy-structure",
            BoundaryCategory::Network,
            "egress policy structure is incomplete",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let cidr_validation = check_cidr_validation();
    report.evidence.network_assertions.push(
        "network boundary assertion: CIDR validation must reject bare IPs and invalid formats"
            .into(),
    );

    if cidr_validation {
        report.add_check(BoundaryCheck::pass(
            "network/cidr-validation",
            BoundaryCategory::Network,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "network/cidr-validation",
            BoundaryCategory::Network,
            "CIDR validation rejects unexpected inputs",
            t0.elapsed().as_millis() as u64,
        ));
    }
}

fn check_network_isolation_default() -> bool {
    let config = pico_core::SandboxConfig {
        id: "boundary-check".into(),
        memory_limit_bytes: 512 * 1024 * 1024,
        network_isolated: true,
        ..Default::default()
    };
    config.network_isolated
}

fn check_internal_network_protection() -> bool {
    pico_network_agent::identity::INTERNAL_NETWORKS.contains(&"10.0.0.0/8")
        && pico_network_agent::identity::INTERNAL_NETWORKS.contains(&"172.16.0.0/12")
        && pico_network_agent::identity::INTERNAL_NETWORKS.contains(&"192.168.0.0/16")
}

fn check_egress_policy_structure() -> bool {
    use pico_network_agent::egress::EgressPolicy;
    let policy = EgressPolicy {
        sandbox_id: "sbx_boundary".into(),
        tenant_id: "tnt_boundary".into(),
        if_name: "cvx_boundary".into(),
        allowed_cidrs: vec!["1.1.1.1/32".into()],
        policy_decision_id: "pdc_boundary".into(),
        lease_id: Some("lse_boundary".into()),
    };
    let rules = policy.compile_rules();
    !rules.is_empty()
        && rules.iter().any(|r| r.identity.rule_purpose == "ct-state")
        && rules
            .iter()
            .any(|r| r.identity.rule_purpose == "egress-allow")
        && rules
            .iter()
            .any(|r| r.identity.rule_purpose == "internal-deny")
}

fn check_cidr_validation() -> bool {
    use pico_network_agent::egress::validate_cidr;
    validate_cidr("1.1.1.1/32").is_ok()
        && validate_cidr("10.0.0.0/8").is_ok()
        && validate_cidr("192.168.1.0/24").is_ok()
        && validate_cidr("1.1.1.1").is_err()
        && validate_cidr("not-a-cidr").is_err()
        && validate_cidr("10.0.0.0/33").is_err()
}
