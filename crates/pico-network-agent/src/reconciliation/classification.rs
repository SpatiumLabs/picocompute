//! Classification helpers — determine whether a discovered resource
//! is owned, safe to remove, or requires operator review.

use super::expected::ExpectedResources;
use super::{KnownSandboxIds, SafetyAssessment};

// ── Links ───────────────────────────────────────────────────────────────

pub(super) fn classify_link(
    name: &str,
    expected: &ExpectedResources,
) -> (SafetyAssessment, String) {
    if expected.owns_link(name) {
        (
            SafetyAssessment::ConfirmedOwned,
            format!("link {name} belongs to a known sandbox"),
        )
    } else {
        (
            SafetyAssessment::SafeToRemove,
            format!("link {name} does not belong to any known sandbox — safe to remove"),
        )
    }
}

// ── Namespaces ──────────────────────────────────────────────────────────

pub(super) fn classify_namespace(
    name: &str,
    expected: &ExpectedResources,
) -> (SafetyAssessment, String) {
    if expected.owns_ns(name) {
        (
            SafetyAssessment::ConfirmedOwned,
            format!("namespace {name} belongs to a known sandbox"),
        )
    } else {
        (
            SafetyAssessment::SafeToRemove,
            format!("namespace {name} does not belong to any known sandbox — safe to remove"),
        )
    }
}

// ── nftables tables ─────────────────────────────────────────────────────

pub(super) fn classify_nft_table(
    table_name: &str,
    known_ids: &KnownSandboxIds,
    expected: &ExpectedResources,
) -> (SafetyAssessment, String) {
    use super::expected::PREFIX_NFT_TABLE;

    let Some(rest) = table_name.strip_prefix(PREFIX_NFT_TABLE) else {
        return (
            SafetyAssessment::RequiresReview,
            format!(
                "nftables table {table_name} does not match PicoCompute naming — requires operator review"
            ),
        );
    };

    let (sandbox_id, if_name) = split_nft_table_suffix(rest);

    if known_ids.contains(sandbox_id) && expected.owns_link(if_name) {
        (
            SafetyAssessment::ConfirmedOwned,
            format!("nftables table {table_name} belongs to known sandbox {sandbox_id}"),
        )
    } else {
        (
            SafetyAssessment::SafeToRemove,
            format!(
                "nftables table {table_name} (sandbox {sandbox_id}) does not match any known sandbox — safe to remove"
            ),
        )
    }
}

/// Split `{sandbox_id}-{if_name}` on the interface prefix from `expected`.
fn split_nft_table_suffix(suffix: &str) -> (&str, &str) {
    super::expected::split_resource_suffix(suffix).unwrap_or((suffix, ""))
}

// ── Routes ──────────────────────────────────────────────────────────────

pub(super) fn classify_route(
    _route_line: &str,
    if_name: &str,
    expected: &ExpectedResources,
) -> (SafetyAssessment, String) {
    if expected.owns_link(if_name) {
        (
            SafetyAssessment::ConfirmedOwned,
            format!("route on {if_name} belongs to a known sandbox"),
        )
    } else {
        (
            SafetyAssessment::SafeToRemove,
            format!("route on {if_name} (no known sandbox) — safe to remove"),
        )
    }
}

// ── Addresses ───────────────────────────────────────────────────────────

pub(super) fn classify_address(
    addr: &str,
    if_name: &str,
    expected: &ExpectedResources,
) -> (SafetyAssessment, String) {
    if expected.owns_link(if_name) {
        (
            SafetyAssessment::ConfirmedOwned,
            format!("address {addr} on {if_name} belongs to a known sandbox"),
        )
    } else {
        (
            SafetyAssessment::SafeToRemove,
            format!("address {addr} on {if_name} (no known sandbox) — safe to remove"),
        )
    }
}

// ── Policy rules ────────────────────────────────────────────────────────

pub(super) fn classify_policy_rule(
    rule_line: &str,
    expected: &ExpectedResources,
) -> (SafetyAssessment, String) {
    // Check if any PicoCompute-referenced interface in the rule is owned
    let has_owned_if = expected
        .link_names
        .iter()
        .any(|name| rule_line.contains(name.as_str()));

    if has_owned_if {
        (
            SafetyAssessment::ConfirmedOwned,
            "policy rule references a known sandbox interface".to_string(),
        )
    } else {
        (
            SafetyAssessment::SafeToRemove,
            format!("policy rule ({rule_line}) — no known sandbox, safe to remove"),
        )
    }
}

// ── NAT chains ──────────────────────────────────────────────────────────

pub(super) fn classify_nft_chain(
    table_name: &str,
    _family: &str,
    chain_name: &str,
    known_ids: &KnownSandboxIds,
    expected: &ExpectedResources,
) -> (SafetyAssessment, String) {
    use super::expected::PREFIX_NFT_TABLE;

    let Some(rest) = table_name.strip_prefix(PREFIX_NFT_TABLE) else {
        return (
            SafetyAssessment::RequiresReview,
            format!("nft chain {chain_name} in {table_name} — unparseable name"),
        );
    };

    let (sandbox_id, if_name) = split_nft_table_suffix(rest);

    if known_ids.contains(sandbox_id) && expected.owns_link(if_name) {
        (
            SafetyAssessment::ConfirmedOwned,
            format!("NAT chain {chain_name} in {table_name} belongs to known sandbox {sandbox_id}"),
        )
    } else {
        (
            SafetyAssessment::SafeToRemove,
            format!("NAT chain {chain_name} in {table_name} — no known sandbox, safe to remove"),
        )
    }
}

// ── tc qdisc ────────────────────────────────────────────────────────────

pub(super) fn classify_tc_qdisc(
    qdisc_line: &str,
    if_name: &str,
    expected: &ExpectedResources,
) -> (SafetyAssessment, String) {
    if expected.owns_link(if_name) {
        (
            SafetyAssessment::ConfirmedOwned,
            format!("tc qdisc on {if_name} belongs to a known sandbox"),
        )
    } else {
        (
            SafetyAssessment::SafeToRemove,
            format!("tc qdisc on {if_name} (no known sandbox) — safe to remove: {qdisc_line}"),
        )
    }
}

// ── DNS registrations ───────────────────────────────────────────────────

pub(super) fn classify_dns_registration(
    sandbox_id: &str,
    known_ids: &KnownSandboxIds,
    expected: &ExpectedResources,
) -> (SafetyAssessment, String) {
    if known_ids.contains(sandbox_id) {
        (
            SafetyAssessment::ConfirmedOwned,
            format!("DNS registration for {sandbox_id} belongs to known sandbox"),
        )
    } else if !expected.owns_guest_ip(sandbox_id) {
        (
            SafetyAssessment::SafeToRemove,
            format!("DNS registration for {sandbox_id} — no known sandbox, safe to remove"),
        )
    } else {
        (
            SafetyAssessment::RequiresReview,
            format!("DNS registration for {sandbox_id} — ambiguous ownership"),
        )
    }
}

// ── Port-forwarding ─────────────────────────────────────────────────────

pub(super) fn classify_port_forward(
    sandbox_id: &str,
    known_ids: &KnownSandboxIds,
) -> (SafetyAssessment, String) {
    if known_ids.contains(sandbox_id) {
        (
            SafetyAssessment::ConfirmedOwned,
            format!("port-forward for {sandbox_id} belongs to known sandbox"),
        )
    } else {
        (
            SafetyAssessment::SafeToRemove,
            format!("port-forward for {sandbox_id} — no known sandbox, safe to remove"),
        )
    }
}
