//! Enumeration functions — discover all PicoCompute-owned resources on the host.
//!
//! Each function returns `Vec<StaleObject>` findings. Only resources that
//! match PicoCompute naming conventions are included.

use tokio_stream::StreamExt;
use tracing::{debug, warn};

use super::StaleObject;
use crate::netlink::Handle;

use super::classification::{
    classify_address, classify_dns_registration, classify_link, classify_namespace,
    classify_nft_chain, classify_nft_table, classify_policy_rule, classify_port_forward,
    classify_route, classify_tc_qdisc,
};
use super::expected::{ExpectedResources, is_pico_link, is_pico_ns, link_kind_to_class};
use super::inspectors::{DnsInspector, PortForwardInspector};
use super::{KnownSandboxIds, ResourceClass};

// ── Links ───────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub(super) async fn enumerate_links(
    handle: &Handle,
    expected: &ExpectedResources,
) -> Vec<StaleObject> {
    let mut findings = Vec::new();

    let mut stream = handle.link().get().execute();
    while let Some(Ok(link)) = stream.next().await {
        for attr in &link.attributes {
            if let crate::netlink::packet::link::LinkAttribute::IfName(name) = attr {
                let name_str = name.as_str();
                if is_pico_link(name_str) {
                    let (safety, evidence) = classify_link(name_str, expected);
                    findings.push(StaleObject {
                        resource_name: name_str.to_string(),
                        resource_class: link_kind_to_class(name_str),
                        derived_sandbox_id: super::derive_id::derive_sandbox_id_from_link(name_str),
                        safety,
                        evidence,
                        cleaned_up: false,
                        cleanup_error: None,
                    });
                }
            }
        }
    }

    findings
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn enumerate_links(
    _handle: &Handle,
    _expected: &ExpectedResources,
) -> Vec<StaleObject> {
    Vec::new()
}

// ── Namespaces ──────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub(super) fn enumerate_namespaces(expected: &ExpectedResources) -> Vec<StaleObject> {
    let mut findings = Vec::new();

    let entries = match std::fs::read_dir("/var/run/netns") {
        Ok(entries) => entries,
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                warn!(error = %error, "failed to read /var/run/netns for reconciliation");
            }
            return findings;
        }
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !is_pico_ns(name) {
            continue;
        }
        let ns_path = format!("/var/run/netns/{name}");
        let (safety, evidence) = classify_namespace(name, expected);
        findings.push(StaleObject {
            resource_name: ns_path,
            resource_class: ResourceClass::Namespace,
            derived_sandbox_id: super::derive_id::derive_sandbox_id_from_ns(name),
            safety,
            evidence,
            cleaned_up: false,
            cleanup_error: None,
        });
    }

    findings
}

#[cfg(not(target_os = "linux"))]
pub(super) fn enumerate_namespaces(_expected: &ExpectedResources) -> Vec<StaleObject> {
    Vec::new()
}

// ── nftables ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub(super) struct NftTableEntry {
    pub family: String,
    pub name: String,
}

#[cfg(target_os = "linux")]
pub(super) async fn enumerate_nftables(
    known_ids: &KnownSandboxIds,
    expected: &ExpectedResources,
) -> Vec<StaleObject> {
    let mut findings = Vec::new();
    let tables = list_pico_nft_tables().await;
    for table in &tables {
        let derived = super::derive_id::derive_sandbox_id_from_nft_table(&table.name);
        let (safety, evidence) = classify_nft_table(&table.name, known_ids, expected);
        findings.push(StaleObject {
            resource_name: format!("{}:{}", table.family, table.name),
            resource_class: ResourceClass::Nftables,
            derived_sandbox_id: derived,
            safety,
            evidence,
            cleaned_up: false,
            cleanup_error: None,
        });
    }
    findings
}

#[cfg(target_os = "linux")]
async fn list_pico_nft_tables() -> Vec<NftTableEntry> {
    use std::process::Stdio;
    use tokio::process::Command;

    let output = match Command::new("nft")
        .args(["-j", "list", "tables"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            debug!(error = %e, "nft list tables failed");
            return Vec::new();
        }
    };
    if !output.status.success() {
        return Vec::new();
    }
    super::nft_json::extract_pico_table_entries(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn enumerate_nftables(
    _known_ids: &KnownSandboxIds,
    _expected: &ExpectedResources,
) -> Vec<StaleObject> {
    Vec::new()
}

// ── CLI output enumerator (shared) ─────────────────────────────────────

/// Run a CLI command, parse its stdout line-by-line, and classify each
/// line that references a PicoCompute interface via the named fields.
#[cfg(target_os = "linux")]
async fn enumerate_cli_output(
    program: &str,
    args: &[&str],
    field_names: &[&str],
    classify: impl Fn(&str, &str, &ExpectedResources) -> (super::SafetyAssessment, String),
    resource_class: ResourceClass,
    expected: &ExpectedResources,
) -> Vec<StaleObject> {
    use std::process::Stdio;
    use tokio::process::Command;

    let mut findings = Vec::new();

    let output = match Command::new(program)
        .args(args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "{program} failed for reconciliation");
            return findings;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let if_name = line
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .find(|w| field_names.iter().any(|&f| f == w[0]))
            .map(|w| w[1]);

        let Some(if_name) = if_name else {
            continue;
        };
        if !is_pico_link(if_name) {
            continue;
        }

        let (safety, evidence) = classify(line, if_name, expected);
        findings.push(StaleObject {
            resource_name: line.to_string(),
            resource_class,
            derived_sandbox_id: super::derive_id::derive_sandbox_id_from_link(if_name),
            safety,
            evidence,
            cleaned_up: false,
            cleanup_error: None,
        });
    }

    findings
}

// ── Routes ──────────────────────────────────────────────────────────────

/// Enumerate IPv4 routes associated with PicoCompute interfaces.
#[cfg(target_os = "linux")]
pub(super) async fn enumerate_routes(expected: &ExpectedResources) -> Vec<StaleObject> {
    enumerate_cli_output(
        "ip",
        &["-4", "route", "list"],
        &["dev"],
        classify_route,
        ResourceClass::Route,
        expected,
    )
    .await
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn enumerate_routes(_expected: &ExpectedResources) -> Vec<StaleObject> {
    Vec::new()
}

// ── Addresses ───────────────────────────────────────────────────────────

/// Enumerate IPv4 addresses on PicoCompute interfaces via netlink.
#[cfg(target_os = "linux")]
pub(super) async fn enumerate_addresses(
    handle: &Handle,
    expected: &ExpectedResources,
) -> Vec<StaleObject> {
    let mut findings = Vec::new();

    let mut stream = handle.address().get().execute();
    while let Some(Ok(msg)) = stream.next().await {
        // Map address to interface name via link index
        let mut addr_str = String::new();
        let if_index = msg.header.index;
        for attr in &msg.attributes {
            if let crate::netlink::packet::address::AddressAttribute::Address(ip) = attr {
                addr_str = ip.to_string();
            }
        }
        if addr_str.is_empty() || if_index == 0 {
            continue;
        }
        // Resolve if_index to interface name
        let if_name = resolve_if_name(handle, if_index).await;
        let Some(ref if_name) = if_name else {
            continue;
        };
        if !is_pico_link(if_name) {
            continue;
        }

        let (safety, evidence) = classify_address(&addr_str, if_name, expected);
        findings.push(StaleObject {
            resource_name: format!("{addr_str}@{}", if_name),
            resource_class: ResourceClass::Address,
            derived_sandbox_id: super::derive_id::derive_sandbox_id_from_link(if_name),
            safety,
            evidence,
            cleaned_up: false,
            cleanup_error: None,
        });
    }

    findings
}

#[cfg(target_os = "linux")]
async fn resolve_if_name(handle: &Handle, index: u32) -> Option<String> {
    let mut links = handle.link().get().execute();
    while let Some(Ok(link)) = links.next().await {
        if link.header.index == index {
            for attr in &link.attributes {
                if let crate::netlink::packet::link::LinkAttribute::IfName(name) = attr {
                    return Some(name.clone());
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn enumerate_addresses(
    _handle: &Handle,
    _expected: &ExpectedResources,
) -> Vec<StaleObject> {
    Vec::new()
}

// ── Policy rules ────────────────────────────────────────────────────────

/// Enumerate ip-rule policy routing entries referencing PicoCompute interfaces.
#[cfg(target_os = "linux")]
pub(super) async fn enumerate_policy_rules(expected: &ExpectedResources) -> Vec<StaleObject> {
    enumerate_cli_output(
        "ip",
        &["-4", "rule", "list"],
        &["iif", "oif", "dev"],
        |line, _if_name, expected| classify_policy_rule(line, expected),
        ResourceClass::PolicyRule,
        expected,
    )
    .await
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn enumerate_policy_rules(_expected: &ExpectedResources) -> Vec<StaleObject> {
    Vec::new()
}

// ── NAT chains ──────────────────────────────────────────────────────────

/// For each PicoCompute nftables table, check if the `snat` (postrouting) chain
/// exists — if so, the NAT state for that sandbox is present.
#[cfg(target_os = "linux")]
pub(super) async fn enumerate_nat_chains(
    known_ids: &KnownSandboxIds,
    expected: &ExpectedResources,
) -> Vec<StaleObject> {
    use std::process::Stdio;
    use tokio::process::Command;

    let mut findings = Vec::new();

    // Reuse the nftables table list
    let tables = list_pico_nft_tables().await;
    for table in &tables {
        let output = match Command::new("nft")
            .args(["-j", "list", "chain", &table.family, &table.name, "snat"])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
        {
            Ok(o) => o,
            Err(_) => continue,
        };

        // If the chain exists, report the NAT state
        if output.status.success() {
            let derived = super::derive_id::derive_sandbox_id_from_nft_table(&table.name);
            let (safety, evidence) =
                classify_nft_chain(&table.name, &table.family, "snat", known_ids, expected);
            findings.push(StaleObject {
                resource_name: format!("{}:{}:snat", table.family, table.name),
                resource_class: ResourceClass::NatChain,
                derived_sandbox_id: derived,
                safety,
                evidence,
                cleaned_up: false,
                cleanup_error: None,
            });
        }
    }

    findings
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn enumerate_nat_chains(
    _known_ids: &KnownSandboxIds,
    _expected: &ExpectedResources,
) -> Vec<StaleObject> {
    Vec::new()
}

// ── tc qdisc ────────────────────────────────────────────────────────────

/// Enumerate tc qdisc entries on PicoCompute interfaces.
#[cfg(target_os = "linux")]
pub(super) async fn enumerate_tc_qdiscs(expected: &ExpectedResources) -> Vec<StaleObject> {
    enumerate_cli_output(
        "tc",
        &["qdisc", "list"],
        &["dev"],
        classify_tc_qdisc,
        ResourceClass::TcQdisc,
        expected,
    )
    .await
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn enumerate_tc_qdiscs(_expected: &ExpectedResources) -> Vec<StaleObject> {
    Vec::new()
}

// ── DNS registrations ───────────────────────────────────────────────────

pub(super) fn enumerate_dns_registrations(
    inspector: &dyn DnsInspector,
    known_ids: &KnownSandboxIds,
    expected: &ExpectedResources,
) -> Vec<StaleObject> {
    let mut findings = Vec::new();

    for sandbox_id in inspector.registered_sandbox_ids() {
        let entry_count = inspector.sandbox_cache_entry_count(&sandbox_id);
        let (safety, evidence) = classify_dns_registration(&sandbox_id, known_ids, expected);
        findings.push(StaleObject {
            resource_name: format!("dns:{sandbox_id}"),
            derived_sandbox_id: Some(sandbox_id),
            resource_class: ResourceClass::DnsRegistration,
            safety,
            evidence: format!("{evidence} (cache entries: {entry_count})"),
            cleaned_up: false,
            cleanup_error: None,
        });
    }

    findings
}

// ── Port-forwarding ─────────────────────────────────────────────────────

pub(super) fn enumerate_port_forwards(
    inspector: &dyn PortForwardInspector,
    known_ids: &KnownSandboxIds,
) -> Vec<StaleObject> {
    let mut findings = Vec::new();

    for sandbox_id in inspector.registered_sandbox_ids() {
        let (safety, evidence) = classify_port_forward(&sandbox_id, known_ids);
        findings.push(StaleObject {
            resource_name: format!("port-forward:{sandbox_id}"),
            derived_sandbox_id: Some(sandbox_id),
            resource_class: ResourceClass::PortForward,
            safety,
            evidence,
            cleaned_up: false,
            cleanup_error: None,
        });
    }

    findings
}
