//! Cleanup functions for stale network resources.
//!
//! Each function is idempotent — already-absent resources return `Ok(())`.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use tokio_stream::StreamExt;
use tracing::debug;

use super::ResourceClass;
use super::StaleObject;
use crate::netlink::Handle;

/// Dispatch cleanup by resource class.
#[cfg(target_os = "linux")]
pub(super) async fn cleanup_stale_resource(
    handle: &Handle,
    finding: &StaleObject,
) -> Result<(), String> {
    debug!(
        resource = %finding.resource_name,
        class = %finding.resource_class.as_str(),
        "cleaning up stale network resource"
    );

    match finding.resource_class {
        ResourceClass::TapOrVeth | ResourceClass::HostPeer | ResourceClass::Unknown => {
            cleanup_link(handle, &finding.resource_name).await
        }
        ResourceClass::Namespace => cleanup_namespace(&finding.resource_name),
        ResourceClass::Nftables | ResourceClass::NatChain => {
            cleanup_nft_resource(&finding.resource_name).await
        }
        ResourceClass::Route => cleanup_route(&finding.resource_name).await,
        ResourceClass::Address => {
            // Addresses are removed when the interface is deleted; report as already gone
            Ok(())
        }
        ResourceClass::PolicyRule => cleanup_policy_rule(&finding.resource_name).await,
        ResourceClass::TcQdisc => cleanup_tc_qdisc(&finding.resource_name).await,
        ResourceClass::DnsRegistration => cleanup_dns_registration(&finding.resource_name),
        ResourceClass::PortForward => cleanup_port_forward(&finding.resource_name),
    }
}

#[cfg(target_os = "linux")]
async fn cleanup_link(handle: &Handle, name: &str) -> Result<(), String> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(Ok(link)) = links.next().await else {
        return Ok(()); // already gone
    };

    handle
        .link()
        .del(link.header.index)
        .execute()
        .await
        .map_err(|e| format!("failed to delete link {name}: {e}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_namespace(path: &str) -> Result<(), String> {
    std::fs::remove_file(path)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(|e| format!("failed to remove namespace {path}: {e}"))
}

/// Clean up an nftables table or NAT chain. The resource_name format is:
/// - Tables: `family:table_name`
/// - Chains: `family:table_name:chain_name`
#[cfg(target_os = "linux")]
async fn cleanup_nft_resource(resource_name: &str) -> Result<(), String> {
    let parts: Vec<&str> = resource_name.splitn(4, ':').collect();
    if parts.len() < 2 {
        return Err(format!("invalid nft resource name: {resource_name}"));
    }
    run_cli_cleanup(
        "nft",
        &["delete", "table", parts[0], parts[1]],
        "nft delete table",
    )
    .await
}

// ── Shared CLI cleanup helper ───────────────────────────────────────────

/// Run a CLI command for cleanup and check for "already absent" output.
#[cfg(target_os = "linux")]
async fn run_cli_cleanup(program: &str, args: &[&str], label: &str) -> Result<(), String> {
    use std::process::Stdio;
    use tokio::process::Command;

    let output = Command::new(program)
        .args(args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("{label}: {e}"))?;

    if output.status.success() || stderr_contains_absent(&output.stderr) {
        Ok(())
    } else {
        Err(format!(
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(target_os = "linux")]
async fn cleanup_route(route_line: &str) -> Result<(), String> {
    let rest = route_line.trim();
    if rest.is_empty() || rest.starts_with("default") {
        let mut args = vec!["route", "del"];
        args.extend(rest.split_whitespace());
        run_cli_cleanup("ip", &args, "ip route del").await
    } else {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.is_empty() {
            return Err("empty route line".to_string());
        }
        run_cli_cleanup("ip", &["route", "del", parts[0]], "ip route del").await
    }
}

#[cfg(target_os = "linux")]
async fn cleanup_policy_rule(rule_line: &str) -> Result<(), String> {
    let (prio, rest) = if let Some((p, r)) = rule_line.split_once(':') {
        (p.trim(), r.trim())
    } else {
        return Err("unparseable rule line".to_string());
    };
    let mut args = vec!["rule", "del", "priority", prio];
    args.extend(rest.split_whitespace());
    run_cli_cleanup("ip", &args, "ip rule del").await
}

#[cfg(target_os = "linux")]
async fn cleanup_tc_qdisc(qdisc_line: &str) -> Result<(), String> {
    let if_name = qdisc_line
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1]);
    let Some(if_name) = if_name else {
        return Err("no dev in qdisc line".to_string());
    };
    run_cli_cleanup(
        "tc",
        &["qdisc", "del", "dev", if_name, "root"],
        "tc qdisc del",
    )
    .await
}

fn cleanup_dns_registration(_resource_name: &str) -> Result<(), String> {
    // DNS registrations are in-memory state cleared on proxy restart.
    // If the reconciler runs after restart, stale DNS registrations are
    // absent by definition.
    Ok(())
}

fn cleanup_port_forward(_resource_name: &str) -> Result<(), String> {
    // Port-forwarding endpoints managed by host-agent; cleanup requires
    // cross-crate coordination. Findings are reported for operator action.
    Ok(())
}

#[cfg(target_os = "linux")]
fn stderr_contains_absent(stderr: &[u8]) -> bool {
    let s = String::from_utf8_lossy(stderr);
    s.contains("No such file")
        || s.contains("does not exist")
        || s.contains("Cannot find device")
        || s.contains("No such process")
        || s.contains("RTNETLINK answers: No such file")
        || s.contains("Error:") && s.contains("not found")
}
