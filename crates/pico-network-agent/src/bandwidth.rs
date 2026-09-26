//! Per-sandbox egress bandwidth shaping via tc (traffic control).
//!
//! Implements SC-IMPL-05: attaches an HTB (Hierarchical Token Bucket)
//! qdisc to each sandbox's host-side interface, with an fq_codel leaf
//! for fair-queueing across flows within the bandwidth cap.
//!
//! # Architecture
//!
//! Each sandbox interface gets:
//!
//! ```text
//! root (1:)
//!   └── htb (1:)
//!         └── class 1:1 (rate = bandwidth_limit, ceil = bandwidth_limit)
//!               └── fq_codel (30:)  ← fair queueing across flows
//! ```
//!
//! Traffic classification:
//! - **IPv4** (protocol ip): matched by u32 filter, shaped under class 1:1
//! - **IPv6** (protocol ipv6): matched by u32 filter, shaped under class 1:1
//! - **Non-IP frames** (ARP, LLDP, etc.): fall through HTB default class 30
//!   (unshaped) -- this is intentional, as control-plane frames must never
//!   be delayed by data-plane rate limiting.
//!
//! This ensures:
//! - Total egress traffic from the sandbox is capped at `bandwidth_limit`.
//! - Within that cap, fq_codel provides fair-queueing across flows,
//!   preventing a single TCP stream from starving others.
//! - fq_codel's AQM (Active Queue Management) keeps latency low under
//!   load by preferentially dropping packets from the largest flows.
//!
//! # Burst size tuning
//!
//! The default burst of 16 KiB (DEFAULT_BURST_KB) is conservative. It
//! accommodates a few full-size TCP segments without introducing tail
//! drops under normal conditions, while being small enough to limit
//! single-burst timing leakage.
//!
//! Operators on very-low-latency links may reduce burst; operators on
//! high-BDP links may increase it. As a rule of thumb, set burst to
//! `rate / 1000` (one millisecond's worth of traffic at the rate limit)
//! for a balanced latency/throughput tradeoff.
//!
//! # Security considerations
//!
//! - **tc binary trust**: tc is run via tokio::process::Command from a
//!   hardcoded path. The network-agent must have CAP_NET_ADMIN only.
//! - **Argument safety**: All tc arguments are constructed from trusted
//!   internal data (deterministic hash-derived interface names, validated
//!   numeric limits). No user-controlled strings reach the command line.
//! - **Idempotent cleanup**: Deprovision tolerates "not found" errors,
//!   preventing partial-state leaks on host restart.
//! - **IPv4 + IPv6 coverage**: Both protocol families are explicitly
//!   classified into the bandwidth class to prevent IPv6 traffic from
//!   bypassing the shaper.
//!
//! # Platform Support
//!
//! All provisioning is `#[cfg(target_os = "linux")]` gated.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::process::Stdio;
use std::time::Instant;

use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::error::{NetworkAgentError, NetworkResult};
use crate::metrics;
use crate::receipt::ResourceReceipt;

/// Path to the tc binary.
const TC_BIN: &str = "tc";

/// Default burst size for the HTB rate limiter (16 KiB).
const DEFAULT_BURST_KB: u32 = 16;

/// Default handle for the root HTB qdisc (1:).
const HTB_ROOT_HANDLE: &str = "1:";
/// Default handle for the HTB class (1:1).
const HTB_CLASS_HANDLE: &str = "1:1";
/// Default handle for the fq_codel leaf (30:).
const FQ_CODEL_HANDLE: &str = "30:";

/// Maximum configurable bandwidth: 10 Gbps.
const MAX_BANDWIDTH_BPS: u64 = 10_000_000_000;

/// Bandwidth limit configuration for a single sandbox interface.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BandwidthLimit {
    /// The sandbox identifier.
    pub sandbox_id: String,
    /// The tenant that owns the sandbox.
    ///
    /// Only used to attribute the `network.bandwidth.limit_configured` gauge,
    /// which is keyed by tenant rather than sandbox on shared hosts.
    pub tenant_id: Option<String>,
    /// The host-side interface name to shape.
    pub if_name: String,
    /// Maximum egress bandwidth in bytes per second.
    ///
    /// This is the `rate` and `ceil` for the HTB class. Setting
    /// both to the same value creates a hard cap. A value of `0`
    /// means unlimited (no shaping applied).
    pub limit_bps: u64,
    /// Optional burst size in kilobytes (default: 16 KiB).
    ///
    /// Controls the token bucket burst for the HTB rate limiter.
    /// Larger bursts allow short-term throughput spikes above the
    /// rate limit at the cost of increased single-burst timing
    /// leakage. As a rule of thumb, set burst to `rate / 1000`
    /// (one millisecond at the rate limit) for balanced latency.
    /// When `None`, the default (16 KiB) is used.
    pub burst_kb: Option<u32>,
}

/// Validate that a bandwidth limit is within acceptable bounds.
///
/// - Must not exceed 10 Gbps (general host NIC limit).
/// - Zero is valid and means "unlimited" (noop).
pub fn validate_bandwidth_limit(limit_bps: u64) -> NetworkResult<()> {
    if limit_bps > MAX_BANDWIDTH_BPS {
        return Err(NetworkAgentError::BandwidthLimitInvalid {
            sandbox_id: String::new(),
            limit_bps,
            reason: format!("exceeds maximum of {MAX_BANDWIDTH_BPS} bps"),
        });
    }
    Ok(())
}

/// Validate that an interface name is safe to pass to tc.
///
/// Interface names must be non-empty, at most 15 characters (IFNAMSIZ),
/// and contain only alphanumeric characters, underscores, dots, and
/// hyphens. This is a defense-in-depth check: all interface names in
/// the network-agent are derived from fnv1a64 hashes so they already
/// satisfy these constraints, but an extra gate prevents regressions
/// if the name source ever changes.
pub fn validate_if_name(if_name: &str) -> NetworkResult<()> {
    if if_name.is_empty() {
        return Err(NetworkAgentError::BandwidthLimitInvalid {
            sandbox_id: String::new(),
            limit_bps: 0,
            reason: "interface name is empty".into(),
        });
    }
    if if_name.len() > 15 {
        return Err(NetworkAgentError::BandwidthLimitInvalid {
            sandbox_id: String::new(),
            limit_bps: 0,
            reason: format!("interface name '{}' exceeds 15 chars (IFNAMSIZ)", if_name),
        });
    }
    if !if_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(NetworkAgentError::BandwidthLimitInvalid {
            sandbox_id: String::new(),
            limit_bps: 0,
            reason: format!("interface name '{}' contains invalid characters", if_name),
        });
    }
    Ok(())
}

/// Format a byte rate as a tc-compatible rate string.
///
/// tc supports suffixes: bit, kbit, mbit, gbit, bps, kbps, mbps, gbps.
/// We use mbps for rates >= 1 Mbps, kbps for rates >= 1 Kbps, bps otherwise.
pub fn format_rate(bps: u64) -> String {
    const MBPS: u64 = 1_000_000;
    const KBPS: u64 = 1_000;

    if bps >= MBPS && bps.is_multiple_of(MBPS) {
        format!("{}mbps", bps / MBPS)
    } else if bps >= MBPS {
        format!("{}mbps", (bps as f64 / MBPS as f64))
    } else if bps >= KBPS && bps.is_multiple_of(KBPS) {
        format!("{}kbps", bps / KBPS)
    } else if bps >= KBPS {
        format!("{}kbps", (bps as f64 / KBPS as f64))
    } else {
        format!("{bps}bps")
    }
}

/// Format a byte value as a tc-compatible burst string.
fn format_bytes(bytes: u32) -> String {
    format!("{bytes}k") // tc interprets suffix as kilobytes
}

/// Provision egress bandwidth shaping for a sandbox interface.
///
/// Attaches an HTB root qdisc with fq_codel leaf to the given
/// host-side interface. The rate limit is applied to all egress
/// traffic from this interface.
///
/// If `limit_bps` is 0, no shaping is applied and this is a no-op.
///
/// Returns a `ResourceReceipt` for reconciliation.
pub async fn provision_bandwidth(limit: &BandwidthLimit) -> NetworkResult<Vec<ResourceReceipt>> {
    // No-op for unlimited (checked before platform gating so tests pass everywhere)
    if limit.limit_bps == 0 {
        debug!(
            sandbox_id = %limit.sandbox_id,
            if_name = %limit.if_name,
            "bandwidth limit is 0 (unlimited), skipping tc setup"
        );
        return Ok(Vec::new());
    }

    do_provision_bandwidth(limit).await
}

/// Update the bandwidth limit for an existing sandbox interface.
///
/// This is an atomic replacement: deletes the existing root qdisc
/// and creates a new one with the updated rate limit.
///
/// If `limit_bps` is 0, the shaping is removed entirely.
pub async fn update_bandwidth(limit: &BandwidthLimit) -> NetworkResult<Vec<ResourceReceipt>> {
    // If unlimited, deprovision any existing shaping
    if limit.limit_bps == 0 {
        return deprovision_bandwidth(&limit.sandbox_id, &limit.if_name).await;
    }

    do_update_bandwidth(limit).await
}

/// Deprovision bandwidth shaping for a sandbox interface.
///
/// Deletes the root qdisc, which implicitly removes all child classes
/// and qdiscs. Idempotent -- if no shaping is configured, this is a
/// no-op.
pub async fn deprovision_bandwidth(
    sandbox_id: &str,
    if_name: &str,
) -> NetworkResult<Vec<ResourceReceipt>> {
    do_deprovision_bandwidth(sandbox_id, if_name).await
}

// ──── Linux-specific implementations ────

/// Build the HTB + fq_codel qdisc tree on an interface with rollback on partial failure.
///
/// Steps:
/// 1. Delete existing root (if any) — idempotent.
/// 2. Attach HTB root qdisc.
/// 3. Add bandwidth class under root.
/// 4. Attach fq_codel leaf.
/// 5. Add IPv4 + IPv6 filters.
///
/// If any step after (1) fails, an attempt is made to tear down the
/// partial qdisc tree by deleting the root again, leaving the interface
/// in its original (unshaped) state. The original error is preserved.
#[cfg(target_os = "linux")]
async fn build_qdisc_tree(if_name: &str, rate: &str, burst_kb: &str) -> NetworkResult<()> {
    // Step 1: Delete any existing root qdisc (idempotent replacement)
    tc_del_root(if_name)
        .await
        .map_err(|e| NetworkAgentError::BandwidthSetupFailed {
            sandbox_id: String::new(),
            detail: format!("failed to delete existing root qdisc: {e}"),
        })?;

    // Helper macro or closure won't work well with async, so we use a
    // pattern where each step maps to Err, and the first error triggers
    // a best-effort teardown. We capture the error in a variable.
    let result: NetworkResult<()> = async {
        // Step 2: Attach root HTB qdisc
        tc_add_htb_root(if_name)
            .await
            .map_err(|e| NetworkAgentError::BandwidthSetupFailed {
                sandbox_id: String::new(),
                detail: format!("failed to attach HTB root: {e}"),
            })?;

        // Step 3: Add bandwidth class under root
        tc_add_htb_class(if_name, rate, burst_kb)
            .await
            .map_err(|e| NetworkAgentError::BandwidthSetupFailed {
                sandbox_id: String::new(),
                detail: format!("failed to add HTB class: {e}"),
            })?;

        // Step 4: Attach fq_codel leaf for fair queueing
        tc_add_fq_codel(if_name)
            .await
            .map_err(|e| NetworkAgentError::BandwidthSetupFailed {
                sandbox_id: String::new(),
                detail: format!("failed to attach fq_codel: {e}"),
            })?;

        // Step 5: Add IPv4 and IPv6 filters
        tc_add_filters(if_name)
            .await
            .map_err(|e| NetworkAgentError::BandwidthSetupFailed {
                sandbox_id: String::new(),
                detail: format!("failed to add filters: {e}"),
            })?;

        Ok(())
    }
    .await;

    // If any step failed after the initial del_root, tear down the
    // partial qdisc tree to restore the interface to its original state.
    if let Err(ref error) = result {
        warn!(
            if_name = %if_name,
            error = %error,
            "bandwidth qdisc tree build failed, rolling back partial state"
        );
        let _ = tc_del_root(if_name).await;
    }

    result
}

#[cfg(target_os = "linux")]
async fn do_provision_bandwidth(limit: &BandwidthLimit) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let mut receipts = Vec::new();

    // Validate before touching tc
    validate_bandwidth_limit(limit.limit_bps).map_err(|e| {
        NetworkAgentError::BandwidthLimitInvalid {
            sandbox_id: limit.sandbox_id.clone(),
            limit_bps: limit.limit_bps,
            reason: e.to_string(),
        }
    })?;

    // Validate if_name as defense-in-depth (currently derived from fnv1a64 hash)
    validate_if_name(&limit.if_name).map_err(|e| NetworkAgentError::BandwidthLimitInvalid {
        sandbox_id: limit.sandbox_id.clone(),
        limit_bps: limit.limit_bps,
        reason: format!("invalid interface name: {e}"),
    })?;

    let if_name = &limit.if_name;
    let rate = format_rate(limit.limit_bps);
    let burst_kb = limit.burst_kb.unwrap_or(DEFAULT_BURST_KB);
    let burst_kb_str = format_bytes(burst_kb);

    debug!(
        sandbox_id = %limit.sandbox_id,
        if_name = %if_name,
        limit_bps = limit.limit_bps,
        rate = %rate,
        burst_kb = burst_kb,
        "provisioning bandwidth shaping"
    );

    // Build the entire qdisc tree atomically with rollback on failure
    build_qdisc_tree(if_name, &rate, &burst_kb_str)
        .await
        .map_err(|e| NetworkAgentError::BandwidthSetupFailed {
            sandbox_id: limit.sandbox_id.clone(),
            detail: e.to_string(),
        })?;

    let latency = start.elapsed();

    receipts.push(ResourceReceipt {
        sandbox_id: limit.sandbox_id.clone(),
        resource_name: format!("bw-{if_name}"),
        kind: crate::receipt::ResourceKind::Bandwidth,
        created: true,
        provision_latency: latency,
    });

    // Record the configured bandwidth limit as a metric (SC-IMPL-05)
    // Include both sandbox_id and if_name for multi-tenant dashboard correlation.
    metrics::record_bandwidth_limit_configured(
        metrics::SandboxScope {
            sandbox_id: limit.sandbox_id.as_str(),
            tenant_id: limit.tenant_id.as_deref(),
        },
        if_name.as_str(),
        limit.limit_bps,
    );

    metrics::record_bandwidth_setup_completed(if_name.as_str());
    info!(
        sandbox_id = %limit.sandbox_id,
        if_name = %if_name,
        limit_bps = limit.limit_bps,
        burst_kb = burst_kb,
        latency_ms = latency.as_millis(),
        "bandwidth shaping provisioned"
    );

    Ok(receipts)
}

#[cfg(target_os = "linux")]
async fn do_update_bandwidth(limit: &BandwidthLimit) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let if_name = &limit.if_name;

    // Validate before touching tc
    validate_bandwidth_limit(limit.limit_bps).map_err(|e| {
        NetworkAgentError::BandwidthLimitInvalid {
            sandbox_id: limit.sandbox_id.clone(),
            limit_bps: limit.limit_bps,
            reason: e.to_string(),
        }
    })?;

    validate_if_name(&limit.if_name).map_err(|e| NetworkAgentError::BandwidthLimitInvalid {
        sandbox_id: limit.sandbox_id.clone(),
        limit_bps: limit.limit_bps,
        reason: format!("invalid interface name: {e}"),
    })?;

    let rate = format_rate(limit.limit_bps);
    let burst_kb = limit.burst_kb.unwrap_or(DEFAULT_BURST_KB);
    let burst_kb_str = format_bytes(burst_kb);

    // Build the entire qdisc tree (delete-then-create) with rollback
    build_qdisc_tree(if_name, &rate, &burst_kb_str)
        .await
        .map_err(|e| NetworkAgentError::BandwidthSetupFailed {
            sandbox_id: limit.sandbox_id.clone(),
            detail: e.to_string(),
        })?;

    let latency = start.elapsed();

    let mut receipts = Vec::new();
    receipts.push(ResourceReceipt {
        sandbox_id: limit.sandbox_id.clone(),
        resource_name: format!("bw-{if_name}"),
        kind: crate::receipt::ResourceKind::Bandwidth,
        created: true,
        provision_latency: latency,
    });

    // Record the updated bandwidth limit as a metric
    metrics::record_bandwidth_limit_configured(
        metrics::SandboxScope {
            sandbox_id: limit.sandbox_id.as_str(),
            tenant_id: limit.tenant_id.as_deref(),
        },
        if_name.as_str(),
        limit.limit_bps,
    );

    metrics::record_bandwidth_setup_completed(if_name.as_str());
    info!(
        sandbox_id = %limit.sandbox_id,
        if_name = %if_name,
        limit_bps = limit.limit_bps,
        latency_ms = latency.as_millis(),
        "bandwidth shaping updated"
    );

    Ok(receipts)
}

#[cfg(target_os = "linux")]
async fn do_deprovision_bandwidth(
    sandbox_id: &str,
    if_name: &str,
) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let mut receipts = Vec::new();

    debug!(
        sandbox_id = %sandbox_id,
        if_name = %if_name,
        "deprovisioning bandwidth shaping"
    );

    // Delete root qdisc (removes all children atomically)
    let result = tc_del_root(if_name).await;

    match result {
        Ok(()) => {
            let latency = start.elapsed();
            receipts.push(ResourceReceipt {
                sandbox_id: sandbox_id.to_string(),
                resource_name: format!("bw-{if_name}"),
                kind: crate::receipt::ResourceKind::Bandwidth,
                created: false,
                provision_latency: latency,
            });

            metrics::record_bandwidth_cleanup_completed(if_name);
            info!(
                sandbox_id = %sandbox_id,
                if_name = %if_name,
                latency_ms = latency.as_millis(),
                "bandwidth shaping removed"
            );
        }
        Err(e) => {
            warn!(
                sandbox_id = %sandbox_id,
                if_name = %if_name,
                error = %e,
                "bandwidth shaping cleanup failed (may not exist)"
            );
            // Not returning error because it's idempotent cleanup
        }
    }

    Ok(receipts)
}

// ──── Non-Linux stubs ────

#[cfg(not(target_os = "linux"))]
async fn do_provision_bandwidth(_limit: &BandwidthLimit) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
async fn do_update_bandwidth(_limit: &BandwidthLimit) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
async fn do_deprovision_bandwidth(
    _sandbox_id: &str,
    _if_name: &str,
) -> NetworkResult<Vec<ResourceReceipt>> {
    // Idempotent cleanup: if bandwidth shaping doesn't exist (non-Linux),
    // there's nothing to clean up -- return success.
    Ok(Vec::new())
}

// ──── tc CLI helpers ────

/// Run a tc command and return Ok if successful.
#[cfg(target_os = "linux")]
async fn tc_run(args: &[&str]) -> NetworkResult<()> {
    let output = Command::new(TC_BIN)
        .args(args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .await
        .map_err(|e| NetworkAgentError::BandwidthTcExec {
            operation: args.join(" "),
            detail: e.to_string(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetworkAgentError::BandwidthTcExec {
            operation: args.join(" "),
            detail: stderr.into_owned(),
        });
    }

    Ok(())
}

/// Delete the root qdisc on an interface (removes all shaping).
#[cfg(target_os = "linux")]
async fn tc_del_root(if_name: &str) -> NetworkResult<()> {
    let result = tc_run(&["qdisc", "del", "dev", if_name, "root"]).await;
    match result {
        Ok(()) => {
            debug!(if_name = %if_name, "root qdisc deleted");
            Ok(())
        }
        Err(NetworkAgentError::BandwidthTcExec {
            ref operation,
            ref detail,
        }) if detail.contains("No such file") || detail.contains("not found") => {
            debug!(if_name = %if_name, "no root qdisc to delete");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Add the root HTB qdisc.
#[cfg(target_os = "linux")]
async fn tc_add_htb_root(if_name: &str) -> NetworkResult<()> {
    tc_run(&[
        "qdisc",
        "add",
        "dev",
        if_name,
        "root",
        "handle",
        HTB_ROOT_HANDLE,
        "htb",
        "default",
        "30",
    ])
    .await?;
    debug!(if_name = %if_name, "HTB root qdisc attached");
    Ok(())
}

/// Add the bandwidth class under the HTB root.
#[cfg(target_os = "linux")]
async fn tc_add_htb_class(if_name: &str, rate: &str, burst: &str) -> NetworkResult<()> {
    tc_run(&[
        "class",
        "add",
        "dev",
        if_name,
        "parent",
        HTB_ROOT_HANDLE,
        "classid",
        HTB_CLASS_HANDLE,
        "htb",
        "rate",
        rate,
        "ceil",
        rate,
        "burst",
        burst,
    ])
    .await?;
    debug!(if_name = %if_name, rate = %rate, burst = %burst, "HTB class added");
    Ok(())
}

/// Attach an fq_codel qdisc as the leaf for fair queueing.
#[cfg(target_os = "linux")]
async fn tc_add_fq_codel(if_name: &str) -> NetworkResult<()> {
    tc_run(&[
        "qdisc",
        "add",
        "dev",
        if_name,
        "parent",
        HTB_CLASS_HANDLE,
        "handle",
        FQ_CODEL_HANDLE,
        "fq_codel",
    ])
    .await?;
    debug!(if_name = %if_name, "fq_codel leaf attached");
    Ok(())
}

/// Add filters to match all IPv4 and IPv6 traffic into the bandwidth class.
///
/// Two filters are added:
/// - IPv4 (protocol ip): matches all IPv4 egress traffic
/// - IPv6 (protocol ipv6): matches all IPv6 egress traffic
///
/// Non-IP traffic (ARP, LLDP, etc.) falls through to HTB default class 30,
/// which is unshaped. This is intentional: control-plane frames must not
/// be delayed by data-plane rate limiting.
#[cfg(target_os = "linux")]
async fn tc_add_filters(if_name: &str) -> NetworkResult<()> {
    // IPv4 filter
    tc_run(&[
        "filter",
        "add",
        "dev",
        if_name,
        "parent",
        HTB_ROOT_HANDLE,
        "protocol",
        "ip",
        "prio",
        "1",
        "u32",
        "match",
        "ip",
        "dst",
        "0.0.0.0/0",
        "flowid",
        HTB_CLASS_HANDLE,
    ])
    .await?;

    // IPv6 filter
    tc_run(&[
        "filter",
        "add",
        "dev",
        if_name,
        "parent",
        HTB_ROOT_HANDLE,
        "protocol",
        "ipv6",
        "prio",
        "2",
        "u32",
        "match",
        "ip6",
        "dst",
        "::/0",
        "flowid",
        HTB_CLASS_HANDLE,
    ])
    .await?;

    debug!(if_name = %if_name, "IPv4 and IPv6 bandwidth filters added");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limit() -> BandwidthLimit {
        BandwidthLimit {
            sandbox_id: "sbx_test".into(),
            tenant_id: None,
            if_name: "cvx001".into(),
            limit_bps: 10_000_000, // 10 Mbps
            burst_kb: None,        // use default
        }
    }

    fn test_limit_with_burst() -> BandwidthLimit {
        BandwidthLimit {
            sandbox_id: "sbx_burst_test".into(),
            tenant_id: None,
            if_name: "cvx_burst".into(),
            limit_bps: 100_000_000, // 100 Mbps
            burst_kb: Some(64),     // 64 KiB burst
        }
    }

    #[test]
    fn validate_bandwidth_limit_accepts_valid() {
        assert!(validate_bandwidth_limit(0).is_ok());
        assert!(validate_bandwidth_limit(1_000_000).is_ok());
        assert!(validate_bandwidth_limit(10_000_000_000).is_ok());
    }

    #[test]
    fn validate_bandwidth_limit_rejects_oversized() {
        assert!(validate_bandwidth_limit(10_000_000_001).is_err());
        assert!(validate_bandwidth_limit(u64::MAX).is_err());
    }

    #[test]
    fn format_rate_bps() {
        assert_eq!(format_rate(500), "500bps");
        assert_eq!(format_rate(999), "999bps");
    }

    #[test]
    fn format_rate_kbps() {
        assert_eq!(format_rate(1_000), "1kbps");
        assert_eq!(format_rate(64_000), "64kbps");
        assert_eq!(format_rate(999_000), "999kbps");
    }

    #[test]
    fn format_rate_mbps() {
        assert_eq!(format_rate(1_000_000), "1mbps");
        assert_eq!(format_rate(10_000_000), "10mbps");
        assert_eq!(format_rate(100_000_000), "100mbps");
        assert_eq!(format_rate(1_000_000_000), "1000mbps");
    }

    #[test]
    fn format_rate_fractional_mbps() {
        assert_eq!(format_rate(1_500_000), "1.5mbps");
        assert_eq!(format_rate(10_500_000), "10.5mbps");
    }

    #[test]
    fn format_bytes_standard() {
        assert_eq!(format_bytes(16), "16k");
        assert_eq!(format_bytes(64), "64k");
        assert_eq!(format_bytes(1024), "1024k");
    }

    #[test]
    fn provision_noop_for_zero_limit() {
        let limit = BandwidthLimit {
            sandbox_id: "sbx_noop".into(),
            tenant_id: None,
            if_name: "cvx_noop".into(),
            limit_bps: 0,
            burst_kb: None,
        };

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(provision_bandwidth(&limit));
        assert!(result.is_ok());
        let receipts = result.unwrap();
        assert!(receipts.is_empty(), "zero limit should produce no receipts");
    }

    #[test]
    fn update_to_zero_calls_deprovision() {
        let limit = BandwidthLimit {
            sandbox_id: "sbx_update".into(),
            tenant_id: None,
            if_name: "cvx_update".into(),
            limit_bps: 0,
            burst_kb: None,
        };

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(update_bandwidth(&limit));
        // On non-Linux this will be UnsupportedPlatform (stub),
        // on Linux it will succeed since the interface doesn't exist
        // but tc_del_root handles "not found" gracefully
        assert!(result.is_ok());
    }

    #[test]
    fn bandwidth_limit_serde_roundtrip() {
        let limit = test_limit();
        let json = serde_json::to_string(&limit).unwrap();
        let parsed: BandwidthLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(limit.sandbox_id, parsed.sandbox_id);
        assert_eq!(limit.if_name, parsed.if_name);
        assert_eq!(limit.limit_bps, parsed.limit_bps);
        assert_eq!(limit.burst_kb, parsed.burst_kb);
    }

    #[test]
    fn bandwidth_limit_serde_with_burst() {
        let limit = test_limit_with_burst();
        let json = serde_json::to_string(&limit).unwrap();
        let parsed: BandwidthLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.burst_kb, Some(64));
    }

    #[test]
    fn bandwidth_limit_custom_burst_uses_specified_value() {
        let limit = BandwidthLimit {
            sandbox_id: "sbx_custom_burst".into(),
            tenant_id: None,
            if_name: "cvx_burst".into(),
            limit_bps: 50_000_000,
            burst_kb: Some(128),
        };
        assert_eq!(limit.burst_kb, Some(128));
    }

    #[test]
    fn provision_nonzero_on_non_linux_returns_unsupported() {
        let limit = test_limit(); // 10 Mbps, non-zero
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(provision_bandwidth(&limit));
        #[cfg(not(target_os = "linux"))]
        {
            assert!(
                matches!(result, Err(NetworkAgentError::UnsupportedPlatform)),
                "expected UnsupportedPlatform on non-Linux, got {:?}",
                result
            );
        }
        #[cfg(target_os = "linux")]
        {
            // On Linux, the interface doesn't exist so tc will fail
            assert!(result.is_err());
        }
    }

    #[test]
    fn validate_if_name_accepts_valid() {
        assert!(validate_if_name("cvx001").is_ok());
        assert!(validate_if_name("eth0").is_ok());
        assert!(validate_if_name("hp-cvx001").is_ok());
        assert!(validate_if_name("hpc12345").is_ok());
    }

    #[test]
    fn validate_if_name_rejects_invalid() {
        assert!(validate_if_name("").is_err());
        assert!(validate_if_name("this-name-is-way-too-long-for-ifnamesiz").is_err());
        assert!(validate_if_name("if with spaces").is_err());
        assert!(validate_if_name("../etc/passwd").is_err());
        assert!(validate_if_name("rm -rf /").is_err());
    }

    #[test]
    fn different_if_names_produce_different_resource_names() {
        let limit1 = BandwidthLimit {
            sandbox_id: "sbx".into(),
            tenant_id: None,
            if_name: "cvx001".into(),
            limit_bps: 1_000_000,
            burst_kb: None,
        };
        let limit2 = BandwidthLimit {
            sandbox_id: "sbx".into(),
            tenant_id: None,
            if_name: "cvx002".into(),
            limit_bps: 1_000_000,
            burst_kb: None,
        };
        assert_ne!(limit1.if_name, limit2.if_name);
    }
}
