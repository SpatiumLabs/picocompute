//! Operator helper for quarantine and fenced cleanup (G-04).
//!
//! Offline checks validate ticket plus fencing-token evidence before any
//! mutation. Only `drain` performs network IO, against the existing
//! `POST /rpc/v1/drain` host-agent endpoint with bearer auth. There is no
//! undrain, no force GC, and no ledger write path by design.

use pico_core::{
    FencingToken, LedgerInspectQuery, ReadmitChecks, UNDRAIN_NOT_SUPPORTED, parse_condition,
    validate_acknowledge, validate_drain, validate_fenced_cleanup, validate_ledger_inspect,
    validate_readmit, validate_resolve,
};

fn trim_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Runs the quarantine acknowledge check and returns ticket evidence text.
pub(crate) fn run_quarantine_ack(
    ticket: &str,
    host: &str,
    condition: &str,
    owner: &str,
) -> Result<String, String> {
    let evidence = validate_acknowledge(ticket, owner).map_err(|e| e.to_string())?;
    let parsed = parse_condition(condition).map_err(|e| e.to_string())?;
    if host.trim().is_empty() {
        return Err("host id is required".to_string());
    }
    Ok(format!(
        "ack ready: host={} condition={} ticket={} owner={}\nnext: call AlertStateManager::acknowledge in-process with this ticket and owner; host stays out of placement",
        host.trim(),
        parsed.as_str(),
        evidence.ticket,
        evidence.owner,
    ))
}

/// Runs the quarantine resolve check. Requires `--condition-cleared`.
pub(crate) fn run_quarantine_resolve(
    ticket: &str,
    host: &str,
    condition: &str,
    condition_cleared: bool,
) -> Result<String, String> {
    let evidence = validate_resolve(ticket, condition_cleared).map_err(|e| e.to_string())?;
    let parsed = parse_condition(condition).map_err(|e| e.to_string())?;
    if host.trim().is_empty() {
        return Err("host id is required".to_string());
    }
    Ok(format!(
        "resolve ready: host={} condition={} ticket={}\nnext: call AlertStateManager::resolve in-process only because the condition is gone; record re-admit checks",
        host.trim(),
        parsed.as_str(),
        evidence.ticket,
    ))
}

/// Runs the fenced cleanup check. Requires at least one fencing token.
pub(crate) fn run_fenced_cleanup(ticket: &str, token_strs: &[String]) -> Result<String, String> {
    if token_strs.is_empty() {
        return Err("at least one --fencing-token <epoch.sequence> is required".to_string());
    }
    let mut tokens = Vec::with_capacity(token_strs.len());
    for raw in token_strs {
        let token: FencingToken = raw
            .trim()
            .parse()
            .map_err(|e: String| format!("invalid fencing token {raw:?}: {e}"))?;
        tokens.push(token);
    }
    let evidence = validate_fenced_cleanup(ticket, &tokens).map_err(|e| e.to_string())?;
    let list = evidence
        .tokens
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "fenced cleanup ready: ticket={} tokens={list}\nnext: run fenced cleanup with these tokens; mismatched tokens stop the cleanup and page control-plane",
        evidence.ticket,
    ))
}

/// Runs the ledger inspect check. Read-only queries only.
pub(crate) fn run_ledger_inspect(
    ticket: &str,
    query: &str,
    sandbox_id: Option<&str>,
) -> Result<String, String> {
    let evidence = validate_ledger_inspect(ticket, query).map_err(|e| e.to_string())?;
    match evidence.query {
        LedgerInspectQuery::SandboxStatus | LedgerInspectQuery::ListReceipts => {
            let scope = sandbox_id.unwrap_or("").trim();
            if scope.is_empty() {
                return Err(format!(
                    "--sandbox-id is required for query {}",
                    evidence.query.as_str()
                ));
            }
        }
        LedgerInspectQuery::ListSandboxes
        | LedgerInspectQuery::GcStats
        | LedgerInspectQuery::Findings => {}
    }
    let allowed = LedgerInspectQuery::all()
        .iter()
        .map(|q| q.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let scope = sandbox_id.unwrap_or("-");
    Ok(format!(
        "ledger inspect ready: ticket={} query={} sandbox={scope}\nallowed queries: {allowed}\nledger edits by hand remain prohibited",
        evidence.ticket,
        evidence.query.as_str(),
    ))
}

/// Runs the re-admit checklist. Every gate must pass. No undrain exists.
pub(crate) fn run_readmit_check(
    quarantine_gauge_zero: bool,
    capacity_age_secs: u64,
    health: &str,
    reconciliation_clean: bool,
    watch_clean: bool,
) -> Result<String, String> {
    let health_admitting = match health.trim() {
        "ready" | "degraded" => true,
        "draining" | "unsafe" => false,
        _ => return Err("health must be one of: ready, degraded, draining, unsafe".to_string()),
    };
    let checks = ReadmitChecks {
        quarantine_gauge_zero,
        capacity_age_secs,
        health_admitting,
        reconciliation_clean,
        five_minute_watch_clean: watch_clean,
    };
    validate_readmit(&checks).map_err(|e| e.to_string())?;
    Ok(format!(
        "re-admit ready: gauge_zero={quarantine_gauge_zero} capacity_age_secs={capacity_age_secs} health={} clean={reconciliation_clean} watch={watch_clean}\n{UNDRAIN_NOT_SUPPORTED}",
        health.trim(),
    ))
}

/// Name of the env var that can carry the host-agent bearer token so the
/// secret stays out of shell history and process lists.
pub(crate) const HOST_TOKEN_ENV: &str = "PICO_HOST_TOKEN";

/// Resolves the host-agent bearer token: explicit CLI arg wins, then the
/// `PICO_HOST_TOKEN` value supplied by the caller (read from the
/// environment in `main`, kept out of here so tests stay pure).
pub(crate) fn resolve_host_token(
    arg: Option<&str>,
    env_val: Option<&str>,
) -> Result<String, String> {
    let from_arg = arg.unwrap_or("").trim();
    if !from_arg.is_empty() {
        return Ok(from_arg.to_string());
    }
    let from_env = env_val.unwrap_or("").trim();
    if !from_env.is_empty() {
        return Ok(from_env.to_string());
    }
    Err(format!(
        "host token is required via --host-token or {HOST_TOKEN_ENV}"
    ))
}

/// Calls the existing host-agent drain RPC with ticket evidence.
///
/// `host_url` is the host-agent base URL (for example `http://hst-01:8081`).
/// Uses bearer auth with `host_token`. Records the ticket in the output so
/// the operator can paste it into the incident ticket.
pub(crate) async fn run_drain(
    host_url: &str,
    host_token: &str,
    ticket: &str,
) -> Result<String, String> {
    let evidence = validate_drain(ticket).map_err(|e| e.to_string())?;
    if host_url.trim().is_empty() {
        return Err("host url is required".to_string());
    }
    if host_token.trim().is_empty() {
        return Err("host token is required".to_string());
    }
    let base = trim_url(host_url);
    let url = format!("{base}/rpc/v1/drain");
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", host_token.trim()))
        .send()
        .await
        .map_err(|e| format!("drain request failed: {e}"))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("drain RPC failed: {body}"));
    }
    Ok(format!(
        "drain posted: host={base} ticket={}\nwatch pico_host_draining and Active Sandbox Count per Host; {}",
        evidence.ticket, UNDRAIN_NOT_SUPPORTED,
    ))
}

/// Reads host health for drain status. Health endpoint is public.
pub(crate) async fn run_drain_status(host_url: &str) -> Result<String, String> {
    if host_url.trim().is_empty() {
        return Err("host url is required".to_string());
    }
    let base = trim_url(host_url);
    let url = format!("{base}/rpc/v1/health");
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("health request failed: {e}"))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("health RPC failed: {body}"));
    }
    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("decode failed: {e}"))?;
    let status = value
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "health response missing status; expected host-agent /rpc/v1/health".to_string()
        })?;
    let count = value
        .get("sandbox_count")
        .and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(str::to_string))
        })
        .ok_or_else(|| {
            "health response missing sandbox_count; expected host-agent /rpc/v1/health".to_string()
        })?;
    Ok(format!("host={base} status={status} sandbox_count={count}"))
}

#[cfg(test)]
mod tests;
