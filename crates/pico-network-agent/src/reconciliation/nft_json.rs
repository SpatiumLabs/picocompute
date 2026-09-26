//! JSON parsing for `nft -j list tables` output.
//!
//! Uses serde_json for robust parsing of the `nft` JSON schema.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
use tracing::debug;

#[cfg(target_os = "linux")]
use super::enumeration::NftTableEntry;
#[cfg(target_os = "linux")]
use super::expected::PREFIX_NFT_TABLE;

/// Extract PicoCompute-prefixed nftables table entries from `nft -j list tables` JSON.
#[cfg(target_os = "linux")]
pub(super) fn extract_pico_table_entries(json_output: &str) -> Vec<NftTableEntry> {
    let mut entries = Vec::new();

    let parsed: serde_json::Value = match serde_json::from_str(json_output) {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "failed to parse nft JSON output");
            return entries;
        }
    };

    let Some(items) = parsed.get("nftables").and_then(|v| v.as_array()) else {
        debug!("nft JSON missing nftables array");
        return entries;
    };

    for item in items {
        let Some(table) = item.get("table") else {
            continue;
        };
        let Some(family) = table.get("family").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if name.starts_with(PREFIX_NFT_TABLE) {
            entries.push(NftTableEntry {
                family: family.to_string(),
                name: name.to_string(),
            });
        }
    }

    entries
}
