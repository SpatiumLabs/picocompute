//! Derive stable audit-evidence identifiers from resource names.
//!
//! These produce `anon-cvx-{hex}` or original sandbox IDs for audit
//! tracking. They do not need to reverse back to the actual sandbox ID;
//! classification is handled by matching against [`ExpectedResources`].

use super::expected::{
    PREFIX_HOST_PEER_CT, PREFIX_HOST_PEER_VM, PREFIX_NFT_TABLE, PREFIX_NS_CT, PREFIX_SANDBOX_IF,
    split_resource_suffix,
};

fn anon_from_hex(hex_part: &str) -> Option<String> {
    if hex_part.len() == 10 && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(format!("anon-cvx-{hex_part}"))
    } else {
        None
    }
}

/// Derive a sandbox identity from a link name.
///
/// Prefixes come from [`super::expected`] so a rename of `hp-`, `hpc`, or
/// `cvx` stays aligned with provisioning.
pub(super) fn derive_sandbox_id_from_link(name: &str) -> Option<String> {
    let hex_part = name
        .strip_prefix(PREFIX_HOST_PEER_VM)
        .or_else(|| name.strip_prefix(PREFIX_HOST_PEER_CT))
        .or_else(|| name.strip_prefix(PREFIX_SANDBOX_IF))?;
    anon_from_hex(hex_part)
}

/// Derive a sandbox identity from a namespace base name.
pub(super) fn derive_sandbox_id_from_ns(name: &str) -> Option<String> {
    let rest = name.strip_prefix(PREFIX_NS_CT).unwrap_or(name);
    let hex_part = rest.strip_prefix(PREFIX_SANDBOX_IF)?;
    anon_from_hex(hex_part)
}

/// Derive a sandbox identity from an nftables table name.
pub(super) fn derive_sandbox_id_from_nft_table(table_name: &str) -> Option<String> {
    let rest = table_name.strip_prefix(PREFIX_NFT_TABLE)?;
    let (sandbox_id, _) = split_resource_suffix(rest)?;
    if sandbox_id.is_empty() {
        None
    } else {
        Some(sandbox_id.to_string())
    }
}
