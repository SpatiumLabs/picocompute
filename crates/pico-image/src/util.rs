//! Shared utility functions used across the image pipeline.
//!
//! Centralized helpers for hex encoding, digest computation, and git
//! metadata to avoid duplication across modules.

use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Hex-encode a byte slice (lowercase, no prefix).
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(s, "{byte:02x}").unwrap();
    }
    s
}

/// Compute the SHA-256 digest of some bytes, returning `sha256:<hex>`.
pub(crate) fn compute_sha256_digest(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("sha256:{}", hex_encode(&hasher.finalize()))
}

/// Get the short git SHA of HEAD, or `"unknown"` if not available.
pub(crate) fn get_git_sha() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into())
}
