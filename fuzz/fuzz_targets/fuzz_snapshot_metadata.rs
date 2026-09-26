//! Fuzz target for snapshot metadata and exclusion parsers.
//!
//! Parses SnapshotMetadata and MountContract JSON from arbitrary bytes and
//! runs credential-exclusion and compatibility checks. Must never panic and
//! must fail closed on missing exclusion evidence.

#![no_main]

use pico_core::mount::MountContract;
use pico_core::snapshot::SnapshotMetadata;
use libfuzzer_sys::fuzz_target;

fn fuzz_one(data: &[u8]) {
    if let Ok(meta) = serde_json::from_slice::<SnapshotMetadata>(data) {
        let _ = meta.validate_credential_exclusion();
        let _ = meta.to_compatibility_record();
        let _ = meta.to_lineage();
        let _ = meta.effective_credential_policy();
    }
    if let Ok(contract) = serde_json::from_slice::<MountContract>(data) {
        let _ = contract.is_valid();
        let _ = contract.snapshot_excluded_classes();
    }
    // Raw string paths: ensure mount-point comparisons never panic on
    // non-UTF8 or overlong inputs (from_slice already rejects invalid UTF8).
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<SnapshotMetadata>(text).map(|m| {
            let _ = m.validate_credential_exclusion();
        });
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_one(data);
});
