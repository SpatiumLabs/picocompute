//! PicoCompute image validation engine.
//!
//! Validates manifest schema, artifact integrity, kernel configuration,
//! guest-agent identity, filesystem policy, mount contract, backend
//! compatibility metadata, and security posture.

pub mod checks;
pub mod report;

use crate::definition::ImageDefinition;
use crate::lock::PackageLock;
use crate::manifest;
use crate::types::{CycloneDxSbom, PicoComputeGuestManifest, ProvenanceMetadata};
use report::{CheckOutcome, CheckResult, ValidationReport};

/// A named validation check: (check name, deferred validation function).
type ValidationCheck<'a> = (&'a str, Box<dyn FnOnce() -> Result<(), String> + 'a>);

/// Run all in-process validation checks against a built manifest and its
/// associated definition. This does not require a live backend or OCI
/// registry.
///
/// Returns a [`ValidationReport`] with per-check pass/fail outcomes and
/// an overall pass/fail summary.
pub fn validate_static(
    manifest: &PicoComputeGuestManifest,
    definition: &ImageDefinition,
) -> ValidationReport {
    let mut report =
        ValidationReport::new(manifest.image_id.clone(), manifest.release.version.clone());

    let checks: Vec<ValidationCheck<'_>> = vec![
        (
            "schema and required fields",
            Box::new(|| {
                manifest::validate_manifest(manifest, definition).map_err(|e| e.to_string())
            }),
        ),
        (
            "schema_version format",
            Box::new(|| checks::check_schema_version(manifest)),
        ),
        (
            "image_id is non-empty",
            Box::new(|| checks::check_non_empty("image_id", &manifest.image_id)),
        ),
        (
            "rootfs descriptor",
            Box::new(|| checks::check_rootfs_descriptor(manifest)),
        ),
        (
            "guest-agent descriptor",
            Box::new(|| checks::check_guest_agent_descriptor(manifest, definition)),
        ),
        (
            "kernel descriptor",
            Box::new(|| checks::check_kernel_descriptor(manifest, definition)),
        ),
        (
            "initrd and firmware consistency",
            Box::new(|| checks::check_initrd_and_firmware(manifest)),
        ),
        (
            "digest reference consistency",
            Box::new(|| checks::check_digest_references(manifest)),
        ),
        (
            "protocol information",
            Box::new(|| checks::check_protocol_info(manifest)),
        ),
        (
            "backend compatibility metadata",
            Box::new(|| checks::check_backend_compatibility(manifest)),
        ),
        (
            "kernel cmdline policy",
            Box::new(|| checks::check_kernel_cmdline_policy(manifest, definition)),
        ),
        (
            "mount contract",
            Box::new(|| checks::check_mount_contract(manifest)),
        ),
        (
            "snapshot exclusions",
            Box::new(|| checks::check_snapshot_exclusions(manifest)),
        ),
        (
            "filesystem label and uuid",
            Box::new(|| checks::check_filesystem_identity(definition)),
        ),
        (
            "security posture: no secrets in manifest",
            Box::new(|| checks::check_no_secrets_in_manifest(manifest)),
        ),
        (
            "security posture: production variant check",
            Box::new(|| checks::check_production_variant(manifest, definition)),
        ),
        (
            "platform and architecture",
            Box::new(|| checks::check_platform_info(manifest)),
        ),
        (
            "environment layer composition",
            Box::new(|| checks::check_environment_composition(manifest)),
        ),
    ];

    for (name, check_fn) in checks {
        let outcome = match check_fn() {
            Ok(()) => CheckOutcome::Pass,
            Err(msg) => CheckOutcome::Fail(msg),
        };
        report.add_check(CheckResult {
            name: name.to_string(),
            outcome,
        });
    }

    report
}

/// Run supply-chain validation checks against SBOM and provenance artifacts.
///
/// Complements [`validate_static`] with checks that require the generated
/// SBOM and provenance JSON. These checks verify that the SBOM covers all
/// declared components and that provenance metadata is consistent with the
/// image definition and lock file.
///
/// Returns a [`ValidationReport`] with per-check pass/fail outcomes.
pub fn validate_supply_chain(
    manifest: &PicoComputeGuestManifest,
    definition: &ImageDefinition,
    lock: &PackageLock,
    sbom: &CycloneDxSbom,
    provenance: &ProvenanceMetadata,
) -> ValidationReport {
    let mut report =
        ValidationReport::new(manifest.image_id.clone(), manifest.release.version.clone());

    let checks: Vec<ValidationCheck<'_>> = vec![
        (
            "SBOM completeness",
            Box::new(|| checks::check_sbom_completeness(sbom, manifest, lock)),
        ),
        (
            "provenance consistency",
            Box::new(|| checks::check_provenance_consistency(provenance, definition)),
        ),
    ];

    for (name, check_fn) in checks {
        let outcome = match check_fn() {
            Ok(()) => CheckOutcome::Pass,
            Err(msg) => CheckOutcome::Fail(msg),
        };
        report.add_check(CheckResult {
            name: name.to_string(),
            outcome,
        });
    }

    report
}
