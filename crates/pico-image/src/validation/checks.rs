//! Individual validation check functions.
//!
//! Each function returns `Ok(())` on pass or `Err(String)` with a
//! human-readable failure reason. These are composed by the top-level
//! `validate_static` orchestrator in the parent module.

use crate::definition::{ImageDefinition, KernelSource};
use crate::kernel::{self, BootVariant};
use crate::types::*;
use pico_core::mount::MountClass;

/// Validate `schema_version` is a non-zero major.minor pair.
pub(super) fn check_schema_version(manifest: &PicoComputeGuestManifest) -> Result<(), String> {
    let parts: Vec<&str> = manifest.schema_version.split('.').collect();
    if parts.len() != 2 {
        return Err(format!(
            "schema_version '{}' must be major.minor",
            manifest.schema_version
        ));
    }
    let major = parts[0]
        .parse::<u32>()
        .map_err(|_| format!("invalid schema major: {}", parts[0]))?;
    let _minor = parts[1]
        .parse::<u32>()
        .map_err(|_| format!("invalid schema minor: {}", parts[1]))?;
    if major == 0 {
        return Err("schema major version 0 is not valid".into());
    }
    Ok(())
}

/// Validate a named string field is non-empty.
pub(super) fn check_non_empty(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} is empty", name));
    }
    Ok(())
}

/// Validate the rootfs artifact descriptor.
pub(super) fn check_rootfs_descriptor(manifest: &PicoComputeGuestManifest) -> Result<(), String> {
    let r = &manifest.artifacts.rootfs;
    if r.digest.is_empty() {
        return Err("rootfs digest is empty".into());
    }
    if r.size == 0 {
        return Err("rootfs size is zero".into());
    }
    if r.media_type.is_empty() {
        return Err("rootfs media_type is empty".into());
    }
    if r.format.is_none() {
        return Err("rootfs format must be declared (e.g. ext4)".into());
    }
    Ok(())
}

/// Validate the guest-agent artifact descriptor and cross-check against the
/// image definition.
pub(super) fn check_guest_agent_descriptor(
    manifest: &PicoComputeGuestManifest,
    definition: &ImageDefinition,
) -> Result<(), String> {
    let ga = &manifest.artifacts.guest_agent;
    if ga.digest.is_empty() {
        return Err("guest_agent digest is empty".into());
    }
    if ga.size == 0 {
        return Err("guest_agent size is zero".into());
    }
    if ga.version.is_none() {
        return Err("guest_agent version is missing".into());
    }
    if ga.protocol_version.is_none() {
        return Err("guest_agent protocol_version is missing".into());
    }

    if let Some(declared) = definition.guest_agent.version() {
        let manifest_version = ga
            .version
            .as_ref()
            .ok_or("guest_agent version is missing from manifest")?;
        if declared != manifest_version {
            return Err(format!(
                "guest_agent version mismatch: definition declares {} but manifest has {}",
                declared, manifest_version
            ));
        }
    }

    if let Some(declared) = definition.guest_agent.protocol_version() {
        let manifest_proto = ga
            .protocol_version
            .as_ref()
            .ok_or("guest_agent protocol_version is missing from manifest")?;
        if declared != manifest_proto {
            return Err(format!(
                "guest_agent protocol_version mismatch: definition declares {} but manifest has {}",
                declared, manifest_proto
            ));
        }
    }

    Ok(())
}

/// Validate kernel descriptor presence and cross-reference against the
/// definition's kernel section.
pub(super) fn check_kernel_descriptor(
    manifest: &PicoComputeGuestManifest,
    definition: &ImageDefinition,
) -> Result<(), String> {
    match (&manifest.artifacts.kernel, &definition.kernel) {
        (Some(kd), Some(ks)) => {
            check_kernel_descriptor_inner(kd, ks)?;
        }
        (None, Some(_)) => {
            return Err(
                "definition declares kernel section but manifest has null kernel descriptor".into(),
            );
        }
        (Some(_), None) => {
            return Err(
                "manifest has kernel descriptor but definition has no kernel section".into(),
            );
        }
        (None, None) => {
            // Both absent is fine - e.g. gVisor variants
        }
    }
    Ok(())
}

fn check_kernel_descriptor_inner(kd: &ArtifactDescriptor, ks: &KernelSource) -> Result<(), String> {
    if kd.digest.is_empty() {
        return Err("kernel digest is empty".into());
    }
    if kd.size == 0 {
        return Err("kernel size is zero".into());
    }
    if kd.format.is_none() {
        return Err("kernel format must be declared (e.g. linux-vmlinux)".into());
    }
    if kd.version.is_none() {
        return Err("kernel version must be declared".into());
    }

    // cmdline existence and non-empty validated above. Content-level
    // policy (init=/init, root=/dev/vda, debug settings, credentials)
    // is handled by check_kernel_cmdline_policy.
    let _ = kd
        .cmdline
        .as_ref()
        .filter(|c| !c.is_empty())
        .ok_or("kernel cmdline is missing or empty")?;

    // If a config profile is specified, validate it is known and consistent
    if let Some(profile_id) = &ks.config_profile {
        if let Some(profile) = kernel::find_profile(profile_id) {
            if profile.variant == BootVariant::Production && ks.variant.to_lowercase() == "debug" {
                return Err(format!(
                    "kernel variant '{}' conflicts with production profile '{}'",
                    ks.variant, profile_id
                ));
            }
        } else {
            return Err(format!("unknown kernel config profile: '{}'", profile_id));
        }
    }

    Ok(())
}

/// Validate initrd and firmware descriptors (optional, but must be valid if
/// present).
pub(super) fn check_initrd_and_firmware(manifest: &PicoComputeGuestManifest) -> Result<(), String> {
    if let Some(ref initrd) = manifest.artifacts.initrd {
        if initrd.digest.is_empty() {
            return Err("initrd digest is empty".into());
        }
        if initrd.size == 0 {
            return Err("initrd size is zero".into());
        }
    }

    if let Some(ref fw) = manifest.artifacts.firmware {
        if fw.digest.is_empty() {
            return Err("firmware digest is empty".into());
        }
        if fw.size == 0 {
            return Err("firmware size is zero".into());
        }
    }

    Ok(())
}

/// Validate digest references use the `sha256:` prefix and have no collisions.
pub(super) fn check_digest_references(manifest: &PicoComputeGuestManifest) -> Result<(), String> {
    for (name, digest) in [
        ("rootfs", &manifest.artifacts.rootfs.digest),
        ("guest_agent", &manifest.artifacts.guest_agent.digest),
    ] {
        if !digest.starts_with("sha256:") {
            return Err(format!(
                "{} digest '{}' does not use sha256: prefix",
                name, digest
            ));
        }
    }

    if let Some(ref kd) = manifest.artifacts.kernel
        && !kd.digest.starts_with("sha256:")
    {
        return Err(format!(
            "kernel digest '{}' does not use sha256: prefix",
            kd.digest
        ));
    }

    if let Some(ref initrd) = manifest.artifacts.initrd
        && !initrd.digest.starts_with("sha256:")
    {
        return Err("initrd digest does not use sha256: prefix".into());
    }

    if let Some(ref fw) = manifest.artifacts.firmware
        && !fw.digest.starts_with("sha256:")
    {
        return Err("firmware digest does not use sha256: prefix".into());
    }

    let digests = [
        ("rootfs", &manifest.artifacts.rootfs.digest),
        ("guest_agent", &manifest.artifacts.guest_agent.digest),
    ];
    for (i, (name_a, d_a)) in digests.iter().enumerate() {
        for (name_b, d_b) in digests.iter().skip(i + 1) {
            if d_a == d_b {
                return Err(format!(
                    "digest collision: {} and {} share digest {}",
                    name_a, name_b, d_a
                ));
            }
        }
    }

    if let Some(ref kd) = manifest.artifacts.kernel {
        if kd.digest == manifest.artifacts.rootfs.digest {
            return Err("kernel and rootfs share the same digest".into());
        }
        if kd.digest == manifest.artifacts.guest_agent.digest {
            return Err("kernel and guest_agent share the same digest".into());
        }
    }

    Ok(())
}

/// Validate protocol information: bootstrap, supported versions, and
/// capability consistency with guest-agent.
pub(super) fn check_protocol_info(manifest: &PicoComputeGuestManifest) -> Result<(), String> {
    if manifest.protocol.bootstrap.is_empty() {
        return Err("protocol.bootstrap is empty".into());
    }
    if manifest.protocol.supported.is_empty() {
        return Err("protocol.supported is empty; at least one protocol version required".into());
    }

    for range in &manifest.protocol.supported {
        if range.major == 0 {
            return Err("protocol version range includes major version 0".into());
        }
        if range.min_minor > range.max_minor {
            return Err(format!(
                "protocol range min_minor ({}) > max_minor ({})",
                range.min_minor, range.max_minor
            ));
        }
    }

    let ga_caps: hashbrown::HashSet<&str> = manifest
        .artifacts
        .guest_agent
        .capabilities
        .iter()
        .map(|s| s.as_str())
        .collect();
    let proto_caps: hashbrown::HashSet<&str> = manifest
        .protocol
        .capabilities
        .iter()
        .map(|s| s.as_str())
        .collect();

    if ga_caps != proto_caps {
        return Err(format!(
            "protocol capabilities {:?} do not match guest_agent capabilities {:?}",
            manifest.protocol.capabilities, manifest.artifacts.guest_agent.capabilities
        ));
    }

    Ok(())
}

/// Validate backend compatibility metadata: profile, families, architecture,
/// and deduplication.
pub(super) fn check_backend_compatibility(
    manifest: &PicoComputeGuestManifest,
) -> Result<(), String> {
    if manifest.compatibility.profile_id.is_empty() {
        return Err("compatibility.profile_id is empty".into());
    }

    if manifest.compatibility.backends.is_empty() {
        return Err(
            "compatibility.backends is empty; at least one backend must be declared".into(),
        );
    }

    let known_backends = ["firecracker", "qemu", "gvisor"];
    for be in &manifest.compatibility.backends {
        if be.family.is_empty() {
            return Err("backend family is empty".into());
        }
        if !known_backends.contains(&be.family.as_str()) {
            return Err(format!(
                "unknown backend family: '{}'. Known backends: {:?}",
                be.family, known_backends
            ));
        }
        if be.runtime_version.is_empty() {
            return Err("backend runtime_version is empty".into());
        }
        if be.architecture.is_empty() {
            return Err("backend architecture is empty".into());
        }
    }

    let mut seen = hashbrown::HashSet::new();
    for be in &manifest.compatibility.backends {
        if !seen.insert(&be.family) {
            return Err(format!("duplicate backend family: '{}'", be.family));
        }
    }

    for be in &manifest.compatibility.backends {
        if be.architecture != manifest.platform.architecture {
            return Err(format!(
                "backend '{}' architecture '{}' does not match platform architecture '{}'",
                be.family, be.architecture, manifest.platform.architecture
            ));
        }
    }

    if kernel::find_profile(&manifest.compatibility.profile_id).is_none() {
        return Err(format!(
            "unknown compatibility profile_id: '{}'",
            manifest.compatibility.profile_id
        ));
    }

    Ok(())
}

/// Validate kernel cmdline policy: required tokens, no debug settings in
/// production, and consistency with the declared kernel config profile.
pub(super) fn check_kernel_cmdline_policy(
    manifest: &PicoComputeGuestManifest,
    definition: &ImageDefinition,
) -> Result<(), String> {
    let Some(ref kd) = manifest.artifacts.kernel else {
        return Ok(());
    };

    let cmdline = kd.cmdline.as_ref().ok_or("kernel cmdline is missing")?;

    if let Some(ref ks) = definition.kernel
        && (ks.variant.to_lowercase() == "production" || ks.variant.to_lowercase() == "prod")
    {
        let debug_settings = [
            "debug",
            "loglevel=7",
            "loglevel=8",
            "earlyprintk",
            "ignore_loglevel",
            "initcall_debug",
            "dyndbg",
            "slub_debug",
        ];
        for setting in &debug_settings {
            if cmdline.to_lowercase().contains(setting) {
                return Err(format!(
                    "production kernel cmdline contains debug setting: '{}'",
                    setting
                ));
            }
        }
    }

    let profile_id = &manifest.compatibility.profile_id;
    let actual_tokens: Vec<&str> = cmdline.split_whitespace().collect();

    for expected in &["init=/init", "root=/dev/vda", "rw"] {
        if !actual_tokens.contains(expected) {
            return Err(format!(
                "kernel cmdline missing required token '{}' for profile '{}'",
                expected, profile_id
            ));
        }
    }

    Ok(())
}

/// Validate the mount contract: all required classes present, canonical paths,
/// no duplicate paths or classes.
pub(super) fn check_mount_contract(manifest: &PicoComputeGuestManifest) -> Result<(), String> {
    if manifest.mount_contract.mounts.is_empty() {
        return Err("mount_contract has no mounts".into());
    }

    manifest
        .mount_contract
        .is_valid()
        .map_err(|e| format!("mount contract invalid: {}", e))?;

    for entry in &manifest.mount_contract.mounts {
        let canonical = entry.class.canonical_path();
        if entry.path != canonical {
            return Err(format!(
                "mount class '{}' at path '{}' should use canonical path '{}'",
                entry.class.as_str(),
                entry.path,
                canonical
            ));
        }
    }

    let required_classes = [
        MountClass::Workspace,
        MountClass::RuntimeTmp,
        MountClass::Secret,
        MountClass::GuestLogs,
    ];

    for required in &required_classes {
        let found = manifest
            .mount_contract
            .mounts
            .iter()
            .any(|m| m.class == *required);
        if !found {
            return Err(format!(
                "missing required mount class '{}'",
                required.as_str()
            ));
        }
    }

    let mut seen_paths = hashbrown::HashSet::new();
    for entry in &manifest.mount_contract.mounts {
        if !seen_paths.insert(&entry.path) {
            return Err(format!("duplicate mount path: '{}'", entry.path));
        }
    }

    let mut seen_classes = hashbrown::HashSet::new();
    for entry in &manifest.mount_contract.mounts {
        let class_str = entry.class.as_str();
        if !seen_classes.insert(class_str) {
            return Err(format!("duplicate mount class: '{}'", class_str));
        }
    }

    Ok(())
}

/// Validate snapshot exclusion policy: all ephemeral classes excluded, no
/// non-ephemeral classes excluded, secret and runtime_tmp always excluded.
pub(super) fn check_snapshot_exclusions(manifest: &PicoComputeGuestManifest) -> Result<(), String> {
    if manifest.snapshot.excluded_mount_classes.is_empty() {
        return Err(
            "snapshot.excluded_mount_classes is empty; at least one ephemeral class must be excluded"
                .into(),
        );
    }

    let ephemeral_classes: hashbrown::HashSet<&str> = manifest
        .mount_contract
        .mounts
        .iter()
        .filter(|m| m.lifecycle == pico_core::mount::PathLifecycle::Ephemeral)
        .map(|m| m.class.as_str())
        .collect();

    for excluded in &manifest.snapshot.excluded_mount_classes {
        if !ephemeral_classes.contains(excluded.as_str()) {
            return Err(format!(
                "excluded mount class '{}' does not have ephemeral lifecycle",
                excluded
            ));
        }
    }

    for ephemeral in &ephemeral_classes {
        if !manifest
            .snapshot
            .excluded_mount_classes
            .contains(&ephemeral.to_string())
        {
            return Err(format!(
                "ephemeral mount class '{}' is not in snapshot.excluded_mount_classes",
                ephemeral
            ));
        }
    }

    if !manifest
        .snapshot
        .excluded_mount_classes
        .contains(&"secret".to_string())
    {
        return Err("secret mount class must be excluded from snapshots".into());
    }

    if !manifest
        .snapshot
        .excluded_mount_classes
        .contains(&"runtime_tmp".to_string())
    {
        return Err("runtime_tmp mount class must be excluded from snapshots".into());
    }

    Ok(())
}

/// Validate filesystem identity: label, UUID format, non-zero UUID, and
/// non-empty size.
pub(super) fn check_filesystem_identity(definition: &ImageDefinition) -> Result<(), String> {
    if definition.filesystem.label.is_empty() {
        return Err("filesystem label is empty".into());
    }
    if definition.filesystem.uuid.is_empty() {
        return Err("filesystem UUID is empty".into());
    }
    if definition.filesystem.size.is_empty() {
        return Err("filesystem size is empty".into());
    }

    if !is_valid_uuid(&definition.filesystem.uuid) {
        return Err(format!(
            "filesystem UUID '{}' is not valid format",
            definition.filesystem.uuid
        ));
    }

    if definition.filesystem.uuid == "00000000-0000-0000-0000-000000000000" {
        return Err("filesystem UUID must not be all zeros".into());
    }

    Ok(())
}

fn is_valid_uuid(uuid: &str) -> bool {
    uuid.len() == 36
        && uuid.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Scan the serialized manifest JSON for common secret patterns and check the
/// kernel cmdline for inline credentials.
pub(super) fn check_no_secrets_in_manifest(
    manifest: &PicoComputeGuestManifest,
) -> Result<(), String> {
    // The pattern list below is deliberately broad, so it is matched against
    // the manifest without the environment block: layer names are free text
    // and a legitimate name such as `toolkit-tokenizer` would otherwise fail
    // with a misleading "may contain a secret" error. Environment fields get
    // the narrower assignment-shaped scan in
    // `check_environment_no_secrets`.
    let mut without_environment = manifest.clone();
    without_environment.environment = None;
    let json = serde_json::to_string(&without_environment)
        .map_err(|e| format!("failed to serialize manifest for secret scan: {}", e))?;

    let secret_patterns = [
        "private_key",
        "private-key",
        "PRIVATE KEY",
        "Bearer ",
        "access_key",
        "secret_key",
        "api_key",
        "password",
        "token",
    ];

    for pattern in &secret_patterns {
        if json.contains(pattern) {
            return Err(format!(
                "manifest may contain a secret: found '{}'",
                pattern
            ));
        }
    }

    if let Some(ref kd) = manifest.artifacts.kernel
        && let Some(ref cmdline) = kd.cmdline
        && (cmdline.contains("password=")
            || cmdline.contains("token=")
            || cmdline.contains("secret="))
    {
        return Err("kernel cmdline contains potential credential".into());
    }

    Ok(())
}

/// Validate that production kernel variants do not reference debug config
/// profiles.
pub(super) fn check_production_variant(
    manifest: &PicoComputeGuestManifest,
    definition: &ImageDefinition,
) -> Result<(), String> {
    let Some(ref ks) = definition.kernel else {
        return Ok(());
    };

    // Production variants must not use debug kernel config profiles
    let profile_id = &manifest.compatibility.profile_id;
    if let Some(profile) = kernel::find_profile(profile_id)
        && profile.variant == BootVariant::Debug
        && (ks.variant.to_lowercase() == "production" || ks.variant.to_lowercase() == "prod")
    {
        return Err(format!(
            "production kernel variant '{}' references debug config profile '{}'",
            ks.variant, profile_id
        ));
    }

    Ok(())
}

/// Validate platform metadata: OS and architecture.
pub(super) fn check_platform_info(manifest: &PicoComputeGuestManifest) -> Result<(), String> {
    if manifest.platform.os.is_empty() {
        return Err("platform.os is empty".into());
    }
    if manifest.platform.architecture.is_empty() {
        return Err("platform.architecture is empty".into());
    }
    if manifest.platform.os != "linux" {
        return Err(format!(
            "platform.os must be 'linux', got '{}'",
            manifest.platform.os
        ));
    }

    let valid_archs = ["aarch64", "x86_64"];
    if !valid_archs.contains(&manifest.platform.architecture.as_str()) {
        return Err(format!(
            "unsupported architecture '{}'. Supported: {:?}",
            manifest.platform.architecture, valid_archs
        ));
    }

    Ok(())
}

/// Validate the optional environment layer composition.
///
/// Monolithic manifests without an environment pass. Layered manifests must
/// bind the same image family, compatibility profile, architecture, and
/// snapshot exclusions as the manifest so scheduler placement and host boot
/// cannot diverge by layer, and must declare the required feature marker so a
/// reader that predates `environment` refuses the manifest instead of
/// silently booting the monolithic rootfs.
pub(super) fn check_environment_composition(
    manifest: &PicoComputeGuestManifest,
) -> Result<(), String> {
    let Some(ref env) = manifest.environment else {
        if manifest
            .required_features
            .iter()
            .any(|f| f == crate::layers::ENVIRONMENT_LAYER_FEATURE)
        {
            return Err(format!(
                "required feature '{}' declared but no environment composition present",
                crate::layers::ENVIRONMENT_LAYER_FEATURE
            ));
        }
        return Ok(());
    };
    crate::layers::validate_environment_composition(env)?;
    if env.image_id != manifest.image_id {
        return Err(format!(
            "environment image_id '{}' does not match manifest image_id '{}'",
            env.image_id, manifest.image_id
        ));
    }
    if env.compatibility.profile_id != manifest.compatibility.profile_id {
        return Err(format!(
            "environment profile '{}' does not match manifest profile '{}'",
            env.compatibility.profile_id, manifest.compatibility.profile_id
        ));
    }
    if env.compatibility.architecture != manifest.platform.architecture {
        return Err(format!(
            "environment architecture '{}' does not match manifest platform '{}'",
            env.compatibility.architecture, manifest.platform.architecture
        ));
    }
    let mut env_excl = env.compatibility.snapshot_excluded_classes.clone();
    env_excl.sort();
    let mut manifest_excl = manifest.snapshot.excluded_mount_classes.clone();
    manifest_excl.sort();
    if env_excl != manifest_excl {
        return Err(format!(
            "environment snapshot exclusions {env_excl:?} do not match manifest {manifest_excl:?}"
        ));
    }
    if !manifest
        .required_features
        .iter()
        .any(|f| f == crate::layers::ENVIRONMENT_LAYER_FEATURE)
    {
        return Err(format!(
            "layered manifest must declare required feature '{}'",
            crate::layers::ENVIRONMENT_LAYER_FEATURE
        ));
    }
    crate::layers::unknown_required_features(manifest).map_err(|e| e.to_string())?;
    Ok(())
}

/// Enforce the per-layer supply-chain gate: every layer must carry SBOM,
/// provenance, and signature evidence digests.
///
/// Without this the evidence fields are decorative, because a composition with
/// no evidence at all still builds and promotes. A failed check blocks
/// promotion at `RootfsBuilder::build`, which runs
/// `validate_supply_chain` and refuses to sign when the report does not pass.
pub(super) fn check_environment_supply_chain(
    manifest: &PicoComputeGuestManifest,
) -> Result<(), String> {
    let Some(ref env) = manifest.environment else {
        return Ok(());
    };
    let missing = crate::layers::layers_missing_supply_chain_evidence(env);
    if !missing.is_empty() {
        return Err(format!(
            "environment layers missing sbom/provenance/signature evidence: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

/// Credential keywords checked against environment layer free-text fields.
///
/// Lowercase by construction: the scanned value is lowercased once per field,
/// so patterns are stored lowercase and compared directly. What keeps a
/// legitimate name such as `toolkit-tokenizer` from matching `token` is
/// [`is_assignment_shaped`], not the pattern list.
const LAYER_SECRET_PATTERNS: &[&str] = &[
    "private_key",
    "private-key",
    "private key",
    "bearer ",
    "access_key",
    "secret_key",
    "api_key",
    "password",
    "token",
];

/// Scan only the environment layer free-text fields for credential patterns.
///
/// The whole-manifest scan uses a deliberately broad word list to catch
/// credentials anywhere in the manifest, which produces false positives on
/// legitimate layer names (for example a toolkit named `*tokenizer*`). Layer
/// names and media types are therefore scanned here with assignment-shaped
/// patterns instead.
pub(super) fn check_environment_no_secrets(
    manifest: &PicoComputeGuestManifest,
) -> Result<(), String> {
    let Some(ref env) = manifest.environment else {
        return Ok(());
    };
    for layer in env.ordered_layers() {
        for (field, value) in [
            ("name", layer.name.as_str()),
            ("media_type", layer.media_type.as_str()),
        ] {
            let lower = value.to_ascii_lowercase();
            for &pattern in LAYER_SECRET_PATTERNS {
                if let Some(pos) = lower.find(pattern)
                    && is_assignment_shaped(&lower, pos, pattern)
                {
                    return Err(format!(
                        "environment layer '{}' {field} may contain a secret near '{pattern}'",
                        layer.name
                    ));
                }
            }
        }
    }
    Ok(())
}

/// True when a match of `pattern` at `pos` reads as a credential keyword
/// rather than part of a longer identifier.
///
/// Two shapes are accepted:
///
/// - an explicit assignment after the keyword (`token=`, `token:`, `api_key:`),
///   or
/// - the keyword standing alone at a field boundary.
///
/// A keyword embedded in an identifier must not match, so `toolkit-tokenizer`
/// is accepted against the `token` pattern.
fn is_assignment_shaped(haystack: &str, pos: usize, pattern: &str) -> bool {
    let after = haystack[pos + pattern.len()..].chars().next();
    let before = haystack[..pos].chars().next_back();
    let starts_word = before.is_none_or(|c| !is_word_char(c));

    // A pattern that itself ends in a separator (for example `"bearer "`) is
    // already unambiguous, so the trailing-character check does not apply: the
    // character after it begins the value, not a longer identifier.
    let pattern_ends_word = pattern.chars().next_back().is_some_and(is_word_char);
    if pattern_ends_word {
        let ends_word = after.is_none_or(|c| !is_word_char(c));
        if !ends_word {
            // Embedded in a longer identifier, for example `tokenizer`.
            return false;
        }
        if after.is_some_and(|c| c == '=' || c == ':') {
            return true;
        }
    }

    starts_word
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Validate that the SBOM covers all components declared in the manifest and
/// lock file.
pub(super) fn check_sbom_completeness(
    sbom: &CycloneDxSbom,
    manifest: &PicoComputeGuestManifest,
    lock: &crate::lock::PackageLock,
) -> Result<(), String> {
    crate::sbom::validate_sbom(sbom, manifest, lock).map_err(|e| e.to_string())
}

/// Validate that provenance metadata matches the image definition.
pub(super) fn check_provenance_consistency(
    provenance: &ProvenanceMetadata,
    definition: &ImageDefinition,
) -> Result<(), String> {
    crate::provenance::validate_provenance(provenance, definition).map_err(|e| e.to_string())
}
