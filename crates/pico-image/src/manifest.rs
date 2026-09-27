use crate::definition::{ImageDefinition, KernelSource};
use crate::error::ImageError;
use crate::kernel;
use crate::lock::PackageLock;
use crate::render::OutputInfo;
use crate::types::*;
use camino::Utf8Path;
use pico_core::mount::MountContract;
use tracing::info;

pub fn generate_manifest(
    definition: &ImageDefinition,
    _lock: &PackageLock,
    rootfs: &OutputInfo,
    guest_agent: &OutputInfo,
    output_dir: &Utf8Path,
    mount_contract: &MountContract,
    kernel_source: Option<&KernelSource>,
) -> Result<(camino::Utf8PathBuf, PicoComputeGuestManifest), ImageError> {
    info!("generating PicoCompute manifest");

    let snapshot_info = SnapshotInfo {
        filesystem: true,
        memory: false,
        excluded_mount_classes: mount_contract.snapshot_excluded_classes(),
    };

    let (kernel_descriptor, initrd_descriptor, firmware_descriptor, profile_id, cmdline) =
        build_kernel_artifacts(kernel_source)?;

    let backend_family = kernel_source
        .map(|ks| ks.backend.as_str())
        .unwrap_or("firecracker");
    let architecture = std::env::consts::ARCH.to_string();

    let guest_agent_version = definition
        .guest_agent
        .version()
        .map(String::from)
        .or_else(|| Some(env!("CARGO_PKG_VERSION").into()));
    let agent_protocol_version = definition.guest_agent.protocol_version().map(String::from);
    let agent_capabilities = definition.guest_agent.capabilities().to_vec();

    let manifest = PicoComputeGuestManifest {
        schema_version: "1.0".into(),
        image_id: definition.image.id.clone(),
        release: ReleaseInfo {
            version: definition.image.version.clone(),
            source_revision: get_git_sha().unwrap_or_else(|_| "unknown".into()),
            build_epoch: definition.image.source_date_epoch,
        },
        platform: PlatformInfo {
            os: "linux".into(),
            architecture: architecture.clone(),
        },
        artifacts: Artifacts {
            rootfs: ArtifactDescriptor {
                format: Some("ext4".into()),
                media_type: "application/vnd.pico.rootfs.ext4".into(),
                digest: rootfs.digest.clone(),
                size: rootfs.size,
                version: None,
                cmdline: None,
                protocol_version: None,
                capabilities: vec![],
            },
            kernel: kernel_descriptor,
            initrd: initrd_descriptor,
            firmware: firmware_descriptor,
            guest_agent: ArtifactDescriptor {
                format: None,
                media_type: "application/vnd.pico.guest-agent".into(),
                digest: guest_agent.digest.clone(),
                size: guest_agent.size,
                version: guest_agent_version,
                cmdline: None,
                protocol_version: agent_protocol_version,
                capabilities: agent_capabilities.clone(),
            },
        },
        protocol: ProtocolInfo {
            bootstrap: "pico.guest.bootstrap.v1".into(),
            supported: vec![ProtocolVersionRange {
                major: 1,
                min_minor: 0,
                max_minor: 0,
            }],
            capabilities: agent_capabilities,
        },
        compatibility: CompatibilityInfo {
            profile_id: profile_id.clone(),
            backends: vec![BackendCompatibility {
                family: backend_family.into(),
                runtime_version: "1.0".into(),
                architecture: architecture.clone(),
            }],
            required_cpu_features: vec![],
            required_devices: vec![],
            required_host_features: vec![],
            kernel_cmdline: Some(cmdline),
        },
        mount_contract: mount_contract.clone(),
        snapshot: snapshot_info,
        environment: None,
    };

    let manifest_path = output_dir.join("manifest.json");
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| ImageError::ParseError(format!("failed to serialize manifest: {}", e)))?;

    std::fs::write(&manifest_path, json)?;

    validate_manifest(&manifest, definition)?;

    info!(?manifest_path, "manifest generated");

    Ok((manifest_path, manifest))
}

/// Generate a manifest with an attached independently versioned environment
/// composition (base/workspace/toolkit).
///
/// The composition is validated before attach; the manifest signature written
/// later covers the composition bytes, making host verification a signed
/// composition check.
#[expect(
    clippy::too_many_arguments,
    reason = "layered manifest generation mirrors generate_manifest inputs plus one composition"
)]
pub fn generate_manifest_with_environment(
    definition: &ImageDefinition,
    lock: &PackageLock,
    rootfs: &OutputInfo,
    guest_agent: &OutputInfo,
    output_dir: &Utf8Path,
    mount_contract: &MountContract,
    kernel_source: Option<&KernelSource>,
    environment: crate::layers::EnvironmentComposition,
) -> Result<(camino::Utf8PathBuf, PicoComputeGuestManifest), ImageError> {
    crate::layers::validate_environment_composition(&environment)
        .map_err(ImageError::CompositionValidationFailed)?;
    let (manifest_path, mut manifest) = generate_manifest(
        definition,
        lock,
        rootfs,
        guest_agent,
        output_dir,
        mount_contract,
        kernel_source,
    )?;
    if environment.image_id != manifest.image_id {
        return Err(ImageError::CompositionValidationFailed(format!(
            "environment image_id '{}' does not match manifest image_id '{}'",
            environment.image_id, manifest.image_id
        )));
    }
    // Compatibility profiles must agree so scheduler placement (manifest)
    // and host boot (composition) cannot diverge by layer.
    if environment.compatibility.profile_id != manifest.compatibility.profile_id {
        return Err(ImageError::CompositionValidationFailed(format!(
            "environment profile '{}' does not match manifest profile '{}'",
            environment.compatibility.profile_id, manifest.compatibility.profile_id
        )));
    }
    manifest.environment = Some(environment);
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| ImageError::ParseError(format!("failed to serialize manifest: {}", e)))?;
    std::fs::write(&manifest_path, json)?;
    validate_manifest(&manifest, definition)?;
    Ok((manifest_path, manifest))
}

pub fn validate_manifest(
    manifest: &PicoComputeGuestManifest,
    definition: &ImageDefinition,
) -> Result<(), ImageError> {
    if manifest.schema_version.is_empty() {
        return Err(ImageError::ManifestValidationFailed(
            "schema_version is empty".into(),
        ));
    }

    if manifest.image_id.is_empty() {
        return Err(ImageError::ManifestValidationFailed(
            "image_id is empty".into(),
        ));
    }

    if manifest.artifacts.rootfs.digest.is_empty() {
        return Err(ImageError::ManifestValidationFailed(
            "rootfs digest is empty".into(),
        ));
    }

    if manifest.artifacts.guest_agent.digest.is_empty() {
        return Err(ImageError::ManifestValidationFailed(
            "guest_agent digest is empty".into(),
        ));
    }

    if manifest.artifacts.guest_agent.version.is_none() {
        return Err(ImageError::ManifestValidationFailed(
            "guest_agent version is missing; specify it in the guest_agent section of the image definition".into(),
        ));
    }

    if manifest.artifacts.guest_agent.protocol_version.is_none() {
        return Err(ImageError::ManifestValidationFailed(
            "guest_agent protocol_version is missing; specify it in the guest_agent section of the image definition".into(),
        ));
    }

    if definition.guest_agent.version().is_none() {
        return Err(ImageError::GuestAgentVersionMissing);
    }

    let declared_version = definition.guest_agent.version().unwrap();
    let effective = manifest.artifacts.guest_agent.version.as_ref().unwrap();
    if declared_version != effective {
        return Err(ImageError::GuestAgentVersionIncompatible {
            declared: declared_version.into(),
            found: effective.clone(),
        });
    }

    if manifest.mount_contract.mounts.is_empty() {
        return Err(ImageError::ManifestValidationFailed(
            "mount_contract has no mounts".into(),
        ));
    }

    manifest
        .mount_contract
        .is_valid()
        .map_err(ImageError::ManifestValidationFailed)?;

    if manifest.snapshot.excluded_mount_classes.is_empty() {
        return Err(ImageError::ManifestValidationFailed(
            "snapshot.excluded_mount_classes is empty; at least one ephemeral class must be excluded"
                .into(),
        ));
    }

    let derived = manifest.mount_contract.snapshot_excluded_classes();
    if manifest.snapshot.excluded_mount_classes != derived {
        return Err(ImageError::ManifestValidationFailed(format!(
            "snapshot.excluded_mount_classes {:?} does not match derived {:?}",
            manifest.snapshot.excluded_mount_classes, derived
        )));
    }

    if let Some(ref env) = manifest.environment {
        crate::layers::validate_environment_composition(env)
            .map_err(ImageError::ManifestValidationFailed)?;
        if env.image_id != manifest.image_id {
            return Err(ImageError::ManifestValidationFailed(format!(
                "environment image_id '{}' does not match manifest image_id '{}'",
                env.image_id, manifest.image_id
            )));
        }
        if env.compatibility.profile_id != manifest.compatibility.profile_id {
            return Err(ImageError::ManifestValidationFailed(format!(
                "environment profile '{}' does not match manifest profile '{}'",
                env.compatibility.profile_id, manifest.compatibility.profile_id
            )));
        }
        let mut env_excl = env.compatibility.snapshot_excluded_classes.clone();
        env_excl.sort();
        let mut manifest_excl = manifest.snapshot.excluded_mount_classes.clone();
        manifest_excl.sort();
        if env_excl != manifest_excl {
            return Err(ImageError::ManifestValidationFailed(format!(
                "environment snapshot exclusions {env_excl:?} do not match manifest {manifest_excl:?}"
            )));
        }
    }

    Ok(())
}

fn get_git_sha() -> Result<String, ImageError> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .map_err(|_| ImageError::ParseError("git not found".into()))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Ok("unknown".into())
    }
}

type KernelArtifacts = (
    Option<ArtifactDescriptor>,
    Option<ArtifactDescriptor>,
    Option<ArtifactDescriptor>,
    String,
    String,
);

fn build_kernel_artifacts(
    kernel_source: Option<&KernelSource>,
) -> Result<KernelArtifacts, ImageError> {
    let default_profile_id = format!("firecracker-{}-v1", std::env::consts::ARCH);
    let default_cmdline = kernel::kernel_cmdline(std::env::consts::ARCH, "firecracker");

    let Some(ks) = kernel_source else {
        return Ok((None, None, None, default_profile_id, default_cmdline));
    };

    let profile_id = ks.profile_id();
    let cmdline = ks
        .cmdline
        .clone()
        .unwrap_or_else(|| kernel::kernel_cmdline(std::env::consts::ARCH, &ks.backend));

    let profile = kernel::find_profile(&profile_id);
    let kernel_version = profile
        .as_ref()
        .map(|p| p.kernel_version.clone())
        .unwrap_or_else(|| ks.version.clone());

    let kernel_descriptor = ks.vmlinux_path.as_ref().and_then(|path| {
        let p = camino::Utf8Path::new(path);
        if !p.exists() {
            return None;
        }
        let digest = crate::render::compute_file_digest(p).ok()?;
        let size = std::fs::metadata(p).ok().map(|m| m.len()).unwrap_or(0);
        Some(ArtifactDescriptor {
            format: Some("linux-vmlinux".into()),
            media_type: "application/vnd.pico.kernel.vmlinux".into(),
            digest,
            size,
            version: Some(kernel_version.clone()),
            cmdline: Some(cmdline.clone()),
            protocol_version: None,
            capabilities: vec![],
        })
    });

    let initrd_descriptor = ks.initrd_path.as_ref().and_then(|path| {
        let p = camino::Utf8Path::new(path);
        if !p.exists() {
            return None;
        }
        let digest = crate::render::compute_file_digest(p).ok()?;
        let size = std::fs::metadata(p).ok().map(|m| m.len()).unwrap_or(0);
        Some(ArtifactDescriptor {
            format: Some("initrd-gz".into()),
            media_type: "application/vnd.pico.initrd".into(),
            digest,
            size,
            version: None,
            cmdline: None,
            protocol_version: None,
            capabilities: vec![],
        })
    });

    let firmware_descriptor = ks.firmware_path.as_ref().and_then(|path| {
        let p = camino::Utf8Path::new(path);
        if !p.exists() {
            return None;
        }
        let digest = crate::render::compute_file_digest(p).ok()?;
        let size = std::fs::metadata(p).ok().map(|m| m.len()).unwrap_or(0);
        Some(ArtifactDescriptor {
            format: Some("firmware".into()),
            media_type: "application/vnd.pico.firmware".into(),
            digest,
            size,
            version: None,
            cmdline: None,
            protocol_version: None,
            capabilities: vec![],
        })
    });

    Ok((
        kernel_descriptor,
        initrd_descriptor,
        firmware_descriptor,
        profile_id,
        cmdline,
    ))
}
