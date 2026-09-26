//! CycloneDX SBOM generation for PicoCompute guest images.
//!
//! Produces a CycloneDX 1.5 JSON SBOM describing all artifacts in a
//! PicoCompute guest image: rootfs, kernel, initrd, firmware, guest-agent,
//! and user-space packages from the lock file.

use crate::error::ImageError;
use crate::lock::PackageLock;
use crate::types::*;
use camino::Utf8Path;
use chrono::Utc;
use tracing::info;

/// Generate a CycloneDX SBOM for the given image artifacts and package lock.
///
/// The SBOM enumerates all components: the rootfs filesystem image, the
/// guest-agent binary, kernel/initrd/firmware artifacts (if present), and
/// every locked user-space package.
///
/// # Errors
///
/// Returns [`ImageError::SbomGenerationFailed`] if serialization or file
/// I/O fails, or if any digest lacks the `sha256:` prefix.
pub fn generate_sbom(
    manifest: &PicoComputeGuestManifest,
    lock: &PackageLock,
    output_dir: &Utf8Path,
) -> Result<camino::Utf8PathBuf, ImageError> {
    info!("generating CycloneDX SBOM");

    let serial_number = format!(
        "urn:uuid:{}",
        uuid::Uuid::new_v4().to_string().replace('-', "")
    );

    let mut components: Vec<SbomComponent> = Vec::new();

    components.push(build_rootfs_component(manifest)?);
    components.push(build_guest_agent_component(manifest));

    if let Some(ref kd) = manifest.artifacts.kernel {
        components.push(build_kernel_component(kd));
    }

    if let Some(ref id) = manifest.artifacts.initrd {
        components.push(build_initrd_component(id));
    }

    if let Some(ref fw) = manifest.artifacts.firmware {
        components.push(build_firmware_component(fw));
    }

    for pkg in &lock.packages {
        components.push(build_package_component(pkg));
    }

    let now = Utc::now().to_rfc3339();

    let sbom = CycloneDxSbom {
        bom_format: "CycloneDX".into(),
        spec_version: "1.5".into(),
        serial_number,
        version: 1,
        metadata: SbomMetadata {
            timestamp: now,
            tools: vec![SbomTool {
                name: "pico-image".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            }],
            component: SbomRootComponent {
                component_type: "container".into(),
                name: manifest.image_id.clone(),
                version: manifest.release.version.clone(),
                description: Some(format!(
                    "PicoCompute guest image {} ({})",
                    manifest.image_id, manifest.release.version
                )),
            },
        },
        components,
    };

    let sbom_path = output_dir.join("sbom.cdx.json");
    let json = serde_json::to_string_pretty(&sbom).map_err(|e| {
        ImageError::SbomGenerationFailed(format!("failed to serialize SBOM: {}", e))
    })?;

    std::fs::write(&sbom_path, &json)
        .map_err(|e| ImageError::SbomGenerationFailed(format!("failed to write SBOM: {}", e)))?;

    info!(?sbom_path, "SBOM generated");

    Ok(sbom_path)
}

fn build_rootfs_component(
    manifest: &PicoComputeGuestManifest,
) -> Result<SbomComponent, ImageError> {
    let rootfs = &manifest.artifacts.rootfs;
    let digest_hex = require_sha256_prefix(&rootfs.digest)?;

    Ok(SbomComponent {
        component_type: "file".into(),
        bom_ref: format!("rootfs@{}", &rootfs.digest[..16]),
        name: "rootfs".into(),
        version: Some(manifest.release.version.clone()),
        description: Some("PicoCompute root filesystem (ext4)".into()),
        purl: Some(format!(
            "pkg:pico/{}/rootfs@{}",
            manifest.image_id, manifest.release.version
        )),
        hashes: Some(vec![SbomHash {
            alg: "SHA-256".into(),
            content: digest_hex,
        }]),
        properties: Some(vec![
            SbomProperty {
                name: "pico:format".into(),
                value: rootfs.format.clone().unwrap_or_default(),
            },
            SbomProperty {
                name: "pico:size".into(),
                value: rootfs.size.to_string(),
            },
        ]),
    })
}

fn build_guest_agent_component(manifest: &PicoComputeGuestManifest) -> SbomComponent {
    let ga = &manifest.artifacts.guest_agent;
    let digest_hex = strip_sha256_prefix(&ga.digest).unwrap_or_else(|| ga.digest.clone());

    let mut props = vec![SbomProperty {
        name: "pico:size".into(),
        value: ga.size.to_string(),
    }];

    if let Some(ref version) = ga.version {
        props.push(SbomProperty {
            name: "pico:version".into(),
            value: version.clone(),
        });
    }
    if let Some(ref proto) = ga.protocol_version {
        props.push(SbomProperty {
            name: "pico:protocol_version".into(),
            value: proto.clone(),
        });
    }
    for cap in &ga.capabilities {
        props.push(SbomProperty {
            name: "pico:capability".into(),
            value: cap.clone(),
        });
    }

    SbomComponent {
        component_type: "application".into(),
        bom_ref: format!("guest-agent@{}", &ga.digest[..16]),
        name: "pico-guest-agent".into(),
        version: ga.version.clone(),
        description: Some("PicoCompute guest agent binary".into()),
        purl: Some(format!(
            "pkg:pico/{}/guest-agent@{}",
            manifest.image_id,
            ga.version.as_deref().unwrap_or("unknown")
        )),
        hashes: Some(vec![SbomHash {
            alg: "SHA-256".into(),
            content: digest_hex,
        }]),
        properties: Some(props),
    }
}

fn build_kernel_component(kd: &ArtifactDescriptor) -> SbomComponent {
    let digest_hex = strip_sha256_prefix(&kd.digest).unwrap_or_else(|| kd.digest.clone());

    let mut props = vec![
        SbomProperty {
            name: "pico:format".into(),
            value: kd.format.clone().unwrap_or_default(),
        },
        SbomProperty {
            name: "pico:size".into(),
            value: kd.size.to_string(),
        },
    ];

    if let Some(ref cmdline) = kd.cmdline {
        props.push(SbomProperty {
            name: "pico:cmdline".into(),
            value: cmdline.clone(),
        });
    }

    SbomComponent {
        component_type: "file".into(),
        bom_ref: format!("kernel@{}", &kd.digest[..16]),
        name: "kernel".into(),
        version: kd.version.clone(),
        description: Some("PicoCompute guest kernel (vmlinux)".into()),
        purl: Some(format!(
            "pkg:pico/kernel@{}",
            kd.version.as_deref().unwrap_or("unknown")
        )),
        hashes: Some(vec![SbomHash {
            alg: "SHA-256".into(),
            content: digest_hex,
        }]),
        properties: Some(props),
    }
}

fn build_initrd_component(id: &ArtifactDescriptor) -> SbomComponent {
    let digest_hex = strip_sha256_prefix(&id.digest).unwrap_or_else(|| id.digest.clone());

    SbomComponent {
        component_type: "file".into(),
        bom_ref: format!("initrd@{}", &id.digest[..16]),
        name: "initrd".into(),
        version: None,
        description: Some("PicoCompute initial ramdisk".into()),
        purl: Some(format!("pkg:pico/initrd@{}", &id.digest[..16])),
        hashes: Some(vec![SbomHash {
            alg: "SHA-256".into(),
            content: digest_hex,
        }]),
        properties: Some(vec![
            SbomProperty {
                name: "pico:format".into(),
                value: id.format.clone().unwrap_or_else(|| "initrd-gz".into()),
            },
            SbomProperty {
                name: "pico:size".into(),
                value: id.size.to_string(),
            },
        ]),
    }
}

fn build_firmware_component(fw: &ArtifactDescriptor) -> SbomComponent {
    let digest_hex = strip_sha256_prefix(&fw.digest).unwrap_or_else(|| fw.digest.clone());

    SbomComponent {
        component_type: "firmware".into(),
        bom_ref: format!("firmware@{}", &fw.digest[..16]),
        name: "firmware".into(),
        version: None,
        description: Some("PicoCompute guest firmware".into()),
        purl: Some(format!("pkg:pico/firmware@{}", &fw.digest[..16])),
        hashes: Some(vec![SbomHash {
            alg: "SHA-256".into(),
            content: digest_hex,
        }]),
        properties: Some(vec![SbomProperty {
            name: "pico:size".into(),
            value: fw.size.to_string(),
        }]),
    }
}

fn build_package_component(pkg: &crate::lock::LockedPackage) -> SbomComponent {
    let digest_hex = strip_sha256_prefix(&pkg.digest).unwrap_or_else(|| pkg.digest.clone());

    SbomComponent {
        component_type: "library".into(),
        bom_ref: format!("pkg-{}@{}", pkg.name, pkg.version),
        name: pkg.name.clone(),
        version: Some(pkg.version.clone()),
        description: Some(format!("Locked package: {} {}", pkg.name, pkg.version)),
        purl: Some(format!("pkg:apk/{}@{}", pkg.name, pkg.version)),
        hashes: Some(vec![SbomHash {
            alg: "SHA-256".into(),
            content: digest_hex,
        }]),
        properties: None,
    }
}

/// Strip the `sha256:` prefix from a digest, returning `None` if absent.
fn strip_sha256_prefix(digest: &str) -> Option<String> {
    digest.strip_prefix("sha256:").map(|s| s.to_string())
}

/// Strip the `sha256:` prefix from a digest, erroring if absent.
fn require_sha256_prefix(digest: &str) -> Result<String, ImageError> {
    strip_sha256_prefix(digest).ok_or_else(|| {
        ImageError::SbomGenerationFailed(format!(
            "digest '{}' does not have sha256: prefix",
            digest
        ))
    })
}

/// Validate an SBOM against its referenced manifest.
///
/// Checks that the SBOM contains entries for rootfs, guest-agent, and all
/// locked packages. Returns `Ok(())` if the SBOM is complete, or an error
/// describing what is missing.
///
/// # Errors
///
/// Returns [`ImageError::SbomValidationFailed`] if any required component
/// (rootfs, guest-agent, kernel, initrd, firmware, or locked package) is
/// missing from the SBOM.
pub fn validate_sbom(
    sbom: &CycloneDxSbom,
    manifest: &PicoComputeGuestManifest,
    lock: &PackageLock,
) -> Result<(), ImageError> {
    let has_rootfs = sbom
        .components
        .iter()
        .any(|c| c.bom_ref.starts_with("rootfs@"));
    if !has_rootfs {
        return Err(ImageError::SbomValidationFailed(
            "SBOM missing rootfs component".into(),
        ));
    }

    let has_ga = sbom
        .components
        .iter()
        .any(|c| c.bom_ref.starts_with("guest-agent@"));
    if !has_ga {
        return Err(ImageError::SbomValidationFailed(
            "SBOM missing guest-agent component".into(),
        ));
    }

    if manifest.artifacts.kernel.is_some() {
        let has_kernel = sbom
            .components
            .iter()
            .any(|c| c.bom_ref.starts_with("kernel@"));
        if !has_kernel {
            return Err(ImageError::SbomValidationFailed(
                "SBOM missing kernel component".into(),
            ));
        }
    }

    if manifest.artifacts.initrd.is_some() {
        let has_initrd = sbom
            .components
            .iter()
            .any(|c| c.bom_ref.starts_with("initrd@"));
        if !has_initrd {
            return Err(ImageError::SbomValidationFailed(
                "SBOM missing initrd component".into(),
            ));
        }
    }

    if manifest.artifacts.firmware.is_some() {
        let has_firmware = sbom
            .components
            .iter()
            .any(|c| c.bom_ref.starts_with("firmware@"));
        if !has_firmware {
            return Err(ImageError::SbomValidationFailed(
                "SBOM missing firmware component".into(),
            ));
        }
    }

    for pkg in &lock.packages {
        let expected_ref = format!("pkg-{}@{}", pkg.name, pkg.version);
        let found = sbom.components.iter().any(|c| c.bom_ref == expected_ref);
        if !found {
            return Err(ImageError::SbomValidationFailed(format!(
                "SBOM missing locked package: {}",
                expected_ref
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{LockArtifact, LockBase, LockMetadata, LockedPackage};

    fn sample_manifest() -> PicoComputeGuestManifest {
        PicoComputeGuestManifest {
            schema_version: "1.0".into(),
            image_id: "test-sbom-image".into(),
            release: ReleaseInfo {
                version: "0.1.0".into(),
                source_revision: "abc1234".into(),
                build_epoch: 1781170000,
            },
            platform: PlatformInfo {
                os: "linux".into(),
                architecture: "aarch64".into(),
            },
            artifacts: Artifacts {
                rootfs: ArtifactDescriptor {
                    format: Some("ext4".into()),
                    media_type: "application/vnd.pico.rootfs.ext4".into(),
                    digest: "sha256:aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222".into(),
                    size: 67108864,
                    version: None,
                    cmdline: None,
                    protocol_version: None,
                    capabilities: vec![],
                },
                kernel: Some(ArtifactDescriptor {
                    format: Some("linux-vmlinux".into()),
                    media_type: "application/vnd.pico.kernel.vmlinux".into(),
                    digest: "sha256:kern1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff".into(),
                    size: 25165824,
                    version: Some("pico-linux-6.18".into()),
                    cmdline: Some("console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init".into()),
                    protocol_version: None,
                    capabilities: vec![],
                }),
                initrd: None,
                firmware: None,
                guest_agent: ArtifactDescriptor {
                    format: None,
                    media_type: "application/vnd.pico.guest-agent".into(),
                    digest: "sha256:agent1111222233334444555566667777888899990000aaaabbbbccccddddeeee".into(),
                    size: 5242880,
                    version: Some("0.3.0".into()),
                    cmdline: None,
                    protocol_version: Some("1.0".into()),
                    capabilities: vec!["exec".into()],
                },
            },
            protocol: ProtocolInfo {
                bootstrap: "pico.guest.bootstrap.v1".into(),
                supported: vec![ProtocolVersionRange {
                    major: 1,
                    min_minor: 0,
                    max_minor: 0,
                }],
                capabilities: vec!["exec".into()],
            },
            compatibility: CompatibilityInfo {
                profile_id: "firecracker-aarch64-v1".into(),
                backends: vec![BackendCompatibility {
                    family: "firecracker".into(),
                    runtime_version: "1.0".into(),
                    architecture: "aarch64".into(),
                }],
                required_cpu_features: vec![],
                required_devices: vec![],
                required_host_features: vec![],
                kernel_cmdline: None,
            },
            mount_contract: MountContract {
                version: "1.0".into(),
                mounts: vec![
                    MountEntry {
                        path: "/workspace".into(),
                        class: MountClass::Workspace,
                        writable: true,
                        lifecycle: PathLifecycle::Persistent,
                    },
                    MountEntry {
                        path: "/run/pico/tmp".into(),
                        class: MountClass::RuntimeTmp,
                        writable: true,
                        lifecycle: PathLifecycle::Ephemeral,
                    },
                ],
            },
            snapshot: pico_core::mount::SnapshotInfo {
                filesystem: true,
                memory: false,
                excluded_mount_classes: vec!["runtime_tmp".into(), "secret".into()],
            },
        }
    }

    fn sample_lock() -> PackageLock {
        PackageLock {
            metadata: LockMetadata {
                image_id: "test-sbom-image".into(),
                version: "0.1.0".into(),
                source_date_epoch: 1781170000,
            },
            base: LockBase {
                url: "https://example.com/rootfs.tar.gz".into(),
                digest: "sha256:abc123".into(),
            },
            guest_agent: LockArtifact {
                digest: "sha256:agent1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
                    .into(),
            },
            packages: vec![
                LockedPackage {
                    name: "openssh-server".into(),
                    version: "9.9_p2-r0".into(),
                    digest:
                        "sha256:pkgssh1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
                            .into(),
                },
                LockedPackage {
                    name: "ca-certificates".into(),
                    version: "20240705-r0".into(),
                    digest:
                        "sha256:pkgcacert111222333444555666777888999000aaaabbbbccccddddeeeeffff"
                            .into(),
                },
            ],
        }
    }

    #[test]
    fn sbom_generates_cyclonedx_json() {
        let manifest = sample_manifest();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sbom_path = generate_sbom(&manifest, &lock, &output_dir).unwrap();
        assert!(sbom_path.exists());

        let content = std::fs::read_to_string(&sbom_path).unwrap();
        let sbom: CycloneDxSbom = serde_json::from_str(&content).unwrap();

        assert_eq!(sbom.bom_format, "CycloneDX");
        assert_eq!(sbom.spec_version, "1.5");
        assert_eq!(sbom.version, 1);

        // Should have rootfs, guest-agent, kernel, and 2 packages = 5 components
        let component_names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
        assert!(
            component_names.contains(&"rootfs"),
            "SBOM should contain rootfs component"
        );
        assert!(
            component_names.contains(&"pico-guest-agent"),
            "SBOM should contain guest-agent component"
        );
        assert!(
            component_names.contains(&"kernel"),
            "SBOM should contain kernel component"
        );
        assert!(
            component_names.contains(&"openssh-server"),
            "SBOM should contain openssh-server component"
        );
        assert!(
            component_names.contains(&"ca-certificates"),
            "SBOM should contain ca-certificates component"
        );
    }

    #[test]
    fn sbom_rootfs_component_has_hashes() {
        let manifest = sample_manifest();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sbom_path = generate_sbom(&manifest, &lock, &output_dir).unwrap();
        let content = std::fs::read_to_string(&sbom_path).unwrap();
        let sbom: CycloneDxSbom = serde_json::from_str(&content).unwrap();

        let rootfs = sbom.components.iter().find(|c| c.name == "rootfs").unwrap();
        let hashes = rootfs.hashes.as_ref().unwrap();
        assert_eq!(hashes[0].alg, "SHA-256");
        assert!(!hashes[0].content.is_empty());
        // Content should NOT have the sha256: prefix
        assert!(!hashes[0].content.contains("sha256:"));
    }

    #[test]
    fn sbom_serial_number_is_unique() {
        let manifest = sample_manifest();
        let lock = sample_lock();
        let dir1 = tempfile::TempDir::new().unwrap();
        let dir2 = tempfile::TempDir::new().unwrap();
        let out1 = camino::Utf8PathBuf::from_path_buf(dir1.path().to_path_buf()).unwrap();
        let out2 = camino::Utf8PathBuf::from_path_buf(dir2.path().to_path_buf()).unwrap();

        let p1 = generate_sbom(&manifest, &lock, &out1).unwrap();
        let p2 = generate_sbom(&manifest, &lock, &out2).unwrap();

        let s1: CycloneDxSbom =
            serde_json::from_str(&std::fs::read_to_string(&p1).unwrap()).unwrap();
        let s2: CycloneDxSbom =
            serde_json::from_str(&std::fs::read_to_string(&p2).unwrap()).unwrap();

        assert_ne!(s1.serial_number, s2.serial_number);
    }

    #[test]
    fn sbom_without_kernel_has_no_kernel_component() {
        let mut manifest = sample_manifest();
        manifest.artifacts.kernel = None;
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sbom_path = generate_sbom(&manifest, &lock, &output_dir).unwrap();
        let content = std::fs::read_to_string(&sbom_path).unwrap();
        let sbom: CycloneDxSbom = serde_json::from_str(&content).unwrap();

        let has_kernel = sbom.components.iter().any(|c| c.name == "kernel");
        assert!(
            !has_kernel,
            "SBOM should not have kernel when manifest has none"
        );
    }

    #[test]
    fn sbom_guest_agent_has_capabilities() {
        let manifest = sample_manifest();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sbom_path = generate_sbom(&manifest, &lock, &output_dir).unwrap();
        let content = std::fs::read_to_string(&sbom_path).unwrap();
        let sbom: CycloneDxSbom = serde_json::from_str(&content).unwrap();

        let ga = sbom
            .components
            .iter()
            .find(|c| c.name == "pico-guest-agent")
            .unwrap();
        let props = ga.properties.as_ref().unwrap();
        let caps: Vec<&str> = props
            .iter()
            .filter(|p| p.name == "pico:capability")
            .map(|p| p.value.as_str())
            .collect();
        assert!(caps.contains(&"exec"));
    }

    #[test]
    fn validate_sbom_passes_for_complete_sbom() {
        let manifest = sample_manifest();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sbom_path = generate_sbom(&manifest, &lock, &output_dir).unwrap();
        let content = std::fs::read_to_string(&sbom_path).unwrap();
        let sbom: CycloneDxSbom = serde_json::from_str(&content).unwrap();

        assert!(validate_sbom(&sbom, &manifest, &lock).is_ok());
    }

    #[test]
    fn validate_sbom_fails_when_missing_package() {
        let manifest = sample_manifest();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sbom_path = generate_sbom(&manifest, &lock, &output_dir).unwrap();
        let content = std::fs::read_to_string(&sbom_path).unwrap();
        let mut sbom: CycloneDxSbom = serde_json::from_str(&content).unwrap();

        // Remove the openssh-server component
        sbom.components.retain(|c| c.name != "openssh-server");

        assert!(validate_sbom(&sbom, &manifest, &lock).is_err());
    }

    #[test]
    fn sbom_with_initrd_and_firmware_includes_them() {
        let mut manifest = sample_manifest();
        manifest.artifacts.initrd = Some(ArtifactDescriptor {
            format: Some("initrd-gz".into()),
            media_type: "application/vnd.pico.initrd".into(),
            digest: "sha256:initrd1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
                .into(),
            size: 4194304,
            version: None,
            cmdline: None,
            protocol_version: None,
            capabilities: vec![],
        });
        manifest.artifacts.firmware = Some(ArtifactDescriptor {
            format: Some("firmware".into()),
            media_type: "application/vnd.pico.firmware".into(),
            digest: "sha256:firmw1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
                .into(),
            size: 1048576,
            version: None,
            cmdline: None,
            protocol_version: None,
            capabilities: vec![],
        });
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sbom_path = generate_sbom(&manifest, &lock, &output_dir).unwrap();
        let content = std::fs::read_to_string(&sbom_path).unwrap();
        let sbom: CycloneDxSbom = serde_json::from_str(&content).unwrap();

        assert!(sbom.components.iter().any(|c| c.name == "initrd"));
        assert!(sbom.components.iter().any(|c| c.name == "firmware"));
    }
}
