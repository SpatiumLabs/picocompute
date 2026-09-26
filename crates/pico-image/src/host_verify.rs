//! Host-side verification of a PicoCompute guest image before cache or boot.
//!
//! Production mode fails closed: an unsigned image, an unpinned signer, a
//! signature that does not match an approved key, or a materialized artifact
//! whose digest or size differs from the signed manifest is rejected.
//!
//! The host re-checks the same contract the builder signed. A scheduler
//! decision never waives this check.

use crate::error::ImageError;
use crate::render::compute_file_digest;
use crate::signature::{verify_manifest_bytes, verify_manifest_bytes_with_key};
use crate::types::{ArtifactDescriptor, PicoComputeGuestManifest};
use crate::util::compute_sha256_digest;
use camino::Utf8Path;
use ed25519_dalek::VerifyingKey;

/// Local files the host is about to cache or boot, plus the signed manifest.
#[derive(Debug, Clone)]
pub struct HostImageLayout<'a> {
    /// Path to `manifest.json`.
    pub manifest_path: &'a Utf8Path,
    /// Path to the detached signature bundle. Required in production mode.
    pub signature_path: Option<&'a Utf8Path>,
    /// Materialized ext4 (or other) rootfs matching `artifacts.rootfs`.
    pub rootfs_path: &'a Utf8Path,
    /// Materialized kernel matching `artifacts.kernel`, when the variant has one.
    pub kernel_path: Option<&'a Utf8Path>,
    /// Materialized guest-agent binary matching `artifacts.guest_agent`.
    pub guest_agent_path: &'a Utf8Path,
    /// Materialized initrd matching `artifacts.initrd`, when present.
    pub initrd_path: Option<&'a Utf8Path>,
    /// Materialized firmware matching `artifacts.firmware`, when present.
    pub firmware_path: Option<&'a Utf8Path>,
}

/// Policy the host applies when verifying a layout.
#[derive(Debug, Clone)]
pub enum HostVerificationPolicy {
    /// Reject unsigned images and pin the signer to `trusted_key`.
    Production { trusted_key: VerifyingKey },
    /// Allow unsigned images; a present signature must still be valid.
    Development,
}

/// Manifest and digest accepted by [`verify_for_host`].
#[derive(Debug, Clone)]
pub struct VerifiedImage {
    /// Parsed PicoCompute guest manifest after signature and digest checks.
    pub manifest: PicoComputeGuestManifest,
    /// SHA-256 digest of the manifest bytes (`sha256:<hex>`).
    pub manifest_digest: String,
    /// Signer identity from the signature bundle, when a signature was present.
    pub signer_identity: Option<String>,
}

/// Verify a materialized guest image before cache use or boot.
///
/// Production mode requires a detached signature, an approved verifying key,
/// and a matching digest and size for every declared artifact that the host
/// presents. Non-production mode still rejects a present but invalid
/// signature and any digest or size mismatch.
pub fn verify_for_host(
    layout: &HostImageLayout<'_>,
    policy: &HostVerificationPolicy,
) -> Result<VerifiedImage, ImageError> {
    let manifest_bytes = std::fs::read(layout.manifest_path).map_err(|e| {
        ImageError::IoError(std::io::Error::new(
            e.kind(),
            format!("failed to read manifest {}: {e}", layout.manifest_path),
        ))
    })?;
    let manifest: PicoComputeGuestManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| {
            ImageError::ParseError(format!(
                "invalid PicoCompute guest manifest at {}: {e}",
                layout.manifest_path
            ))
        })?;

    let signer_identity = verify_signature(layout, policy, &manifest_bytes, &manifest)?;
    verify_artifacts(layout, &manifest)?;

    Ok(VerifiedImage {
        manifest,
        manifest_digest: compute_sha256_digest(&manifest_bytes),
        signer_identity,
    })
}

fn verify_signature(
    layout: &HostImageLayout<'_>,
    policy: &HostVerificationPolicy,
    manifest_bytes: &[u8],
    manifest: &PicoComputeGuestManifest,
) -> Result<Option<String>, ImageError> {
    match (policy, layout.signature_path) {
        (HostVerificationPolicy::Production { trusted_key }, Some(signature_path)) => {
            let bundle =
                verify_manifest_bytes_with_key(manifest_bytes, signature_path, trusted_key)?;
            check_bundle_image_id(&bundle.image_id, &bundle.signer_identity, manifest)?;
            Ok(Some(bundle.signer_identity))
        }
        (HostVerificationPolicy::Production { .. }, None) => {
            Err(ImageError::UnsignedImageRejected {
                image_id: manifest.image_id.clone(),
            })
        }
        (HostVerificationPolicy::Development, Some(signature_path)) => {
            let bundle = verify_manifest_bytes(manifest_bytes, signature_path)?;
            check_bundle_image_id(&bundle.image_id, &bundle.signer_identity, manifest)?;
            Ok(Some(bundle.signer_identity))
        }
        (HostVerificationPolicy::Development, None) => Ok(None),
    }
}

fn check_bundle_image_id(
    bundle_image_id: &str,
    _signer_identity: &str,
    manifest: &PicoComputeGuestManifest,
) -> Result<(), ImageError> {
    if bundle_image_id != manifest.image_id {
        return Err(ImageError::SignatureVerificationFailed(format!(
            "signature image_id '{bundle_image_id}' does not match manifest image_id '{}'",
            manifest.image_id
        )));
    }
    Ok(())
}

struct Binding<'a> {
    name: &'static str,
    descriptor: Option<&'a ArtifactDescriptor>,
    path: Option<&'a Utf8Path>,
    required: bool,
}

fn verify_artifacts(
    layout: &HostImageLayout<'_>,
    manifest: &PicoComputeGuestManifest,
) -> Result<(), ImageError> {
    let bindings = [
        Binding {
            name: "rootfs",
            descriptor: Some(&manifest.artifacts.rootfs),
            path: Some(layout.rootfs_path),
            required: true,
        },
        Binding {
            name: "guest_agent",
            descriptor: Some(&manifest.artifacts.guest_agent),
            path: Some(layout.guest_agent_path),
            required: true,
        },
        Binding {
            name: "kernel",
            descriptor: manifest.artifacts.kernel.as_ref(),
            path: layout.kernel_path,
            required: manifest.artifacts.kernel.is_some(),
        },
        Binding {
            name: "initrd",
            descriptor: manifest.artifacts.initrd.as_ref(),
            path: layout.initrd_path,
            required: manifest.artifacts.initrd.is_some(),
        },
        Binding {
            name: "firmware",
            descriptor: manifest.artifacts.firmware.as_ref(),
            path: layout.firmware_path,
            required: manifest.artifacts.firmware.is_some(),
        },
    ];

    for binding in &bindings {
        verify_one(binding, &manifest.image_id)?;
    }
    Ok(())
}

fn verify_one(binding: &Binding<'_>, image_id: &str) -> Result<(), ImageError> {
    let Some(descriptor) = binding.descriptor else {
        return Ok(());
    };
    let Some(path) = binding.path else {
        if binding.required {
            return Err(ImageError::MissingHostArtifact {
                artifact: binding.name.into(),
                image_id: image_id.into(),
                reason: "declared in manifest but missing on host".into(),
            });
        }
        return Ok(());
    };
    // Size is cheap metadata; check it before hashing the file.
    let actual_size = std::fs::metadata(path)
        .map_err(|e| {
            ImageError::IoError(std::io::Error::new(
                e.kind(),
                format!("failed to stat {} at {path}: {e}", binding.name),
            ))
        })?
        .len();
    if actual_size != descriptor.size {
        return Err(ImageError::SizeMismatch {
            artifact: binding.name.into(),
            expected: descriptor.size,
            actual: actual_size,
        });
    }
    let actual_digest = compute_file_digest(path)?;
    if actual_digest != descriptor.digest {
        return Err(ImageError::DigestMismatch {
            artifact: binding.name.into(),
            expected: descriptor.digest.clone(),
            actual: actual_digest,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{generate_signing_key, sign_manifest};
    use crate::types::{
        ArtifactDescriptor, Artifacts, BackendCompatibility, CompatibilityInfo, PlatformInfo,
        ProtocolInfo, ProtocolVersionRange, ReleaseInfo, SignatureBundle, SnapshotInfo,
    };
    use pico_core::mount::{MountClass, MountContract, MountEntry, PathLifecycle};
    use tempfile::TempDir;

    fn write_bytes(dir: &Utf8Path, name: &str, bytes: &[u8]) -> camino::Utf8PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn digest_of(bytes: &[u8]) -> String {
        compute_sha256_digest(bytes)
    }

    fn descriptor(bytes: &[u8], media_type: &str) -> ArtifactDescriptor {
        ArtifactDescriptor {
            format: None,
            media_type: media_type.into(),
            digest: digest_of(bytes),
            size: bytes.len() as u64,
            version: None,
            cmdline: None,
            protocol_version: None,
            capabilities: vec![],
        }
    }

    fn test_manifest(
        rootfs: &[u8],
        agent: &[u8],
        kernel: Option<&[u8]>,
    ) -> PicoComputeGuestManifest {
        let artifacts = Artifacts {
            rootfs: {
                let mut d = descriptor(rootfs, "application/vnd.pico.rootfs.ext4");
                d.format = Some("ext4".into());
                d
            },
            kernel: kernel.map(|k| {
                let mut d = descriptor(k, "application/vnd.pico.kernel.vmlinux");
                d.format = Some("linux-vmlinux".into());
                d.version = Some("pico-linux-6.18".into());
                d.cmdline = Some(
                    "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/init nomodules"
                        .into(),
                );
                d
            }),
            initrd: None,
            firmware: None,
            guest_agent: {
                let mut d = descriptor(agent, "application/vnd.pico.guest-agent");
                d.version = Some("0.3.0".into());
                d.protocol_version = Some("1.0".into());
                d.capabilities = vec!["exec".into()];
                d
            },
        };
        PicoComputeGuestManifest {
            schema_version: "1.0".into(),
            image_id: "pico-guest-standard".into(),
            release: ReleaseInfo {
                version: "2026.06.0".into(),
                source_revision: "abc1234".into(),
                build_epoch: 1781170000,
            },
            platform: PlatformInfo {
                os: "linux".into(),
                architecture: "aarch64".into(),
            },
            artifacts,
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
                mounts: vec![MountEntry {
                    path: "/workspace".into(),
                    class: MountClass::Workspace,
                    writable: true,
                    lifecycle: PathLifecycle::Persistent,
                }],
            },
            snapshot: SnapshotInfo {
                filesystem: true,
                memory: false,
                excluded_mount_classes: vec!["secret".into(), "runtime_tmp".into()],
            },
        }
    }

    struct Fixture {
        manifest_path: camino::Utf8PathBuf,
        signature_path: camino::Utf8PathBuf,
        rootfs_path: camino::Utf8PathBuf,
        agent_path: camino::Utf8PathBuf,
        kernel_path: camino::Utf8PathBuf,
        verifying_key: VerifyingKey,
        _temp: TempDir,
    }

    fn signed_fixture() -> Fixture {
        let temp = TempDir::new().unwrap();
        let dir = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let rootfs = b"rootfs-bytes";
        let agent = b"guest-agent-bytes";
        let kernel = b"vmlinux-bytes";
        let manifest = test_manifest(rootfs, agent, Some(kernel));
        let manifest_json = serde_json::to_vec_pretty(&manifest).unwrap();
        let manifest_path = write_bytes(&dir, "manifest.json", &manifest_json);
        let rootfs_path = write_bytes(&dir, "rootfs.ext4", rootfs);
        let agent_path = write_bytes(&dir, "pico-agent", agent);
        let kernel_path = write_bytes(&dir, "vmlinux", kernel);
        let (signing_key, verifying_key) = generate_signing_key();
        let signature_path = sign_manifest(
            &manifest_path,
            &signing_key,
            "ci-builder",
            &manifest.image_id,
            &dir,
        )
        .unwrap();
        Fixture {
            manifest_path,
            signature_path,
            rootfs_path,
            agent_path,
            kernel_path,
            verifying_key,
            _temp: temp,
        }
    }

    fn layout_from(f: &Fixture) -> HostImageLayout<'_> {
        HostImageLayout {
            manifest_path: &f.manifest_path,
            signature_path: Some(&f.signature_path),
            rootfs_path: &f.rootfs_path,
            kernel_path: Some(&f.kernel_path),
            guest_agent_path: &f.agent_path,
            initrd_path: None,
            firmware_path: None,
        }
    }

    fn production_policy(key: VerifyingKey) -> HostVerificationPolicy {
        HostVerificationPolicy::Production { trusted_key: key }
    }

    fn development_policy() -> HostVerificationPolicy {
        HostVerificationPolicy::Development
    }

    #[test]
    fn production_accepts_signed_matching_artifacts() {
        let f = signed_fixture();
        let verified = verify_for_host(&layout_from(&f), &production_policy(f.verifying_key))
            .expect("signed matching layout must pass");
        assert_eq!(verified.manifest.image_id, "pico-guest-standard");
        assert_eq!(verified.signer_identity.as_deref(), Some("ci-builder"));
        assert!(verified.manifest_digest.starts_with("sha256:"));
    }

    #[test]
    fn production_rejects_unsigned_image() {
        let f = signed_fixture();
        let mut layout = layout_from(&f);
        layout.signature_path = None;
        let err = verify_for_host(&layout, &production_policy(f.verifying_key)).unwrap_err();
        match err {
            ImageError::UnsignedImageRejected { image_id } => {
                assert_eq!(image_id, "pico-guest-standard");
            }
            other => panic!("expected UnsignedImageRejected, got {other:?}"),
        }
    }

    #[test]
    fn production_rejects_unapproved_signer() {
        let f = signed_fixture();
        let (_other_signing, other_key) = generate_signing_key();
        let err = verify_for_host(&layout_from(&f), &production_policy(other_key)).unwrap_err();
        match err {
            ImageError::SignatureVerificationFailed(_) => {}
            other => panic!("expected SignatureVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn production_rejects_tampered_manifest() {
        let f = signed_fixture();
        let mut manifest: PicoComputeGuestManifest =
            serde_json::from_slice(&std::fs::read(&f.manifest_path).unwrap()).unwrap();
        manifest.image_id = "evil-image".into();
        std::fs::write(
            &f.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let err =
            verify_for_host(&layout_from(&f), &production_policy(f.verifying_key)).unwrap_err();
        match err {
            ImageError::SignatureVerificationFailed(_) => {}
            other => panic!("expected SignatureVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn production_rejects_rootfs_digest_mismatch() {
        let f = signed_fixture();
        // Same length as `b"rootfs-bytes"` so the size check passes and the
        // digest check is what fails.
        std::fs::write(&f.rootfs_path, b"rootfs-byteX").unwrap();
        let err =
            verify_for_host(&layout_from(&f), &production_policy(f.verifying_key)).unwrap_err();
        match err {
            ImageError::DigestMismatch { artifact, .. } => assert_eq!(artifact, "rootfs"),
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn production_rejects_guest_agent_size_mismatch() {
        let f = signed_fixture();
        // Size is checked before digest, so a longer file reports a size
        // mismatch even though the digest also changed.
        std::fs::write(&f.agent_path, b"guest-agent-bytes-extra").unwrap();
        let err =
            verify_for_host(&layout_from(&f), &production_policy(f.verifying_key)).unwrap_err();
        match err {
            ImageError::SizeMismatch { artifact, .. } => assert_eq!(artifact, "guest_agent"),
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn development_rejects_guest_agent_size_mismatch_without_signature() {
        let f = signed_fixture();
        let mut manifest: PicoComputeGuestManifest =
            serde_json::from_slice(&std::fs::read(&f.manifest_path).unwrap()).unwrap();
        // Keep the file bytes (and digest) but lie about the size in an
        // unsigned manifest, so only the size check can fail.
        manifest.artifacts.guest_agent.size += 1;
        std::fs::write(
            &f.manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let mut layout = layout_from(&f);
        layout.signature_path = None;
        let err = verify_for_host(&layout, &development_policy()).unwrap_err();
        match err {
            ImageError::SizeMismatch { artifact, .. } => assert_eq!(artifact, "guest_agent"),
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn production_rejects_missing_kernel_when_manifest_declares_it() {
        let f = signed_fixture();
        let mut layout = layout_from(&f);
        layout.kernel_path = None;
        let err = verify_for_host(&layout, &production_policy(f.verifying_key)).unwrap_err();
        match err {
            ImageError::MissingHostArtifact { artifact, .. } => assert_eq!(artifact, "kernel"),
            other => panic!("expected MissingHostArtifact, got {other:?}"),
        }
    }

    #[test]
    fn non_production_allows_unsigned_when_digests_match() {
        let f = signed_fixture();
        let mut layout = layout_from(&f);
        layout.signature_path = None;
        let verified =
            verify_for_host(&layout, &development_policy()).expect("unsigned debug image may boot");
        assert!(verified.signer_identity.is_none());
    }

    #[test]
    fn non_production_still_rejects_digest_mismatch() {
        let f = signed_fixture();
        let mut layout = layout_from(&f);
        layout.signature_path = None;
        std::fs::write(&f.rootfs_path, b"rootfs-byteX").unwrap();
        let err = verify_for_host(&layout, &development_policy()).unwrap_err();
        match err {
            ImageError::DigestMismatch { artifact, .. } => assert_eq!(artifact, "rootfs"),
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn production_rejects_signature_image_id_mismatch() {
        let f = signed_fixture();
        let json = std::fs::read_to_string(&f.signature_path).unwrap();
        let mut bundle: SignatureBundle = serde_json::from_str(&json).unwrap();
        bundle.image_id = "other-image".into();
        std::fs::write(&f.signature_path, serde_json::to_string(&bundle).unwrap()).unwrap();
        let err =
            verify_for_host(&layout_from(&f), &production_policy(f.verifying_key)).unwrap_err();
        match err {
            ImageError::SignatureVerificationFailed(msg) => {
                assert!(msg.contains("image_id"));
            }
            other => panic!("expected SignatureVerificationFailed, got {other:?}"),
        }
    }
}
