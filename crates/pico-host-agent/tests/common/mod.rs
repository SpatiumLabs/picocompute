//! Shared fixtures for the host image-verification suite.
//!
//! Builds a minimal but *self-consistent* PicoCompute guest image on disk: a
//! manifest whose artifact digests, artifact sizes, and per-layer digests all
//! match the bytes written next to it. Verification tests need genuine bytes,
//! otherwise they would pass or fail for the wrong reason.

use camino::Utf8PathBuf;
use pico_core::mount::{MountClass, MountEntry, PathLifecycle, SnapshotInfo};
use pico_image::layers::{
    CompositionCompatibility, ENVIRONMENT_LAYER_FEATURE, EnvironmentComposition, EnvironmentLayer,
    EnvironmentLayerKind,
};
use pico_image::render::compute_file_digest;
use pico_image::types::*;

/// Artifact bytes written for every bundle, in fixed form so sizes and digests
/// are deterministic.
const ROOTFS_BYTES: &[u8] = b"rootfs-image-bytes";
const AGENT_BYTES: &[u8] = b"guest-agent-bytes";
const KERNEL_BYTES: &[u8] = b"vmlinux-bytes";

/// Write a complete, self-consistent image bundle into `dir` and return the
/// manifest describing it.
///
/// When `layered` is set, a three-layer composition (base, workspace, toolkit)
/// is attached with digests computed from the layer files written to `dir`, and
/// the required-feature marker is declared.
pub(crate) fn write_image_bundle(dir: &Utf8PathBuf, layered: bool) -> PicoComputeGuestManifest {
    write_file(dir, "rootfs.ext4", ROOTFS_BYTES);
    write_file(dir, "pico-guest-agent", AGENT_BYTES);
    write_file(dir, "vmlinux", KERNEL_BYTES);

    let mut manifest = base_manifest(dir);
    if layered {
        attach_real_composition(&mut manifest, dir);
    }
    manifest
}

fn write_file(dir: &Utf8PathBuf, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).unwrap();
}

fn digest_of(dir: &Utf8PathBuf, name: &str) -> String {
    compute_file_digest(&dir.join(name)).unwrap()
}

fn size_of(dir: &Utf8PathBuf, name: &str) -> u64 {
    std::fs::metadata(dir.join(name)).unwrap().len()
}

fn base_manifest(dir: &Utf8PathBuf) -> PicoComputeGuestManifest {
    PicoComputeGuestManifest {
        schema_version: "1.0".into(),
        image_id: "test-image".into(),
        release: ReleaseInfo {
            version: "0.1.0".into(),
            source_revision: "abc1234".into(),
            build_epoch: 1781170000,
        },
        platform: PlatformInfo {
            os: "linux".into(),
            architecture: current_arch(),
        },
        artifacts: Artifacts {
            rootfs: ArtifactDescriptor {
                format: Some("ext4".into()),
                media_type: "application/vnd.pico.rootfs.ext4".into(),
                digest: digest_of(dir, "rootfs.ext4"),
                size: size_of(dir, "rootfs.ext4"),
                version: None,
                cmdline: None,
                protocol_version: None,
                capabilities: vec![],
            },
            kernel: Some(ArtifactDescriptor {
                format: Some("linux-vmlinux".into()),
                media_type: "application/vnd.pico.kernel.vmlinux".into(),
                digest: digest_of(dir, "vmlinux"),
                size: size_of(dir, "vmlinux"),
                version: Some("pico-linux-6.18".into()),
                cmdline: Some(
                    "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/init nomodules"
                        .into(),
                ),
                protocol_version: None,
                capabilities: vec![],
            }),
            initrd: None,
            firmware: None,
            guest_agent: ArtifactDescriptor {
                format: None,
                media_type: "application/vnd.pico.guest-agent".into(),
                digest: digest_of(dir, "pico-guest-agent"),
                size: size_of(dir, "pico-guest-agent"),
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
            profile_id: profile_id_for(&current_arch()).into(),
            backends: vec![BackendCompatibility {
                family: "firecracker".into(),
                runtime_version: "1.0".into(),
                architecture: current_arch(),
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
                MountEntry {
                    path: "/run/pico/secrets".into(),
                    class: MountClass::Secret,
                    writable: false,
                    lifecycle: PathLifecycle::Ephemeral,
                },
                MountEntry {
                    path: "/var/log/pico".into(),
                    class: MountClass::GuestLogs,
                    writable: true,
                    lifecycle: PathLifecycle::Persistent,
                },
            ],
        },
        snapshot: SnapshotInfo {
            filesystem: true,
            memory: false,
            excluded_mount_classes: vec!["runtime_tmp".into(), "secret".into()],
        },
        required_features: vec![],
        environment: None,
    }
}

fn current_arch() -> String {
    std::env::consts::ARCH.to_string()
}

fn profile_id_for(arch: &str) -> &'static str {
    match arch {
        "aarch64" => "firecracker-aarch64-v1",
        _ => "firecracker-x86_64-v1",
    }
}

/// Attach a three-layer composition whose digests match bytes written to `dir`.
pub(crate) fn attach_real_composition(manifest: &mut PicoComputeGuestManifest, dir: &Utf8PathBuf) {
    let make = |name: &str, kind: EnvironmentLayerKind, bytes: &[u8], tag: &str| {
        let file = format!("{name}.erofs");
        write_file(dir, &file, bytes);
        EnvironmentLayer::new(
            name,
            kind,
            digest_of(dir, &file),
            size_of(dir, &file),
            "application/vnd.pico.layer.erofs",
        )
        .unwrap()
        .with_version("2026.09.1")
        .with_evidence(
            Some(format!("sha256:sbom{tag}")),
            Some(format!("sha256:prv{tag}")),
            Some(format!("sha256:sig{tag}")),
        )
    };

    let base = make(
        "debian-base",
        EnvironmentLayerKind::Base,
        b"base-layer",
        "b",
    );
    let workspace = make(
        "workspace-seed",
        EnvironmentLayerKind::Workspace,
        b"workspace-layer",
        "w",
    );
    let toolkit = make(
        "toolkit-python",
        EnvironmentLayerKind::Toolkit,
        b"toolkit-layer",
        "t",
    );

    let composition = EnvironmentComposition::new(
        manifest.image_id.clone(),
        base,
        workspace,
        vec![toolkit],
        CompositionCompatibility {
            profile_id: manifest.compatibility.profile_id.clone(),
            backends: manifest.compatibility.backends.clone(),
            architecture: manifest.platform.architecture.clone(),
            protocol_supported: manifest.protocol.supported.clone(),
            snapshot_excluded_classes: manifest.snapshot.excluded_mount_classes.clone(),
        },
        manifest.release.build_epoch,
    )
    .expect("test composition must validate");

    manifest.environment = Some(composition);
    manifest.required_features = vec![ENVIRONMENT_LAYER_FEATURE.into()];
}

/// Attach a composition whose layer files are *not* written to `dir`.
///
/// Used to prove that a host missing a declared layer fails closed rather than
/// skipping the layer check. Digests are synthetic because the point is that
/// discovery fails before any digest is compared.
pub(crate) fn attach_composition_without_files(manifest: &mut PicoComputeGuestManifest) {
    let layer = |name: &str, kind: EnvironmentLayerKind, digest: &str| {
        EnvironmentLayer::new(
            name,
            kind,
            format!("sha256:{digest}"),
            16,
            "application/vnd.pico.layer.erofs",
        )
        .unwrap()
        .with_version("2026.09.1")
        .with_evidence(
            Some("sha256:sbomx".into()),
            Some("sha256:prvx".into()),
            Some("sha256:sigx".into()),
        )
    };

    let composition = EnvironmentComposition::new(
        manifest.image_id.clone(),
        layer("debian-base", EnvironmentLayerKind::Base, "base"),
        layer("workspace-seed", EnvironmentLayerKind::Workspace, "work"),
        vec![layer(
            "toolkit-python",
            EnvironmentLayerKind::Toolkit,
            "tool",
        )],
        CompositionCompatibility {
            profile_id: manifest.compatibility.profile_id.clone(),
            backends: manifest.compatibility.backends.clone(),
            architecture: manifest.platform.architecture.clone(),
            protocol_supported: manifest.protocol.supported.clone(),
            snapshot_excluded_classes: manifest.snapshot.excluded_mount_classes.clone(),
        },
        manifest.release.build_epoch,
    )
    .expect("test composition must validate");

    manifest.environment = Some(composition);
    manifest.required_features = vec![ENVIRONMENT_LAYER_FEATURE.into()];
}
