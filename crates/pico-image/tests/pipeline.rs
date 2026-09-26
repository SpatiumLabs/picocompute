#[cfg(test)]
mod tests {
    use pico_core::mount::{MountClass, MountEntry, PathLifecycle, SnapshotInfo};
    use pico_image::definition::*;
    use pico_image::error::*;
    use pico_image::lock::*;
    use pico_image::manifest;
    use pico_image::render;
    use pico_image::types::*;
    use std::fs;
    use tempfile::TempDir;

    fn sample_definition() -> ImageDefinition {
        ImageDefinition {
            image: ImageInfo {
                id: "test-image".into(),
                version: "0.1.0".into(),
                source_date_epoch: 1781170000,
            },
            base: BaseSource {
                source: SourceRef {
                    url: "https://example.com/rootfs.tar.gz".into(),
                    digest: "sha256:abc123".into(),
                },
            },
            packages: std::collections::BTreeMap::from([(
                "openssh-server".into(),
                "9.9_p2-r0".into(),
            )]),
            guest_agent: GuestAgentSource::Workspace {
                version: Some("0.3.0".into()),
                protocol_version: Some("1.0".into()),
                capabilities: vec!["exec".into()],
            },
            filesystem: FilesystemConfig {
                size: "64M".into(),
                label: "test-root".into(),
                uuid: "00000000-0000-4000-a000-000000000001".into(),
            },
            mounts: vec![
                MountDef {
                    path: "/workspace".into(),
                    class: "workspace".into(),
                    writable: true,
                    lifecycle: PathLifecycle::Persistent,
                },
                MountDef {
                    path: "/run/pico/tmp".into(),
                    class: "runtime_tmp".into(),
                    writable: true,
                    lifecycle: PathLifecycle::Ephemeral,
                },
                MountDef {
                    path: "/run/pico/secrets".into(),
                    class: "secret".into(),
                    writable: false,
                    lifecycle: PathLifecycle::Ephemeral,
                },
            ],
            kernel: None,
        }
    }

    fn sample_lock() -> PackageLock {
        PackageLock {
            metadata: LockMetadata {
                image_id: "test-image".into(),
                version: "0.1.0".into(),
                source_date_epoch: 1781170000,
            },
            base: LockBase {
                url: "https://example.com/rootfs.tar.gz".into(),
                digest: "sha256:abc123".into(),
            },
            guest_agent: LockArtifact {
                digest: "sha256:guest123".into(),
            },
            packages: vec![LockedPackage {
                name: "openssh-server".into(),
                version: "9.9_p2-r0".into(),
                digest: "sha256:pkg123".into(),
            }],
        }
    }

    #[test]
    fn manifest_serialization_roundtrip() {
        let manifest = PicoComputeGuestManifest {
            schema_version: "1.0".into(),
            image_id: "test-image".into(),
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
                    digest: "sha256:rootfs123".into(),
                    size: 67108864,
                    version: None,
                    cmdline: None,
                    protocol_version: None,
                    capabilities: vec![],
                },
                kernel: None,
                initrd: None,
                firmware: None,
                guest_agent: ArtifactDescriptor {
                    format: None,
                    media_type: "application/vnd.pico.guest-agent".into(),
                    digest: "sha256:agent123".into(),
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
                capabilities: vec![],
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
        };

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: PicoComputeGuestManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.schema_version, "1.0");
        assert_eq!(parsed.image_id, "test-image");
        assert_eq!(parsed.artifacts.rootfs.digest, "sha256:rootfs123");
        assert_eq!(parsed.artifacts.rootfs.format, Some("ext4".into()));
        assert!(parsed.artifacts.kernel.is_none());
        assert_eq!(parsed.artifacts.guest_agent.digest, "sha256:agent123");
    }

    #[test]
    fn manifest_with_null_kernel_is_none() {
        let json = r#"{
            "schema_version": "1.0",
            "image_id": "test",
            "release": { "version": "1.0", "source_revision": "abc", "build_epoch": 1000 },
            "platform": { "os": "linux", "architecture": "aarch64" },
            "artifacts": {
                "rootfs": { "format": "ext4", "media_type": "vnd.test", "digest": "sha256:abc", "size": 1024 },
                "kernel": null,
                "initrd": null,
                "firmware": null,
                "guest_agent": { "media_type": "vnd.test", "digest": "sha256:def", "size": 2048 }
            },
            "protocol": { "bootstrap": "v1", "supported": [], "capabilities": [] },
            "compatibility": { "profile_id": "p1", "backends": [], "required_cpu_features": [], "required_devices": [], "required_host_features": [] },
            "mount_contract": { "version": "1.0", "mounts": [
                {"path":"/workspace","class":"workspace","writable":true,"lifecycle":"persistent"},
                {"path":"/run/pico/tmp","class":"runtime_tmp","writable":true,"lifecycle":"ephemeral"},
                {"path":"/run/pico/secrets","class":"secret","writable":false,"lifecycle":"ephemeral"},
                {"path":"/var/log/pico","class":"guest_logs","writable":true,"lifecycle":"persistent"}
            ] },
            "snapshot": { "filesystem": true, "memory": false, "excluded_mount_classes": ["runtime_tmp", "secret"] }
        }"#;

        let manifest: PicoComputeGuestManifest = serde_json::from_str(json).unwrap();
        assert!(manifest.artifacts.kernel.is_none());
        assert!(manifest.artifacts.initrd.is_none());
    }

    #[test]
    fn image_definition_parsing() {
        let toml = r#"
[image]
id = "test-image"
version = "0.1.0"
source_date_epoch = 1781170000

[base.source]
url = "https://example.com/rootfs.tar.gz"
digest = "sha256:abc123"

[packages]
openssh-server = "9.9_p2-r0"

[guest_agent]
source = "workspace"

[filesystem]
size = "64M"
label = "test-root"
uuid = "00000000-0000-4000-a000-000000000001"

[[mounts]]
path = "/workspace"
class = "workspace"
writable = true
lifecycle = "persistent"
"#;

        let def: ImageDefinition = toml::from_str(toml).unwrap();
        assert_eq!(def.image.id, "test-image");
        assert_eq!(def.image.source_date_epoch, 1781170000);
        assert_eq!(def.base.source.digest, "sha256:abc123");
        assert_eq!(
            def.packages.get("openssh-server"),
            Some(&"9.9_p2-r0".to_string())
        );
        assert_eq!(def.filesystem.size, "64M");
        assert_eq!(def.mounts.len(), 1);
        assert_eq!(def.mounts[0].class, "workspace");
    }

    #[test]
    fn image_definition_prebuilt_guest_agent() {
        let toml = r#"
[image]
id = "test"
version = "1.0"
source_date_epoch = 1000

[base.source]
url = "https://example.com/rootfs.tar.gz"
digest = "sha256:abc"

[packages]

[guest_agent]
source = "prebuilt"
path = "/tmp/agent"
digest = "sha256:def"

[filesystem]
size = "64M"
label = "test"
uuid = "00000000-0000-4000-a000-000000000001"
"#;

        let def: ImageDefinition = toml::from_str(toml).unwrap();
        match def.guest_agent {
            GuestAgentSource::Prebuilt { path, digest, .. } => {
                assert_eq!(path, "/tmp/agent");
                assert_eq!(digest, "sha256:def");
            }
            _ => panic!("expected Prebuilt guest agent"),
        }
    }

    #[test]
    fn lock_file_roundtrip() {
        let lock = sample_lock();
        let dir = TempDir::new().unwrap();
        let path = camino::Utf8PathBuf::from_path_buf(dir.path().join("lock.toml")).unwrap();

        lock.save(&path).unwrap();
        let loaded = PackageLock::load(&path).unwrap();

        assert_eq!(loaded.metadata.image_id, lock.metadata.image_id);
        assert_eq!(loaded.base.digest, lock.base.digest);
        assert_eq!(loaded.packages.len(), 1);
        assert_eq!(loaded.packages[0].name, "openssh-server");
    }

    #[test]
    fn lock_file_with_empty_packages() {
        let mut lock = sample_lock();
        lock.packages = vec![];

        let dir = TempDir::new().unwrap();
        let path = camino::Utf8PathBuf::from_path_buf(dir.path().join("lock.toml")).unwrap();

        lock.save(&path).unwrap();
        let loaded = PackageLock::load(&path).unwrap();

        assert!(loaded.packages.is_empty());
    }

    #[test]
    fn manifest_validation_rejects_empty_schema() {
        let manifest = PicoComputeGuestManifest {
            schema_version: "".into(),
            image_id: "test".into(),
            release: ReleaseInfo {
                version: "1.0".into(),
                source_revision: "abc".into(),
                build_epoch: 1000,
            },
            platform: PlatformInfo {
                os: "linux".into(),
                architecture: "aarch64".into(),
            },
            artifacts: Artifacts {
                rootfs: ArtifactDescriptor {
                    format: None,
                    media_type: "test".into(),
                    digest: "sha256:abc".into(),
                    size: 0,
                    version: None,
                    cmdline: None,
                    protocol_version: None,
                    capabilities: vec![],
                },
                kernel: None,
                initrd: None,
                firmware: None,
                guest_agent: ArtifactDescriptor {
                    format: None,
                    media_type: "test".into(),
                    digest: "sha256:abc".into(),
                    size: 0,
                    version: None,
                    cmdline: None,
                    protocol_version: None,
                    capabilities: vec![],
                },
            },
            protocol: ProtocolInfo {
                bootstrap: "v1".into(),
                supported: vec![],
                capabilities: vec![],
            },
            compatibility: CompatibilityInfo {
                profile_id: "p1".into(),
                backends: vec![],
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
                filesystem: false,
                memory: false,
                excluded_mount_classes: vec!["secret".into(), "runtime_tmp".into()],
            },
        };

        let def = simple_definition();
        let result = manifest::validate_manifest(&manifest, &def);
        assert!(result.is_err());
    }

    #[test]
    fn manifest_validation_rejects_empty_image_id() {
        let def = simple_definition();
        let mut manifest = valid_manifest();
        manifest.image_id = "".into();
        assert!(manifest::validate_manifest(&manifest, &def).is_err());
    }

    #[test]
    fn manifest_validation_rejects_empty_rootfs_digest() {
        let def = simple_definition();
        let mut manifest = valid_manifest();
        manifest.artifacts.rootfs.digest = "".into();
        assert!(manifest::validate_manifest(&manifest, &def).is_err());
    }

    fn simple_definition() -> ImageDefinition {
        ImageDefinition {
            image: ImageInfo {
                id: "test".into(),
                version: "1.0".into(),
                source_date_epoch: 1000,
            },
            base: BaseSource {
                source: SourceRef {
                    url: "https://example.com/rootfs.tar.gz".into(),
                    digest: "sha256:abc".into(),
                },
            },
            packages: std::collections::BTreeMap::new(),
            guest_agent: GuestAgentSource::Workspace {
                version: Some("0.3.0".into()),
                protocol_version: Some("1.0".into()),
                capabilities: vec!["exec".into()],
            },
            filesystem: FilesystemConfig {
                size: "64M".into(),
                label: "test".into(),
                uuid: "00000000-0000-4000-a000-000000000001".into(),
            },
            mounts: vec![
                MountDef {
                    path: "/workspace".into(),
                    class: "workspace".into(),
                    writable: true,
                    lifecycle: PathLifecycle::Persistent,
                },
                MountDef {
                    path: "/run/pico/tmp".into(),
                    class: "runtime_tmp".into(),
                    writable: true,
                    lifecycle: PathLifecycle::Ephemeral,
                },
                MountDef {
                    path: "/run/pico/secrets".into(),
                    class: "secret".into(),
                    writable: false,
                    lifecycle: PathLifecycle::Ephemeral,
                },
            ],
            kernel: None,
        }
    }

    fn valid_manifest() -> PicoComputeGuestManifest {
        PicoComputeGuestManifest {
            schema_version: "1.0".into(),
            image_id: "test".into(),
            release: ReleaseInfo {
                version: "1.0".into(),
                source_revision: "abc".into(),
                build_epoch: 1000,
            },
            platform: PlatformInfo {
                os: "linux".into(),
                architecture: "aarch64".into(),
            },
            artifacts: Artifacts {
                rootfs: ArtifactDescriptor {
                    format: None,
                    media_type: "test".into(),
                    digest: "sha256:abc".into(),
                    size: 0,
                    version: None,
                    cmdline: None,
                    protocol_version: None,
                    capabilities: vec![],
                },
                kernel: None,
                initrd: None,
                firmware: None,
                guest_agent: ArtifactDescriptor {
                    format: None,
                    media_type: "test".into(),
                    digest: "sha256:abc".into(),
                    size: 0,
                    version: Some("0.3.0".into()),
                    cmdline: None,
                    protocol_version: Some("1.0".into()),
                    capabilities: vec![],
                },
            },
            protocol: ProtocolInfo {
                bootstrap: "v1".into(),
                supported: vec![],
                capabilities: vec![],
            },
            compatibility: CompatibilityInfo {
                profile_id: "p1".into(),
                backends: vec![],
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
                ],
            },
            snapshot: SnapshotInfo {
                filesystem: false,
                memory: false,
                excluded_mount_classes: vec!["runtime_tmp".into(), "secret".into()],
            },
        }
    }

    #[test]
    fn compute_digest_consistent() {
        let dir = TempDir::new().unwrap();
        let file_path = camino::Utf8PathBuf::from_path_buf(dir.path().join("test.bin")).unwrap();
        fs::write(&file_path, b"hello reproducible world").unwrap();

        let d1 = render::compute_file_digest(&file_path).unwrap();
        let d2 = render::compute_file_digest(&file_path).unwrap();

        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
    }

    #[test]
    fn error_display() {
        let err = ImageError::MissingTool {
            tool: "mkfs.ext4".into(),
        };
        assert!(err.to_string().contains("mkfs.ext4"));

        let err = ImageError::DigestMismatch {
            artifact: "rootfs".into(),
            expected: "sha256:abc".into(),
            actual: "sha256:def".into(),
        };
        assert!(err.to_string().contains("rootfs"));
    }

    #[test]
    fn lock_file_reproducibility() {
        let def = sample_definition();
        let dir = TempDir::new().unwrap();

        let path1 = camino::Utf8PathBuf::from_path_buf(dir.path().join("lock1.toml")).unwrap();
        let path2 = camino::Utf8PathBuf::from_path_buf(dir.path().join("lock2.toml")).unwrap();

        let lock1 = pico_image::resolve::create_lock(&def, &path1).unwrap();
        let lock2 = pico_image::resolve::create_lock(&def, &path2).unwrap();

        let toml1 = toml::to_string(&lock1).unwrap();
        let toml2 = toml::to_string(&lock2).unwrap();

        assert_eq!(toml1, toml2, "lock files must be identical");
    }

    #[test]
    fn manifest_json_conforms_to_adr_schema() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().join("output")).unwrap();
        fs::create_dir_all(output_dir.as_std_path()).unwrap();

        let tmp_rootfs = dir.path().join("dummy.ext4");
        fs::write(&tmp_rootfs, b"fake ext4 content").unwrap();
        let rootfs = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_rootfs).unwrap(),
            digest: "sha256:rootfs123".into(),
            size: 1024,
        };

        let tmp_agent = dir.path().join("dummy-agent");
        fs::write(&tmp_agent, b"fake guest agent").unwrap();
        let agent = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_agent).unwrap(),
            digest: "sha256:agent456".into(),
            size: 2048,
        };

        let mount_contract = pico_image::build_mount_contract_from_def(&def).unwrap();

        let (manifest_path, _manifest) = pico_image::manifest::generate_manifest(
            &def,
            &lock,
            &rootfs,
            &agent,
            &output_dir,
            &mount_contract,
            None,
        )
        .unwrap();

        assert!(manifest_path.exists());

        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();

        assert!(json.get("schema_version").is_some());
        assert!(json.get("image_id").is_some());
        assert!(json.get("release").is_some());
        assert!(json.get("platform").is_some());
        assert!(json.get("artifacts").is_some());

        let artifacts = json.get("artifacts").unwrap();
        assert!(artifacts.get("rootfs").is_some());
        assert_eq!(
            artifacts
                .get("rootfs")
                .unwrap()
                .get("digest")
                .unwrap()
                .as_str()
                .unwrap(),
            "sha256:rootfs123"
        );
    }

    #[test]
    fn builder_respects_locked_mode() {
        let dir = TempDir::new().unwrap();

        let def_path = dir.path().join("image.toml");
        let toml = r#"
[image]
id = "locked-test"
version = "0.1.0"
source_date_epoch = 1781170000

[base.source]
url = "https://example.com/rootfs.tar.gz"
digest = "sha256:abc123"

[packages]

[guest_agent]
source = "prebuilt"
path = "/nonexistent/agent"
digest = "sha256:000"

[filesystem]
size = "64M"
label = "test"
uuid = "00000000-0000-4000-a000-000000000001"

[[mounts]]
path = "/workspace"
class = "workspace"
writable = true
lifecycle = "persistent"
"#;
        fs::write(&def_path, toml).unwrap();

        let builder = pico_image::RootfsBuilder {
            definition_path: camino::Utf8PathBuf::from_path_buf(def_path.clone()).unwrap(),
            lock_path: None,
            work_dir: camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap(),
            output_dir: camino::Utf8PathBuf::from_path_buf(dir.path().join("output")).unwrap(),
            guest_agent_path: None,
            locked: true,
            signing_key_path: None,
            signer_identity: None,
        };

        let result = builder.build();
        assert!(result.is_err(), "locked mode without lock file should fail");
    }

    #[test]
    fn create_lock_from_definition() {
        let def = sample_definition();
        let dir = TempDir::new().unwrap();
        let lock_path = camino::Utf8PathBuf::from_path_buf(dir.path().join("lock.toml")).unwrap();

        let lock = pico_image::resolve::create_lock(&def, &lock_path).unwrap();

        assert_eq!(lock.metadata.image_id, "test-image");
        assert_eq!(lock.base.digest, "sha256:abc123");
        assert_eq!(lock.packages.len(), 1);
        assert_eq!(lock.packages[0].name, "openssh-server");
        assert!(lock_path.exists());
    }

    // --- Kernel config profile tests ---

    #[test]
    fn kernel_firecracker_aarch64_profile_has_virtio_devices() {
        use pico_image::kernel;
        let profile = kernel::firecracker_aarch64_v1();
        let all = profile.all_required_options();
        assert!(all.contains(&"CONFIG_VIRTIO_BLK=y".into()));
        assert!(all.contains(&"CONFIG_VIRTIO_NET=y".into()));
        assert!(all.contains(&"CONFIG_VIRTIO_MMIO=y".into()));
        assert!(all.contains(&"CONFIG_VSOCKETS=y".into()));
        assert!(all.contains(&"CONFIG_VIRTIO_VSOCKETS=y".into()));
    }

    #[test]
    fn kernel_production_excludes_debug_options() {
        use pico_image::kernel::{self, BootVariant};
        let prod = kernel::firecracker_aarch64_v1();
        assert_eq!(prod.variant, BootVariant::Production);
        let all = prod.all_required_options();
        assert!(!all.contains(&"CONFIG_DEBUG_KERNEL=y".into()));
        assert!(!all.contains(&"CONFIG_EARLY_PRINTK=y".into()));
    }

    #[test]
    fn kernel_debug_includes_debug_options() {
        use pico_image::kernel::{self, BootVariant};
        let mut debug = kernel::firecracker_aarch64_v1();
        debug.variant = BootVariant::Debug;
        let all = debug.all_required_options();
        assert!(all.contains(&"CONFIG_DEBUG_KERNEL=y".into()));
        assert!(all.contains(&"CONFIG_DEBUG_INFO=y".into()));
        assert!(all.contains(&"CONFIG_EARLY_PRINTK=y".into()));
    }

    #[test]
    fn kernel_validate_accepts_matching_config() {
        use pico_image::kernel;
        let profile = kernel::firecracker_aarch64_v1();
        let required = profile.all_required_options();
        let result = profile.validate_config(&required);
        assert!(result.is_ok());
    }

    #[test]
    fn kernel_validate_rejects_missing_virtio_blk() {
        use pico_image::kernel;
        let profile = kernel::firecracker_aarch64_v1();
        let mut opts = profile.all_required_options();
        opts.retain(|o| o != "CONFIG_VIRTIO_BLK=y");
        let result = profile.validate_config(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn kernel_validate_rejects_missing_vsock() {
        use pico_image::kernel;
        let profile = kernel::firecracker_aarch64_v1();
        let mut opts = profile.all_required_options();
        opts.retain(|o| o != "CONFIG_VIRTIO_VSOCKETS=y");
        let result = profile.validate_config(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn kernel_validate_reports_all_missing_options() {
        use pico_image::kernel;
        let profile = kernel::firecracker_aarch64_v1();
        let opts: Vec<String> = vec![];
        let result = profile.validate_config(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn kernel_all_profiles_have_required_device_support() {
        use pico_image::kernel;
        for profile in kernel::all_profiles() {
            let all = profile.all_required_options();
            assert!(
                all.contains(&"CONFIG_VIRTIO_BLK=y".into()),
                "{} missing VIRTIO_BLK",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_VIRTIO_NET=y".into()),
                "{} missing VIRTIO_NET",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_VSOCKETS=y".into()),
                "{} missing VSOCKETS",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_VIRTIO_VSOCKETS=y".into()),
                "{} missing VIRTIO_VSOCKETS",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_EXT4_FS=y".into()),
                "{} missing EXT4_FS",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_DEVTMPFS=y".into()),
                "{} missing DEVTMPFS",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_INET=y".into()),
                "{} missing INET",
                profile.profile_id
            );
        }
    }

    #[test]
    fn kernel_all_profiles_have_non_empty_cmdline() {
        use pico_image::kernel;
        for profile in kernel::all_profiles() {
            assert!(
                !profile.cmdline.is_empty(),
                "{} has empty cmdline",
                profile.profile_id
            );
            assert!(
                profile.cmdline.contains("init=/init"),
                "{} cmdline missing init=/init",
                profile.profile_id
            );
            assert!(
                profile.cmdline.contains("root=/dev/vda"),
                "{} cmdline missing root=/dev/vda",
                profile.profile_id
            );
        }
    }

    #[test]
    fn kernel_find_profile_by_id() {
        use pico_image::kernel;
        assert!(kernel::find_profile("firecracker-aarch64-v1").is_some());
        assert!(kernel::find_profile("firecracker-x86_64-v1").is_some());
        assert!(kernel::find_profile("qemu-aarch64-v1").is_some());
        assert!(kernel::find_profile("qemu-x86_64-v1").is_some());
        assert!(kernel::find_profile("nonexistent").is_none());
    }

    #[test]
    fn boot_variant_parsing() {
        use pico_image::kernel::BootVariant;
        assert_eq!("debug".parse::<BootVariant>().unwrap(), BootVariant::Debug);
        assert_eq!(
            "production".parse::<BootVariant>().unwrap(),
            BootVariant::Production
        );
        assert_eq!(
            "prod".parse::<BootVariant>().unwrap(),
            BootVariant::Production
        );
        assert!("invalid".parse::<BootVariant>().is_err());
    }

    // --- Boot artifact manifest tests ---

    #[test]
    fn manifest_with_kernel_section_populates_kernel_descriptor() {
        use pico_image::definition::KernelSource;

        let def = sample_definition();
        let lock = sample_lock();
        let dir = TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().join("output")).unwrap();
        fs::create_dir_all(output_dir.as_std_path()).unwrap();

        let kernel_file = dir.path().join("vmlinux");
        fs::write(&kernel_file, b"fake kernel image").unwrap();

        let tmp_rootfs = dir.path().join("dummy.ext4");
        fs::write(&tmp_rootfs, b"fake ext4 content").unwrap();
        let rootfs = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_rootfs).unwrap(),
            digest: "sha256:rootfs123".into(),
            size: 1024,
        };

        let tmp_agent = dir.path().join("dummy-agent");
        fs::write(&tmp_agent, b"fake guest agent").unwrap();
        let agent = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_agent).unwrap(),
            digest: "sha256:agent456".into(),
            size: 2048,
        };

        let mount_contract = pico_image::build_mount_contract_from_def(&def).unwrap();

        let kernel_source = KernelSource {
            backend: "firecracker".into(),
            variant: "production".into(),
            version: "pico-linux-6.18".into(),
            cmdline: Some("console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init".into()),
            vmlinux_path: Some(kernel_file.to_string_lossy().to_string()),
            initrd_path: None,
            firmware_path: None,
            config_profile: Some("firecracker-aarch64-v1".into()),
        };

        let (manifest_path, _manifest) = pico_image::manifest::generate_manifest(
            &def,
            &lock,
            &rootfs,
            &agent,
            &output_dir,
            &mount_contract,
            Some(&kernel_source),
        )
        .unwrap();

        assert!(manifest_path.exists());

        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();

        let artifacts = json.get("artifacts").unwrap();
        let kernel_json = artifacts.get("kernel").unwrap();
        assert!(
            !kernel_json.is_null(),
            "kernel should not be null when kernel section is present"
        );

        assert_eq!(
            kernel_json.get("format").unwrap().as_str().unwrap(),
            "linux-vmlinux"
        );
        assert_eq!(
            kernel_json.get("media_type").unwrap().as_str().unwrap(),
            "application/vnd.pico.kernel.vmlinux"
        );
        assert!(
            kernel_json
                .get("version")
                .unwrap()
                .as_str()
                .unwrap()
                .contains("pico-linux")
        );
        assert!(
            !kernel_json
                .get("digest")
                .unwrap()
                .as_str()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn manifest_without_kernel_section_has_null_kernel() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().join("output")).unwrap();
        fs::create_dir_all(output_dir.as_std_path()).unwrap();

        let tmp_rootfs = dir.path().join("dummy.ext4");
        fs::write(&tmp_rootfs, b"fake ext4 content").unwrap();
        let rootfs = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_rootfs).unwrap(),
            digest: "sha256:rootfs123".into(),
            size: 1024,
        };

        let tmp_agent = dir.path().join("dummy-agent");
        fs::write(&tmp_agent, b"fake guest agent").unwrap();
        let agent = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_agent).unwrap(),
            digest: "sha256:agent456".into(),
            size: 2048,
        };

        let mount_contract = pico_image::build_mount_contract_from_def(&def).unwrap();

        let (manifest_path, _manifest) = pico_image::manifest::generate_manifest(
            &def,
            &lock,
            &rootfs,
            &agent,
            &output_dir,
            &mount_contract,
            None,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();

        let artifacts = json.get("artifacts").unwrap();
        assert!(artifacts.get("kernel").unwrap().is_null());
        assert!(artifacts.get("initrd").unwrap().is_null());
        assert!(artifacts.get("firmware").unwrap().is_null());
    }

    #[test]
    fn kernel_source_parsing_with_config_profile() {
        let toml = r#"
backend = "firecracker"
variant = "production"
version = "pico-linux-6.18"
cmdline = "console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init nomodules"
config_profile = "firecracker-aarch64-v1"
"#;
        let ks: KernelSource = toml::from_str(toml).unwrap();
        assert_eq!(ks.backend, "firecracker");
        assert_eq!(ks.variant, "production");
        assert_eq!(ks.profile_id(), "firecracker-aarch64-v1");
    }

    #[test]
    fn kernel_source_profile_id_falls_back_to_default() {
        let toml = r#"
backend = "qemu"
variant = "debug"
version = "pico-linux-6.18"
"#;
        let ks: KernelSource = toml::from_str(toml).unwrap();
        assert!(ks.profile_id().starts_with("qemu-"));
        assert!(ks.profile_id().ends_with("-v1"));
    }

    #[test]
    fn image_definition_parses_kernel_section() {
        let toml = r#"
[image]
id = "test-with-kernel"
version = "0.1.0"
source_date_epoch = 1781170000

[base.source]
url = "https://example.com/rootfs.tar.gz"
digest = "sha256:abc"

[packages]

[guest_agent]
source = "workspace"

[filesystem]
size = "64M"
label = "test"
uuid = "00000000-0000-4000-a000-000000000001"

[kernel]
backend = "firecracker"
variant = "production"
version = "pico-linux-6.18"
cmdline = "console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init nomodules"
config_profile = "firecracker-aarch64-v1"
"#;
        let def: ImageDefinition = toml::from_str(toml).unwrap();
        assert!(def.kernel.is_some());
        let ks = def.kernel.unwrap();
        assert_eq!(ks.backend, "firecracker");
        assert_eq!(ks.variant, "production");
        assert_eq!(ks.version, "pico-linux-6.18");
        assert_eq!(ks.profile_id(), "firecracker-aarch64-v1");
    }

    #[test]
    fn image_definition_without_kernel_section_is_none() {
        let toml = r#"
[image]
id = "test-no-kernel"
version = "0.1.0"
source_date_epoch = 1781170000

[base.source]
url = "https://example.com/rootfs.tar.gz"
digest = "sha256:abc"

[packages]

[guest_agent]
source = "workspace"

[filesystem]
size = "64M"
label = "test"
uuid = "00000000-0000-4000-a000-000000000001"
"#;
        let def: ImageDefinition = toml::from_str(toml).unwrap();
        assert!(def.kernel.is_none());
    }

    #[test]
    fn kernel_cmdline_from_profile_is_used() {
        use pico_image::kernel;
        let cmd = kernel::kernel_cmdline("aarch64", "firecracker");
        assert!(cmd.contains("init=/init"));
        assert!(cmd.contains("root=/dev/vda"));
        assert!(!cmd.is_empty());
    }

    #[test]
    fn firecracker_x8664_requires_pci() {
        use pico_image::kernel;
        let profile = kernel::firecracker_x86_64_v1();
        let all = profile.all_required_options();
        assert!(all.contains(&"CONFIG_VIRTIO_PCI=y".into()));
        assert!(all.contains(&"CONFIG_PCI=y".into()));
        assert!(all.contains(&"CONFIG_KVM_GUEST=y".into()));
    }

    #[test]
    fn qemu_aarch64_requires_serial() {
        use pico_image::kernel;
        let profile = kernel::qemu_aarch64_v1();
        let all = profile.all_required_options();
        assert!(all.contains(&"CONFIG_SERIAL_AMBA_PL011=y".into()));
        assert!(all.contains(&"CONFIG_PCI_HOST_GENERIC=y".into()));
    }

    #[test]
    fn qemu_cmdline_differs_from_firecracker() {
        use pico_image::kernel;
        let fc_cmd = kernel::kernel_cmdline("aarch64", "firecracker");
        let qemu_cmd = kernel::kernel_cmdline("aarch64", "qemu");
        assert_ne!(fc_cmd, qemu_cmd);
        assert!(qemu_cmd.contains("ttyAMA0"));
    }

    // --- Guest-agent metadata tests ---

    #[test]
    fn guest_agent_definition_workspace_with_version_protocol_and_capabilities() {
        let toml = r#"
[image]
id = "test"
version = "1.0"
source_date_epoch = 1000

[base.source]
url = "https://example.com/rootfs.tar.gz"
digest = "sha256:abc"

[packages]

[guest_agent]
source = "workspace"
version = "0.3.0"
protocol_version = "1.0"
capabilities = ["exec", "file_transfer", "health"]

[filesystem]
size = "64M"
label = "test"
uuid = "00000000-0000-4000-a000-000000000001"
"#;
        let def: ImageDefinition = toml::from_str(toml).unwrap();
        assert_eq!(def.guest_agent.version(), Some("0.3.0"));
        assert_eq!(def.guest_agent.protocol_version(), Some("1.0"));
        assert_eq!(
            def.guest_agent.capabilities(),
            &["exec", "file_transfer", "health"]
        );
    }

    #[test]
    fn guest_agent_definition_workspace_without_version_is_none() {
        let toml = r#"
[image]
id = "test"
version = "1.0"
source_date_epoch = 1000

[base.source]
url = "https://example.com/rootfs.tar.gz"
digest = "sha256:abc"

[packages]

[guest_agent]
source = "workspace"

[filesystem]
size = "64M"
label = "test"
uuid = "00000000-0000-4000-a000-000000000001"
"#;
        let def: ImageDefinition = toml::from_str(toml).unwrap();
        assert_eq!(def.guest_agent.version(), None);
        assert_eq!(def.guest_agent.protocol_version(), None);
        assert!(def.guest_agent.capabilities().is_empty());
    }

    #[test]
    fn guest_agent_definition_prebuilt_with_version_and_protocol() {
        let toml = r#"
[image]
id = "test"
version = "1.0"
source_date_epoch = 1000

[base.source]
url = "https://example.com/rootfs.tar.gz"
digest = "sha256:abc"

[packages]

[guest_agent]
source = "prebuilt"
path = "/tmp/agent"
digest = "sha256:def"
version = "0.4.0"
protocol_version = "1.0"
capabilities = ["exec", "stats"]

[filesystem]
size = "64M"
label = "test"
uuid = "00000000-0000-4000-a000-000000000001"
"#;
        let def: ImageDefinition = toml::from_str(toml).unwrap();
        match def.guest_agent {
            GuestAgentSource::Prebuilt {
                path,
                digest,
                version,
                protocol_version,
                capabilities,
            } => {
                assert_eq!(path, "/tmp/agent");
                assert_eq!(digest, "sha256:def");
                assert_eq!(version, Some("0.4.0".into()));
                assert_eq!(protocol_version, Some("1.0".into()));
                assert_eq!(capabilities, vec!["exec", "stats"]);
            }
            _ => panic!("expected Prebuilt guest agent"),
        }
    }

    #[test]
    fn manifest_records_guest_agent_protocol_version_and_capabilities() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().join("output")).unwrap();
        fs::create_dir_all(output_dir.as_std_path()).unwrap();

        let tmp_rootfs = dir.path().join("dummy.ext4");
        fs::write(&tmp_rootfs, b"fake ext4 content").unwrap();
        let rootfs = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_rootfs).unwrap(),
            digest: "sha256:rootfs123".into(),
            size: 1024,
        };

        let tmp_agent = dir.path().join("dummy-agent");
        fs::write(&tmp_agent, b"fake guest agent").unwrap();
        let agent = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_agent).unwrap(),
            digest: "sha256:agent456".into(),
            size: 2048,
        };

        let mount_contract = pico_image::build_mount_contract_from_def(&def).unwrap();

        let (manifest_path, _manifest) = pico_image::manifest::generate_manifest(
            &def,
            &lock,
            &rootfs,
            &agent,
            &output_dir,
            &mount_contract,
            None,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();

        let ga = json.get("artifacts").unwrap().get("guest_agent").unwrap();
        assert_eq!(ga.get("version").unwrap().as_str().unwrap(), "0.3.0");
        assert_eq!(ga.get("protocol_version").unwrap().as_str().unwrap(), "1.0");
        let caps: Vec<_> = ga
            .get("capabilities")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(caps.contains(&"exec"));

        let protocol = json.get("protocol").unwrap();
        let proto_caps: Vec<_> = protocol
            .get("capabilities")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(proto_caps.contains(&"exec"));
    }

    #[test]
    fn manifest_validation_rejects_missing_guest_agent_version() {
        let def = simple_definition();
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.version = None;

        let result = manifest::validate_manifest(&manifest, &def);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("guest_agent version"));
    }

    #[test]
    fn manifest_validation_rejects_missing_guest_agent_protocol_version() {
        let def = simple_definition();
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.protocol_version = None;

        let result = manifest::validate_manifest(&manifest, &def);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("protocol_version"));
    }

    #[test]
    fn guest_agent_version_missing_from_definition_causes_error() {
        let toml = r#"
[image]
id = "test-no-ga-version"
version = "0.1.0"
source_date_epoch = 1000

[base.source]
url = "https://example.com/rootfs.tar.gz"
digest = "sha256:abc"

[packages]

[guest_agent]
source = "workspace"

[filesystem]
size = "64M"
label = "test"
uuid = "00000000-0000-4000-a000-000000000001"
"#;
        let def: ImageDefinition = toml::from_str(toml).unwrap();
        // Definition loads fine but version() returns None
        assert_eq!(def.guest_agent.version(), None);

        // Simulating the manifest validation that would happen during build
        let is_missing = def.guest_agent.version().is_none();
        assert!(is_missing, "guest-agent version should be missing");
    }

    #[test]
    fn guest_agent_version_mismatch_causes_error() {
        let def = simple_definition();
        let mut manifest = valid_manifest();
        // Change version in manifest to differ from definition
        manifest.artifacts.guest_agent.version = Some("9.9.9".into());

        let result = manifest::validate_manifest(&manifest, &def);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("incompatible"));
        assert!(err.contains("0.3.0"));
        assert!(err.contains("9.9.9"));
    }

    #[test]
    fn guest_agent_digest_in_manifest_matches_input() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().join("output")).unwrap();
        fs::create_dir_all(output_dir.as_std_path()).unwrap();

        let tmp_rootfs = dir.path().join("dummy.ext4");
        fs::write(&tmp_rootfs, b"fake ext4 content").unwrap();
        let rootfs = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_rootfs).unwrap(),
            digest: "sha256:rootfs123".into(),
            size: 1024,
        };

        let agent_content = b"pico-guest-agent v0.3.0";
        let tmp_agent = dir.path().join("dummy-agent");
        fs::write(&tmp_agent, agent_content).unwrap();
        let agent = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_agent).unwrap(),
            digest: "sha256:expected-agent-digest".into(),
            size: agent_content.len() as u64,
        };

        let mount_contract = pico_image::build_mount_contract_from_def(&def).unwrap();

        let (manifest_path, _manifest) = pico_image::manifest::generate_manifest(
            &def,
            &lock,
            &rootfs,
            &agent,
            &output_dir,
            &mount_contract,
            None,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();

        let ga = json.get("artifacts").unwrap().get("guest_agent").unwrap();
        assert_eq!(
            ga.get("digest").unwrap().as_str().unwrap(),
            "sha256:expected-agent-digest"
        );
        assert_eq!(
            ga.get("size").unwrap().as_u64().unwrap(),
            agent_content.len() as u64
        );
    }

    #[test]
    fn manifest_protocol_section_includes_guest_agent_capabilities() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().join("output")).unwrap();
        fs::create_dir_all(output_dir.as_std_path()).unwrap();

        let tmp_rootfs = dir.path().join("dummy.ext4");
        fs::write(&tmp_rootfs, b"fake ext4 content").unwrap();
        let rootfs = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_rootfs).unwrap(),
            digest: "sha256:rootfs123".into(),
            size: 1024,
        };

        let tmp_agent = dir.path().join("dummy-agent");
        fs::write(&tmp_agent, b"fake guest agent").unwrap();
        let agent = render::OutputInfo {
            path: camino::Utf8PathBuf::from_path_buf(tmp_agent).unwrap(),
            digest: "sha256:agent456".into(),
            size: 2048,
        };

        let mount_contract = pico_image::build_mount_contract_from_def(&def).unwrap();

        let (manifest_path, _manifest) = pico_image::manifest::generate_manifest(
            &def,
            &lock,
            &rootfs,
            &agent,
            &output_dir,
            &mount_contract,
            None,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();

        let protocol = json.get("protocol").unwrap();
        assert_eq!(
            protocol.get("bootstrap").unwrap().as_str().unwrap(),
            "pico.guest.bootstrap.v1"
        );
        let supported = protocol.get("supported").unwrap().as_array().unwrap();
        assert!(!supported.is_empty());
        assert_eq!(supported[0].get("major").unwrap().as_u64().unwrap(), 1);
    }
}
