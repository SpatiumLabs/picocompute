//! Composable environment layers: base plus workspace plus toolkit at boot.
//!
//! - independent toolkit bump requires only toolkit-layer rebuild plus
//!   recomposition (base/workspace digests unchanged, `plan_rebuild`
//!   reports `toolkit_only`)
//! - boot reaches READY with composition recorded in placement/host audit
//!   (`verify_for_host` plus `verify_environment_layers` plus
//!   `verify_environment_compatibility`, then `plan_overlay_stack` and
//!   `format_composition_audit_record`)
//! - supply-chain gates hold per layer (SBOM/provenance/signature digests
//!   plus digest/size verification of materialized bytes)

mod common;

#[cfg(test)]
mod composable_layers {
    use crate::common::{valid_definition, valid_manifest};
    use camino::Utf8PathBuf;
    use pico_image::render::compute_file_digest;
    use pico_image::signature::{generate_signing_key, sign_manifest};
    use pico_image::types::{BackendCompatibility, ProtocolVersionRange};
    use pico_image::validation;
    use pico_image::{
        COLLAPSE_THRESHOLD_LAYERS, CompositionCompatibility, CompositionPromotion,
        CompositionPromotionStage, EnvironmentComposition, EnvironmentLayer, EnvironmentLayerKind,
        HostCompatibilityExpectation, HostImageLayout, HostLayerFile, HostVerificationPolicy,
        MAX_ENVIRONMENT_LAYERS, collapse_advice, format_composition_audit_record,
        layers_missing_supply_chain_evidence, plan_overlay_stack, plan_rebuild,
        verify_composition_compatibility, verify_environment_compatibility,
        verify_environment_layers, verify_environment_supply_chain, verify_for_host,
    };

    fn write_layer_bytes(
        dir: &Utf8PathBuf,
        name: &str,
        bytes: &[u8],
    ) -> (Utf8PathBuf, String, u64) {
        let path = dir.join(format!("{name}.erofs"));
        std::fs::write(&path, bytes).unwrap();
        let digest = compute_file_digest(&path).unwrap();
        let size = std::fs::metadata(&path).unwrap().len();
        (path, digest, size)
    }

    fn evidence_triplet(tag: &str) -> (String, String, String) {
        (
            format!("sha256:sbom{tag}00000000000000000000000000000000000000000000000000"),
            format!("sha256:prov{tag}00000000000000000000000000000000000000000000000000"),
            format!("sha256:sig{tag}000000000000000000000000000000000000000000000000000"),
        )
    }

    fn test_compatibility() -> CompositionCompatibility {
        CompositionCompatibility {
            profile_id: "firecracker-aarch64-v1".into(),
            backends: vec![BackendCompatibility {
                family: "firecracker".into(),
                runtime_version: "1.0".into(),
                architecture: "aarch64".into(),
            }],
            architecture: "aarch64".into(),
            protocol_supported: vec![ProtocolVersionRange {
                major: 1,
                min_minor: 0,
                max_minor: 0,
            }],
            snapshot_excluded_classes: vec!["runtime_tmp".into(), "secret".into()],
        }
    }

    struct LayerFixture {
        _temp: tempfile::TempDir,
        dir: Utf8PathBuf,
        base_path: Utf8PathBuf,
        workspace_path: Utf8PathBuf,
        python_path: Utf8PathBuf,
        node_path: Utf8PathBuf,
        composition: EnvironmentComposition,
    }

    fn layered_fixture() -> LayerFixture {
        let temp = tempfile::TempDir::new().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let (base_path, base_digest, base_size) =
            write_layer_bytes(&dir, "base", b"base-layer-bytes-v1");
        let (workspace_path, workspace_digest, workspace_size) =
            write_layer_bytes(&dir, "workspace", b"workspace-layer-bytes-v1");
        let (python_path, python_digest, python_size) =
            write_layer_bytes(&dir, "python", b"toolkit-python-bytes-v1");
        let (node_path, node_digest, node_size) =
            write_layer_bytes(&dir, "node", b"toolkit-node-bytes-v1");

        let (sbom_b, prov_b, sig_b) = evidence_triplet("b");
        let (sbom_w, prov_w, sig_w) = evidence_triplet("w");
        let (sbom_p, prov_p, sig_p) = evidence_triplet("p");
        let (sbom_n, prov_n, sig_n) = evidence_triplet("n");

        let base = EnvironmentLayer {
            name: "debian-base".into(),
            order: 0,
            kind: EnvironmentLayerKind::Base,
            digest: base_digest,
            size: base_size,
            media_type: "application/vnd.pico.layer.erofs".into(),
            version: Some("2026.09.1".into()),
            sbom_digest: Some(sbom_b),
            provenance_digest: Some(prov_b),
            signature_digest: Some(sig_b),
        };
        let workspace = EnvironmentLayer {
            name: "workspace-seed".into(),
            order: 0,
            kind: EnvironmentLayerKind::Workspace,
            digest: workspace_digest,
            size: workspace_size,
            media_type: "application/vnd.pico.layer.erofs".into(),
            version: Some("2026.09.1".into()),
            sbom_digest: Some(sbom_w),
            provenance_digest: Some(prov_w),
            signature_digest: Some(sig_w),
        };
        let python = EnvironmentLayer {
            name: "toolkit-python".into(),
            order: 0,
            kind: EnvironmentLayerKind::Toolkit,
            digest: python_digest,
            size: python_size,
            media_type: "application/vnd.pico.layer.erofs".into(),
            version: Some("2026.09.1".into()),
            sbom_digest: Some(sbom_p),
            provenance_digest: Some(prov_p),
            signature_digest: Some(sig_p),
        };
        let node = EnvironmentLayer {
            name: "toolkit-node".into(),
            order: 0,
            kind: EnvironmentLayerKind::Toolkit,
            digest: node_digest,
            size: node_size,
            media_type: "application/vnd.pico.layer.erofs".into(),
            version: Some("2026.09.1".into()),
            sbom_digest: Some(sbom_n),
            provenance_digest: Some(prov_n),
            signature_digest: Some(sig_n),
        };
        let composition = EnvironmentComposition::new(
            "test-image",
            base,
            workspace,
            vec![python, node],
            test_compatibility(),
            1781170000,
        )
        .unwrap();
        LayerFixture {
            _temp: temp,
            dir,
            base_path,
            workspace_path,
            python_path,
            node_path,
            composition,
        }
    }

    fn host_expectation() -> HostCompatibilityExpectation {
        HostCompatibilityExpectation {
            backend: "firecracker".into(),
            architecture: "aarch64".into(),
            protocol_major: 1,
        }
    }

    fn write_manifest_artifacts(dir: &Utf8PathBuf) -> (Utf8PathBuf, Utf8PathBuf, Utf8PathBuf) {
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs-bytes").unwrap();
        let agent = dir.join("pico-agent");
        std::fs::write(&agent, b"guest-agent-bytes").unwrap();
        let kernel = dir.join("vmlinux");
        std::fs::write(&kernel, b"vmlinux-bytes").unwrap();
        (rootfs, agent, kernel)
    }

    fn write_signed_layered_manifest(
        dir: &Utf8PathBuf,
        composition: &EnvironmentComposition,
    ) -> (
        Utf8PathBuf,
        Utf8PathBuf,
        Utf8PathBuf,
        Utf8PathBuf,
        Utf8PathBuf,
        ed25519_dalek::VerifyingKey,
    ) {
        let mut manifest = valid_manifest();
        attach_environment(&mut manifest, composition.clone());
        // Recompute manifest bytes with the environment attached.
        let manifest_path = dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let (rootfs, agent, kernel) = write_manifest_artifacts(dir);
        // Patch artifact descriptors to match the written bytes so host
        // verification passes on sizes and digests.
        let mut manifest: pico_image::types::PicoComputeGuestManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest.artifacts.rootfs.digest = compute_file_digest(&rootfs).unwrap();
        manifest.artifacts.rootfs.size = std::fs::metadata(&rootfs).unwrap().len();
        manifest.artifacts.guest_agent.digest = compute_file_digest(&agent).unwrap();
        manifest.artifacts.guest_agent.size = std::fs::metadata(&agent).unwrap().len();
        // valid_manifest carries a kernel descriptor; match it to the file.
        if let Some(ref mut kd) = manifest.artifacts.kernel {
            kd.digest = compute_file_digest(&kernel).unwrap();
            kd.size = std::fs::metadata(&kernel).unwrap().len();
        }
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let (signing_key, verifying_key) = generate_signing_key();
        let signature_path = sign_manifest(
            &manifest_path,
            &signing_key,
            "test-builder",
            &manifest.image_id,
            dir,
        )
        .unwrap();
        (
            manifest_path,
            signature_path,
            rootfs,
            agent,
            kernel,
            verifying_key,
        )
    }

    /// Attach a composition the way the build path does: environment plus the
    /// required-feature marker a reader needs in order to honor it.
    fn attach_environment(
        manifest: &mut pico_image::types::PicoComputeGuestManifest,
        composition: EnvironmentComposition,
    ) {
        manifest.environment = Some(composition);
        if !manifest
            .required_features
            .iter()
            .any(|f| f == pico_image::ENVIRONMENT_LAYER_FEATURE)
        {
            manifest
                .required_features
                .push(pico_image::ENVIRONMENT_LAYER_FEATURE.into());
        }
    }

    #[test]
    fn toolkit_bump_requires_only_toolkit_rebuild_plus_recomposition() {
        let fx = layered_fixture();
        let before = fx.composition.clone();

        // Rebuild only the python toolkit: new bytes, new digest, new size.
        let rebuilt_path = fx.dir.join("python-v2.erofs");
        std::fs::write(&rebuilt_path, b"toolkit-python-bytes-v2-longer").unwrap();
        let rebuilt_digest = compute_file_digest(&rebuilt_path).unwrap();
        let rebuilt_size = std::fs::metadata(&rebuilt_path).unwrap().len();
        let mut rebuilt = before
            .toolkits
            .iter()
            .find(|t| t.name == "toolkit-python")
            .unwrap()
            .clone();
        rebuilt.digest = rebuilt_digest;
        rebuilt.size = rebuilt_size;
        rebuilt.version = Some("2026.09.2".into());

        let after = before
            .with_rebuilt_toolkit("toolkit-python", rebuilt)
            .unwrap();

        // Base and workspace are byte-identical: only toolkit plus
        // recomposition changed.
        assert_eq!(after.base.digest, before.base.digest);
        assert_eq!(after.workspace.digest, before.workspace.digest);
        assert_ne!(after.composition_digest, before.composition_digest);

        let plan = plan_rebuild(&before, &after).unwrap();
        assert!(plan.toolkit_only);
        assert!(!plan.base_or_workspace_changed);
        assert_eq!(plan.changed_layers, vec!["toolkit-python"]);
        assert_eq!(plan.from_digest, before.composition_digest);
        assert_eq!(plan.to_digest, after.composition_digest);
    }

    #[test]
    fn base_change_is_not_toolkit_only() {
        let fx = layered_fixture();
        let mut next = fx.composition.clone();
        next.base.digest =
            "sha256:basechanged0000000000000000000000000000000000000000000000".into();
        // Recompute the binding digest for the edited composition.
        next.composition_digest = pico_image::compute_composition_digest(
            &next.image_id,
            &next.base,
            &next.workspace,
            &next.toolkits,
            &next.compatibility,
        );
        let plan = plan_rebuild(&fx.composition, &next).unwrap();
        assert!(plan.base_or_workspace_changed);
        assert!(!plan.toolkit_only);
    }

    #[test]
    fn boot_verifies_signed_composition_and_records_audit() {
        let fx = layered_fixture();
        let temp = tempfile::TempDir::new().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let (manifest_path, signature_path, rootfs, agent, kernel, verifying_key) =
            write_signed_layered_manifest(&dir, &fx.composition);

        let layout = HostImageLayout {
            manifest_path: &manifest_path,
            signature_path: Some(&signature_path),
            rootfs_path: &rootfs,
            kernel_path: Some(&kernel),
            guest_agent_path: &agent,
            initrd_path: None,
            firmware_path: None,
        };
        let verified = verify_for_host(
            &layout,
            &HostVerificationPolicy::Production {
                trusted_key: verifying_key,
            },
        )
        .expect("signed layered manifest must verify");
        assert_eq!(
            verified.composition_digest.as_deref(),
            Some(fx.composition.composition_digest.as_str())
        );
        let audit = verified
            .composition_audit_record
            .as_deref()
            .expect("layered manifest must carry an audit record");
        assert!(audit.contains(&fx.composition.composition_digest));
        assert!(audit.contains("toolkit-python"));
        assert!(audit.contains("firecracker-aarch64-v1"));

        // Composition bytes presented by the host must match the signed set.
        let layer_files = vec![
            HostLayerFile {
                name: "debian-base",
                path: &fx.base_path,
            },
            HostLayerFile {
                name: "workspace-seed",
                path: &fx.workspace_path,
            },
            HostLayerFile {
                name: "toolkit-python",
                path: &fx.python_path,
            },
            HostLayerFile {
                name: "toolkit-node",
                path: &fx.node_path,
            },
        ];
        verify_environment_layers(&verified, &layer_files).unwrap();
        verify_environment_compatibility(&verified, &host_expectation()).unwrap();
        verify_environment_supply_chain(&verified).unwrap();
        verify_composition_compatibility(&fx.composition, &verified.manifest, &host_expectation())
            .unwrap();

        // Prepare plans the overlay stack: base bottom, workspace middle,
        // toolkits in declared precedence, local writable upper.
        let plan = plan_overlay_stack(&fx.composition, "/mnt/layers", "/upper", "/work", "/merged")
            .unwrap();
        assert_eq!(plan.lowerdirs.len(), 4);
        assert!(plan.lowerdirs[0].ends_with("debian-base"));
        assert!(plan.lowerdirs[1].ends_with("workspace-seed"));
        assert_eq!(plan.composition_digest, fx.composition.composition_digest);
        assert!(!plan.upperdir.is_empty());

        // Placement/host audit persists the same record that READY reports.
        let audit_record =
            format_composition_audit_record(&fx.composition, &verified.manifest_digest);
        assert!(audit_record.contains("test-image"));
        assert!(audit_record.contains(&fx.composition.composition_digest));
    }

    #[test]
    fn tampered_layer_bytes_fail_host_verification() {
        let fx = layered_fixture();
        let temp = tempfile::TempDir::new().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let (manifest_path, signature_path, rootfs, agent, kernel, verifying_key) =
            write_signed_layered_manifest(&dir, &fx.composition);
        let layout = HostImageLayout {
            manifest_path: &manifest_path,
            signature_path: Some(&signature_path),
            rootfs_path: &rootfs,
            kernel_path: Some(&kernel),
            guest_agent_path: &agent,
            initrd_path: None,
            firmware_path: None,
        };
        let verified = verify_for_host(
            &layout,
            &HostVerificationPolicy::Production {
                trusted_key: verifying_key,
            },
        )
        .unwrap();

        // Mutating a released layer changes bytes and must fail digest
        // verification: hosts mount lowers read-only and keep writes in the
        // upper. Same length so the size check passes and digest is decisive.
        std::fs::write(&fx.python_path, b"toolkit-python-bytes-v1!").unwrap();
        let layer_files = vec![
            HostLayerFile {
                name: "debian-base",
                path: &fx.base_path,
            },
            HostLayerFile {
                name: "workspace-seed",
                path: &fx.workspace_path,
            },
            HostLayerFile {
                name: "toolkit-node",
                path: &fx.node_path,
            },
            HostLayerFile {
                name: "toolkit-python",
                path: &fx.python_path,
            },
        ];
        let err = verify_environment_layers(&verified, &layer_files).unwrap_err();
        assert!(err.to_string().contains("toolkit-python"));
    }

    #[test]
    fn tampered_composition_fails_signature_check() {
        let fx = layered_fixture();
        let temp = tempfile::TempDir::new().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let (manifest_path, signature_path, rootfs, agent, kernel, verifying_key) =
            write_signed_layered_manifest(&dir, &fx.composition);
        // Edit the composition inside the signed manifest: signature must fail.
        let mut manifest: pico_image::types::PicoComputeGuestManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let mut env = manifest.environment.clone().unwrap();
        env.toolkits[0].digest =
            "sha256:evil0000000000000000000000000000000000000000000000000000".into();
        manifest.environment = Some(env);
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let layout = HostImageLayout {
            manifest_path: &manifest_path,
            signature_path: Some(&signature_path),
            rootfs_path: &rootfs,
            kernel_path: Some(&kernel),
            guest_agent_path: &agent,
            initrd_path: None,
            firmware_path: None,
        };
        let err = verify_for_host(
            &layout,
            &HostVerificationPolicy::Production {
                trusted_key: verifying_key,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("signature") || err.to_string().contains("Signature"));
    }

    #[test]
    fn supply_chain_gates_hold_per_layer() {
        let fx = layered_fixture();
        assert!(layers_missing_supply_chain_evidence(&fx.composition).is_empty());

        // The fixture declares python before node, so index 0 is toolkit-python.
        let mut without_evidence = fx.composition.clone();
        without_evidence.toolkits[0].sbom_digest = None;
        let missing = layers_missing_supply_chain_evidence(&without_evidence);
        assert_eq!(missing, vec!["toolkit-python"]);
    }

    #[test]
    fn overlay_stack_preserves_order_and_whiteout_contract() {
        let fx = layered_fixture();
        let plan = plan_overlay_stack(&fx.composition, "/mnt/layers", "/upper", "/work", "/merged")
            .unwrap();
        // Base bottom, workspace middle, then toolkits in declared precedence
        // (the fixture declares python first, so python is topmost and last).
        assert!(plan.lowerdirs[0].ends_with("debian-base"));
        assert!(plan.lowerdirs[1].ends_with("workspace-seed"));
        assert!(plan.lowerdirs[2].ends_with("toolkit-python"));
        assert!(plan.lowerdirs[3].ends_with("toolkit-node"));
        // Writable upper is separate from every released lower.
        for lower in &plan.lowerdirs {
            assert_ne!(lower, &plan.upperdir);
        }
        // Overlayfs consumes whiteouts and opaque markers itself; Pico never
        // merges the upper down, so these constants are documentation of the
        // marker the collapse policy must preserve, not something parsing code.
        assert_eq!(pico_image::OVERLAYFS_OPAQUE_XATTR, "trusted.overlay.opaque");
        assert_eq!(pico_image::OVERLAYFS_OPAQUE_VALUE, "y");
        assert!(plan.lowerdir_option.contains("/mnt/layers/debian-base"));
    }

    /// Sign a manifest, verify it, and return the result. Keeps the
    /// compatibility-drift cases below focused on one assertion each.
    fn verified_layered_image(
        dir: &Utf8PathBuf,
        composition: &EnvironmentComposition,
    ) -> (pico_image::host_verify::VerifiedImage, Utf8PathBuf) {
        let (manifest_path, signature_path, rootfs, agent, kernel, verifying_key) =
            write_signed_layered_manifest(dir, composition);
        let layout = HostImageLayout {
            manifest_path: &manifest_path,
            signature_path: Some(&signature_path),
            rootfs_path: &rootfs,
            kernel_path: Some(&kernel),
            guest_agent_path: &agent,
            initrd_path: None,
            firmware_path: None,
        };
        let verified = verify_for_host(
            &layout,
            &HostVerificationPolicy::Production {
                trusted_key: verifying_key,
            },
        )
        .expect("signed layered manifest must verify");
        (verified, manifest_path)
    }

    #[test]
    fn compatibility_gates_reject_backend_arch_protocol_and_snapshot_drift() {
        let fx = layered_fixture();
        let temp = tempfile::TempDir::new().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let (verified, _) = verified_layered_image(&dir, &fx.composition);

        // Wrong backend.
        let wrong_backend = HostCompatibilityExpectation {
            backend: "qemu".into(),
            architecture: "aarch64".into(),
            protocol_major: 1,
        };
        assert!(verify_environment_compatibility(&verified, &wrong_backend).is_err());

        // Wrong arch.
        let wrong_arch = HostCompatibilityExpectation {
            backend: "firecracker".into(),
            architecture: "x86_64".into(),
            protocol_major: 1,
        };
        assert!(verify_environment_compatibility(&verified, &wrong_arch).is_err());

        // Wrong protocol major.
        let wrong_proto = HostCompatibilityExpectation {
            backend: "firecracker".into(),
            architecture: "aarch64".into(),
            protocol_major: 2,
        };
        assert!(verify_environment_compatibility(&verified, &wrong_proto).is_err());

        // Snapshot exclusion drift between composition and manifest.
        let mut drifted = verified.manifest.clone();
        drifted.snapshot.excluded_mount_classes = vec!["secret".into()];
        assert!(
            verify_composition_compatibility(&fx.composition, &drifted, &host_expectation())
                .is_err()
        );
    }

    #[test]
    fn compatibility_rejects_profile_drift_between_composition_and_manifest() {
        // The composition claims a different tested profile than the manifest.
        // Before the fix this was accepted because nothing read profile_id.
        let fx = layered_fixture();
        let mut mismatched = fx.composition.clone();
        mismatched.compatibility.profile_id = "qemu-aarch64-v1".into();
        mismatched.composition_digest = pico_image::compute_composition_digest(
            &mismatched.image_id,
            &mismatched.base,
            &mismatched.workspace,
            &mismatched.toolkits,
            &mismatched.compatibility,
        );
        let manifest = valid_manifest();
        let err = verify_composition_compatibility(&mismatched, &manifest, &host_expectation())
            .expect_err("profile drift must be rejected");
        assert!(err.to_string().contains("profile"), "unexpected: {err}");
    }

    #[test]
    fn compatibility_rejects_protocol_allowed_only_by_composition() {
        // The manifest (what ADR-0003 negotiates against) does not allow
        // protocol major 1, so a composition that does must not admit it.
        let fx = layered_fixture();
        let mut manifest = valid_manifest();
        manifest.protocol.supported = vec![pico_image::types::ProtocolVersionRange {
            major: 2,
            min_minor: 0,
            max_minor: 0,
        }];
        let err = verify_composition_compatibility(&fx.composition, &manifest, &host_expectation())
            .expect_err("manifest protocol drift must be rejected");
        assert!(
            err.to_string().contains("manifest allowlist"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn layer_names_cannot_escape_the_layer_store_or_inject_a_lower() {
        // A name carrying a ':' would inject an extra lower layer into the
        // mount option; '..' would escape the layer store directory. Both are
        // rejected at validation time now.
        assert!(pico_image::validate_layer_name("toolkit-a:/etc").is_err());
        assert!(pico_image::validate_layer_name("../../../../etc").is_err());
        assert!(pico_image::validate_layer_name("a/b").is_err());
        assert!(pico_image::validate_layer_name("..").is_err());
        assert!(pico_image::validate_layer_name(".").is_err());
        assert!(pico_image::validate_layer_name("").is_err());
        assert!(pico_image::validate_layer_name("toolkit-python_3.11").is_ok());
    }

    #[test]
    fn overlay_plan_rejects_unsafe_layer_store_dir() {
        let fx = layered_fixture();
        for bad in [
            "",
            "relative/dir",
            "/mnt/with:colon",
            "/mnt//double",
            "/mnt/../etc",
        ] {
            let err = plan_overlay_stack(&fx.composition, bad, "/upper", "/work", "/merged")
                .expect_err("unsafe layer store dir must be rejected");
            assert!(
                matches!(
                    err,
                    pico_image::error::ImageError::CompositionValidationFailed(_)
                ),
                "unexpected error for {bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn unknown_required_feature_blocks_host_boot() {
        // A manifest requiring a feature this reader does not implement must
        // be refused rather than booted as a monolithic image.
        let fx = layered_fixture();
        let temp = tempfile::TempDir::new().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let (manifest_path, _signature_path, rootfs, agent, kernel, _verifying_key) =
            write_signed_layered_manifest(&dir, &fx.composition);
        // Re-sign after adding an unknown required feature: the signature is
        // valid, so only the required-feature check can reject this.
        let mut manifest: pico_image::types::PicoComputeGuestManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest.required_features.push("gpu-offload-v9".into());
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let (signing_key, verifying_key) = generate_signing_key();
        sign_manifest(
            &manifest_path,
            &signing_key,
            "test-builder",
            &manifest.image_id,
            &dir,
        )
        .unwrap();
        let layout = HostImageLayout {
            manifest_path: &manifest_path,
            signature_path: Some(&dir.join("manifest.sig.json")),
            rootfs_path: &rootfs,
            kernel_path: Some(&kernel),
            guest_agent_path: &agent,
            initrd_path: None,
            firmware_path: None,
        };
        let err = verify_for_host(
            &layout,
            &HostVerificationPolicy::Production {
                trusted_key: verifying_key,
            },
        )
        .expect_err("unknown required feature must block boot");
        assert!(
            err.to_string().contains("gpu-offload-v9"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn layered_manifest_without_feature_marker_fails_validation() {
        let fx = layered_fixture();
        let mut manifest = valid_manifest();
        manifest.environment = Some(fx.composition.clone());
        // Feature marker deliberately omitted.
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        assert!(
            report
                .failed_check_names()
                .iter()
                .any(|n| n.contains("environment")),
            "failed: {:?}",
            report.failed_check_names()
        );
    }

    #[test]
    fn host_gate_rejects_layers_missing_evidence() {
        let fx = layered_fixture();
        let temp = tempfile::TempDir::new().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();

        // Build a composition whose toolkit lacks a signature digest, then
        // check the host boot gate refuses it.
        let mut comp = fx.composition.clone();
        comp.toolkits[0].signature_digest = None;
        comp.composition_digest = pico_image::compute_composition_digest(
            &comp.image_id,
            &comp.base,
            &comp.workspace,
            &comp.toolkits,
            &comp.compatibility,
        );
        let (verified, _) = verified_layered_image(&dir, &comp);
        let err = verify_environment_supply_chain(&verified)
            .expect_err("missing per-layer evidence must block boot");
        assert!(
            err.to_string().contains("toolkit-python"),
            "unexpected: {err}"
        );

        // The complete composition passes the same gate.
        let temp2 = tempfile::TempDir::new().unwrap();
        let dir2 = Utf8PathBuf::from_path_buf(temp2.path().to_path_buf()).unwrap();
        let (ok, _) = verified_layered_image(&dir2, &fx.composition);
        verify_environment_supply_chain(&ok).unwrap();
    }

    #[test]
    fn layer_name_with_tokenizer_is_not_a_secret_false_positive() {
        // The broad whole-manifest word scan used to trip on legitimate layer
        // names such as this one.
        let fx = layered_fixture();
        let mut comp = fx.composition.clone();
        comp.toolkits[0].name = "toolkit-tokenizer".into();
        comp.composition_digest = pico_image::compute_composition_digest(
            &comp.image_id,
            &comp.base,
            &comp.workspace,
            &comp.toolkits,
            &comp.compatibility,
        );
        let mut manifest = valid_manifest();
        attach_environment(&mut manifest, comp);
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(
            report.all_passed(),
            "tokenizer must not trip the secret scan: {:?}",
            report.failed_checks()
        );
    }

    #[test]
    fn layer_name_with_credential_assignment_is_rejected() {
        let fx = layered_fixture();
        let mut comp = fx.composition.clone();
        comp.toolkits[0].name = "toolkit-api_key=abc".into();
        comp.composition_digest = pico_image::compute_composition_digest(
            &comp.image_id,
            &comp.base,
            &comp.workspace,
            &comp.toolkits,
            &comp.compatibility,
        );
        let mut manifest = valid_manifest();
        attach_environment(&mut manifest, comp);
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    /// Composition with `count` toolkits, built through the validating
    /// Composition with `count` toolkits, built through the validating
    /// constructor so overlay order and the composition digest are correct.
    fn composition_with_toolkits(
        fx: &LayerFixture,
        count: usize,
        digest_tag: &str,
    ) -> EnvironmentComposition {
        let toolkits = (0..count)
            .map(|i| {
                EnvironmentLayer::new(
                    format!("toolkit-{i:02}"),
                    EnvironmentLayerKind::Toolkit,
                    format!("{digest_tag}{i:02}0000000000000000000000000000000000000000000000"),
                    1024,
                    "application/vnd.pico.layer.erofs",
                )
                .unwrap()
            })
            .collect();
        EnvironmentComposition::new(
            "test-image",
            fx.composition.base.clone(),
            fx.composition.workspace.clone(),
            toolkits,
            fx.composition.compatibility.clone(),
            1,
        )
        .unwrap()
    }
    #[test]
    fn too_many_layers_reports_typed_error() {
        // `TooManyLayers` was previously unreachable: `plan_overlay_stack` ran
        // full validation first, which returned the generic composition error.
        // The cap check now runs first, so an over-cap composition reports the
        // typed reason. It is assembled by deserialization here because the
        // validating constructor refuses to build one.
        let fx = layered_fixture();

        // Sanity: a composition exactly at the cap plans fine.
        let at_cap = composition_with_toolkits(&fx, MAX_ENVIRONMENT_LAYERS - 2, "sha256:atcap");
        assert_eq!(at_cap.layer_count(), MAX_ENVIRONMENT_LAYERS);
        plan_overlay_stack(&at_cap, "/mnt/layers", "/upper", "/work", "/merged").unwrap();

        // `layer_count()` is base + workspace + toolkits, so one over the cap
        // needs `MAX_ENVIRONMENT_LAYERS - 1` toolkits.
        let toolkits: Vec<serde_json::Value> = (0..(MAX_ENVIRONMENT_LAYERS - 1))
            .map(|i| {
                serde_json::json!({
                    "name": format!("toolkit-{i:02}"),
                    "order": i + 2,
                    "kind": "toolkit",
                    "digest": format!("sha256:over{i:02}00000000000000000000000000000000000000000000"),
                    "size": 1024,
                    "media_type": "application/vnd.pico.layer.erofs",
                })
            })
            .collect();
        let mut json = serde_json::to_value(&at_cap).unwrap();
        json["toolkits"] = serde_json::Value::Array(toolkits);
        let too_many: EnvironmentComposition = serde_json::from_value(json).unwrap();
        assert_eq!(too_many.layer_count(), MAX_ENVIRONMENT_LAYERS + 1);

        let err = plan_overlay_stack(&too_many, "/mnt/layers", "/upper", "/work", "/merged")
            .expect_err("over-cap composition must be rejected");
        assert!(
            matches!(err, pico_image::error::ImageError::TooManyLayers { .. }),
            "expected TooManyLayers, got {err:?}"
        );
    }

    #[test]
    fn plan_rebuild_rejects_malformed_operands() {
        // `toolkit_only` selects the fast path that skips full revalidation, so
        // a stale digest must not be able to reach it.
        let fx = layered_fixture();
        let mut stale = fx.composition.clone();
        stale.composition_digest = "sha256:not-recomputed".into();
        let err = plan_rebuild(&fx.composition, &stale)
            .expect_err("stale composition digest must be rejected");
        assert!(
            err.to_string().contains("digest mismatch"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn layer_collapse_threshold_and_max_are_enforced() {
        let fx = layered_fixture();
        assert!(collapse_advice(&fx.composition).is_none());

        // At the threshold, collapse becomes advisory.
        let at_threshold =
            composition_with_toolkits(&fx, COLLAPSE_THRESHOLD_LAYERS - 2, "sha256:thr");
        assert_eq!(at_threshold.layer_count(), COLLAPSE_THRESHOLD_LAYERS);
        let advice = collapse_advice(&at_threshold).expect("threshold must advise collapse");
        assert!(advice.contains("squash") || advice.contains("collapse"));
        let plan = plan_overlay_stack(&at_threshold, "/mnt/layers", "/u", "/w", "/m").unwrap();
        assert!(plan.collapse_recommended);

        // Beyond the hard cap, the composition itself is refused at build time.
        let over_cap_toolkits: Vec<EnvironmentLayer> = (0..(MAX_ENVIRONMENT_LAYERS - 1))
            .map(|i| {
                EnvironmentLayer::new(
                    format!("toolkit-{i:02}"),
                    EnvironmentLayerKind::Toolkit,
                    format!("sha256:over{i:02}00000000000000000000000000000000000000000000"),
                    1024,
                    "application/vnd.pico.layer.erofs",
                )
                .unwrap()
            })
            .collect();
        let err = EnvironmentComposition::new(
            "test-image",
            fx.composition.base.clone(),
            fx.composition.workspace.clone(),
            over_cap_toolkits,
            test_compatibility(),
            1,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("exceeding max"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn monolithic_manifest_still_verifies_without_environment() {
        let manifest = valid_manifest();
        assert!(manifest.environment.is_none());
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(report.all_passed());

        let temp = tempfile::TempDir::new().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let manifest_path = dir.join("manifest.json");
        let mut manifest = manifest;
        let (rootfs, agent, kernel) = write_manifest_artifacts(&dir);
        manifest.artifacts.rootfs.digest = compute_file_digest(&rootfs).unwrap();
        manifest.artifacts.rootfs.size = std::fs::metadata(&rootfs).unwrap().len();
        manifest.artifacts.guest_agent.digest = compute_file_digest(&agent).unwrap();
        manifest.artifacts.guest_agent.size = std::fs::metadata(&agent).unwrap().len();
        if let Some(ref mut kd) = manifest.artifacts.kernel {
            kd.digest = compute_file_digest(&kernel).unwrap();
            kd.size = std::fs::metadata(&kernel).unwrap().len();
        }
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let (signing_key, verifying_key) = generate_signing_key();
        let signature_path = sign_manifest(
            &manifest_path,
            &signing_key,
            "test-builder",
            &manifest.image_id,
            &dir,
        )
        .unwrap();
        let layout = HostImageLayout {
            manifest_path: &manifest_path,
            signature_path: Some(&signature_path),
            rootfs_path: &rootfs,
            kernel_path: Some(&kernel),
            guest_agent_path: &agent,
            initrd_path: None,
            firmware_path: None,
        };
        let verified = verify_for_host(
            &layout,
            &HostVerificationPolicy::Production {
                trusted_key: verifying_key,
            },
        )
        .unwrap();
        assert!(verified.composition_digest.is_none());
        assert!(verified.composition_audit_record.is_none());
        verify_environment_layers(&verified, &[]).unwrap();
        verify_environment_compatibility(&verified, &host_expectation()).unwrap();
    }

    #[test]
    fn layered_manifest_passes_static_validation_and_rejects_profile_drift() {
        let fx = layered_fixture();
        let mut manifest = valid_manifest();
        attach_environment(&mut manifest, fx.composition.clone());
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(
            report.all_passed(),
            "layered manifest should pass: {:?}",
            report.failed_checks()
        );
        assert!(
            manifest
                .required_features
                .contains(&"environment-layers-v1".to_string())
        );

        let mut drifted = manifest.clone();
        let mut env = drifted.environment.clone().unwrap();
        env.compatibility.profile_id = "qemu-aarch64-v1".into();
        // Keep the digest binding honest: recompute after editing.
        env.composition_digest = pico_image::compute_composition_digest(
            &env.image_id,
            &env.base,
            &env.workspace,
            &env.toolkits,
            &env.compatibility,
        );
        drifted.environment = Some(env);
        let report = validation::validate_static(&drifted, &def);
        assert!(!report.all_passed());
        assert!(
            report
                .failed_check_names()
                .iter()
                .any(|n| n.contains("environment"))
        );
    }

    #[test]
    fn composition_promotion_is_monotonic_per_digest() {
        let fx = layered_fixture();
        let built = CompositionPromotion {
            composition_digest: fx.composition.composition_digest.clone(),
            stage: CompositionPromotionStage::Built,
            policy_revision: "pol-1".into(),
            evidence_digests: vec!["sha256:evidence".into()],
            approver: "builder".into(),
            decided_at: 1,
        };
        let validated = CompositionPromotion {
            stage: CompositionPromotionStage::Validated,
            ..built.clone()
        };
        let candidate = CompositionPromotion {
            stage: CompositionPromotionStage::Candidate,
            approver: "release".into(),
            decided_at: 2,
            ..validated.clone()
        };
        let production = CompositionPromotion {
            stage: CompositionPromotionStage::Production,
            approver: "release".into(),
            decided_at: 3,
            ..candidate.clone()
        };
        let validated = built.advance(&validated).unwrap();
        let candidate = validated.advance(&candidate).unwrap();
        candidate.advance(&production).unwrap();

        // Skip, regression, and digest change all fail.
        assert!(built.advance(&candidate).is_err());
        assert!(candidate.advance(&validated).is_err());
        let wrong_digest = CompositionPromotion {
            composition_digest: "sha256:other".into(),
            ..production.clone()
        };
        assert!(candidate.advance(&wrong_digest).is_err());
    }
}
