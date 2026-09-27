//! Host-side image verification gate.
//!
//! Covers the admission outcomes the prepare path depends on: a signed
//! monolithic image is admitted and its evidence recorded, a tampered artifact
//! is rejected, an unsigned image is rejected in production mode, and a layered
//! image is refused on a backend that cannot present a merged layer stack.

mod common;

#[cfg(test)]
mod image_verify {
    use camino::Utf8PathBuf;
    use ed25519_dalek::VerifyingKey;
    use pico_core::runtime::{BackendCapabilities, BackendCapability, RuntimeType};
    use pico_host_agent::image_verify::{
        HOST_PROTOCOL_MAJOR, ImageAdmissionError, ImageVerificationConfig, ImageVerificationMode,
        ImageVerifier,
    };
    use pico_image::signature::{encode_verifying_key, generate_signing_key, sign_manifest};
    use pico_image::types::PicoComputeGuestManifest;

    use crate::common::{attach_composition_without_files, write_image_bundle};

    /// A signed (or deliberately unsigned) image bundle on disk.
    struct Bundle {
        _dir: tempfile::TempDir,
        dir: Utf8PathBuf,
        verifying_key: VerifyingKey,
    }

    impl Bundle {
        fn verifier(&self, mode: ImageVerificationMode) -> ImageVerifier {
            ImageVerifier::new(&ImageVerificationConfig {
                image_dir: Some(self.dir.to_string()),
                trusted_signing_key: match mode {
                    ImageVerificationMode::Production => {
                        Some(encode_verifying_key(&self.verifying_key))
                    }
                    ImageVerificationMode::Development => None,
                },
                mode,
            })
            .expect("valid config must construct a verifier")
        }
    }

    /// Write a bundle and sign its manifest, mirroring the production layout:
    /// `manifest.json` plus `manifest.sig.json` beside the artifact files.
    fn signed_bundle(layered: bool) -> Bundle {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let manifest = write_image_bundle(&path, layered);
        write_manifest(&path, &manifest);
        let (signing_key, verifying_key) = generate_signing_key();
        sign_manifest(
            &path.join("manifest.json"),
            &signing_key,
            "test-builder",
            &manifest.image_id,
            &path,
        )
        .expect("signing must succeed");
        Bundle {
            _dir: dir,
            dir: path,
            verifying_key,
        }
    }

    /// Write a bundle but deliberately omit the signature.
    fn unsigned_bundle() -> Bundle {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let manifest = write_image_bundle(&path, false);
        write_manifest(&path, &manifest);
        let (_, verifying_key) = generate_signing_key();
        Bundle {
            _dir: dir,
            dir: path,
            verifying_key,
        }
    }

    fn write_manifest(dir: &Utf8PathBuf, manifest: &PicoComputeGuestManifest) {
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(manifest).unwrap(),
        )
        .unwrap();
    }

    fn verify(
        bundle: &Bundle,
        mode: ImageVerificationMode,
        caps: &BackendCapabilities,
    ) -> Result<pico_host_agent::image_verify::VerifiedImageRecord, ImageAdmissionError> {
        bundle.verifier(mode).verify(RuntimeType::Firecracker, caps)
    }

    #[test]
    fn signed_monolithic_image_is_admitted_with_evidence() {
        let bundle = signed_bundle(false);
        let record = verify(
            &bundle,
            ImageVerificationMode::Production,
            &BackendCapabilities::default(),
        )
        .expect("signed matching image must be admitted");

        assert_eq!(record.image_id, "test-image");
        assert_eq!(record.signer_identity.as_deref(), Some("test-builder"));
        assert!(record.manifest_digest.starts_with("sha256:"));
        assert!(!record.is_layered());
        assert_eq!(record.layer_count, 0);
        assert!(record.composition_audit_record.is_none());
        assert_eq!(record.mode, ImageVerificationMode::Production);
    }

    #[test]
    fn production_mode_rejects_a_digest_mismatch() {
        let bundle = signed_bundle(false);
        // Same length, different bytes, so the size check passes and the
        // digest is decisive.
        let original = std::fs::read(bundle.dir.join("rootfs.ext4")).unwrap();
        let mut mutated = original.clone();
        mutated[0] = b'X';
        std::fs::write(bundle.dir.join("rootfs.ext4"), mutated).unwrap();

        let err = verify(
            &bundle,
            ImageVerificationMode::Production,
            &BackendCapabilities::default(),
        )
        .expect_err("tampered rootfs must be rejected");
        match err {
            ImageAdmissionError::Rejected(msg) => {
                assert!(msg.contains("digest mismatch"), "unexpected: {msg}")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn production_mode_rejects_an_unsigned_image() {
        let bundle = unsigned_bundle();
        let err = verify(
            &bundle,
            ImageVerificationMode::Production,
            &BackendCapabilities::default(),
        )
        .expect_err("unsigned image must be rejected in production");
        match err {
            ImageAdmissionError::Rejected(msg) => {
                assert!(msg.contains("unsigned"), "unexpected: {msg}")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn production_mode_rejects_a_tampered_manifest() {
        let bundle = signed_bundle(false);
        let manifest_path = bundle.dir.join("manifest.json");
        let mut tampered: PicoComputeGuestManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        tampered.image_id = "evil-image".into();
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&tampered).unwrap(),
        )
        .unwrap();

        let err = verify(
            &bundle,
            ImageVerificationMode::Production,
            &BackendCapabilities::default(),
        )
        .expect_err("tampered manifest must fail signature verification");
        assert!(matches!(err, ImageAdmissionError::Rejected(_)));
    }

    #[test]
    fn layered_image_is_refused_on_a_backend_without_layer_support() {
        // The central new gate: without it, a layered manifest would boot and
        // silently run the monolithic rootfs instead of its layer stack.
        let bundle = signed_bundle(true);
        let err = verify(
            &bundle,
            ImageVerificationMode::Production,
            &BackendCapabilities::default(),
        )
        .expect_err("layered image must be refused without EnvironmentLayers");
        match err {
            ImageAdmissionError::BackendLacksLayerSupport { runtime, reason } => {
                assert_eq!(runtime, "firecracker");
                assert!(reason.contains("monolithic rootfs"), "unexpected: {reason}");
            }
            other => panic!("expected BackendLacksLayerSupport, got {other:?}"),
        }
    }

    #[test]
    fn layered_image_is_admitted_when_the_backend_declares_layer_support() {
        // Proves the gate is the only thing blocking admission: with the
        // capability declared, the same bundle verifies and its composition is
        // recorded for the audit trail.
        let bundle = signed_bundle(true);
        let caps = BackendCapabilities::from([BackendCapability::EnvironmentLayers]);
        let record = verify(&bundle, ImageVerificationMode::Production, &caps)
            .expect("a backend declaring layer support must admit the layered image");

        assert!(record.is_layered());
        assert_eq!(record.layer_count, 3);
        let audit = record
            .composition_audit_record
            .as_deref()
            .expect("a layered image must produce a composition audit record");
        assert!(audit.contains("debian-base"));
        assert!(audit.contains("toolkit-python"));
        assert!(audit.contains(record.composition_digest.as_deref().unwrap()));
    }

    #[test]
    fn no_real_backend_declares_layer_support() {
        // Guards the gate from being defeated by a future adapter that declares
        // EnvironmentLayers without actually assembling the stack. No backend
        // exposes a merged rootfs view to the guest today, so none may declare it.
        for runtime in [
            RuntimeType::Firecracker,
            RuntimeType::RemoteFirecracker,
            RuntimeType::Qemu,
            RuntimeType::GVisor,
        ] {
            let caps = pico_runtime::declared_capabilities(runtime);
            assert!(
                !caps.contains(BackendCapability::EnvironmentLayers),
                "{runtime} must not declare EnvironmentLayers until it can present a merged stack"
            );
        }
    }

    #[test]
    fn missing_layer_file_is_a_configuration_error() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let mut manifest = write_image_bundle(&path, false);
        // Attach a composition but never write the layer files.
        attach_composition_without_files(&mut manifest);
        write_manifest(&path, &manifest);
        let (_, verifying_key) = generate_signing_key();
        sign_manifest(
            &path.join("manifest.json"),
            &generate_signing_key().0,
            "test-builder",
            &manifest.image_id,
            &path,
        )
        .unwrap();
        let bundle = Bundle {
            _dir: dir,
            dir: path,
            verifying_key,
        };

        let err = verify(
            &bundle,
            ImageVerificationMode::Production,
            &BackendCapabilities::from([BackendCapability::EnvironmentLayers]),
        )
        .expect_err("a missing layer file must fail closed");
        assert!(matches!(err, ImageAdmissionError::Misconfigured(_)));
    }

    #[test]
    fn host_protocol_major_matches_the_manifest_allowlist() {
        // The compatibility expectation is the host's own protocol major. If it
        // drifted from what manifests declare, every layered image would fail
        // compatibility. That is the safe direction, but it is a config bug.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let manifest = write_image_bundle(&path, false);
        assert!(
            manifest
                .protocol
                .supported
                .iter()
                .any(|r| r.major == HOST_PROTOCOL_MAJOR),
            "the fixture protocol ranges must include the host major"
        );
    }

    #[test]
    fn development_mode_admits_an_unsigned_image() {
        let bundle = unsigned_bundle();
        let record = verify(
            &bundle,
            ImageVerificationMode::Development,
            &BackendCapabilities::default(),
        )
        .expect("development mode tolerates a missing signature");
        assert!(record.signer_identity.is_none());
        assert_eq!(record.mode, ImageVerificationMode::Development);
    }
}
