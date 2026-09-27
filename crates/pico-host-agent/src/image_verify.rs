//! Host-side image verification gate for `prepare` and `boot`.
//!
//! `pico-image` already knows how to verify a materialized guest image: the
//! manifest signature, every declared artifact's size and digest, the
//! required-feature marker, the per-layer digests of an environment
//! composition, and the composition's compatibility allowlist. Until now
//! nothing in the host called it, so `prepare` only checked that a configured
//! path existed.
//!
//! This module is the caller. It answers one question on the host's behalf:
//! *may this host boot this image?* It resolves the image layout from host
//! configuration, runs the verification library, and converts the result into
//! the evidence the host records on the sandbox entry and reports on READY.
//!
//! ## Why the host agent owns this
//!
//! The runtime adapters read `PICO_ROOTFS_PATH` and friends from the
//! `sandboxd` process environment. `host-agent` and `sandboxd` are separate
//! processes (ADR-0011), so the host cannot see those variables. More
//! importantly, "which image am I allowed to boot" is host admission policy,
//! not a property of the VMM process. The host agent therefore resolves the
//! image store from its own configuration and verifies it itself; adapters
//! still attach the artifacts they were configured with.
//!
//! ## Layered images
//!
//! A manifest may carry a `pico_image::layers::EnvironmentComposition`. The
//! host verifies the composition signature and per-layer digests, then checks
//! that the selected backend can actually present a merged layer stack. A
//! backend must declare [`BackendCapability::EnvironmentLayers`] for that to
//! pass. No adapter declares it yet, because no backend currently exposes a
//! merged rootfs view to the guest (see the open limitation in
//! `docs/image/composable-environment-layers.md`). That is deliberate: the
//! gate fails closed rather than letting a layered manifest boot as a
//! monolithic rootfs.

use camino::{Utf8Path, Utf8PathBuf};
use ed25519_dalek::VerifyingKey;
use pico_core::runtime::{BackendCapabilities, BackendCapability, NonReadyReason, RuntimeType};
use pico_image::error::ImageError;
use pico_image::host_verify::{
    HostImageLayout, HostVerificationPolicy, verify_environment_compatibility,
    verify_environment_layers, verify_environment_supply_chain, verify_for_host,
};
use pico_image::layers::HostCompatibilityExpectation;
use pico_image::signature::decode_verifying_key;
use serde::{Deserialize, Serialize};

/// Host/guest protocol major version this host implements (ADR-0003).
///
/// Used as the host's compatibility expectation when checking an image's
/// declared protocol allowlists. A wrong value is not a silent risk: the
/// manifest's own `protocol.supported` ranges are cross-checked against it, so
/// a mismatch fails verification.
pub const HOST_PROTOCOL_MAJOR: u32 = 1;

/// How strictly the host verifies an image before boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ImageVerificationMode {
    /// Require a detached signature from a pinned trusted key and verify every
    /// declared digest. The only mode permitted on a host that accepts
    /// untrusted workloads.
    Production,
    /// Reject a present-but-invalid signature and any digest or size mismatch,
    /// but tolerate a missing signature. Local development hosts only.
    #[default]
    Development,
}

/// Why the host refused an image.
///
/// Each variant maps onto the existing failure taxonomy: [`Self::non_ready_reason`]
/// feeds the boot report, and [`Self::reason_label`] feeds structured logs.
#[derive(Debug, thiserror::Error)]
pub enum ImageAdmissionError {
    /// The verifier itself is misconfigured, or the image directory is
    /// unreadable. An operator problem, not a tenant problem.
    #[error("image verification is not usable: {0}")]
    Misconfigured(String),

    /// The image failed a signature, digest, size, or feature gate.
    #[error("image rejected: {0}")]
    Rejected(String),

    /// The image declares a composable layer stack the selected backend cannot
    /// present, so booting it would silently run the monolithic rootfs.
    #[error("backend {runtime} cannot present environment layers: {reason}")]
    BackendLacksLayerSupport { runtime: String, reason: String },
}

impl ImageAdmissionError {
    /// Typed boot-failure classification for this rejection.
    pub fn non_ready_reason(&self) -> NonReadyReason {
        // Every variant is an image-materialization failure rather than a
        // backend or protocol fault: the guest never started with the
        // requested image.
        NonReadyReason::Image
    }

    /// Stable short reason label for metrics and audit records.
    pub fn reason_label(&self) -> &'static str {
        match self {
            Self::Misconfigured(_) => "image_verification_misconfigured",
            Self::Rejected(_) => "image_rejected",
            Self::BackendLacksLayerSupport { .. } => "image_layer_support_missing",
        }
    }
}

/// Where the host resolves guest images and how strictly it verifies them.
///
/// Manual `Debug` (no derived): `trusted_signing_key` is a public key, not a
/// secret, but a config dump has no reason to carry key material. Only the
/// presence of a key is reported.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImageVerificationConfig {
    /// Directory holding one materialized image bundle: `manifest.json`, an
    /// optional `manifest.sig.json`, the artifact files, and one
    /// `<layer-name>.erofs` per declared environment layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_dir: Option<String>,
    /// Base64-encoded Ed25519 public key pinning the approved image signing
    /// identity. Required in production mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_signing_key: Option<String>,
    /// Verification strictness.
    #[serde(default)]
    pub mode: ImageVerificationMode,
}

impl std::fmt::Debug for ImageVerificationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageVerificationConfig")
            .field("image_dir", &self.image_dir)
            .field(
                "trusted_signing_key",
                &if self.trusted_signing_key.is_some() {
                    "[SET]"
                } else {
                    "none"
                },
            )
            .field("mode", &self.mode)
            .finish()
    }
}

impl ImageVerificationConfig {
    /// True when a layout has been configured and verification should run.
    ///
    /// A host with no `image_dir` performs no image verification, which keeps
    /// existing deployments working but also means such a host boots whatever
    /// its adapter was pointed at. Operators must set `image_dir` for image
    /// admission to mean anything.
    pub fn is_configured(&self) -> bool {
        self.image_dir.is_some()
    }
}

/// Evidence about a verified image, recorded on the sandbox entry and reported
/// when the sandbox reaches READY.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedImageRecord {
    /// Image family from the signed manifest.
    pub image_id: String,
    /// SHA-256 digest of the signed manifest bytes.
    pub manifest_digest: String,
    /// Signer identity from the signature bundle, when a signature was present.
    pub signer_identity: Option<String>,
    /// Composition digest when the manifest carries an environment
    /// composition, otherwise `None` for a monolithic image.
    pub composition_digest: Option<String>,
    /// JSON audit record naming the exact ordered layer set that was verified.
    pub composition_audit_record: Option<String>,
    /// Number of released layers verified, or `0` for a monolithic image.
    pub layer_count: usize,
    /// Verification mode that admitted this image.
    pub mode: ImageVerificationMode,
}

impl VerifiedImageRecord {
    /// True when the verified image carried a composable layer stack.
    pub fn is_layered(&self) -> bool {
        self.composition_digest.is_some()
    }
}

/// One discovered image bundle, holding owned paths.
///
/// [`HostImageLayout`] borrows, so the layout is built inside `verify` from a
/// borrow of this struct rather than stored here.
#[derive(Debug, Clone)]
struct BundleLayout {
    /// Image directory this bundle was discovered in.
    #[expect(
        dead_code,
        reason = "retained for operator diagnostics; discovery errors already embed the path"
    )]
    image_dir: Utf8PathBuf,
    manifest: Utf8PathBuf,
    signature: Option<Utf8PathBuf>,
    rootfs: Utf8PathBuf,
    kernel: Option<Utf8PathBuf>,
    guest_agent: Utf8PathBuf,
    initrd: Option<Utf8PathBuf>,
    firmware: Option<Utf8PathBuf>,
    layer_names: Vec<String>,
    layer_paths: Vec<Utf8PathBuf>,
}

impl BundleLayout {
    /// Discover the files of one image bundle.
    ///
    /// `manifest.json` and the rootfs must exist. `manifest.sig.json` and the
    /// optional kernel/initrd/firmware artifacts are resolved by the media
    /// type the manifest declares, so the host does not need a second source
    /// of truth for layout. Every resolved file is still size- and
    /// digest-checked against the manifest by `verify_for_host`.
    fn discover(image_dir: &Utf8Path) -> Result<Self, ImageAdmissionError> {
        let manifest = image_dir.join("manifest.json");
        let manifest_bytes = std::fs::read(&manifest).map_err(|e| {
            ImageAdmissionError::Misconfigured(format!("failed to read {}: {e}", manifest))
        })?;
        let parsed: pico_image::types::PicoComputeGuestManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| {
                ImageAdmissionError::Misconfigured(format!("invalid manifest {manifest}: {e}"))
            })?;

        let signature_path = image_dir.join("manifest.sig.json");
        let signature = signature_path.is_file().then_some(signature_path);

        let rootfs = require_file(image_dir, "rootfs.ext4")?;
        let kernel = parsed
            .artifacts
            .kernel
            .as_ref()
            .map(|d| require_file(image_dir, artifact_file_name(&d.media_type, "vmlinux")))
            .transpose()?;
        let guest_agent = require_file(image_dir, "pico-guest-agent")?;
        let initrd = parsed
            .artifacts
            .initrd
            .as_ref()
            .map(|d| require_file(image_dir, artifact_file_name(&d.media_type, "initrd.img")))
            .transpose()?;
        let firmware = parsed
            .artifacts
            .firmware
            .as_ref()
            .map(|d| require_file(image_dir, artifact_file_name(&d.media_type, "firmware.bin")))
            .transpose()?;

        let layer_names = parsed
            .environment
            .as_ref()
            .map(|env| {
                env.ordered_layers()
                    .iter()
                    .map(|l| l.name.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // Resolved now so a missing layer file is a configuration error rather
        // than a borrow-lifetime problem in the verification path.
        let mut layer_paths = Vec::with_capacity(layer_names.len());
        for name in &layer_names {
            let path = image_dir.join(format!("{name}.erofs"));
            if !path.is_file() {
                return Err(ImageAdmissionError::Misconfigured(format!(
                    "image dir {image_dir} is missing layer file {name}.erofs"
                )));
            }
            layer_paths.push(path);
        }

        Ok(Self {
            image_dir: image_dir.to_path_buf(),
            manifest,
            signature,
            rootfs,
            kernel,
            guest_agent,
            initrd,
            firmware,
            layer_names,
            layer_paths,
        })
    }

    /// Build the borrowed layout handed to `verify_for_host`.
    fn host_layout(&self) -> HostImageLayout<'_> {
        HostImageLayout {
            manifest_path: &self.manifest,
            signature_path: self.signature.as_deref(),
            rootfs_path: &self.rootfs,
            kernel_path: self.kernel.as_deref(),
            guest_agent_path: &self.guest_agent,
            initrd_path: self.initrd.as_deref(),
            firmware_path: self.firmware.as_deref(),
        }
    }

    /// Resolve the on-disk file for each declared layer.
    ///
    /// Paths are stored on the bundle so the returned slice borrows `self`
    /// rather than a loop-local.
    fn layer_files(&self) -> Vec<pico_image::layers::HostLayerFile<'_>> {
        self.layer_names
            .iter()
            .zip(self.layer_paths.iter())
            .map(|(name, path)| pico_image::layers::HostLayerFile { name, path })
            .collect()
    }
}

/// Conventional on-disk filename for a declared artifact media type.
fn artifact_file_name<'a>(media_type: &'a str, fallback: &'a str) -> &'a str {
    match media_type {
        "application/vnd.pico.kernel.vmlinux" => "vmlinux",
        "application/vnd.pico.initrd" => "initrd.img",
        "application/vnd.pico.firmware" => "firmware.bin",
        _ => fallback,
    }
}

fn require_file(dir: &Utf8Path, name: &str) -> Result<Utf8PathBuf, ImageAdmissionError> {
    let path = dir.join(name);
    if !path.is_file() {
        return Err(ImageAdmissionError::Misconfigured(format!(
            "image dir {dir} is missing required artifact {name}"
        )));
    }
    Ok(path)
}

/// Verifies guest images on behalf of the host agent.
#[derive(Debug, Clone)]
pub struct ImageVerifier {
    image_dir: Option<Utf8PathBuf>,
    mode: ImageVerificationMode,
    policy: HostVerificationPolicy,
}

impl ImageVerifier {
    /// Build a verifier, decoding the trusted key up front so a bad key fails
    /// at construction rather than on the first sandbox.
    pub fn new(config: &ImageVerificationConfig) -> Result<Self, ImageAdmissionError> {
        let policy = match (config.mode, config.trusted_signing_key.as_deref()) {
            (ImageVerificationMode::Production, Some(encoded)) => {
                let key: VerifyingKey = decode_verifying_key(encoded)
                    .map_err(|e| ImageAdmissionError::Misconfigured(e.to_string()))?;
                HostVerificationPolicy::Production { trusted_key: key }
            }
            (ImageVerificationMode::Production, None) => {
                return Err(ImageAdmissionError::Misconfigured(
                    "image verification mode 'production' requires trusted_signing_key".into(),
                ));
            }
            (ImageVerificationMode::Development, _) => HostVerificationPolicy::Development,
        };

        let image_dir = match config.image_dir.as_deref() {
            Some(raw) => {
                // An image directory is joined with a layer name, so it must be
                // absolute and free of the `:` that separates overlayfs
                // lowerdir entries. `pico-image` validates the layer names.
                if !raw.starts_with('/') {
                    return Err(ImageAdmissionError::Misconfigured(format!(
                        "image_dir {raw} must be an absolute path"
                    )));
                }
                if raw.contains(':') {
                    return Err(ImageAdmissionError::Misconfigured(format!(
                        "image_dir {raw} must not contain ':'"
                    )));
                }
                if raw.split('/').any(|c| c == "." || c == "..") {
                    return Err(ImageAdmissionError::Misconfigured(format!(
                        "image_dir {raw} must be lexically normalized"
                    )));
                }
                Some(Utf8PathBuf::from(raw))
            }
            None => None,
        };

        Ok(Self {
            image_dir,
            mode: config.mode,
            policy,
        })
    }

    /// Verification mode in force.
    pub fn mode(&self) -> ImageVerificationMode {
        self.mode
    }

    /// Whether an image directory is configured.
    pub fn is_configured(&self) -> bool {
        self.image_dir.is_some()
    }

    /// Verify the configured image bundle for a sandbox about to be prepared.
    ///
    /// Returns the evidence to record. A host with no configured image
    /// directory returns `Ok(None)` and performs no verification, so callers
    /// must treat `None` as "unverified" rather than "allowed".
    ///
    /// `capabilities` is the selected backend's declared capability set; a
    /// layered image is refused unless the backend declares
    /// [`BackendCapability::EnvironmentLayers`].
    pub fn verify(
        &self,
        runtime: RuntimeType,
        capabilities: &BackendCapabilities,
    ) -> Result<VerifiedImageRecord, ImageAdmissionError> {
        let image_dir = self
            .image_dir
            .as_ref()
            .ok_or_else(|| ImageAdmissionError::Misconfigured("no image_dir configured".into()))?;
        let bundle = BundleLayout::discover(image_dir)?;
        let verified = verify_for_host(&bundle.host_layout(), &self.policy).map_err(rejected)?;

        if let Some(comp) = &verified.manifest.environment {
            if !capabilities.contains(BackendCapability::EnvironmentLayers) {
                return Err(ImageAdmissionError::BackendLacksLayerSupport {
                    runtime: runtime.to_string(),
                    reason: format!(
                        "image declares an environment composition ({} layers, {}) but the \
                         backend declares no EnvironmentLayers capability; booting it would \
                         silently run the monolithic rootfs",
                        comp.layer_count(),
                        comp.composition_digest
                    ),
                });
            }
            verify_environment_layers(&verified, &bundle.layer_files()).map_err(rejected)?;
            verify_environment_supply_chain(&verified).map_err(rejected)?;
            verify_environment_compatibility(
                &verified,
                &HostCompatibilityExpectation {
                    backend: runtime.to_string(),
                    architecture: host_architecture(),
                    protocol_major: HOST_PROTOCOL_MAJOR,
                },
            )
            .map_err(rejected)?;
        }

        let layer_count = verified
            .manifest
            .environment
            .as_ref()
            .map_or(0, |c| c.layer_count());

        Ok(VerifiedImageRecord {
            image_id: verified.manifest.image_id.clone(),
            manifest_digest: verified.manifest_digest.clone(),
            signer_identity: verified.signer_identity.clone(),
            composition_digest: verified.composition_digest.clone(),
            composition_audit_record: verified.composition_audit_record.clone(),
            layer_count,
            mode: self.mode,
        })
    }
}

fn rejected(err: ImageError) -> ImageAdmissionError {
    ImageAdmissionError::Rejected(err.to_string())
}

/// Host architecture string in the form manifests record it.
fn host_architecture() -> String {
    std::env::consts::ARCH.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_mode_requires_a_trusted_key() {
        let config = ImageVerificationConfig {
            image_dir: Some("/var/lib/pico/images/standard".into()),
            trusted_signing_key: None,
            mode: ImageVerificationMode::Production,
        };
        let err = ImageVerifier::new(&config).expect_err("production without a key must fail");
        assert!(matches!(err, ImageAdmissionError::Misconfigured(_)));
    }

    #[test]
    fn production_mode_rejects_a_malformed_trusted_key() {
        let config = ImageVerificationConfig {
            image_dir: Some("/var/lib/pico/images/standard".into()),
            trusted_signing_key: Some("!!!not-base64!!!".into()),
            mode: ImageVerificationMode::Production,
        };
        let err = ImageVerifier::new(&config).expect_err("malformed key must fail");
        assert!(matches!(err, ImageAdmissionError::Misconfigured(_)));
    }

    #[test]
    fn image_dir_must_be_absolute_normalized_and_separator_free() {
        for bad in ["relative/images", "/var/lib/pico:evil", "/var/lib/../etc"] {
            let config = ImageVerificationConfig {
                image_dir: Some(bad.into()),
                trusted_signing_key: None,
                mode: ImageVerificationMode::Development,
            };
            let err = ImageVerifier::new(&config).expect_err("unsafe image_dir must fail");
            assert!(
                matches!(err, ImageAdmissionError::Misconfigured(_)),
                "{bad:?} produced {err:?}"
            );
        }
    }

    #[test]
    fn unconfigured_verifier_reports_not_configured() {
        let verifier = ImageVerifier::new(&ImageVerificationConfig::default()).unwrap();
        assert!(!verifier.is_configured());
        assert_eq!(verifier.mode(), ImageVerificationMode::Development);
        // verify() must fail loudly rather than silently admitting.
        let err = verifier
            .verify(RuntimeType::Firecracker, &BackendCapabilities::default())
            .expect_err("unconfigured verification must not admit");
        assert!(matches!(err, ImageAdmissionError::Misconfigured(_)));
    }

    #[test]
    fn discovery_reports_a_missing_manifest() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let err = BundleLayout::discover(&path).expect_err("empty dir must fail");
        assert!(matches!(err, ImageAdmissionError::Misconfigured(_)));
    }

    #[test]
    fn admission_errors_classify_as_image_failures() {
        for err in [
            ImageAdmissionError::Misconfigured("x".into()),
            ImageAdmissionError::Rejected("x".into()),
            ImageAdmissionError::BackendLacksLayerSupport {
                runtime: "firecracker".into(),
                reason: "x".into(),
            },
        ] {
            assert_eq!(err.non_ready_reason(), NonReadyReason::Image);
            assert!(err.reason_label().starts_with("image_"));
        }
    }

    #[test]
    fn development_mode_tolerates_a_missing_signature() {
        let config = ImageVerificationConfig {
            image_dir: Some("/var/lib/pico/images/standard".into()),
            trusted_signing_key: None,
            mode: ImageVerificationMode::Development,
        };
        let verifier = ImageVerifier::new(&config).expect("development mode needs no key");
        assert!(verifier.is_configured());
    }
}
