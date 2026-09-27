pub mod definition;
pub mod error;
pub mod host_verify;
pub mod kernel;
pub mod layers;
pub mod lock;
pub mod manifest;
pub mod normalize;
pub mod provenance;
pub mod render;
pub mod resolve;
pub mod sbom;
pub mod signature;
pub mod types;
pub(crate) mod util;
pub mod validation;
pub mod warm_snapshot;

pub use host_verify::{
    HostImageLayout, HostVerificationPolicy, VerifiedImage, verify_environment_compatibility,
    verify_environment_layers, verify_for_host,
};
pub use layers::{
    COLLAPSE_THRESHOLD_LAYERS, CompositionCompatibility, CompositionPromotion,
    CompositionPromotionStage, ENVIRONMENT_SCHEMA_VERSION, EnvironmentComposition,
    EnvironmentLayer, EnvironmentLayerKind, HostCompatibilityExpectation, HostLayerFile,
    LayerRebuildPlan, MAX_ENVIRONMENT_LAYERS, OPAQUE_MARKER, WHITEOUT_PREFIX, collapse_advice,
    compute_composition_digest, format_composition_audit_record,
    layers_missing_supply_chain_evidence, plan_overlay_stack, plan_rebuild,
    validate_environment_composition, validate_environment_layer, verify_composition_compatibility,
    verify_layers_for_host,
};

// TODO: Wire warm snapshot generation into the image pipeline.
// The warm_snapshot module is implemented but not yet called from
// RootfsBuilder::build() or any image profile handler. The wiring
// should:
//  - Check WarmSnapshotConfig::enabled per image profile
//  - Call WarmSnapshotGenerator::generate after image build succeeds
//  - Block promotion when require_restore_validation is set and
//    restore validation fails
//  - Attach snapshot metadata to the image manifest output

use crate::util::compute_sha256_digest;
use tracing::info;

pub struct RootfsBuilder {
    pub definition_path: camino::Utf8PathBuf,
    pub lock_path: Option<camino::Utf8PathBuf>,
    pub work_dir: camino::Utf8PathBuf,
    pub output_dir: camino::Utf8PathBuf,
    pub guest_agent_path: Option<camino::Utf8PathBuf>,
    pub locked: bool,
    /// Optional path to a signing key file (base64-encoded 32-byte Ed25519 seed).
    /// If not set, the `PICO_SIGNING_KEY` env var is checked.
    pub signing_key_path: Option<camino::Utf8PathBuf>,
    /// Identity of the signer (e.g., hostname, CI job name).
    pub signer_identity: Option<String>,
}

impl RootfsBuilder {
    #[tracing::instrument(skip(self), fields(definition = %self.definition_path))]
    pub fn build(&self) -> Result<BuildOutput, error::ImageError> {
        info!("loading image definition from {}", self.definition_path);
        let definition = definition::ImageDefinition::load(&self.definition_path)?;

        let lock = if self.locked {
            let lock_path = self.lock_path.as_ref().ok_or_else(|| {
                error::ImageError::ParseError("lock file required in locked mode".into())
            })?;
            lock::PackageLock::load(lock_path)?
        } else {
            let lock_path = self
                .lock_path
                .clone()
                .unwrap_or_else(|| self.work_dir.join("package-lock.toml"));
            resolve::create_lock(&definition, &lock_path)?
        };

        std::fs::create_dir_all(&self.work_dir)?;
        std::fs::create_dir_all(&self.output_dir)?;

        let base_archive = resolve::fetch_base_rootfs(&lock, &self.work_dir)?;

        let guest_agent_path = self.resolve_guest_agent_path(&definition)?;

        let guest_agent_digest = render::compute_file_digest(&guest_agent_path)?;
        let guest_agent_size = std::fs::metadata(&guest_agent_path)?.len();

        let mount_contract = build_mount_contract_from_def(&definition)?;

        let rootfs_dir = normalize::normalize_rootfs(
            &lock,
            &base_archive,
            &guest_agent_path,
            &self.work_dir,
            definition.image.source_date_epoch,
            &mount_contract,
        )?;

        let rootfs_output = render::render_ext4(
            &rootfs_dir,
            &definition.filesystem.label,
            &definition.filesystem.uuid,
            &definition.filesystem.size,
            &self.output_dir,
        )?;

        let guest_agent_output = render::OutputInfo {
            path: guest_agent_path,
            digest: guest_agent_digest,
            size: guest_agent_size,
        };

        let (manifest_path, manifest) = manifest::generate_manifest(
            &definition,
            &lock,
            &rootfs_output,
            &guest_agent_output,
            &self.output_dir,
            &mount_contract,
            definition.kernel.as_ref(),
        )?;

        let manifest_json = serde_json::to_string(&manifest).map_err(|e| {
            error::ImageError::ParseError(format!("failed to serialize manifest: {}", e))
        })?;
        let manifest_digest = compute_sha256_digest(manifest_json.as_bytes());

        let sbom_path = sbom::generate_sbom(&manifest, &lock, &self.output_dir)?;

        let provenance_path = provenance::generate_provenance(
            &definition,
            &lock,
            &manifest_digest,
            &self.output_dir,
        )?;

        let sbom: types::CycloneDxSbom =
            serde_json::from_str(&std::fs::read_to_string(&sbom_path).map_err(|e| {
                error::ImageError::ParseError(format!("failed to read SBOM: {}", e))
            })?)
            .map_err(|e| error::ImageError::ParseError(format!("failed to parse SBOM: {}", e)))?;

        let provenance: types::ProvenanceMetadata =
            serde_json::from_str(&std::fs::read_to_string(&provenance_path).map_err(|e| {
                error::ImageError::ParseError(format!("failed to read provenance: {}", e))
            })?)
            .map_err(|e| {
                error::ImageError::ParseError(format!("failed to parse provenance: {}", e))
            })?;

        let supply_chain_report =
            validation::validate_supply_chain(&manifest, &definition, &lock, &sbom, &provenance);

        if !supply_chain_report.all_passed() {
            return Err(error::ImageError::ManifestValidationFailed(format!(
                "supply-chain validation failed: {}",
                supply_chain_report.summary()
            )));
        }

        let signature_path = self.try_sign_manifest(&manifest_path, &manifest)?;

        Ok(BuildOutput {
            rootfs: rootfs_output,
            guest_agent: guest_agent_output,
            manifest_path,
            sbom_path,
            signature_path,
            provenance_path,
        })
    }

    /// Try to sign the manifest. Returns `None` if no signing key is configured.
    fn try_sign_manifest(
        &self,
        manifest_path: &camino::Utf8Path,
        manifest: &types::PicoComputeGuestManifest,
    ) -> Result<Option<camino::Utf8PathBuf>, error::ImageError> {
        let signing_key = match self.load_signing_key() {
            Ok(key) => key,
            Err(error::ImageError::SigningKeyUnavailable(_)) => {
                info!("no signing key configured, skipping manifest signing");
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        let signer_identity = self.signer_identity.as_deref().unwrap_or("pico-cli");

        let sig_path = signature::sign_manifest(
            manifest_path,
            &signing_key,
            signer_identity,
            &manifest.image_id,
            &self.output_dir,
        )?;

        Ok(Some(sig_path))
    }

    /// Load the signing key from configured sources.
    fn load_signing_key(&self) -> Result<ed25519_dalek::SigningKey, error::ImageError> {
        if let Some(ref key_path) = self.signing_key_path {
            return signature::load_signing_key_from_path(key_path);
        }
        signature::load_signing_key_from_env()
    }

    fn resolve_guest_agent_path(
        &self,
        definition: &definition::ImageDefinition,
    ) -> Result<camino::Utf8PathBuf, error::ImageError> {
        match &definition.guest_agent {
            definition::GuestAgentSource::Workspace { .. } => {
                if let Some(ref path) = self.guest_agent_path
                    && path.exists()
                {
                    return Ok(path.clone());
                }

                let cargo_target =
                    std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into());

                let profile = if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                };

                let default_path = camino::Utf8PathBuf::from(format!(
                    "{}/{}/pico-guest-agent",
                    cargo_target, profile
                ));

                if default_path.exists() {
                    return Ok(default_path);
                }

                let release_path =
                    camino::Utf8PathBuf::from(format!("{}/release/pico-guest-agent", cargo_target));

                if release_path.exists() {
                    return Ok(release_path);
                }

                Err(error::ImageError::GuestAgentBuildFailed(
                    "guest-agent not found. Build it first with: cargo build -p pico-guest-agent --release".into(),
                ))
            }
            definition::GuestAgentSource::Prebuilt { path, .. } => {
                Ok(camino::Utf8PathBuf::from(path))
            }
        }
    }
}

#[derive(Debug)]
pub struct BuildOutput {
    pub rootfs: render::OutputInfo,
    pub guest_agent: render::OutputInfo,
    pub manifest_path: camino::Utf8PathBuf,
    /// Path to the CycloneDX SBOM (sbom.cdx.json).
    pub sbom_path: camino::Utf8PathBuf,
    /// Path to the detached signature bundle (manifest.sig.json).
    pub signature_path: Option<camino::Utf8PathBuf>,
    /// Path to the provenance metadata (provenance.json).
    pub provenance_path: camino::Utf8PathBuf,
}

pub fn build_mount_contract_from_def(
    definition: &definition::ImageDefinition,
) -> Result<pico_core::mount::MountContract, error::ImageError> {
    use pico_core::mount::{MountClass, MountEntry};

    let mounts = definition
        .mounts
        .iter()
        .map(|m| {
            let class = match m.class.as_str() {
                "workspace" => MountClass::Workspace,
                "runtime_tmp" => MountClass::RuntimeTmp,
                "secret" => MountClass::Secret,
                "guest_logs" => MountClass::GuestLogs,
                other => {
                    return Err(error::ImageError::MountLayoutError(format!(
                        "unknown mount class: '{}'",
                        other
                    )));
                }
            };
            Ok(MountEntry {
                path: m.path.clone(),
                class,
                writable: m.writable,
                lifecycle: m.lifecycle.clone(),
            })
        })
        .collect::<Result<Vec<_>, error::ImageError>>()?;

    let contract = pico_core::mount::MountContract {
        version: "1.0".into(),
        mounts,
    };

    contract
        .is_valid()
        .map_err(error::ImageError::MountLayoutError)?;

    Ok(contract)
}
