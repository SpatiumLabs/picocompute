pub use pico_core::mount::{MountClass, MountContract, MountEntry, PathLifecycle, SnapshotInfo};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PicoComputeGuestManifest {
    pub schema_version: String,
    pub image_id: String,
    pub release: ReleaseInfo,
    pub platform: PlatformInfo,
    pub artifacts: Artifacts,
    pub protocol: ProtocolInfo,
    pub compatibility: CompatibilityInfo,
    pub mount_contract: MountContract,
    pub snapshot: SnapshotInfo,
    /// Independently versioned base/workspace/toolkit composition.
    ///
    /// `None` preserves backward compatibility with monolithic manifests.
    /// When present, the manifest signature covers the composition and the
    /// host verifies it via `layers::verify_layers_for_host` before boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<crate::layers::EnvironmentComposition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub version: String,
    pub source_revision: String,
    pub build_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifacts {
    pub rootfs: ArtifactDescriptor,
    pub kernel: Option<ArtifactDescriptor>,
    pub initrd: Option<ArtifactDescriptor>,
    pub firmware: Option<ArtifactDescriptor>,
    pub guest_agent: ArtifactDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDescriptor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolInfo {
    pub bootstrap: String,
    pub supported: Vec<ProtocolVersionRange>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersionRange {
    pub major: u32,
    pub min_minor: u32,
    pub max_minor: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityInfo {
    pub profile_id: String,
    pub backends: Vec<BackendCompatibility>,
    pub required_cpu_features: Vec<String>,
    pub required_devices: Vec<String>,
    pub required_host_features: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_cmdline: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCompatibility {
    pub family: String,
    pub runtime_version: String,
    pub architecture: String,
}

/// A CycloneDX-compatible Software Bill of Materials for a PicoCompute image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxSbom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: i32,
    pub metadata: SbomMetadata,
    pub components: Vec<SbomComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomMetadata {
    pub timestamp: String,
    pub tools: Vec<SbomTool>,
    pub component: SbomRootComponent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomTool {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomRootComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<SbomHash>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<SbomProperty>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomProperty {
    pub name: String,
    pub value: String,
}

/// A detached signature bundle for a PicoCompute image manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBundle {
    /// PicoCompute signature schema version.
    pub schema_version: String,

    /// The image ID this signature applies to.
    pub image_id: String,

    /// The digest of the manifest that was signed.
    pub manifest_digest: String,

    /// The signing algorithm used.
    pub algorithm: String,

    /// The raw public key (base64-encoded ed25519 public key).
    pub public_key: String,

    /// The signature bytes (base64-encoded).
    pub signature: String,

    /// The identity that produced this signature.
    pub signer_identity: String,

    /// UTC timestamp of signature creation (epoch seconds).
    pub signed_at: i64,
}

/// In-toto / SLSA-style provenance metadata for a PicoCompute image build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceMetadata {
    /// Provenance schema version.
    pub schema_version: String,

    /// The image ID this provenance applies to.
    pub image_id: String,

    /// Builder identity (hostname, CI runner, or manual builder).
    pub builder_identity: BuilderIdentity,

    /// Source control information.
    pub source: ProvenanceSource,

    /// Build inputs and their digests.
    pub build_inputs: Vec<ProvenanceInput>,

    /// Build timestamp (epoch seconds).
    pub build_epoch: i64,

    /// Target platform.
    pub platform: ProvenancePlatform,

    /// Policy profile in effect during build.
    pub policy_profile: String,

    /// Additional build parameters.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderIdentity {
    /// Hostname of the builder.
    pub hostname: String,

    /// Builder type (e.g., "pico-cli", "github-actions", "manual").
    pub builder_type: String,

    /// Builder version.
    pub builder_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceSource {
    /// Git repository URL (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,

    /// Git commit SHA.
    pub revision: String,

    /// Whether the working tree was dirty.
    #[serde(default)]
    pub dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceInput {
    /// Human-readable name of the input (e.g., "image-definition").
    pub name: String,

    /// SHA-256 digest of the input content.
    pub digest: String,

    /// URI or path the input was loaded from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenancePlatform {
    pub os: String,
    pub architecture: String,
}
