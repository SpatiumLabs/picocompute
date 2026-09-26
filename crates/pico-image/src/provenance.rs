//! Provenance metadata generation for PicoCompute guest images.
//!
//! Produces in-toto / SLSA-style provenance attestations documenting
//! the full build context: who built the image, from what source, with
//! what inputs, on what platform, and under what policy profile.

use crate::definition::ImageDefinition;
use crate::error::ImageError;
use crate::lock::PackageLock;
use crate::types::*;
use crate::util::{compute_sha256_digest, get_git_sha};
use camino::Utf8Path;
use std::collections::BTreeMap;
use tracing::info;

/// Provenance schema version.
pub const PROVENANCE_SCHEMA_VERSION: &str = "1.0";

/// Generate provenance metadata for an image build.
///
/// Captures builder identity, source revision, build input digests,
/// timestamp, platform, and policy profile.
///
/// # Errors
///
/// Returns [`ImageError::ProvenanceGenerationFailed`] if serialization of
/// the definition or lock file fails, or if the provenance JSON cannot be
/// written to disk.
pub fn generate_provenance(
    definition: &ImageDefinition,
    lock: &PackageLock,
    manifest_digest: &str,
    output_dir: &Utf8Path,
) -> Result<camino::Utf8PathBuf, ImageError> {
    info!("generating build provenance");

    let hostname = get_hostname();

    let builder_type = detect_builder_type();

    let mut build_inputs: Vec<ProvenanceInput> = Vec::new();

    let def_json = serde_json::to_string(definition).map_err(|e| {
        ImageError::ProvenanceGenerationFailed(format!("failed to serialize definition: {}", e))
    })?;
    build_inputs.push(ProvenanceInput {
        name: "image-definition".into(),
        digest: compute_sha256_digest(def_json.as_bytes()),
        uri: None,
    });

    let lock_toml = toml::to_string(lock).map_err(|e| {
        ImageError::ProvenanceGenerationFailed(format!("failed to serialize lock: {}", e))
    })?;
    build_inputs.push(ProvenanceInput {
        name: "package-lock".into(),
        digest: compute_sha256_digest(lock_toml.as_bytes()),
        uri: None,
    });

    build_inputs.push(ProvenanceInput {
        name: "base-rootfs".into(),
        digest: lock.base.digest.clone(),
        uri: Some(lock.base.url.clone()),
    });

    build_inputs.push(ProvenanceInput {
        name: "guest-agent".into(),
        digest: lock.guest_agent.digest.clone(),
        uri: None,
    });

    build_inputs.push(ProvenanceInput {
        name: "manifest".into(),
        digest: manifest_digest.to_string(),
        uri: None,
    });

    let policy_profile = definition
        .kernel
        .as_ref()
        .map(|ks| ks.profile_id())
        .unwrap_or_else(|| "default-v1".into());

    let source_revision = get_git_sha();
    let source_dirty = is_git_dirty();

    let provenance = ProvenanceMetadata {
        schema_version: PROVENANCE_SCHEMA_VERSION.into(),
        image_id: definition.image.id.clone(),
        builder_identity: BuilderIdentity {
            hostname,
            builder_type,
            builder_version: env!("CARGO_PKG_VERSION").into(),
        },
        source: ProvenanceSource {
            repository: get_git_remote(),
            revision: source_revision,
            dirty: source_dirty,
        },
        build_inputs,
        build_epoch: definition.image.source_date_epoch,
        platform: ProvenancePlatform {
            os: "linux".into(),
            architecture: std::env::consts::ARCH.into(),
        },
        policy_profile,
        parameters: BTreeMap::new(),
    };

    let prov_path = output_dir.join("provenance.json");
    let json = serde_json::to_string_pretty(&provenance).map_err(|e| {
        ImageError::ProvenanceGenerationFailed(format!("failed to serialize provenance: {}", e))
    })?;

    std::fs::write(&prov_path, &json).map_err(|e| {
        ImageError::ProvenanceGenerationFailed(format!("failed to write provenance: {}", e))
    })?;

    info!(?prov_path, "provenance generated");

    Ok(prov_path)
}

/// Get the hostname of the builder.
fn get_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into())
}

/// Detect the builder type from environment variables.
fn detect_builder_type() -> String {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        "github-actions".into()
    } else if std::env::var("GITLAB_CI").is_ok() {
        "gitlab-ci".into()
    } else if std::env::var("JENKINS_HOME").is_ok() {
        "jenkins".into()
    } else if let Ok(builder_type) = std::env::var("PICO_BUILDER_TYPE") {
        builder_type
    } else {
        "pico-cli".into()
    }
}

/// Get the git remote URL.
fn get_git_remote() -> Option<String> {
    std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
}

/// Check if the git working tree is dirty (single `git status` call).
fn is_git_dirty() -> bool {
    std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false)
}

/// Validate provenance metadata against a definition.
///
/// Checks that provenance image_id matches, build inputs cover required
/// artifacts, and platform is consistent.
///
/// # Errors
///
/// Returns [`ImageError::ProvenanceValidationFailed`] if the image_id
/// doesn't match, the schema version is unsupported, any required build
/// input is missing, or the platform OS is not `linux`.
pub fn validate_provenance(
    provenance: &ProvenanceMetadata,
    definition: &ImageDefinition,
) -> Result<(), ImageError> {
    if provenance.image_id != definition.image.id {
        return Err(ImageError::ProvenanceValidationFailed(format!(
            "provenance image_id '{}' does not match definition '{}'",
            provenance.image_id, definition.image.id
        )));
    }

    if provenance.schema_version != PROVENANCE_SCHEMA_VERSION {
        return Err(ImageError::ProvenanceValidationFailed(format!(
            "unsupported provenance schema: {}",
            provenance.schema_version
        )));
    }

    let required_inputs = [
        "image-definition",
        "package-lock",
        "base-rootfs",
        "guest-agent",
        "manifest",
    ];

    for required in &required_inputs {
        let found = provenance
            .build_inputs
            .iter()
            .any(|input| input.name == *required);
        if !found {
            return Err(ImageError::ProvenanceValidationFailed(format!(
                "provenance missing required build input: '{}'",
                required
            )));
        }
    }

    if provenance.platform.os != "linux" {
        return Err(ImageError::ProvenanceValidationFailed(format!(
            "provenance platform.os must be 'linux', got '{}'",
            provenance.platform.os
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definition::{BaseSource, FilesystemConfig, GuestAgentSource, ImageInfo, SourceRef};
    use crate::lock::{LockArtifact, LockBase, LockMetadata, LockedPackage};

    fn sample_definition() -> ImageDefinition {
        ImageDefinition {
            image: ImageInfo {
                id: "test-prov-image".into(),
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
            mounts: vec![],
            kernel: None,
        }
    }

    fn sample_lock() -> PackageLock {
        PackageLock {
            metadata: LockMetadata {
                image_id: "test-prov-image".into(),
                version: "0.1.0".into(),
                source_date_epoch: 1781170000,
            },
            base: LockBase {
                url: "https://example.com/rootfs.tar.gz".into(),
                digest: "sha256:abc123".into(),
            },
            guest_agent: LockArtifact {
                digest: "sha256:agent123".into(),
            },
            packages: vec![LockedPackage {
                name: "openssh-server".into(),
                version: "9.9_p2-r0".into(),
                digest: "sha256:pkg123".into(),
            }],
        }
    }

    #[test]
    fn provenance_generation_contains_expected_fields() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let prov_path =
            generate_provenance(&def, &lock, "sha256:manifest123", &output_dir).unwrap();
        assert!(prov_path.exists());

        let content = std::fs::read_to_string(&prov_path).unwrap();
        let prov: ProvenanceMetadata = serde_json::from_str(&content).unwrap();

        assert_eq!(prov.schema_version, PROVENANCE_SCHEMA_VERSION);
        assert_eq!(prov.image_id, "test-prov-image");
        assert!(!prov.builder_identity.hostname.is_empty());
        assert!(!prov.builder_identity.builder_type.is_empty());
        assert!(!prov.source.revision.is_empty());
        assert_eq!(prov.build_epoch, 1781170000);
        assert_eq!(prov.platform.os, "linux");
        assert!(!prov.platform.architecture.is_empty());
        assert_eq!(prov.policy_profile, "default-v1");
    }

    #[test]
    fn provenance_includes_all_required_inputs() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let prov_path =
            generate_provenance(&def, &lock, "sha256:manifest123", &output_dir).unwrap();
        let content = std::fs::read_to_string(&prov_path).unwrap();
        let prov: ProvenanceMetadata = serde_json::from_str(&content).unwrap();

        let input_names: Vec<&str> = prov.build_inputs.iter().map(|i| i.name.as_str()).collect();

        assert!(input_names.contains(&"image-definition"));
        assert!(input_names.contains(&"package-lock"));
        assert!(input_names.contains(&"base-rootfs"));
        assert!(input_names.contains(&"guest-agent"));
        assert!(input_names.contains(&"manifest"));
    }

    #[test]
    fn provenance_validates_correctly() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let prov_path =
            generate_provenance(&def, &lock, "sha256:manifest123", &output_dir).unwrap();
        let content = std::fs::read_to_string(&prov_path).unwrap();
        let prov: ProvenanceMetadata = serde_json::from_str(&content).unwrap();

        assert!(validate_provenance(&prov, &def).is_ok());
    }

    #[test]
    fn provenance_validation_fails_on_mismatched_image_id() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let prov_path =
            generate_provenance(&def, &lock, "sha256:manifest123", &output_dir).unwrap();
        let content = std::fs::read_to_string(&prov_path).unwrap();
        let mut prov: ProvenanceMetadata = serde_json::from_str(&content).unwrap();

        prov.image_id = "different-image".into();
        let result = validate_provenance(&prov, &def);
        assert!(result.is_err());
    }

    #[test]
    fn provenance_validation_fails_on_missing_input() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let prov_path =
            generate_provenance(&def, &lock, "sha256:manifest123", &output_dir).unwrap();
        let content = std::fs::read_to_string(&prov_path).unwrap();
        let mut prov: ProvenanceMetadata = serde_json::from_str(&content).unwrap();

        prov.build_inputs.retain(|i| i.name != "manifest");
        let result = validate_provenance(&prov, &def);
        assert!(result.is_err());
    }

    #[test]
    fn provenance_with_kernel_profile() {
        use crate::definition::KernelSource;

        let mut def = sample_definition();
        def.kernel = Some(KernelSource {
            backend: "firecracker".into(),
            variant: "production".into(),
            version: "pico-linux-6.18".into(),
            cmdline: None,
            vmlinux_path: None,
            initrd_path: None,
            firmware_path: None,
            config_profile: Some("firecracker-aarch64-v1".into()),
        });

        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let prov_path =
            generate_provenance(&def, &lock, "sha256:manifest123", &output_dir).unwrap();
        let content = std::fs::read_to_string(&prov_path).unwrap();
        let prov: ProvenanceMetadata = serde_json::from_str(&content).unwrap();

        assert_eq!(prov.policy_profile, "firecracker-aarch64-v1");
    }

    #[test]
    fn build_inputs_have_digests() {
        let def = sample_definition();
        let lock = sample_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let prov_path =
            generate_provenance(&def, &lock, "sha256:manifest123", &output_dir).unwrap();
        let content = std::fs::read_to_string(&prov_path).unwrap();
        let prov: ProvenanceMetadata = serde_json::from_str(&content).unwrap();

        for input in &prov.build_inputs {
            assert!(
                !input.digest.is_empty(),
                "build input '{}' has empty digest",
                input.name
            );
            assert!(
                input.digest.starts_with("sha256:"),
                "build input '{}' digest does not have sha256: prefix",
                input.name
            );
        }
    }
}
