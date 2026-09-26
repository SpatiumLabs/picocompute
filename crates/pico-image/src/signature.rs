//! Image manifest signing and verification for PicoCompute guest images.
//!
//! Provides Ed25519-based detached signatures for PicoCompute guest image
//! manifests, with key management and verification. Signatures are
//! stored as JSON bundles alongside the manifest, enabling offline
//! verification by hosts before image use.
//!
//! ## Key management
//!
//! Signing keys are loaded from:
//! 1. The `PICO_SIGNING_KEY` environment variable (base64-encoded 32-byte seed)
//! 2. A key file at a configured path (base64-encoded 32-byte seed)
//!
//! Verification keys are the Ed25519 public key (base64-encoded).
//!
//! ## Production recommendations
//!
//! - Store the signing key in a secrets manager (e.g., Vault, AWS KMS,
//!   GCP Secret Manager), not in files or env vars on long-lived hosts.
//! - Rotate keys on a regular schedule. The signature bundle embeds the
//!   public key, so verifiers can handle key rotation transparently.
//! - Restrict key file permissions to `0600` when using file-based keys.
//! - Never log the signing key seed or private key bytes. The tracing
//!   instrumentation in this module only logs file paths, never key material.
//! - Signing is **optional**: if no key is configured (no env var, no file),
//!   the build proceeds without a signature. Hosts should reject unsigned
//!   images in production mode via [`ImageError::UnsignedImageRejected`].
//!
//! ## Key material safety
//!
//! Error messages and log output never include raw key bytes. Errors report
//! only key lengths (e.g., "must be 32 bytes, got 16") and I/O failure reasons
//! (e.g., "permission denied"), not the key content itself.

use crate::error::ImageError;
use crate::types::SignatureBundle;
use crate::util::{compute_sha256_digest, hex_encode};
use camino::Utf8Path;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use tracing::info;

/// The signing algorithm identifier used in signature bundles.
pub const SIGNING_ALGORITHM: &str = "ed25519";

/// Signature bundle schema version.
pub const SIGNATURE_SCHEMA_VERSION: &str = "1.0";

/// Generate a new Ed25519 signing key and return the base64-encoded seed.
///
/// This is a utility for key generation; production keys should be
/// stored securely (e.g., in a KMS or hardware token).
pub fn generate_signing_key() -> (SigningKey, VerifyingKey) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("failed to generate random seed");
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Load a signing key from a base64-encoded seed string.
///
/// The seed must be exactly 32 bytes (64 characters in base64).
///
/// # Errors
///
/// Returns [`ImageError::KeyFormatError`] if the base64 is invalid or the
/// decoded seed is not exactly 32 bytes.
pub fn load_signing_key_from_base64(encoded: &str) -> Result<SigningKey, ImageError> {
    let seed = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .map_err(|e| ImageError::KeyFormatError(format!("failed to decode signing key: {}", e)))?;

    if seed.len() != 32 {
        return Err(ImageError::KeyFormatError(format!(
            "signing key seed must be 32 bytes, got {}",
            seed.len()
        )));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Load a signing key from a file path.
///
/// The file should contain a base64-encoded 32-byte seed.
///
/// # Errors
///
/// Returns [`ImageError::SigningKeyUnavailable`] if the file cannot be
/// read. Returns [`ImageError::KeyFormatError`] if the content is not a
/// valid base64-encoded 32-byte seed.
pub fn load_signing_key_from_path(path: &Utf8Path) -> Result<SigningKey, ImageError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        ImageError::SigningKeyUnavailable(format!("failed to read key file {}: {}", path, e))
    })?;

    load_signing_key_from_base64(content.trim())
}

/// Load a signing key from the environment.
///
/// Checks `PICO_SIGNING_KEY` environment variable.
///
/// # Errors
///
/// Returns [`ImageError::SigningKeyUnavailable`] if the environment
/// variable is not set. Returns [`ImageError::KeyFormatError`] if the
/// value is not a valid base64-encoded 32-byte seed.
pub fn load_signing_key_from_env() -> Result<SigningKey, ImageError> {
    let encoded = std::env::var("PICO_SIGNING_KEY").map_err(|_| {
        ImageError::SigningKeyUnavailable("PICO_SIGNING_KEY environment variable not set".into())
    })?;

    load_signing_key_from_base64(&encoded)
}

/// Encode a verifying key (public key) to base64.
pub fn encode_verifying_key(key: &VerifyingKey) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

/// Decode a verifying key from base64.
///
/// # Errors
///
/// Returns [`ImageError::KeyFormatError`] if the base64 is invalid, the
/// decoded bytes are not 32 bytes, or the bytes do not form a valid
/// Ed25519 public key.
pub fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, ImageError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .map_err(|e| {
            ImageError::KeyFormatError(format!("failed to decode verifying key: {}", e))
        })?;

    let key_bytes: &[u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ImageError::KeyFormatError("verifying key must be 32 bytes".into()))?;

    VerifyingKey::from_bytes(key_bytes)
        .map_err(|e| ImageError::KeyFormatError(format!("invalid verifying key: {}", e)))
}

/// Sign a manifest file and write the signature bundle next to it.
///
/// The manifest content is hashed with SHA-256, and the hash is signed.
/// The resulting signature bundle includes the manifest digest, algorithm,
/// public key, and signature bytes.
///
/// # Errors
///
/// Returns [`ImageError::IoError`] if the manifest cannot be read or the
/// signature cannot be written. Returns [`ImageError::ParseError`] if
/// serialization of the signature bundle fails.
pub fn sign_manifest(
    manifest_path: &Utf8Path,
    signing_key: &SigningKey,
    signer_identity: &str,
    image_id: &str,
    output_dir: &Utf8Path,
) -> Result<camino::Utf8PathBuf, ImageError> {
    info!(%manifest_path, "signing manifest");

    let manifest_content = std::fs::read(manifest_path).map_err(ImageError::IoError)?;

    let mut hasher = Sha256::new();
    hasher.update(&manifest_content);
    let manifest_hash = hasher.finalize();

    let manifest_digest = format!("sha256:{}", hex_encode(&manifest_hash));

    let signature = signing_key.sign(&manifest_hash);
    let verifying_key = signing_key.verifying_key();

    let signature_bundle = SignatureBundle {
        schema_version: SIGNATURE_SCHEMA_VERSION.into(),
        image_id: image_id.into(),
        manifest_digest,
        algorithm: SIGNING_ALGORITHM.into(),
        public_key: encode_verifying_key(&verifying_key),
        signature: {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        },
        signer_identity: signer_identity.into(),
        signed_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    };

    let sig_path = output_dir.join("manifest.sig.json");
    let json = serde_json::to_string_pretty(&signature_bundle)
        .map_err(|e| ImageError::ParseError(format!("failed to serialize signature: {}", e)))?;

    std::fs::write(&sig_path, &json).map_err(ImageError::IoError)?;

    info!(?sig_path, "manifest signed");

    Ok(sig_path)
}

/// Verify a manifest signature against the manifest content.
///
/// Loads the manifest file and its detached signature bundle, verifies
/// the Ed25519 signature against the SHA-256 hash of the manifest content.
///
/// Returns the validated [`SignatureBundle`] on successful verification.
///
/// # Errors
///
/// Returns [`ImageError::SignatureVerificationFailed`] if the manifest or
/// signature cannot be read, the bundle is malformed, the schema or
/// algorithm is unsupported, the manifest digest doesn't match, or the
/// Ed25519 signature is invalid.
pub fn verify_manifest(
    manifest_path: &Utf8Path,
    signature_path: &Utf8Path,
) -> Result<SignatureBundle, ImageError> {
    let manifest_content = std::fs::read(manifest_path).map_err(|e| {
        ImageError::SignatureVerificationFailed(format!("failed to read manifest: {e}"))
    })?;
    verify_manifest_bytes(&manifest_content, signature_path)
}

/// Verify a manifest signature with an explicit verifying key.
///
/// This variant accepts the verifying key directly rather than reading it
/// from the signature bundle, allowing key pinning.
///
/// Returns the validated [`SignatureBundle`] on successful verification.
///
/// # Errors
///
/// Returns [`ImageError::SignatureVerificationFailed`] for the same reasons
/// as [`verify_manifest`].
pub fn verify_manifest_with_key(
    manifest_path: &Utf8Path,
    signature_path: &Utf8Path,
    verifying_key: &VerifyingKey,
) -> Result<SignatureBundle, ImageError> {
    let manifest_content = std::fs::read(manifest_path).map_err(|e| {
        ImageError::SignatureVerificationFailed(format!("failed to read manifest: {e}"))
    })?;
    verify_manifest_bytes_with_key(&manifest_content, signature_path, verifying_key)
}

/// Verify already-read manifest bytes against a detached signature bundle.
///
/// This avoids re-reading the manifest when the caller already holds the
/// bytes (e.g. [`crate::host_verify::verify_for_host`], which parses the
/// manifest once). Returns the validated bundle.
pub(crate) fn verify_manifest_bytes(
    manifest_content: &[u8],
    signature_path: &Utf8Path,
) -> Result<SignatureBundle, ImageError> {
    let bundle = load_bundle(signature_path)?;
    validate_bundle(&bundle, manifest_content)?;
    let verifying_key = decode_verifying_key(&bundle.public_key)?;
    verify_signature(manifest_content, &bundle, &verifying_key)?;
    Ok(bundle)
}

/// Pinned-key variant of [`verify_manifest_bytes`].
pub(crate) fn verify_manifest_bytes_with_key(
    manifest_content: &[u8],
    signature_path: &Utf8Path,
    verifying_key: &VerifyingKey,
) -> Result<SignatureBundle, ImageError> {
    let bundle = load_bundle(signature_path)?;
    validate_bundle(&bundle, manifest_content)?;
    verify_signature(manifest_content, &bundle, verifying_key)?;
    Ok(bundle)
}

/// Load a signature bundle from disk without validating it.
fn load_bundle(signature_path: &Utf8Path) -> Result<SignatureBundle, ImageError> {
    let sig_json = std::fs::read_to_string(signature_path).map_err(|e| {
        ImageError::SignatureVerificationFailed(format!("failed to read signature: {e}"))
    })?;

    serde_json::from_str(&sig_json).map_err(|e| {
        ImageError::SignatureVerificationFailed(format!("invalid signature bundle: {e}"))
    })
}

/// Validate schema/algorithm/digest of a bundle against manifest bytes.
fn validate_bundle(bundle: &SignatureBundle, manifest_content: &[u8]) -> Result<(), ImageError> {
    if bundle.schema_version != SIGNATURE_SCHEMA_VERSION {
        return Err(ImageError::SignatureVerificationFailed(format!(
            "unsupported signature schema version: {}",
            bundle.schema_version
        )));
    }

    if bundle.algorithm != SIGNING_ALGORITHM {
        return Err(ImageError::SignatureVerificationFailed(format!(
            "unsupported signing algorithm: {}",
            bundle.algorithm
        )));
    }

    let computed_digest = compute_sha256_digest(manifest_content);
    if computed_digest != bundle.manifest_digest {
        return Err(ImageError::SignatureVerificationFailed(format!(
            "manifest digest mismatch: expected {}, got {}",
            bundle.manifest_digest, computed_digest
        )));
    }

    Ok(())
}

/// Perform the Ed25519 signature verification.
fn verify_signature(
    manifest_content: &[u8],
    bundle: &SignatureBundle,
    verifying_key: &VerifyingKey,
) -> Result<(), ImageError> {
    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &bundle.signature,
    )
    .map_err(|e| {
        ImageError::SignatureVerificationFailed(format!("failed to decode signature: {}", e))
    })?;

    let sig_array: &[u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        ImageError::SignatureVerificationFailed("signature must be 64 bytes".into())
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(sig_array);

    let mut hasher = Sha256::new();
    hasher.update(manifest_content);
    let manifest_hash = hasher.finalize();

    verifying_key
        .verify(&manifest_hash, &signature)
        .map_err(|e| {
            ImageError::SignatureVerificationFailed(format!(
                "ed25519 signature verification failed: {}",
                e
            ))
        })?;

    Ok(())
}

/// Check whether a signature file exists for a given manifest.
pub fn has_signature(manifest_path: &Utf8Path, output_dir: &Utf8Path) -> bool {
    let sig_path = output_dir.join("manifest.sig.json");
    sig_path.exists() && manifest_path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_and_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_signing_key();

        let dir = tempfile::TempDir::new().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let manifest_content = r#"{"schema_version":"1.0","image_id":"test"}"#;
        std::fs::write(&manifest_path, manifest_content).unwrap();

        let manifest_utf8 = camino::Utf8PathBuf::from_path_buf(manifest_path.clone()).unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sig_path = sign_manifest(
            &manifest_utf8,
            &signing_key,
            "test-builder",
            "test-image",
            &output_dir,
        )
        .unwrap();

        assert!(sig_path.exists());

        verify_manifest(&manifest_utf8, &sig_path).unwrap();
        verify_manifest_with_key(&manifest_utf8, &sig_path, &verifying_key).unwrap();
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let (signing_key, _verifying_key) = generate_signing_key();

        let dir = tempfile::TempDir::new().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let original = r#"{"schema_version":"1.0","image_id":"test"}"#;
        std::fs::write(&manifest_path, original).unwrap();

        let manifest_utf8 = camino::Utf8PathBuf::from_path_buf(manifest_path.clone()).unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sig_path = sign_manifest(
            &manifest_utf8,
            &signing_key,
            "test-builder",
            "test-image",
            &output_dir,
        )
        .unwrap();

        let tampered = r#"{"schema_version":"1.0","image_id":"evil"}"#;
        std::fs::write(&manifest_path, tampered).unwrap();

        let result = verify_manifest(&manifest_utf8, &sig_path);
        assert!(
            result.is_err(),
            "tampered manifest should fail verification"
        );
    }

    #[test]
    fn wrong_signing_key_fails_verification() {
        let (signing_key, _) = generate_signing_key();
        let (wrong_signing_key, _) = generate_signing_key();

        let dir = tempfile::TempDir::new().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let content = r#"{"schema_version":"1.0","image_id":"test"}"#;
        std::fs::write(&manifest_path, content).unwrap();

        let manifest_utf8 = camino::Utf8PathBuf::from_path_buf(manifest_path.clone()).unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sig_path = sign_manifest(
            &manifest_utf8,
            &signing_key,
            "builder-a",
            "test-image",
            &output_dir,
        )
        .unwrap();

        let wrong_verifier = wrong_signing_key.verifying_key();
        let result = verify_manifest_with_key(&manifest_utf8, &sig_path, &wrong_verifier);
        assert!(result.is_err(), "verification with wrong key should fail");
    }

    #[test]
    fn key_serialization_roundtrip() {
        let (signing_key, verifying_key) = generate_signing_key();

        let seed = signing_key.to_bytes();
        let encoded = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(seed)
        };

        let loaded_key = load_signing_key_from_base64(&encoded).unwrap();
        assert_eq!(loaded_key.to_bytes(), signing_key.to_bytes());

        let vk_encoded = encode_verifying_key(&verifying_key);

        let loaded_vk = decode_verifying_key(&vk_encoded).unwrap();
        assert_eq!(loaded_vk, verifying_key);
    }

    #[test]
    fn load_signing_key_from_env_var() {
        let (signing_key, _) = generate_signing_key();
        let seed = signing_key.to_bytes();
        let encoded = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(seed)
        };

        unsafe {
            std::env::set_var("PICO_SIGNING_KEY", &encoded);
        }
        let loaded = load_signing_key_from_env().unwrap();
        assert_eq!(loaded.to_bytes(), signing_key.to_bytes());
        unsafe {
            std::env::remove_var("PICO_SIGNING_KEY");
        }
    }

    #[test]
    fn signature_bundle_contains_expected_fields() {
        let (signing_key, _) = generate_signing_key();

        let dir = tempfile::TempDir::new().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let content = r#"{"schema_version":"1.0","image_id":"test"}"#;
        std::fs::write(&manifest_path, content).unwrap();

        let manifest_utf8 = camino::Utf8PathBuf::from_path_buf(manifest_path).unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sig_path = sign_manifest(
            &manifest_utf8,
            &signing_key,
            "ci-builder-01",
            "test-image",
            &output_dir,
        )
        .unwrap();

        let sig_json = std::fs::read_to_string(&sig_path).unwrap();
        let bundle: SignatureBundle = serde_json::from_str(&sig_json).unwrap();

        assert_eq!(bundle.schema_version, "1.0");
        assert_eq!(bundle.image_id, "test-image");
        assert_eq!(bundle.algorithm, "ed25519");
        assert_eq!(bundle.signer_identity, "ci-builder-01");
        assert!(!bundle.signature.is_empty());
        assert!(!bundle.public_key.is_empty());
        assert!(bundle.manifest_digest.starts_with("sha256:"));
        assert!(bundle.signed_at > 0);
    }

    #[test]
    fn tampered_signature_bundle_fails() {
        let (signing_key, _) = generate_signing_key();

        let dir = tempfile::TempDir::new().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let content = r#"{"schema_version":"1.0","image_id":"test"}"#;
        std::fs::write(&manifest_path, content).unwrap();

        let manifest_utf8 = camino::Utf8PathBuf::from_path_buf(manifest_path).unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let sig_path = sign_manifest(
            &manifest_utf8,
            &signing_key,
            "builder",
            "test-image",
            &output_dir,
        )
        .unwrap();

        let sig_json = std::fs::read_to_string(&sig_path).unwrap();
        let tampered_sig = sig_json.replace("sha256:", "sha256:deadbeef");
        std::fs::write(&sig_path, tampered_sig).unwrap();

        let result = verify_manifest(&manifest_utf8, &sig_path);
        assert!(
            result.is_err(),
            "tampered signature bundle should fail verification"
        );
    }

    #[test]
    fn signing_key_invalid_base64_fails() {
        let result = load_signing_key_from_base64("!!!not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn signing_key_wrong_length_fails() {
        let result = load_signing_key_from_base64("dG9vLXNob3J0"); // "too-short" in base64
        assert!(result.is_err());
    }

    #[test]
    fn has_signature_detects_presence() {
        let dir = tempfile::TempDir::new().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        std::fs::write(&manifest_path, "{}").unwrap();

        let manifest_utf8 = camino::Utf8PathBuf::from_path_buf(manifest_path).unwrap();
        let output_dir = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        assert!(!has_signature(&manifest_utf8, &output_dir));

        std::fs::write(dir.path().join("manifest.sig.json"), "{}").unwrap();
        assert!(has_signature(&manifest_utf8, &output_dir));
    }
}
