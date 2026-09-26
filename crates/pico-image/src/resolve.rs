use crate::definition::ImageDefinition;
use crate::error::ImageError;
use crate::lock::{LockArtifact, LockBase, LockMetadata, LockedPackage, PackageLock};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use tracing::info;

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(s, "{byte:02x}").unwrap();
    }
    s
}

pub fn create_lock(
    definition: &ImageDefinition,
    output: &camino::Utf8Path,
) -> Result<PackageLock, ImageError> {
    info!("resolving lock file from image definition");

    let base_digest = verify_or_compute_base_digest(definition)?;

    let guest_agent_digest = compute_guest_agent_digest(definition)?;

    let packages = resolve_packages(definition)?;

    let lock = PackageLock {
        metadata: LockMetadata {
            image_id: definition.image.id.clone(),
            version: definition.image.version.clone(),
            source_date_epoch: definition.image.source_date_epoch,
        },
        base: LockBase {
            url: definition.base.source.url.clone(),
            digest: base_digest,
        },
        guest_agent: LockArtifact {
            digest: guest_agent_digest,
        },
        packages,
    };

    lock.save(output)?;
    info!(?output, "lock file written");

    Ok(lock)
}

fn verify_or_compute_base_digest(definition: &ImageDefinition) -> Result<String, ImageError> {
    let declared_digest = &definition.base.source.digest;
    let digest_algorithm = declared_digest
        .split(':')
        .next()
        .ok_or_else(|| ImageError::ParseError("invalid digest format".into()))?;

    if digest_algorithm != "sha256" {
        return Ok(declared_digest.clone());
    }

    info!(%declared_digest, "base rootfs digest declared; trust on verify");

    Ok(declared_digest.clone())
}

fn compute_guest_agent_digest(definition: &ImageDefinition) -> Result<String, ImageError> {
    match &definition.guest_agent {
        crate::definition::GuestAgentSource::Workspace { .. } => {
            info!("guest-agent built from workspace; digest computed at build time");
            Ok("sha256:unresolved".into())
        }
        crate::definition::GuestAgentSource::Prebuilt { path, digest, .. } => {
            let mut file = fs::File::open(path).map_err(|e| {
                ImageError::ParseError(format!(
                    "failed to open prebuilt guest agent at {}: {}",
                    path, e
                ))
            })?;
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let actual = format!("sha256:{}", hex_encode(&hasher.finalize()));
            if actual != *digest {
                return Err(ImageError::DigestMismatch {
                    artifact: "guest_agent".into(),
                    expected: digest.clone(),
                    actual,
                });
            }
            Ok(actual)
        }
    }
}

fn resolve_packages(definition: &ImageDefinition) -> Result<Vec<LockedPackage>, ImageError> {
    if definition.packages.is_empty() {
        return Ok(Vec::new());
    }

    info!(
        package_count = definition.packages.len(),
        "declared packages (versions pinned in definition)"
    );

    Ok(definition
        .packages
        .iter()
        .map(|(name, version)| LockedPackage {
            name: name.clone(),
            version: version.clone(),
            digest: String::new(),
        })
        .collect())
}

pub fn fetch_base_rootfs(
    lock: &PackageLock,
    work_dir: &camino::Utf8Path,
) -> Result<camino::Utf8PathBuf, ImageError> {
    let base_path = work_dir.join("alpine-minirootfs.tar.gz");

    if base_path.exists() {
        info!(
            ?base_path,
            "base rootfs already downloaded, verifying digest"
        );

        let mut file = fs::File::open(&base_path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual_digest = format!("sha256:{}", hex_encode(&hasher.finalize()));

        if lock.base.digest.strip_prefix("sha256:").is_some() && actual_digest != lock.base.digest {
            return Err(ImageError::DigestMismatch {
                artifact: "base_rootfs".into(),
                expected: lock.base.digest.clone(),
                actual: actual_digest,
            });
        }

        return Ok(base_path);
    }

    info!(url = %lock.base.url, "downloading base rootfs");
    let response = ureq::get(&lock.base.url)
        .call()
        .map_err(|e| ImageError::ParseError(format!("failed to download base rootfs: {}", e)))?;

    let mut reader = response.into_body().into_reader();
    let mut file = fs::File::create(&base_path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])?;
    }

    let actual_digest = format!("sha256:{}", hex_encode(&hasher.finalize()));
    if actual_digest != lock.base.digest {
        return Err(ImageError::DigestMismatch {
            artifact: "base_rootfs".into(),
            expected: lock.base.digest.clone(),
            actual: actual_digest,
        });
    }

    info!(?base_path, %actual_digest, "base rootfs downloaded and verified");

    Ok(base_path)
}

use std::io::Write;
