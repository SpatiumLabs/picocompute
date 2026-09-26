//! Guest-side secrets injection handler.
//!
//! Receives credentials from the host, mounts a private tmpfs at
//! `/run/pico/secrets`, writes credential files, and sends
//! back the response.

use std::path::Path;

use rustix::fs::{Mode, OFlags, open};

use pico_core::mount::CANONICAL_SECRETS_TMPFS;
use pico_guest_protocol::framed;
use pico_guest_protocol::operational_v1::*;

use crate::exec::{OperationalSession, SharedWriter, write_tagged_response};

/// Default tmpfs size for the secrets mount (1 MiB).
///
/// Credentials are typically small (API keys, tokens), but this can be
/// increased if larger credential bundles are needed.
pub(crate) const DEFAULT_SECRETS_TMPFS_SIZE: &str = "1m";

/// Maximum credential name length in bytes.
const MAX_CREDENTIAL_NAME_LEN: usize = 255;

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum SecretsError {
    #[error("context validation failed: {0}")]
    ContextValidation(String),
    #[error("mount failed: {0}")]
    MountFailed(String),
    #[error("credential write failed: {0}")]
    WriteFailed(String),
    #[error("invalid credential name: {0}")]
    InvalidName(String),
}

/// Handle an `InjectSecretsRequest` from the host.
///
/// Validates the request context, ensures the secrets tmpfs is mounted,
/// writes each credential file, and sends back the response.
pub(crate) async fn handle_inject_secrets(
    session: &OperationalSession,
    request: InjectSecretsRequest,
    writer: &SharedWriter,
    timeout: std::time::Duration,
) -> Result<(), SecretsError> {
    let ctx = request
        .context
        .as_ref()
        .ok_or_else(|| SecretsError::ContextValidation("missing context".into()))?;
    session
        .validate_context(ctx)
        .map_err(|e| SecretsError::ContextValidation(e.to_string()))?;

    ensure_secrets_mount().map_err(|e| SecretsError::MountFailed(e.to_string()))?;

    for cred in &request.credentials {
        validate_credential_name(&cred.name)?;
        let path = Path::new(CANONICAL_SECRETS_TMPFS).join(&cred.name);
        write_secret_file(&path, &cred.content, cred.mode).await?;
    }

    tracing::info!(
        lease_id = %request.lease_id,
        policy_decision_id = %request.policy_decision_id,
        credential_count = request.credentials.len(),
        "secrets injected"
    );

    let response = InjectSecretsResponse {
        result: Some(inject_secrets_response::Result::Injected(true)),
    };

    write_tagged_response(
        writer,
        framed::TAG_INJECT_SECRETS_RESPONSE,
        &response,
        timeout,
    )
    .await
    .map_err(|e| SecretsError::WriteFailed(format!("send response: {e}")))?;

    Ok(())
}

/// Unmount and remove the secrets tmpfs.
///
/// Called during quiesce and shutdown to tear down the in-guest
/// secrets mount before the guest is paused or terminated.
pub(crate) fn teardown_secrets_mount() -> Result<(), std::io::Error> {
    teardown_secrets_mount_impl()
}

#[cfg(target_os = "linux")]
fn teardown_secrets_mount_impl() -> Result<(), std::io::Error> {
    use rustix::mount::{UnmountFlags, unmount};

    let path = Path::new(CANONICAL_SECRETS_TMPFS);
    if path.exists() {
        let _ = unmount(path, UnmountFlags::DETACH);
        let _ = std::fs::remove_dir_all(path);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn teardown_secrets_mount_impl() -> Result<(), std::io::Error> {
    Ok(())
}

fn validate_credential_name(name: &str) -> Result<(), SecretsError> {
    if name.is_empty() {
        return Err(SecretsError::InvalidName("empty name".into()));
    }
    // Explicit traversal guard: the allowlist below already rejects dots
    // outside safe positions, but static analysis only recognizes this
    // spelling as a path-injection sanitizer.
    if name.contains("..") {
        return Err(SecretsError::InvalidName(format!(
            "name contains parent reference: {name}"
        )));
    }
    if name.len() > MAX_CREDENTIAL_NAME_LEN {
        return Err(SecretsError::InvalidName(format!(
            "name exceeds {MAX_CREDENTIAL_NAME_LEN} bytes: {} bytes",
            name.len()
        )));
    }
    if name.contains('/') {
        return Err(SecretsError::InvalidName(format!(
            "name contains slash: {name}"
        )));
    }
    if name == "." || name == ".." {
        return Err(SecretsError::InvalidName(format!("reserved name: {name}")));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(SecretsError::InvalidName(format!(
            "name contains unsafe characters (allowed: a-z A-Z 0-9 _ - .): {name}"
        )));
    }
    Ok(())
}

fn ensure_secrets_mount() -> Result<(), std::io::Error> {
    ensure_secrets_mount_impl(DEFAULT_SECRETS_TMPFS_SIZE)
}

#[cfg(target_os = "linux")]
fn ensure_secrets_mount_impl(tmpfs_size: &str) -> Result<(), std::io::Error> {
    use rustix::mount::{MountFlags, mount};
    use std::ffi::CString;

    let path = Path::new(CANONICAL_SECRETS_TMPFS);
    if path.exists() {
        let _ = std::fs::remove_dir_all(path);
    }
    std::fs::create_dir_all(path)?;

    let data = CString::new(format!("mode=500,size={tmpfs_size}"))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    mount(
        "tmpfs",
        path,
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        Some(data.as_c_str()),
    )
    .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_secrets_mount_impl(_tmpfs_size: &str) -> Result<(), std::io::Error> {
    Ok(())
}

async fn write_secret_file(path: &Path, content: &[u8], mode: u32) -> Result<(), SecretsError> {
    use tokio::io::AsyncWriteExt;

    let flags = OFlags::CREATE | OFlags::WRONLY | OFlags::TRUNC;
    #[cfg(target_os = "linux")]
    let file_mode = Mode::from_bits_truncate(mode);
    #[cfg(not(target_os = "linux"))]
    let file_mode = Mode::from_bits_truncate(mode as u16);
    let fd = open(path, flags, file_mode)
        .map_err(|e| SecretsError::WriteFailed(format!("open {path:?}: {e}")))?;
    let mut file = tokio::fs::File::from_std(std::fs::File::from(fd));
    file.write_all(content)
        .await
        .map_err(|e| SecretsError::WriteFailed(format!("write {path:?}: {e}")))?;
    file.flush()
        .await
        .map_err(|e| SecretsError::WriteFailed(format!("flush {path:?}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_credential_names() {
        assert!(validate_credential_name("my-secret").is_ok());
        assert!(validate_credential_name("api_key").is_ok());
        assert!(validate_credential_name("token.json").is_ok());
        assert!(validate_credential_name("a").is_ok());
        assert!(validate_credential_name("ABC123_test-key.file").is_ok());
    }

    #[test]
    fn empty_name_rejected() {
        let err = validate_credential_name("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn slash_in_name_rejected() {
        let err = validate_credential_name("foo/bar").unwrap_err();
        assert!(err.to_string().contains("slash"));
    }

    #[test]
    fn dot_names_rejected() {
        assert!(validate_credential_name(".").is_err());
        assert!(validate_credential_name("..").is_err());
    }

    #[test]
    fn too_long_name_rejected() {
        let long_name = "a".repeat(MAX_CREDENTIAL_NAME_LEN + 1);
        let err = validate_credential_name(&long_name).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn unsafe_characters_rejected() {
        assert!(validate_credential_name("foo@bar").is_err());
        assert!(validate_credential_name("foo bar").is_err());
        assert!(validate_credential_name("foo$bar").is_err());
        assert!(validate_credential_name("foo/bar").is_err());
    }

    #[test]
    fn canonical_secrets_path_is_absolute() {
        assert!(Path::new(CANONICAL_SECRETS_TMPFS).is_absolute());
    }
}
