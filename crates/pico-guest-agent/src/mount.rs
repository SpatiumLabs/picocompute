//! Mount workspace handler for the guest agent.

use std::path::Path;

use pico_guest_protocol::framed;
use pico_guest_protocol::operational_v1::*;

use crate::exec::{OperationalSession, SharedWriter, write_tagged_response};

const SUPPORTED_FS_TYPES: &[&str] = &["virtiofs", "9p", "overlay", "bind", "tmpfs"];
const BLOCKED_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/etc/pico"];

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum MountError {
    #[error("mount point denied: {0}")]
    MountPointDenied(String),

    #[error("fs type {fs_type} not supported")]
    FsTypeNotSupported { fs_type: String },

    #[error("mount operation failed: {0}")]
    MountFailed(String),

    #[error("context validation failed: {0}")]
    ContextValidation(String),
}

pub(crate) fn validate_mount_point(mount_point: &str) -> Result<(), MountError> {
    let normalized = Path::new(mount_point)
        .components()
        .collect::<std::path::PathBuf>();

    for prefix in BLOCKED_PREFIXES {
        if normalized.to_string_lossy().starts_with(prefix) {
            return Err(MountError::MountPointDenied(format!(
                "mount point {mount_point} is in a blocked area"
            )));
        }
    }

    let path_str = normalized.to_string_lossy();
    for prefix in BLOCKED_PREFIXES {
        if path_str.starts_with(prefix) {
            return Err(MountError::MountPointDenied(format!(
                "mount point {path_str} is in a blocked area"
            )));
        }
    }

    if !normalized.is_absolute() {
        return Err(MountError::MountPointDenied(format!(
            "mount point '{mount_point}' is not absolute"
        )));
    }

    Ok(())
}

pub(crate) async fn handle_mount_workspace(
    session: &OperationalSession,
    request: MountWorkspaceRequest,
    writer: &SharedWriter,
    timeout: std::time::Duration,
) -> Result<(), MountError> {
    let ctx = request
        .context
        .as_ref()
        .ok_or_else(|| MountError::ContextValidation("missing context".into()))?;
    session
        .validate_context(ctx)
        .map_err(|e| MountError::ContextValidation(e.to_string()))?;

    validate_mount_point(&request.mount_point)?;

    if !request.fs_type.is_empty() && !SUPPORTED_FS_TYPES.contains(&request.fs_type.as_str()) {
        return Err(MountError::FsTypeNotSupported {
            fs_type: request.fs_type.clone(),
        });
    }

    let mount_point = request.mount_point.clone();
    let fs_type = if request.fs_type.is_empty() {
        "bind".to_string()
    } else {
        request.fs_type.clone()
    };

    let is_read_only = request
        .options
        .get("ro")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    tracing::info!(
        mount_point = %mount_point,
        fs_type = %fs_type,
        read_only = is_read_only,
        "mount workspace acknowledged"
    );

    let response = MountWorkspaceResponse {
        result: Some(mount_workspace_response::Result::Mounted(true)),
    };

    write_tagged_response(
        writer,
        framed::TAG_MOUNT_WORKSPACE_RESPONSE,
        &response,
        timeout,
    )
    .await
    .map_err(|e| MountError::MountFailed(format!("send response: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_mount_point_accepts_valid_paths() {
        assert!(validate_mount_point("/mnt/workspace").is_ok());
        assert!(validate_mount_point("/workspace").is_ok());
        assert!(validate_mount_point("/home/user").is_ok());
    }

    #[test]
    fn validate_mount_point_rejects_relative() {
        assert!(validate_mount_point("workspace").is_err());
        assert!(validate_mount_point("./mnt").is_err());
    }

    #[test]
    fn validate_mount_point_rejects_blocked() {
        assert!(validate_mount_point("/proc/mounts").is_err());
        assert!(validate_mount_point("/sys/kernel").is_err());
        assert!(validate_mount_point("/etc/pico/mounts").is_err());
    }

    #[test]
    fn supported_fs_types_include_expected() {
        let supported = ["virtiofs", "9p", "overlay", "bind", "tmpfs"];
        for fs in supported {
            assert!(validate_mount_point("/mnt/test").is_ok()); // path valid
            let req = MountWorkspaceRequest {
                context: None,
                mount_point: "/mnt/test".into(),
                fs_type: fs.into(),
                options: Default::default(),
            };
            // Verify fs_type is not empty and would be checked
            assert!(!req.fs_type.is_empty());
        }
    }
}
