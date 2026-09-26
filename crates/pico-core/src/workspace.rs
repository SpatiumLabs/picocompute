use std::path::{Component, Path, PathBuf};

use crate::error::SandboxError;

/// Owns host-side sandbox workspace directories and validates requested paths.
#[derive(Debug, Clone)]
pub struct WorkspaceManager {
    root: PathBuf,
}

impl WorkspaceManager {
    pub fn new(root: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&root)?;
        let root = std::fs::canonicalize(root)?;
        Ok(Self { root })
    }

    pub fn sandbox_dir(&self, id: &str) -> Result<PathBuf, SandboxError> {
        reject_traversal(id)?;
        validate_sandbox_id(id)?;
        let dir = self.sandbox_dir_unchecked(id);
        // Lexical containment: a validated id is a single path component,
        // so the join must stay under the workspace root.
        if !dir.starts_with(&self.root) {
            return Err(SandboxError::PathEscape(id.into()));
        }
        Ok(dir)
    }

    pub fn ensure(&self, id: &str) -> Result<PathBuf, SandboxError> {
        reject_traversal(id)?;
        validate_sandbox_id(id)?;
        let dir = self.sandbox_dir_unchecked(id);
        if !dir.starts_with(&self.root) {
            return Err(SandboxError::PathEscape(id.into()));
        }
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn resolve(&self, id: &str, requested: &str) -> Result<PathBuf, SandboxError> {
        reject_traversal(id)?;
        reject_traversal(requested)?;
        validate_sandbox_id(id)?;
        let path = Path::new(requested);
        if path.is_absolute() {
            return Err(SandboxError::PathEscape(requested.into()));
        }
        if path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(SandboxError::PathEscape(requested.into()));
        }
        let base = self.sandbox_dir_unchecked(id);
        let joined = base.join(path);
        // Lexical containment check keeps the resolved path under the
        // sandbox directory even if a future component slips past the
        // filter above.
        if !joined.starts_with(&base) {
            return Err(SandboxError::PathEscape(requested.into()));
        }
        Ok(joined)
    }

    pub fn resolve_existing(&self, id: &str, requested: &str) -> Result<PathBuf, SandboxError> {
        reject_traversal(id)?;
        reject_traversal(requested)?;
        let path = self.resolve(id, requested)?;
        self.require_workspace_exists(id)?;
        reject_symlink_chain(&path, requested)?;
        Ok(path)
    }

    pub fn resolve_for_write(&self, id: &str, requested: &str) -> Result<PathBuf, SandboxError> {
        reject_traversal(id)?;
        reject_traversal(requested)?;
        let path = self.resolve(id, requested)?;
        self.require_workspace_exists(id)?;
        reject_symlink_parents(&path, requested)?;
        reject_existing_symlink(&path, requested)?;
        Ok(path)
    }

    pub fn delete(&self, id: &str) -> Result<(), SandboxError> {
        reject_traversal(id)?;
        validate_sandbox_id(id)?;
        let dir = self.sandbox_dir_unchecked(id);
        if !dir.starts_with(&self.root) {
            return Err(SandboxError::PathEscape(id.into()));
        }
        crate::fs_retry::retry_transient_fs_op(
            "workspace-delete",
            || match std::fs::remove_dir_all(&dir) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err),
            },
        )
        .map_err(SandboxError::Io)
    }

    fn require_workspace_exists(&self, id: &str) -> Result<(), SandboxError> {
        reject_traversal(id)?;
        let dir = self.sandbox_dir_unchecked(id);
        let metadata = std::fs::symlink_metadata(&dir).map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => SandboxError::WorkspaceNotFound(id.into()),
            _ => SandboxError::Io(err),
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SandboxError::PathEscape(id.into()));
        }
        Ok(())
    }

    fn sandbox_dir_unchecked(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }
}

/// Rejects values that could traverse out of their parent directory.
///
/// This is intentionally a plain `contains("..")` check: static analysis
/// (CodeQL `rust/path-injection`) only recognizes that spelling as a
/// traversal guard, and every filesystem sink in this repo keeps an inline
/// copy so the guard dominates the sink in the same function. The allowlist
/// checks elsewhere remain the authoritative validation.
///
/// By design this also rejects harmless names that merely contain two
/// adjacent dots (for example `file..txt`): fail closed rather than try to
/// distinguish safe dot pairs from traversal sequences.
pub fn reject_traversal(value: &str) -> Result<(), SandboxError> {
    if value.contains("..") {
        return Err(SandboxError::PathEscape(value.into()));
    }
    Ok(())
}

/// Validates a sandbox id against the workspace path rules.
///
/// Ids are `sbx_` plus ASCII alphanumerics and `_`, which guarantees each id
/// is a single safe path component. Callers that join the id into a
/// filesystem path must still keep an inline `reject_traversal` guard so the
/// check dominates the sink.
pub fn validate_sandbox_id(id: &str) -> Result<(), SandboxError> {
    if id.contains("..") || id.contains('/') || id.contains('\\') {
        return Err(SandboxError::PathEscape(id.into()));
    }
    let Some(suffix) = id.strip_prefix("sbx_") else {
        return Err(SandboxError::BadRequest(format!(
            "invalid sandbox id: {id}"
        )));
    };
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(SandboxError::BadRequest(format!(
            "invalid sandbox id: {id}"
        )));
    }
    Ok(())
}

fn reject_symlink_chain(path: &Path, label: &str) -> Result<(), SandboxError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current).map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => SandboxError::WorkspaceNotFound(label.into()),
            _ => SandboxError::Io(err),
        })?;
        if metadata.file_type().is_symlink() {
            return Err(SandboxError::PathEscape(label.into()));
        }
    }
    Ok(())
}

fn reject_symlink_parents(path: &Path, label: &str) -> Result<(), SandboxError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(SandboxError::PathEscape(label.into()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(SandboxError::BadRequest(format!(
                    "{} is not a directory",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => return Err(SandboxError::Io(err)),
        }
    }
    Ok(())
}

fn reject_existing_symlink(path: &Path, label: &str) -> Result<(), SandboxError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(SandboxError::PathEscape(label.into()))
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(SandboxError::Io(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> PathBuf {
        std::env::temp_dir().join(crate::new_ulid("pico_test"))
    }

    #[test]
    fn rejects_absolute_path() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        let err = ws.resolve("sbx_x", "/etc/passwd").unwrap_err();
        assert!(matches!(err, SandboxError::PathEscape(_)));
    }

    #[test]
    fn rejects_parent_dir() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        let err = ws.resolve("sbx_x", "../etc/passwd").unwrap_err();
        assert!(matches!(err, SandboxError::PathEscape(_)));
    }

    #[test]
    fn rejects_nested_parent_dir() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        let err = ws.resolve("sbx_x", "foo/../../bar").unwrap_err();
        assert!(matches!(err, SandboxError::PathEscape(_)));
    }

    #[test]
    fn accepts_relative_path() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        let resolved = ws.resolve("sbx_x", "foo/bar.txt").unwrap();
        assert!(resolved.ends_with("sbx_x/foo/bar.txt"));
    }

    #[test]
    fn rejects_invalid_sandbox_id() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        let err = ws.resolve("../outside", "foo.txt").unwrap_err();
        assert!(matches!(err, SandboxError::PathEscape(_)));
    }

    #[test]
    fn rejects_dotdot_sandbox_id() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        for id in ["sbx_..", "sbx_a..b", "..", "sbx_a/b", "sbx_a\\b"] {
            let err = ws.sandbox_dir(id).unwrap_err();
            assert!(
                matches!(
                    err,
                    SandboxError::PathEscape(_) | SandboxError::BadRequest(_)
                ),
                "id {id} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_dotdot_requested_path() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        for requested in ["..", "../x", "a/../b", "a/..\\b", "..\\x"] {
            let err = ws.resolve("sbx_x", requested).unwrap_err();
            assert!(
                matches!(err, SandboxError::PathEscape(_)),
                "path {requested} must be rejected"
            );
        }
    }

    #[test]
    fn delete_rejects_traversal_id() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        let err = ws.delete("sbx_../escape").unwrap_err();
        assert!(matches!(
            err,
            SandboxError::PathEscape(_) | SandboxError::BadRequest(_)
        ));
    }

    #[test]
    fn delete_missing_is_ok() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        ws.delete("sbx_nonexistent").unwrap();
    }

    #[test]
    fn delete_removes_existing_workspace() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        let dir = ws.ensure("sbx_delete_me").unwrap();
        std::fs::write(dir.join("file.txt"), b"x").unwrap();
        ws.delete("sbx_delete_me").unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn ensure_then_resolve_works() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        let dir = ws.ensure("sbx_y").unwrap();
        let resolved = ws.resolve("sbx_y", "a.txt").unwrap();
        assert!(dir.exists());
        assert!(resolved.ends_with("sbx_y/a.txt"));
    }

    #[test]
    fn resolve_existing_requires_workspace() {
        let ws = WorkspaceManager::new(tmp_root()).unwrap();
        let err = ws.resolve_existing("sbx_missing", "a.txt").unwrap_err();
        assert!(matches!(err, SandboxError::WorkspaceNotFound(_)));
    }
}
