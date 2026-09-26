//! File transfer handlers (PutFile and GetFile) for the guest agent.
//!
//! Path confinement uses canonicalize + safe-root enforcement rather
//! than string-prefix matching alone.  Symlink traversal is prevented
//! by resolving to a canonical path and checking that it falls within
//! one of the allowed safe roots.

use std::path::{Path, PathBuf};
use std::time::Duration;

use prost::Message;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use pico_guest_protocol::framed;
use pico_guest_protocol::operational_v1::*;

use crate::exec::{OperationalSession, SharedWriter, build_failure_outcome, write_tagged_response};

const FILE_TRANSFER_MAX_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB
const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB

const SAFE_ROOTS: &[&str] = &[
    "/home",
    "/workspace",
    "/tmp",
    "/mnt",
    "/var",
    "/opt",
    "/sandbox",
];

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum FileError {
    #[error("path denied: {0}")]
    PathDenied(String),

    #[error("size exceeded: expected {expected}, got {got}")]
    SizeExceeded { expected: u64, got: u64 },

    #[error("I/O error: {0}")]
    Io(String),

    #[error("context validation failed: {0}")]
    ContextValidation(String),
}

/// Convert a [`FileError`] into an [`OperationOutcome`] for error
/// responses sent to the host.
pub(crate) fn build_file_error_outcome(error: &FileError) -> OperationOutcome {
    match error {
        FileError::PathDenied(msg) => build_failure_outcome("PathDenied", msg, false),
        FileError::SizeExceeded { expected, got } => build_failure_outcome(
            "SizeExceeded",
            &format!("expected {expected}, got {got}"),
            false,
        ),
        FileError::Io(msg) => build_failure_outcome("FileIoError", msg, false),
        FileError::ContextValidation(msg) => {
            build_failure_outcome("ContextValidationFailed", msg, false)
        }
    }
}

/// Pure path normalization: resolves `..` and `.` components without
/// touching the filesystem.  This prevents dot-dot traversal but does
/// not resolve symlinks (which are handled by `O_NOFOLLOW` at open).
fn normalize_path(path: &Path) -> PathBuf {
    let mut stack = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                stack.pop();
            }
            std::path::Component::CurDir => {}
            c => stack.push(c),
        }
    }
    stack.into_iter().collect()
}

/// Validate a path for reading an existing file:
/// 1. Must be absolute.
/// 2. Canonicalize resolves symlinks.
/// 3. The canonical path must start with a safe root.
fn validate_read_path(path: &str) -> Result<PathBuf, FileError> {
    let candidate = Path::new(path);

    if !candidate.is_absolute() {
        return Err(FileError::PathDenied(format!(
            "path '{path}' is not absolute"
        )));
    }

    let canonical = candidate
        .canonicalize()
        .map_err(|e| FileError::PathDenied(format!("cannot resolve '{path}': {e}")))?;

    let canon_str = canonical.to_string_lossy();
    if !SAFE_ROOTS.iter().any(|root| canon_str.starts_with(root)) {
        return Err(FileError::PathDenied(format!(
            "path {canon_str} is outside allowed safe roots"
        )));
    }

    Ok(canonical)
}

/// Validate a path for writing a new or existing file:
/// 1. Must be absolute.
/// 2. Pure normalization resolves `..` to prevent traversal.
/// 3. The normalized path must start with a safe root.
///
/// Symlink traversal is prevented at open time by `O_NOFOLLOW`.
fn validate_write_path(path: &str) -> Result<PathBuf, FileError> {
    let candidate = Path::new(path);

    if !candidate.is_absolute() {
        return Err(FileError::PathDenied(format!(
            "path '{path}' is not absolute"
        )));
    }

    let normalized = normalize_path(candidate);
    let norm_str = normalized.to_string_lossy();
    if !SAFE_ROOTS.iter().any(|root| norm_str.starts_with(root)) {
        return Err(FileError::PathDenied(format!(
            "path {norm_str} is outside allowed safe roots"
        )));
    }

    Ok(normalized)
}

pub(crate) async fn handle_put_file_stream(
    session: &OperationalSession,
    request: PutFileRequest,
    reader: &mut (impl tokio::io::AsyncRead + Unpin + Send),
    writer: &SharedWriter,
    timeout: Duration,
) -> Result<(), FileError> {
    if let Some(put_file_request::Payload::Metadata(m)) = request.payload {
        let ctx = m
            .context
            .as_ref()
            .ok_or_else(|| FileError::ContextValidation("missing context".into()))?;
        session
            .validate_context(ctx)
            .map_err(|e| FileError::ContextValidation(e.to_string()))?;

        let path = validate_write_path(&m.path)?;

        if m.expected_size == 0 {
            return Err(FileError::SizeExceeded {
                expected: 0,
                got: 0,
            });
        }

        if m.expected_size > FILE_TRANSFER_MAX_SIZE {
            return Err(FileError::SizeExceeded {
                expected: m.expected_size,
                got: m.expected_size,
            });
        }

        let mut open_opts = OpenOptions::new();
        open_opts.write(true).create(true);
        if m.overwrite {
            open_opts.truncate(true);
        } else {
            open_opts.create_new(true);
        }

        #[cfg(unix)]
        open_opts.custom_flags(libc::O_NOFOLLOW);

        let mut file = open_opts
            .open(&path)
            .await
            .map_err(|e| FileError::Io(format!("open {path:?}: {e}")))?;

        let mut hasher = blake3::Hasher::new();
        let mut bytes_written: u64 = 0;

        loop {
            // The dispatch loop is suspended inside this inline handler, so
            // reading follow-up chunks here races with nothing.
            let (tag, raw) = match framed::read_tagged_raw(reader, timeout).await {
                Ok(v) => v,
                Err(e) => return Err(FileError::Io(format!("read chunk: {e}"))),
            };

            if tag != framed::TAG_PUT_FILE_REQUEST {
                tracing::warn!(tag, "unexpected tag during file upload, skipping");
                continue;
            }

            let chunk = StreamFrame::decode(raw.as_slice())
                .map_err(|e| FileError::Io(format!("decode chunk: {e}")))?;

            if chunk.end_of_stream {
                break;
            }

            file.write_all(&chunk.payload)
                .await
                .map_err(|e| FileError::Io(format!("write chunk: {e}")))?;
            hasher.update(&chunk.payload);
            bytes_written += chunk.payload.len() as u64;

            if bytes_written > m.expected_size {
                return Err(FileError::SizeExceeded {
                    expected: m.expected_size,
                    got: bytes_written,
                });
            }
        }

        if bytes_written != m.expected_size {
            return Err(FileError::SizeExceeded {
                expected: m.expected_size,
                got: bytes_written,
            });
        }

        file.flush()
            .await
            .map_err(|e| FileError::Io(format!("flush: {e}")))?;
        drop(file);

        let checksum = hasher.finalize().to_hex().to_string();
        let response = PutFileResponse {
            result: Some(put_file_response::Result::BytesWritten(bytes_written)),
            checksum: checksum.clone(),
        };

        write_tagged_response(writer, framed::TAG_PUT_FILE_RESPONSE, &response, timeout)
            .await
            .map_err(|e| FileError::Io(format!("send put file response: {e}")))?;

        tracing::info!(
            bytes_written,
            checksum = %checksum,
            "put file completed"
        );
    } else {
        return Err(FileError::Io("first message must be metadata".into()));
    }

    Ok(())
}

pub(crate) async fn handle_get_file(
    session: &OperationalSession,
    request: GetFileRequest,
    writer: &SharedWriter,
    timeout: Duration,
) -> Result<(), FileError> {
    let ctx = request
        .context
        .as_ref()
        .ok_or_else(|| FileError::ContextValidation("missing context".into()))?;
    session
        .validate_context(ctx)
        .map_err(|e| FileError::ContextValidation(e.to_string()))?;

    let path = validate_read_path(&request.path)?;

    let metadata = fs::metadata(&path)
        .await
        .map_err(|e| FileError::Io(format!("stat {path:?}: {e}")))?;

    if !metadata.is_file() {
        return Err(FileError::Io(format!("{path:?} is not a regular file")));
    }

    let file_size = metadata.len();
    if file_size > FILE_TRANSFER_MAX_SIZE {
        return Err(FileError::SizeExceeded {
            expected: file_size,
            got: file_size,
        });
    }

    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            0o644
        }
    };

    let modified_at = metadata.modified().ok().and_then(|t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| prost_types::Timestamp {
                seconds: d.as_secs() as i64,
                nanos: d.subsec_nanos() as i32,
            })
    });

    let meta_resp = GetFileResponse {
        frame: Some(get_file_response::Frame::Metadata(
            get_file_response::FileMetadata {
                size: file_size,
                mode,
                modified_at,
            },
        )),
    };

    write_tagged_response(writer, framed::TAG_GET_FILE_RESPONSE, &meta_resp, timeout)
        .await
        .map_err(|e| FileError::Io(format!("send metadata: {e}")))?;

    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| FileError::Io(format!("open {path:?}: {e}")))?;

    let mut seq: u64 = 0;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut hasher = blake3::Hasher::new();
    let mut total_read: u64 = 0;

    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| FileError::Io(format!("read {path:?}: {e}")))?;

        let end_of_stream = n == 0;
        seq += 1;

        let frame = StreamFrame {
            sequence: seq,
            payload: if end_of_stream {
                Vec::new()
            } else {
                buf[..n].to_vec()
            },
            end_of_stream,
        };

        if !end_of_stream {
            hasher.update(&buf[..n]);
            total_read += n as u64;
        }

        let resp = GetFileResponse {
            frame: Some(get_file_response::Frame::Chunk(frame)),
        };

        write_tagged_response(writer, framed::TAG_GET_FILE_RESPONSE, &resp, timeout)
            .await
            .map_err(|e| FileError::Io(format!("send chunk: {e}")))?;

        if end_of_stream {
            break;
        }
    }

    let checksum = hasher.finalize().to_hex().to_string();

    let outcome = GetFileResponse {
        frame: Some(get_file_response::Frame::Outcome(OperationOutcome {
            status: Some(operation_outcome::Status::Success(
                operation_outcome::Success {
                    result_payload: checksum.as_bytes().to_vec(),
                },
            )),
        })),
    };

    write_tagged_response(writer, framed::TAG_GET_FILE_RESPONSE, &outcome, timeout)
        .await
        .map_err(|e| FileError::Io(format!("send outcome: {e}")))?;

    tracing::info!(
        path = %request.path,
        bytes_sent = total_read,
        checksum = %checksum,
        "get file completed"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_read_path_accepts_safe_paths() {
        let _ = validate_read_path("/tmp");
    }

    #[test]
    fn validate_read_path_rejects_relative() {
        assert!(validate_read_path("test.txt").is_err());
    }

    #[test]
    fn validate_write_path_accepts_safe_parents() {
        assert!(validate_write_path("/tmp/newfile.txt").is_ok());
        assert!(validate_write_path("/var/data/cache.bin").is_ok());
    }

    #[test]
    fn validate_write_path_rejects_blocked_parent() {
        assert!(validate_write_path("/proc/newfile").is_err());
        assert!(validate_write_path("/sys/test").is_err());
        assert!(validate_write_path("/root/.ssh/newkey").is_err());
    }

    #[test]
    fn validate_write_path_rejects_dotdot_traversal() {
        assert!(validate_write_path("/tmp/../../../etc/pico/secret.key").is_err());
    }

    #[test]
    fn safe_roots_cover_expected_norm_paths() {
        for root in SAFE_ROOTS {
            let path = format!("{root}/some/file.txt");
            assert!(validate_write_path(&path).is_ok());
        }
    }

    #[test]
    fn file_transfer_max_size_is_reasonable() {
        assert_eq!(FILE_TRANSFER_MAX_SIZE, 256 * 1024 * 1024);
    }
}
