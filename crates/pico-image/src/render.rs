use crate::error::ImageError;
use crate::util::hex_encode;
use camino::Utf8Path;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;
use tracing::info;

pub fn render_ext4(
    rootfs_dir: &Utf8Path,
    filesystem_label: &str,
    filesystem_uuid: &str,
    filesystem_size: &str,
    output_dir: &Utf8Path,
) -> Result<OutputInfo, ImageError> {
    assert_available("mkfs.ext4")?;

    fs::create_dir_all(output_dir)?;

    let output_path = output_dir.join("rootfs.ext4");

    info!(
        ?output_path,
        label = filesystem_label,
        uuid = filesystem_uuid,
        size = filesystem_size,
        "creating deterministic ext4 filesystem"
    );

    let status = Command::new("mkfs.ext4")
        .arg("-F")
        .arg("-L")
        .arg(filesystem_label)
        .arg("-U")
        .arg(filesystem_uuid)
        .arg("-d")
        .arg(rootfs_dir.as_str())
        .arg("-E")
        .arg("encoding=utf8")
        .arg(filesystem_size)
        .arg(output_path.as_str())
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ImageError::MissingTool {
                    tool: "mkfs.ext4".into(),
                }
            } else {
                ImageError::IoError(e)
            }
        })?;

    if !status.success() {
        return Err(ImageError::ParseError("mkfs.ext4 failed".into()));
    }

    let digest = compute_file_digest(&output_path)?;
    let size = fs::metadata(&output_path)?.len();

    info!(%digest, size, "ext4 filesystem rendered");

    run_fsck(&output_path)?;

    Ok(OutputInfo {
        path: output_path,
        digest,
        size,
    })
}

pub fn run_fsck(path: &Utf8Path) -> Result<(), ImageError> {
    assert_available("e2fsck")?;

    let status = Command::new("e2fsck")
        .arg("-f")
        .arg("-n")
        .arg(path.as_str())
        .status()?;

    if !status.success() {
        return Err(ImageError::FsckFailed(
            "e2fsck reported filesystem errors".into(),
        ));
    }

    Ok(())
}

pub fn compute_file_digest(path: &Utf8Path) -> Result<String, ImageError> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = std::io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("sha256:{}", hex_encode(&hasher.finalize())))
}

#[derive(Debug, Clone)]
pub struct OutputInfo {
    pub path: camino::Utf8PathBuf,
    pub digest: String,
    pub size: u64,
}

fn assert_available(tool: &str) -> Result<(), ImageError> {
    let status = Command::new("which")
        .arg(tool)
        .stdout(std::process::Stdio::null())
        .status()?;

    if !status.success() {
        return Err(ImageError::MissingTool { tool: tool.into() });
    }

    Ok(())
}
