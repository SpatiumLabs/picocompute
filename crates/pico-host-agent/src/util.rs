use std::io;
use std::time::Duration;

use pico_core::{ExecRequest, NonReadyReason, Result, SandboxError};

use crate::boot::BootReport;
use crate::sandboxd_client::{CommandMetaParts, RpcOutcome, SandboxdHandle, outcome_error};

/// Maps port binding failures into the public sandbox error model.
pub(crate) fn port_bind_error(port: u16, err: io::Error) -> SandboxError {
    if err.kind() == io::ErrorKind::AddrInUse {
        SandboxError::PortInUse(port)
    } else {
        SandboxError::Io(err)
    }
}

pub(crate) fn operation_outcome_error(outcome: &RpcOutcome) -> SandboxError {
    outcome_error(outcome)
}

pub(crate) fn boot_report_error(report: &BootReport) -> SandboxError {
    let reason = report.reason.unwrap_or(NonReadyReason::Backend);
    let detail = if report.diagnostics.is_empty() {
        "no diagnostics available".to_string()
    } else {
        report.diagnostics.join("; ")
    };
    if reason == NonReadyReason::Cleanup {
        SandboxError::Conflict(format!("boot cleanup failed: {detail}"))
    } else {
        SandboxError::NotReady(format!("boot did not become ready ({reason}): {detail}"))
    }
}

pub(crate) fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(crate) fn nofollow_open_options() -> tokio::fs::OpenOptions {
    let mut options = tokio::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
}

pub(crate) async fn revoke_generated_ssh_key(
    sandboxd: &SandboxdHandle,
    public_key: &str,
    ssh_home_dir: &str,
    meta: CommandMetaParts,
) -> Result<()> {
    let revoke_script = r#"set -eu
auth_keys="$2/.ssh/authorized_keys"
tmp="$(mktemp)"
if [ -f "$auth_keys" ]; then
  grep -F -v -- "$1" "$auth_keys" > "$tmp" || true
  cat "$tmp" > "$auth_keys"
  chmod 600 "$auth_keys"
fi
rm -f "$tmp"
"#;
    let response = sandboxd
        .exec(
            meta,
            ExecRequest {
                command: "sh".into(),
                args: vec![
                    "-c".into(),
                    revoke_script.into(),
                    "ssh-revoke".into(),
                    public_key.into(),
                    ssh_home_dir.into(),
                ],
                env: None,
                working_dir: None,
                timeout_secs: Some(10),
            },
        )
        .await?;
    if response.exit_code == 0 {
        Ok(())
    } else {
        Err(SandboxError::Other(format!(
            "failed to revoke SSH public key: {}",
            response.stderr.trim()
        )))
    }
}
