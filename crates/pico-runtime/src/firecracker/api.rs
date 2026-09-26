//! Minimal Firecracker API client used during VM bootstrapping.

use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use pico_core::Result;
use pico_core::SandboxError;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub struct FirecrackerApiClient {
    socket_path: PathBuf,
}

impl Default for FirecrackerApiClient {
    fn default() -> Self {
        Self::new("/tmp/firecracker.socket")
    }
}

impl FirecrackerApiClient {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn put_logger(&self, log_path: &str) -> Result<()> {
        tracing::info!("Firecracker API: PUT /logger path={log_path}");
        self.put_json(
            "/logger",
            &Logger {
                log_path,
                level: "Debug",
                show_level: true,
                show_log_origin: true,
            },
        )
        .await
    }

    pub async fn put_boot_source(&self, kernel_image_path: &str, boot_args: &str) -> Result<()> {
        tracing::info!("Firecracker API: PUT /boot-source kernel={kernel_image_path}");
        self.put_json(
            "/boot-source",
            &BootSource {
                kernel_image_path,
                boot_args,
            },
        )
        .await
    }

    pub async fn put_machine_config(
        &self,
        vcpu_count: u32,
        mem_size_mib: u32,
        cpu_template: Option<&str>,
    ) -> Result<()> {
        tracing::info!(
            "Firecracker API: PUT /machine-config vcpus={vcpu_count} mem={mem_size_mib}mib cpu_template={cpu_template:?}"
        );
        self.put_json(
            "/machine-config",
            &MachineConfig {
                vcpu_count,
                mem_size_mib,
                smt: false,
                cpu_template,
            },
        )
        .await
    }

    pub async fn put_drive(&self, drive_id: &str, path_on_host: &str) -> Result<()> {
        tracing::info!("Firecracker API: PUT /drives id={drive_id} path={path_on_host}");
        self.put_json(
            &format!("/drives/{drive_id}"),
            &Drive {
                drive_id,
                path_on_host,
                is_root_device: true,
                is_read_only: false,
            },
        )
        .await
    }

    pub async fn put_network_interface(
        &self,
        iface_id: &str,
        host_dev_name: &str,
        guest_mac: &str,
    ) -> Result<()> {
        tracing::info!(
            "Firecracker API: PUT /network-interfaces id={iface_id} tap={host_dev_name}"
        );
        self.put_json(
            &format!("/network-interfaces/{iface_id}"),
            &NetworkInterface {
                iface_id,
                host_dev_name,
                guest_mac,
            },
        )
        .await
    }

    pub async fn put_vsock(&self, vsock_id: &str, guest_cid: u32, uds_path: &str) -> Result<()> {
        tracing::info!(
            "Firecracker API: PUT /vsock id={vsock_id} guest_cid={guest_cid} uds={uds_path}"
        );
        // Firecracker's API exposes the vsock device at singular `/vsock`
        // (verified against v1.17.0: `PUT /vsocks/{id}` returns 400
        // "Invalid request method and/or path"). The device id travels in
        // the body, which v1.17.0 accepts with or without `vsock_id`.
        self.put_json(
            "/vsock",
            &Vsock {
                vsock_id,
                guest_cid,
                uds_path,
            },
        )
        .await
    }

    pub async fn put_entropy(&self) -> Result<()> {
        tracing::info!("Firecracker API: PUT /entropy");
        self.put_json("/entropy", &Entropy {}).await
    }

    pub async fn put_snapshot_load(&self, snapshot_path: &str, mem_file_path: &str) -> Result<()> {
        tracing::info!(
            "Firecracker API: PUT /snapshot/load snapshot={snapshot_path} memory={mem_file_path}"
        );
        self.put_json(
            "/snapshot/load",
            &SnapshotLoad {
                snapshot_path,
                mem_file_path,
                enable_diff_snapshots: false,
                resume_vm: false,
            },
        )
        .await
    }

    pub async fn instance_start(&self) -> Result<()> {
        tracing::info!("Firecracker API: PUT /actions instance_start");
        self.put_json(
            "/actions",
            &Action {
                action_type: "InstanceStart",
            },
        )
        .await
    }

    /// Pauses a booted microVM via `PATCH /vm` with `{"state": "Paused"}`.
    ///
    /// Prerequisites: the microVM is booted. Successive calls keep the
    /// microVM in the `Paused` state with no side effects on failure.
    pub async fn pause_vm(&self) -> Result<()> {
        tracing::info!("Firecracker API: PATCH /vm Paused");
        self.patch_json("/vm", &VmState { state: "Paused" }).await
    }

    /// Resumes a paused microVM via `PATCH /vm` with `{"state": "Resumed"}`.
    ///
    /// Prerequisites: the microVM is `Paused`.
    pub async fn resume_vm(&self) -> Result<()> {
        tracing::info!("Firecracker API: PATCH /vm Resumed");
        self.patch_json("/vm", &VmState { state: "Resumed" }).await
    }

    async fn put_json<T: Serialize + ?Sized>(&self, path: &str, body: &T) -> Result<()> {
        self.request_json("PUT", path, body).await
    }

    async fn patch_json<T: Serialize + ?Sized>(&self, path: &str, body: &T) -> Result<()> {
        self.request_json("PATCH", path, body).await
    }

    async fn request_json<T: Serialize + ?Sized>(
        &self,
        method: &str,
        path: &str,
        body: &T,
    ) -> Result<()> {
        let body = serde_json::to_vec(body)
            .map_err(|err| SandboxError::Other(format!("serialize Firecracker request: {err}")))?;
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|err| {
                SandboxError::Other(format!(
                    "connect Firecracker API socket {} for {method} {path}: {err}",
                    self.socket_path.display()
                ))
            })?;
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );

        stream.write_all(request.as_bytes()).await.map_err(|err| {
            SandboxError::Other(format!(
                "write Firecracker API request headers to {} for {method} {path}: {err}",
                self.socket_path.display()
            ))
        })?;
        stream.write_all(&body).await.map_err(|err| {
            SandboxError::Other(format!(
                "write Firecracker API request body to {} for {method} {path}: {err}",
                self.socket_path.display()
            ))
        })?;
        let response = read_http_response(&mut stream, &self.socket_path, method, path).await?;
        ensure_success_response(method, path, &response)
    }
}

async fn read_http_response(
    stream: &mut UnixStream,
    socket_path: &Path,
    method: &str,
    path: &str,
) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];

    loop {
        let read_result =
            tokio::time::timeout(Duration::from_secs(30), stream.read(&mut chunk)).await;
        match read_result {
            Ok(Ok(0)) if response.is_empty() => {
                return Err(SandboxError::Other(format!(
                    "empty Firecracker API response from {} for {method} {path}",
                    socket_path.display()
                )));
            }
            Ok(Ok(0)) => return Ok(response),
            Ok(Ok(n)) => {
                response.extend_from_slice(&chunk[..n]);
                if response_is_complete(&response)? {
                    return Ok(response);
                }
            }
            Ok(Err(err)) if err.kind() == ErrorKind::ConnectionReset && !response.is_empty() => {
                tracing::debug!(
                    "Firecracker API reset socket after sending response for {method} {path}"
                );
                return Ok(response);
            }
            Ok(Err(err)) => {
                return Err(SandboxError::Other(format!(
                    "read Firecracker API response from {} for {method} {path}: {err}",
                    socket_path.display()
                )));
            }
            Err(_) => {
                return Err(SandboxError::Other(format!(
                    "timeout reading Firecracker API response from {} for {method} {path}",
                    socket_path.display()
                )));
            }
        }
    }
}

fn response_is_complete(response: &[u8]) -> Result<bool> {
    let Some(header_end) = find_header_end(response) else {
        return Ok(false);
    };
    let header = std::str::from_utf8(&response[..header_end])
        .map_err(|err| SandboxError::Other(format!("invalid Firecracker response: {err}")))?;
    let body_len = response.len().saturating_sub(header_end + 4);
    let Some(content_length) = content_length(header)? else {
        return Ok(true);
    };
    Ok(body_len >= content_length)
}

fn find_header_end(response: &[u8]) -> Option<usize> {
    response.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(header: &str) -> Result<Option<usize>> {
    for line in header.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            let len = value.trim().parse::<usize>().map_err(|err| {
                SandboxError::Other(format!("invalid Firecracker Content-Length: {err}"))
            })?;
            return Ok(Some(len));
        }
    }
    Ok(None)
}

#[derive(Serialize)]
struct BootSource<'a> {
    kernel_image_path: &'a str,
    boot_args: &'a str,
}

#[derive(Serialize)]
struct Logger<'a> {
    log_path: &'a str,
    level: &'a str,
    show_level: bool,
    show_log_origin: bool,
}

#[derive(Serialize)]
struct MachineConfig<'a> {
    vcpu_count: u32,
    mem_size_mib: u32,
    smt: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_template: Option<&'a str>,
}

#[derive(Serialize)]
struct Drive<'a> {
    drive_id: &'a str,
    path_on_host: &'a str,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Serialize)]
struct NetworkInterface<'a> {
    iface_id: &'a str,
    host_dev_name: &'a str,
    guest_mac: &'a str,
}

#[derive(Serialize)]
struct Vsock<'a> {
    vsock_id: &'a str,
    guest_cid: u32,
    uds_path: &'a str,
}

#[derive(Serialize)]
struct Entropy {}

#[derive(Serialize)]
struct SnapshotLoad<'a> {
    snapshot_path: &'a str,
    mem_file_path: &'a str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    enable_diff_snapshots: bool,
    resume_vm: bool,
}

#[derive(Serialize)]
struct Action<'a> {
    action_type: &'a str,
}

#[derive(Serialize)]
struct VmState<'a> {
    state: &'a str,
}

fn ensure_success_response(method: &str, path: &str, response: &[u8]) -> Result<()> {
    let response = std::str::from_utf8(response)
        .map_err(|err| SandboxError::Other(format!("invalid Firecracker response: {err}")))?;
    let status_line = response
        .lines()
        .next()
        .ok_or_else(|| SandboxError::Other("empty Firecracker response".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| SandboxError::Other(format!("invalid Firecracker status: {status_line}")))?;
    let status = status.parse::<u16>().map_err(|err| {
        SandboxError::Other(format!("invalid Firecracker status code {status}: {err}"))
    })?;

    if (200..300).contains(&status) {
        return Ok(());
    }

    let body = response.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    Err(SandboxError::Other(format!(
        "Firecracker API {method} {path} failed with HTTP {status}: {body}"
    )))
}
