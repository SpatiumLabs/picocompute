use futures_util::{SinkExt, StreamExt};
use std::io::Write;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::Connector;
use tokio_tungstenite::connect_async_tls_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::client::ApiClient;

pub(crate) async fn ssh_into_sandbox(client: &ApiClient, id: &str) -> Result<(), String> {
    tracing::info!("fetching SSH info for sandbox {id}");
    let info = client.ssh_info(id).await?;

    let key_file = info
        .private_key
        .as_ref()
        .map(|key| {
            let mut f = tempfile::NamedTempFile::new()
                .map_err(|e| format!("failed to create temp key file: {e}"))?;

            f.write_all(key.as_bytes())
                .map_err(|e| format!("failed to write key file: {e}"))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("failed to set key file permissions: {e}"))?;
            }
            Ok::<_, String>(f)
        })
        .transpose()?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("failed to bind local port: {e}"))?;
    let local_port = listener.local_addr().map_err(|e| format!("{e}"))?.port();
    tracing::debug!("SSH forwarder listening on 127.0.0.1:{local_port}");

    let ws_base = client.ws_url();
    let ws_url = format!("{ws_base}/v1/sandboxes/{id}/ssh/tunnel");
    tracing::debug!("connecting WebSocket to {ws_url}");

    let mut ws_request = ws_url
        .into_client_request()
        .map_err(|e| format!("failed to build WebSocket request: {e}"))?;
    ws_request.headers_mut().insert(
        http::header::AUTHORIZATION,
        format!("Bearer {}", client.token())
            .parse()
            .map_err(|e| format!("invalid header value: {e}"))?,
    );

    let username = if info.username.is_empty() {
        "root".to_string()
    } else {
        info.username
    };

    let tls_connector = {
        let mut root_store = rustls::RootCertStore::empty();
        let result = rustls_native_certs::load_native_certs();
        if !result.errors.is_empty() {
            tracing::warn!("native cert loading errors: {:?}", result.errors);
        }
        let (added, _) = root_store.add_parsable_certificates(result.certs);
        if added == 0 {
            return Err("no native root CA certificates found".into());
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Connector::Rustls(Arc::new(config))
    };

    let (ws_stream, _) =
        connect_async_tls_with_config(ws_request, None, false, Some(tls_connector))
            .await
            .map_err(|e| format!("WebSocket connection failed: {e}"))?;
    tracing::debug!("WebSocket tunnel established");

    let mut ssh_cmd = tokio::process::Command::new("ssh");
    if let Some(ref f) = key_file {
        ssh_cmd.arg("-i").arg(f.path());
    }
    let mut ssh_child = ssh_cmd
        .arg("-p")
        .arg(local_port.to_string())
        .arg("-t")
        .arg("-t")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg(format!("{username}@localhost"))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("failed to spawn ssh: {e}"))?;

    let (tcp_stream, _) = listener
        .accept()
        .await
        .map_err(|e| format!("failed to accept connection: {e}"))?;

    let (ws_write, ws_read) = ws_stream.split();
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);

    let tcp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        let mut ws = ws_write;
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let msg = Message::Binary(buf[..n].to_vec().into());
                    if ws.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let ws_to_tcp = tokio::spawn(async move {
        let mut read = ws_read;
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if tcp_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
    });

    let ssh_status = ssh_child.wait().await;

    tcp_to_ws.abort();
    ws_to_tcp.abort();

    match ssh_status {
        Ok(status) => {
            if status.success() {
                Ok(())
            } else {
                Err(format!("ssh exited with code: {:?}", status.code()))
            }
        }
        Err(e) => Err(format!("failed to wait for ssh: {e}")),
    }
}
