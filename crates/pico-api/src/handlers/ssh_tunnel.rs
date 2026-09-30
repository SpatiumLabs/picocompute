//! WebSocket-based SSH tunnel handler.
//!
//! Upgrades a WebSocket connection and proxies raw TCP bytes bidirectionally
//! between the client and the sandbox's SSH port on localhost.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::AppError;
use crate::state::AppState;

pub(crate) async fn ssh_tunnel(
    State(agent): State<AppState>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    let info = agent.ssh_info(&id).await?;
    Ok(ws.on_upgrade(move |socket| proxy_tunnel(socket, info.port)))
}

async fn proxy_tunnel(mut ws: WebSocket, port: u16) {
    let tcp = match TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
        Ok(tcp) => tcp,
        Err(err) => {
            tracing::warn!(port, error = %err, "ssh tunnel: failed to connect to sandbox SSH");
            return;
        }
    };

    let (mut tcp_rd, mut tcp_wr) = tokio::io::split(tcp);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

    let tcp_reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_rd.read(&mut buf).await {
                Ok(0) => {
                    let _ = tx.send(vec![]).await;
                    break;
                }
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            maybe_data = rx.recv() => {
                match maybe_data {
                    Some(data) if data.is_empty() => break,
                    Some(data) => {
                        if ws.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if tcp_wr.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    tcp_reader.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hashbrown::HashMap;
    use pico_core::SandboxService;
    use pico_core::{
        ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest, Result,
        SandboxError, SandboxInfo, SandboxSpec, SshInfo, TaskEvent, TaskInfo, TaskRequest,
    };
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::broadcast;

    struct MockAgent {
        items: Mutex<HashMap<String, SandboxInfo>>,
        ssh_port: u16,
    }

    #[async_trait]
    impl pico_core::SandboxService for MockAgent {
        async fn create(&self, s: SandboxSpec) -> Result<SandboxInfo> {
            let id = s.id.clone().unwrap_or_else(|| pico_core::new_ulid("sbx"));
            let info = SandboxInfo {
                id: id.clone(),
                state: pico_core::SandboxState::Running,
                ports: s.ports.unwrap_or_default(),
                container_id: None,
                created_at: "2026-06-04T00:00:00Z".into(),
                last_activity_at: "2026-06-04T00:00:00Z".into(),
                ssh_port: s.ssh_public_key.is_some().then_some(self.ssh_port),
                ssh_public_key: s.ssh_public_key,
            };
            self.items.lock().unwrap().insert(id, info.clone());
            Ok(info)
        }
        async fn list(
            &self,
            _l: usize,
            _c: Option<String>,
        ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
            unimplemented!()
        }
        async fn get(&self, id: &str) -> Result<SandboxInfo> {
            self.items
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or_else(|| SandboxError::SandboxNotFound(id.into()))
        }
        async fn destroy(&self, _: &str) -> Result<()> {
            unimplemented!()
        }
        async fn purge(&self, _: &str) -> Result<()> {
            unimplemented!()
        }
        async fn stop(&self, _: &str) -> Result<()> {
            unimplemented!()
        }
        async fn keepalive(&self, _: &str) -> Result<()> {
            unimplemented!()
        }
        async fn exec(&self, _: &str, _: ExecRequest) -> Result<ExecResponse> {
            unimplemented!()
        }
        async fn file_read(&self, _: &str, _: &str) -> Result<FileReadResponse> {
            unimplemented!()
        }
        async fn file_write(&self, _: &str, _: FileWriteRequest) -> Result<FileInfo> {
            unimplemented!()
        }
        async fn file_list(&self, _: &str, _: &str, _: bool) -> Result<Vec<FileInfo>> {
            unimplemented!()
        }
        async fn task_start(&self, _: &str, _: TaskRequest) -> Result<TaskInfo> {
            unimplemented!()
        }
        async fn task_get(&self, _: &str, _: &str) -> Result<TaskInfo> {
            unimplemented!()
        }
        async fn task_cancel(&self, _: &str, _: &str) -> Result<()> {
            unimplemented!()
        }
        fn task_subscribe(&self, _: &str, _: &str) -> Result<broadcast::Receiver<TaskEvent>> {
            unimplemented!()
        }
        async fn ssh_info(&self, id: &str) -> Result<SshInfo> {
            let info = self
                .items
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or_else(|| SandboxError::SandboxNotFound(id.into()))?;
            Ok(SshInfo {
                host: "localhost".into(),
                port: info.ssh_port.unwrap_or(22),
                username: "root".into(),
                private_key: None,
                public_key: "ssh-ed25519 test-key".into(),
            })
        }
    }

    #[tokio::test]
    async fn tunnel_proxies_bytes_bidirectionally() {
        // Start a mock SSH server
        let mock = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mock_port = mock.local_addr().unwrap().port();

        // Create agent with sandbox pointing to mock port
        let agent = Arc::new(MockAgent {
            items: Mutex::new(HashMap::new()),
            ssh_port: mock_port,
        });
        agent
            .create(SandboxSpec {
                id: Some("sbx_tunnel_test".into()),
                ports: None,
                env: None,
                memory_mb: None,
                vcpus: None,
                idle_timeout_secs: None,
                ssh_public_key: Some("test-key".into()),
                ssh_key_type: None,
                runtime: None,
                image_id: None,
                image_digest: None,
                credential_request: None,
                service_class: None,
            })
            .await
            .unwrap();

        // Start the API server
        let app = crate::routes::build_router(Arc::<MockAgent>::clone(&agent), "secret".into());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Accept mock SSH connections in background - echo server
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = mock.accept().await {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                stream.write_all(&buf[..n]).await.unwrap();
            }
        });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Manual WebSocket handshake over raw TCP
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Generate a random Sec-WebSocket-Key
        let key_bytes: [u8; 16] = rand::random();
        let ws_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes);

        let handshake = format!(
            "GET /v1/sandboxes/sbx_tunnel_test/ssh/tunnel HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: Bearer secret\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n",
            addr, ws_key
        );
        tcp.write_all(handshake.as_bytes()).await.unwrap();

        // Read response headers (scan for \r\n\r\n)
        let mut buf = vec![0u8; 4096];
        let mut pos = 0;
        loop {
            let n = tcp.read(&mut buf[pos..]).await.unwrap();
            if n == 0 {
                panic!("connection closed before receiving response headers");
            }
            pos += n;
            if pos >= 4 && buf[..pos].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let response_str = String::from_utf8_lossy(&buf[..pos]);
        assert!(
            response_str.contains("101"),
            "expected 101, got: {}",
            response_str.lines().next().unwrap_or("empty")
        );

        // Send a WebSocket binary frame (masked, since client -> server frames must be masked)
        let msg = b"hello sandbox";
        let mask: [u8; 4] = rand::random();
        let frame = build_ws_binary_frame(msg, mask);
        tcp.write_all(&frame).await.unwrap();

        // Read the response frame (unmasked, since server -> client frames are not masked)
        let mut header = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut tcp, &mut header)
            .await
            .unwrap();
        let payload_len = (header[1] & 0x7F) as usize;
        let mut payload = vec![0u8; payload_len];
        tokio::io::AsyncReadExt::read_exact(&mut tcp, &mut payload)
            .await
            .unwrap();

        assert_eq!(payload, msg);
    }

    fn build_ws_binary_frame(data: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let len = data.len();
        let mut frame = Vec::new();
        // FIN + opcode binary (0x2)
        frame.push(0x82);
        // MASK bit + payload length
        frame.push(0x80 | len as u8);
        frame.extend_from_slice(&mask);
        // Masked payload
        for (i, b) in data.iter().enumerate() {
            frame.push(b ^ mask[i & 3]);
        }
        frame
    }
}
