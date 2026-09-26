use pico_core::{
    ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest, LeaseAction,
    LeaseScope, PageResponse, PortForwardEndpoint, PortForwardRequest, PortForwardResponse,
    SandboxInfo, SandboxSpec, SshInfo, TaskInfo, TaskRequest,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub(crate) struct ApiClient {
    client: Client,
    base_url: String,
    token: String,
}

#[derive(Debug, Clone, Serialize)]
struct IssueLeaseRequest {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<LeaseScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IssuedLease {
    pub lease: String,
    pub lease_id: String,
    pub expires_at: String,
    pub action: String,
}

impl ApiClient {
    pub(crate) fn new(base_url: String, token: String) -> Self {
        let client = Client::new();
        Self {
            client,
            base_url,
            token,
        }
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    async fn check_empty(&self, resp: reqwest::Response) -> Result<(), String> {
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }
        Ok(())
    }

    async fn post_empty(&self, path: &str) -> Result<(), String> {
        let resp = self
            .client
            .post(format!("{}{path}", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        self.check_empty(resp).await
    }

    pub(crate) async fn create_sandbox(&self, spec: &SandboxSpec) -> Result<SandboxInfo, String> {
        let resp = self
            .client
            .post(format!("{}/v1/sandboxes", self.base_url))
            .header("Authorization", self.auth_header())
            .json(spec)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn list_sandboxes(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<PageResponse<SandboxInfo>, String> {
        let mut req = self
            .client
            .get(format!("{}/v1/sandboxes", self.base_url))
            .header("Authorization", self.auth_header())
            .query(&[("limit", limit.to_string())]);
        if let Some(cursor) = cursor {
            req = req.query(&[("cursor", cursor)]);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn get_sandbox(&self, id: &str) -> Result<SandboxInfo, String> {
        let resp = self
            .client
            .get(format!("{}/v1/sandboxes/{id}", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn destroy_sandbox(&self, id: &str) -> Result<(), String> {
        let resp = self
            .client
            .delete(format!("{}/v1/sandboxes/{id}", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        self.check_empty(resp).await
    }

    pub(crate) async fn stop_sandbox(&self, id: &str) -> Result<(), String> {
        self.post_empty(&format!("/v1/sandboxes/{id}/stop")).await
    }

    pub(crate) async fn purge_sandbox(&self, id: &str) -> Result<(), String> {
        self.post_empty(&format!("/v1/sandboxes/{id}/purge")).await
    }

    pub(crate) async fn suspend_sandbox(&self, id: &str) -> Result<(), String> {
        self.post_empty(&format!("/v1/sandboxes/{id}/suspend"))
            .await
    }

    pub(crate) async fn resume_sandbox(&self, id: &str) -> Result<(), String> {
        self.post_empty(&format!("/v1/sandboxes/{id}/resume")).await
    }

    pub(crate) async fn keepalive_sandbox(&self, id: &str) -> Result<(), String> {
        self.post_empty(&format!("/v1/sandboxes/{id}/keepalive"))
            .await
    }

    pub(crate) async fn exec_sandbox(
        &self,
        id: &str,
        req: &ExecRequest,
    ) -> Result<ExecResponse, String> {
        let resp = self
            .client
            .post(format!("{}/v1/sandboxes/{id}/exec", self.base_url))
            .header("Authorization", self.auth_header())
            .json(req)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn file_read(&self, id: &str, path: &str) -> Result<FileReadResponse, String> {
        let resp = self
            .client
            .get(format!("{}/v1/sandboxes/{id}/files", self.base_url))
            .header("Authorization", self.auth_header())
            .query(&[("path", path)])
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn file_list(
        &self,
        id: &str,
        dir: &str,
        recursive: bool,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<PageResponse<FileInfo>, String> {
        let mut req = self
            .client
            .get(format!("{}/v1/sandboxes/{id}/files", self.base_url))
            .header("Authorization", self.auth_header())
            .query(&[("dir", dir)])
            .query(&[("recursive", recursive.to_string())])
            .query(&[("limit", limit.to_string())]);
        if let Some(cursor) = cursor {
            req = req.query(&[("cursor", cursor)]);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn file_write(
        &self,
        id: &str,
        req: &FileWriteRequest,
    ) -> Result<FileInfo, String> {
        let resp = self
            .client
            .put(format!("{}/v1/sandboxes/{id}/files", self.base_url))
            .header("Authorization", self.auth_header())
            .json(req)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn task_start(&self, id: &str, req: &TaskRequest) -> Result<TaskInfo, String> {
        let resp = self
            .client
            .post(format!("{}/v1/sandboxes/{id}/tasks", self.base_url))
            .header("Authorization", self.auth_header())
            .json(req)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn task_get(&self, id: &str, task_id: &str) -> Result<TaskInfo, String> {
        let resp = self
            .client
            .get(format!(
                "{}/v1/sandboxes/{id}/tasks/{task_id}",
                self.base_url
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn task_cancel(&self, id: &str, task_id: &str) -> Result<(), String> {
        let resp = self
            .client
            .delete(format!(
                "{}/v1/sandboxes/{id}/tasks/{task_id}",
                self.base_url
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        self.check_empty(resp).await
    }

    pub(crate) fn task_events_url(&self, id: &str, task_id: &str) -> String {
        format!("{}/v1/sandboxes/{id}/tasks/{task_id}/events", self.base_url)
    }

    pub(crate) async fn stream_task_events(&self, id: &str, task_id: &str) -> Result<(), String> {
        use futures_util::StreamExt;

        let resp = self
            .client
            .get(self.task_events_url(id, task_id))
            .header("Authorization", self.auth_header())
            .header("Accept", "text/event-stream")
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        let mut stream = resp.bytes_stream();
        let mut stdout = tokio::io::stdout();
        use tokio::io::AsyncWriteExt;
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(|e| format!("stream failed: {e}"))?;
            stdout
                .write_all(&bytes)
                .await
                .map_err(|e| format!("write failed: {e}"))?;
        }
        stdout
            .flush()
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        Ok(())
    }

    pub(crate) async fn issue_lease(
        &self,
        id: &str,
        action: LeaseAction,
        scope: LeaseScope,
    ) -> Result<IssuedLease, String> {
        let body = IssueLeaseRequest {
            action: action.as_str().to_string(),
            scope: Some(scope),
        };
        let resp = self
            .client
            .post(format!("{}/v1/sandboxes/{id}/lease", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn expose_port(
        &self,
        id: &str,
        req: &PortForwardRequest,
    ) -> Result<PortForwardResponse, String> {
        let resp = self
            .client
            .post(format!("{}/v1/sandboxes/{id}/ports", self.base_url))
            .header("Authorization", self.auth_header())
            .json(req)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn list_ports(&self, id: &str) -> Result<Vec<PortForwardEndpoint>, String> {
        let resp = self
            .client
            .get(format!("{}/v1/sandboxes/{id}/ports", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn revoke_port(
        &self,
        id: &str,
        endpoint_id: &str,
    ) -> Result<PortForwardResponse, String> {
        let resp = self
            .client
            .delete(format!(
                "{}/v1/sandboxes/{id}/ports/{endpoint_id}",
                self.base_url
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn ssh_info(&self, id: &str) -> Result<SshInfo, String> {
        let resp = self
            .client
            .get(format!("{}/v1/sandboxes/{id}/ssh", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) fn ws_url(&self) -> String {
        self.base_url
            .replace("http://", "ws://")
            .replace("https://", "wss://")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    #[test]
    fn ws_url_converts_http() {
        let client = ApiClient::new("http://example.com:8080".into(), "t".into());
        assert_eq!(client.ws_url(), "ws://example.com:8080");
    }

    #[test]
    fn ws_url_converts_https() {
        let client = ApiClient::new("https://api.example.com".into(), "t".into());
        assert_eq!(client.ws_url(), "wss://api.example.com");
    }

    #[test]
    fn token_returns_configured_token() {
        let client = ApiClient::new("http://localhost".into(), "my-token".into());
        assert_eq!(client.token(), "my-token");
    }

    #[test]
    fn task_events_url_includes_ids() {
        let client = ApiClient::new("http://localhost:8080".into(), "t".into());
        assert_eq!(
            client.task_events_url("sbx_1", "task_2"),
            "http://localhost:8080/v1/sandboxes/sbx_1/tasks/task_2/events"
        );
    }

    async fn read_request_line(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> String {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap_or(0);
        line
    }

    async fn read_headers(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> Vec<String> {
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
            headers.push(line);
        }
        headers
    }

    async fn mock_once(
        expected_method: &str,
        expected_path_prefix: &str,
        response_body: &str,
        status: &str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let method = expected_method.to_string();
        let prefix = expected_path_prefix.to_string();
        let body = response_body.to_string();
        let status = status.to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = tokio::io::BufReader::new(read_half);
            let request_line = read_request_line(&mut reader).await;
            assert!(
                request_line.contains(&method),
                "expected {method} got {request_line}"
            );
            assert!(
                request_line.contains(&prefix),
                "expected path {prefix} got {request_line}"
            );
            let headers = read_headers(&mut reader).await;
            assert!(
                headers.iter().any(|h| h.contains("Bearer test-token")),
                "bearer auth required, got {headers:?}"
            );
            let resp = format!(
                "HTTP/1.1 {status}\r\ncontent-length: {}\r\ncontent-type: application/json\r\n\r\n{}",
                body.len(),
                body
            );
            write_half.write_all(resp.as_bytes()).await.unwrap();
        });
        (format!("http://{addr}"), server)
    }

    #[tokio::test]
    async fn destroy_sends_delete() {
        let (url, server) = mock_once("DELETE", "/v1/sandboxes/sbx_1", "", "204 No Content").await;
        let client = ApiClient::new(url, "test-token".into());
        client.destroy_sandbox("sbx_1").await.expect("destroy");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn lifecycle_posts_hit_expected_paths() {
        for (path, call) in [
            ("/v1/sandboxes/sbx_1/stop", "stop"),
            ("/v1/sandboxes/sbx_1/purge", "purge"),
            ("/v1/sandboxes/sbx_1/suspend", "suspend"),
            ("/v1/sandboxes/sbx_1/resume", "resume"),
            ("/v1/sandboxes/sbx_1/keepalive", "keepalive"),
        ] {
            let (url, server) = mock_once("POST", path, "", "204 No Content").await;
            let client = ApiClient::new(url, "test-token".into());
            match call {
                "stop" => client.stop_sandbox("sbx_1").await.expect("stop"),
                "purge" => client.purge_sandbox("sbx_1").await.expect("purge"),
                "suspend" => client.suspend_sandbox("sbx_1").await.expect("suspend"),
                "resume" => client.resume_sandbox("sbx_1").await.expect("resume"),
                _ => client.keepalive_sandbox("sbx_1").await.expect("keepalive"),
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn exec_decodes_response() {
        let body = r#"{"exit_code":0,"stdout":"ok","stderr":"","duration_ms":5}"#;
        let (url, server) = mock_once("POST", "/v1/sandboxes/sbx_1/exec", body, "200 OK").await;
        let client = ApiClient::new(url, "test-token".into());
        let req = ExecRequest {
            command: "echo".into(),
            args: vec!["ok".into()],
            env: None,
            working_dir: None,
            timeout_secs: None,
        };
        let resp = client.exec_sandbox("sbx_1", &req).await.expect("exec");
        assert_eq!(resp.stdout, "ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn file_read_decodes_response() {
        let body =
            r#"{"path":"a.txt","content":"hi","size":2,"modified_at":"2026-01-01T00:00:00Z"}"#;
        let (url, server) = mock_once("GET", "/v1/sandboxes/sbx_1/files", body, "200 OK").await;
        let client = ApiClient::new(url, "test-token".into());
        let resp = client.file_read("sbx_1", "a.txt").await.expect("read");
        assert_eq!(resp.content, "hi");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn file_list_decodes_page() {
        let body = r#"{"items":[{"path":"a.txt","size":2,"is_dir":false,"modified_at":"x"}],"next_cursor":null}"#;
        let (url, server) = mock_once("GET", "/v1/sandboxes/sbx_1/files", body, "200 OK").await;
        let client = ApiClient::new(url, "test-token".into());
        let page = client
            .file_list("sbx_1", "/", false, 50, None)
            .await
            .expect("list");
        assert_eq!(page.items.len(), 1);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn file_write_decodes_info() {
        let body = r#"{"path":"a.txt","size":2,"is_dir":false,"modified_at":"x"}"#;
        let (url, server) = mock_once("PUT", "/v1/sandboxes/sbx_1/files", body, "200 OK").await;
        let client = ApiClient::new(url, "test-token".into());
        let req = FileWriteRequest {
            path: "a.txt".into(),
            content: "hi".into(),
            append: false,
        };
        let info = client.file_write("sbx_1", &req).await.expect("write");
        assert_eq!(info.path, "a.txt");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn task_start_get_cancel_roundtrip() {
        let start_body = r#"{"id":"task_1","state":"Pending","started_at":null,"ended_at":null,"exit_code":null,"error":null}"#;
        let (url, server) = mock_once(
            "POST",
            "/v1/sandboxes/sbx_1/tasks",
            start_body,
            "202 Accepted",
        )
        .await;
        let client = ApiClient::new(url, "test-token".into());
        let req = TaskRequest {
            prompt: "work".into(),
            agent: "echo".into(),
            model: None,
            timeout_secs: None,
        };
        let info = client.task_start("sbx_1", &req).await.expect("start");
        assert_eq!(info.id, "task_1");
        server.await.unwrap();

        let get_body = r#"{"id":"task_1","state":"Completed","started_at":null,"ended_at":null,"exit_code":0,"error":null}"#;
        let (url, server) = mock_once(
            "GET",
            "/v1/sandboxes/sbx_1/tasks/task_1",
            get_body,
            "200 OK",
        )
        .await;
        let client = ApiClient::new(url, "test-token".into());
        let info = client.task_get("sbx_1", "task_1").await.expect("get");
        assert_eq!(info.exit_code, Some(0));
        server.await.unwrap();

        let (url, server) = mock_once(
            "DELETE",
            "/v1/sandboxes/sbx_1/tasks/task_1",
            "",
            "204 No Content",
        )
        .await;
        let client = ApiClient::new(url, "test-token".into());
        client.task_cancel("sbx_1", "task_1").await.expect("cancel");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn list_with_cursor_hits_path() {
        let body = r#"{"items":[],"next_cursor":null}"#;
        let (url, server) = mock_once("GET", "/v1/sandboxes", body, "200 OK").await;
        let client = ApiClient::new(url, "test-token".into());
        let page = client
            .list_sandboxes(10, Some("cur_1"))
            .await
            .expect("list");
        assert!(page.items.is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn issue_lease_decodes_blob() {
        let body = r#"{"lease":"blob","lease_id":"lse_1","expires_at":"2030-01-01T00:00:00Z","action":"exec"}"#;
        let (url, server) = mock_once("POST", "/v1/sandboxes/sbx_1/lease", body, "200 OK").await;
        let client = ApiClient::new(url, "test-token".into());
        let lease = client
            .issue_lease("sbx_1", LeaseAction::Exec, LeaseScope::unbounded())
            .await
            .expect("lease");
        assert_eq!(lease.lease_id, "lse_1");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ports_expose_list_revoke() {
        let expose_body = r#"{"endpoint":{"endpoint_id":"epf_1","sandbox_id":"sbx_1","tenant_id":"tnt_1","lease_id":"lse_1","policy_decision_id":"pdc_1","owner":"usr_1","guest_port":8080,"host_port":32001,"host":"127.0.0.1","localhost_only":true,"created_at":"x","expires_at":"y","revoked_at":null,"state":"active","max_connections":null,"active_connections":0}}"#;
        let (url, server) =
            mock_once("POST", "/v1/sandboxes/sbx_1/ports", expose_body, "200 OK").await;
        let client = ApiClient::new(url, "test-token".into());
        let req = PortForwardRequest {
            tenant_id: pico_core::TenantId::from_string("tnt_1"),
            lease_id: pico_core::LeaseId::from_string("lse_1"),
            guest_port: 8080,
            requested_host_port: None,
            localhost_only: true,
            max_connections: None,
            lease: None,
        };
        let resp = client.expose_port("sbx_1", &req).await.expect("expose");
        assert_eq!(resp.endpoint.endpoint_id, "epf_1");
        server.await.unwrap();

        let list_body = r#"[]"#;
        let (url, server) =
            mock_once("GET", "/v1/sandboxes/sbx_1/ports", list_body, "200 OK").await;
        let client = ApiClient::new(url, "test-token".into());
        let endpoints = client.list_ports("sbx_1").await.expect("list ports");
        assert!(endpoints.is_empty());
        server.await.unwrap();

        let (url, server) = mock_once(
            "DELETE",
            "/v1/sandboxes/sbx_1/ports/epf_1",
            expose_body,
            "200 OK",
        )
        .await;
        let client = ApiClient::new(url, "test-token".into());
        let resp = client.revoke_port("sbx_1", "epf_1").await.expect("revoke");
        assert_eq!(resp.endpoint.host_port, 32001);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn api_error_surfaces_body() {
        let (url, server) = mock_once(
            "GET",
            "/v1/sandboxes/sbx_missing",
            r#"{"error":"not found"}"#,
            "404 Not Found",
        )
        .await;
        let client = ApiClient::new(url, "test-token".into());
        let err = client.get_sandbox("sbx_missing").await.unwrap_err();
        assert!(err.contains("not found"));
        server.await.unwrap();
    }
}
