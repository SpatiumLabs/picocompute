use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[test]
fn quarantine_ack_passes_with_ticket_and_owner() {
    let out = run_quarantine_ack(
        "INC-123",
        "hst_01",
        "repeated_runtime_outcomes",
        "sre-picocompute",
    )
    .expect("ack passes");
    assert!(out.contains("INC-123"));
    assert!(out.contains("hst_01"));
}

#[test]
fn quarantine_ack_rejects_missing_owner() {
    assert!(run_quarantine_ack("INC-123", "hst_01", "stale_resources", "").is_err());
    assert!(run_quarantine_ack("", "hst_01", "stale_resources", "sre").is_err());
    assert!(run_quarantine_ack("INC-123", "hst_01", "bogus", "sre").is_err());
    assert!(run_quarantine_ack("INC-123", "", "stale_resources", "sre").is_err());
}

#[test]
fn quarantine_resolve_requires_cleared_flag() {
    assert!(run_quarantine_resolve("INC-123", "hst_01", "stale_resources", true).is_ok());
    let err = run_quarantine_resolve("INC-123", "hst_01", "stale_resources", false).unwrap_err();
    assert!(err.contains("cleared"));
}

#[test]
fn fenced_cleanup_parses_tokens() {
    let out = run_fenced_cleanup("INC-9", &["42.7".to_string(), "43.0".to_string()])
        .expect("cleanup passes");
    assert!(out.contains("42.7"));
    assert!(run_fenced_cleanup("INC-9", &[]).is_err());
    assert!(run_fenced_cleanup("INC-9", &["bogus".to_string()]).is_err());
    assert!(run_fenced_cleanup("", &["42.7".to_string()]).is_err());
}

#[test]
fn ledger_inspect_rejects_writes() {
    assert!(run_ledger_inspect("INC-4", "sandbox-status", Some("sbx_21")).is_ok());
    assert!(run_ledger_inspect("INC-4", "gc-stats", Some("sbx_1")).is_ok());
    for query in ["edit", "delete", "gc --force-stale", "rm"] {
        assert!(
            run_ledger_inspect("INC-4", query, None).is_err(),
            "query {query:?} must fail"
        );
    }
}

#[test]
fn ledger_inspect_requires_scope_for_per_sandbox_queries() {
    assert!(run_ledger_inspect("INC-4", "sandbox-status", None).is_err());
    assert!(run_ledger_inspect("INC-4", "sandbox-status", Some("")).is_err());
    assert!(run_ledger_inspect("INC-4", "list-receipts", None).is_err());
    assert!(run_ledger_inspect("INC-4", "list-receipts", Some("sbx_21")).is_ok());
    assert!(run_ledger_inspect("INC-4", "list-sandboxes", None).is_ok());
    assert!(run_ledger_inspect("INC-4", "gc-stats", None).is_ok());
    assert!(run_ledger_inspect("INC-4", "findings", None).is_ok());
}

#[test]
fn resolve_host_token_prefers_arg_then_env() {
    assert_eq!(
        resolve_host_token(Some("arg-tok"), Some("env-tok")).unwrap(),
        "arg-tok"
    );
    assert_eq!(
        resolve_host_token(None, Some("env-tok")).unwrap(),
        "env-tok"
    );
    assert_eq!(
        resolve_host_token(Some(""), Some("env-tok")).unwrap(),
        "env-tok"
    );
    assert!(resolve_host_token(None, None).is_err());
    assert!(resolve_host_token(Some(""), Some("  ")).is_err());
}

#[test]
fn readmit_check_enforces_all_gates() {
    assert!(run_readmit_check(true, 12, "ready", true, true).is_ok());
    assert!(run_readmit_check(true, 12, "degraded", true, true).is_ok());
    assert!(run_readmit_check(false, 12, "ready", true, true).is_err());
    assert!(run_readmit_check(true, 60, "ready", true, true).is_err());
    assert!(run_readmit_check(true, 12, "draining", true, true).is_err());
    assert!(run_readmit_check(true, 12, "ready", false, true).is_err());
    assert!(run_readmit_check(true, 12, "ready", true, false).is_err());
    assert!(run_readmit_check(true, 12, "bogus", true, true).is_err());
}

#[test]
fn readmit_output_states_no_undrain() {
    let out = run_readmit_check(true, 5, "ready", true, true).expect("passes");
    assert!(out.contains("no undrain"));
}

async fn read_request_line<R>(reader: &mut tokio::io::BufReader<R>) -> String
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap_or(0);
    line
}

#[tokio::test]
async fn drain_posts_with_bearer_and_ticket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader_half, mut writer_half) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader_half);
        let request_line = read_request_line(&mut reader).await;
        assert!(request_line.contains("POST /rpc/v1/drain"));
        let mut saw_auth = false;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
            if line.contains("Bearer host-secret") {
                saw_auth = true;
            }
        }
        assert!(saw_auth, "drain must send bearer auth");
        writer_half
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\ncontent-type: application/json\r\n\r\nnull")
            .await
            .unwrap();
    });
    let url = format!("http://{addr}");
    let out = run_drain(&url, "host-secret", "INC-7")
        .await
        .expect("drain posts");
    assert!(out.contains("INC-7"));
    server.await.unwrap();
}

#[tokio::test]
async fn drain_rejects_missing_ticket_before_io() {
    let err = run_drain("http://127.0.0.1:1", "tok", "")
        .await
        .unwrap_err();
    assert!(err.contains("ticket"));
}

#[tokio::test]
async fn drain_status_reads_health() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader_half, mut writer_half) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader_half);
        let request_line = read_request_line(&mut reader).await;
        assert!(request_line.contains("GET /rpc/v1/health"));
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
        }
        let body = r#"{"status":"draining","sandbox_count":3}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        writer_half.write_all(resp.as_bytes()).await.unwrap();
    });
    let url = format!("http://{addr}");
    let out = run_drain_status(&url).await.expect("status reads");
    assert!(out.contains("draining"));
    server.await.unwrap();
}

#[tokio::test]
async fn drain_status_rejects_unexpected_shape() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader_half, mut writer_half) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader_half);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
        }
        let body = r#"{"unexpected":true}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        writer_half.write_all(resp.as_bytes()).await.unwrap();
    });
    let url = format!("http://{addr}");
    assert!(run_drain_status(&url).await.is_err());
    server.await.unwrap();
}

#[test]
fn cli_refuses_prohibited_mutations() {
    use crate::cli::Args;
    use clap::Parser;
    for argv in [
        vec!["pc", "operator", "undrain", "--host-url", "http://x"],
        vec![
            "pc",
            "operator",
            "quarantine-resolve",
            "--ticket",
            "INC-1",
            "--host",
            "hst_01",
            "--condition",
            "stale_resources",
            "--force",
        ],
        vec!["pc", "operator", "gc", "--force-stale"],
        vec!["pc", "operator", "ledger-edit", "--ticket", "INC-1"],
    ] {
        assert!(
            Args::try_parse_from(argv.clone()).is_err(),
            "prohibited argv {argv:?} must be rejected"
        );
    }
}

#[test]
fn cli_parses_approved_operator_paths() {
    use crate::cli::Args;
    use clap::Parser;
    assert!(
        Args::try_parse_from(vec![
            "pc",
            "operator",
            "quarantine-ack",
            "--ticket",
            "INC-1",
            "--host",
            "hst_01",
            "--condition",
            "stale_resources",
            "--owner",
            "sre"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from(vec![
            "pc",
            "operator",
            "readmit-check",
            "--quarantine-gauge-zero",
            "--capacity-age-secs",
            "12",
            "--health",
            "ready",
            "--reconciliation-clean",
            "--watch-clean"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from(vec![
            "pc",
            "operator",
            "drain",
            "--host-url",
            "http://hst-01:8081",
            "--ticket",
            "INC-1"
        ])
        .is_ok(),
        "drain without --host-token parses; token comes from PICO_HOST_TOKEN"
    );
}

#[test]
fn cli_requires_explicit_health_for_readmit() {
    use crate::cli::Args;
    use clap::Parser;
    assert!(
        Args::try_parse_from(vec![
            "pc",
            "operator",
            "readmit-check",
            "--quarantine-gauge-zero",
            "--capacity-age-secs",
            "12",
            "--reconciliation-clean",
            "--watch-clean"
        ])
        .is_err(),
        "readmit without --health must fail; no fail-open default"
    );
}
