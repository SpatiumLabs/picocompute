use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::*;

#[test]
fn supervisor_observation_identity_changes_per_process_instance() {
    let first = read_host_boot_id();
    let second = read_host_boot_id();
    assert_ne!(first, second);
    assert!(first.contains(':'));
}

#[tokio::test]
async fn run_until_deadline_completes_before_deadline() {
    let token = CancellationToken::new();
    let deadline = super::system_time_to_unix_ms(SystemTime::now()) + 30_000;
    let result = run_until_deadline(&token, deadline, async { 42 }).await;
    assert!(matches!(result, Execution::Completed(42)));
}

#[tokio::test]
async fn run_until_deadline_cancels_before_deadline() {
    let token = CancellationToken::new();
    token.cancel();
    let deadline = super::system_time_to_unix_ms(SystemTime::now()) + 30_000;
    let result = run_until_deadline(&token, deadline, async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        42
    })
    .await;
    assert!(matches!(result, Execution::Canceled));
}

#[tokio::test]
async fn run_until_deadline_times_out_when_deadline_passes() {
    let token = CancellationToken::new();
    let deadline = super::system_time_to_unix_ms(SystemTime::now()) + 10;
    let result = run_until_deadline(&token, deadline, async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        42
    })
    .await;
    assert!(matches!(result, Execution::TimedOut));
}

#[tokio::test]
async fn run_until_deadline_past_deadline_times_out_immediately() {
    let token = CancellationToken::new();
    let deadline = super::system_time_to_unix_ms(SystemTime::now()) - 10;
    let result = run_until_deadline(&token, deadline, async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        42
    })
    .await;
    assert!(matches!(result, Execution::TimedOut));
}

#[tokio::test]
async fn run_until_deadline_cancellation_wins_over_timeout() {
    let token = CancellationToken::new();
    token.cancel();
    let deadline = super::system_time_to_unix_ms(SystemTime::now()) - 10;
    let result = run_until_deadline(&token, deadline, async { 42 }).await;
    assert!(matches!(result, Execution::Canceled));
}
