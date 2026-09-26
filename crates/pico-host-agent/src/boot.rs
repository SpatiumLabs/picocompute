//! Host-side boot lifecycle command, reporting, and telemetry contracts.

use async_trait::async_trait;
use pico_core::{FencingToken, NonReadyReason, OperationId, SandboxState};
use pico_telemetry::structured_log::{LogRecordBuilder, LogSeverity};
use serde::{Deserialize, Serialize};

use crate::metrics::{HOST_METRICS, is_metric_redaction_enabled, tracing_identity_label, val};

// When reason fields or diagnostics begin to carry host paths, commands,
// or dependency errors, use redaction:
//
//   LogRecordBuilder::new(...)
//       .with_redacted_fields(vec!["diagnostics".into()])
//       .build()
//       .emit();
//
// The redacted_fields list is included in the platform log payload so
// consumers know which fields were intentionally removed.

/// Default deadline budget for a host boot operation.
pub const DEFAULT_BOOT_TIMEOUT_SECS: u64 = 60;

/// Default deadline budget for a host suspend operation.
pub const DEFAULT_SUSPEND_TIMEOUT_SECS: u64 = 120;

/// Default deadline budget for a host resume operation.
pub const DEFAULT_RESUME_TIMEOUT_SECS: u64 = 120;

const PKG_NAME: &str = env!("CARGO_PKG_NAME");

/// Fenced control-plane command for booting one prepared sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootCommand {
    /// Sandbox assigned to this host.
    pub sandbox_id: String,
    /// Stable idempotency identity for this logical boot.
    pub operation_id: OperationId,
    /// Host selected by the scheduler.
    pub assigned_host_id: String,
    /// Cell selected by the scheduler.
    pub assigned_cell_id: String,
    /// Monotonic assignment token.
    pub assignment_fencing_token: FencingToken,
    /// Policy version admitted by the control plane.
    pub policy_epoch: u64,
    /// Total boot budget. Retries reuse the persisted absolute deadline in `sandboxd`.
    #[serde(default = "default_boot_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_boot_timeout_secs() -> u64 {
    DEFAULT_BOOT_TIMEOUT_SECS
}

/// Terminal host boot status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BootStatus {
    /// The guest readiness handshake and host setup completed.
    Ready,
    /// Boot stopped with a typed non-ready reason.
    NotReady,
}

/// Typed result returned to the cell controller for one boot operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootReport {
    /// Sandbox affected by the operation.
    pub sandbox_id: String,
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Terminal result.
    pub status: BootStatus,
    /// Stable failure classification for non-ready results.
    pub reason: Option<NonReadyReason>,
    /// Host-local observed lifecycle state.
    pub observed_state: SandboxState,
    /// End-to-end host boot latency.
    pub latency_ms: u64,
    /// Redacted diagnostic details.
    pub diagnostics: Vec<String>,
}

/// Lifecycle transition reported by `host-agent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootObservation {
    /// Sandbox affected by the transition.
    pub sandbox_id: String,
    /// Stable boot operation identity.
    pub operation_id: OperationId,
    /// Host-local observed state being reported.
    pub observed_state: SandboxState,
    /// Typed failure reason for a failed transition.
    pub reason: Option<NonReadyReason>,
    /// Redacted diagnostic summary.
    pub message: Option<String>,
}

/// Boundary used by `host-agent` to report lifecycle observations.
#[async_trait]
pub trait LifecycleReporter: Send + Sync {
    /// Reports one host-local lifecycle observation to the cell controller.
    async fn report(&self, observation: &BootObservation) -> Result<(), String>;
}

/// Reporter used until a concrete cell-controller transport is configured.
#[derive(Debug, Default)]
pub struct TracingLifecycleReporter;

#[async_trait]
impl LifecycleReporter for TracingLifecycleReporter {
    async fn report(&self, observation: &BootObservation) -> Result<(), String> {
        tracing::info!(
            event = "boot_lifecycle_report",
            sandbox_id = %observation.sandbox_id,
            operation_id = %observation.operation_id,
            observed_state = %observation.observed_state,
            reason = observation.reason.map(|reason| reason.to_string()).as_deref(),
            message = observation.message.as_deref(),
            "reporting host boot lifecycle observation"
        );
        Ok(())
    }
}

pub(crate) fn emit_boot_start(command: &BootCommand, tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(val::BOOT_START, tenant_id);
    HOST_METRICS.boot_events.inc(&attrs);

    let mut record = LogRecordBuilder::new(PKG_NAME, val::BOOT_START, "sandbox boot started")
        .severity(LogSeverity::Info)
        .operation_id(command.operation_id.as_str())
        .host_id(&command.assigned_host_id)
        .cell_id(&command.assigned_cell_id)
        .lifecycle_state("Booting");
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(&command.sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::BOOT_START,
        sandbox_id = %tracing_identity_label(&command.sandbox_id, tenant_id),
        operation_id = %command.operation_id,
        policy_epoch = command.policy_epoch,
        fencing_token = %command.assignment_fencing_token,
        "sandbox boot started"
    );
}

pub(crate) fn emit_boot_ready(report: &BootReport, tenant_id: Option<&str>) {
    record_latency(report, val::READY, tenant_id);
    let attrs = crate::metrics::event_attrs(val::BOOT_READY, tenant_id);
    HOST_METRICS.boot_events.inc(&attrs);

    let mut record = LogRecordBuilder::new(PKG_NAME, val::BOOT_READY, "sandbox boot completed")
        .severity(LogSeverity::Info)
        .operation_id(report.operation_id.as_str())
        .lifecycle_state(report.observed_state.to_string())
        .outcome("success");
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(&report.sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::BOOT_READY,
        sandbox_id = %tracing_identity_label(&report.sandbox_id, tenant_id),
        operation_id = %report.operation_id,
        latency_ms = report.latency_ms,
        "sandbox boot completed"
    );
}

pub(crate) fn emit_boot_not_ready(report: &BootReport, tenant_id: Option<&str>) {
    let reason = report.reason.unwrap_or(NonReadyReason::Backend);
    let reason_str = reason.to_string();
    let outcome = non_ready_reason_to_outcome(reason);

    record_latency(report, val::NOT_READY, tenant_id);

    let attrs = crate::metrics::event_reason_attrs(val::BOOT_NOT_READY, &reason_str, tenant_id);
    HOST_METRICS.boot_events.inc(&attrs);

    let mut record = LogRecordBuilder::new(
        PKG_NAME,
        val::BOOT_NOT_READY,
        "sandbox boot did not become ready",
    )
    .severity(LogSeverity::Error)
    .operation_id(report.operation_id.as_str())
    .lifecycle_state(report.observed_state.to_string())
    .outcome(outcome)
    .reason(&reason_str);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(&report.sandbox_id);
    }
    record.build().emit();

    tracing::warn!(
        event = val::BOOT_NOT_READY,
        sandbox_id = %tracing_identity_label(&report.sandbox_id, tenant_id),
        operation_id = %report.operation_id,
        reason = %reason_str,
        latency_ms = report.latency_ms,
        diagnostics = ?report.diagnostics,
        "sandbox boot did not become ready"
    );
}

fn non_ready_reason_to_outcome(reason: NonReadyReason) -> &'static str {
    match reason {
        NonReadyReason::Image => "image_unavailable",
        NonReadyReason::Network => "network_setup_failed",
        NonReadyReason::Resource => "no_capacity",
        NonReadyReason::Backend => "runtime_start_failed",
        NonReadyReason::Protocol => "protocol_error",
        NonReadyReason::Timeout => "deadline_exceeded",
        NonReadyReason::Cleanup => "cleanup_incomplete",
    }
}

pub(crate) fn emit_boot_cleanup(report: &BootReport, tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(val::BOOT_CLEANUP, tenant_id);
    HOST_METRICS.boot_events.inc(&attrs);

    let (severity, outcome_label, reason_label, message) =
        if report.reason == Some(NonReadyReason::Cleanup) {
            (
                LogSeverity::Warn,
                "cleanup_incomplete",
                "cleanup_incomplete",
                "sandbox boot cleanup requires review",
            )
        } else {
            (
                LogSeverity::Info,
                "success",
                "success",
                "sandbox boot cleanup completed",
            )
        };

    let mut record = LogRecordBuilder::new(PKG_NAME, val::BOOT_CLEANUP, message)
        .severity(severity)
        .operation_id(report.operation_id.as_str())
        .lifecycle_state(report.observed_state.to_string())
        .outcome(outcome_label)
        .reason(reason_label);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(&report.sandbox_id);
    }
    record.build().emit();
}

fn record_latency(report: &BootReport, status: &'static str, tenant_id: Option<&str>) {
    let attrs = crate::metrics::latency_attrs(status, tenant_id);
    HOST_METRICS
        .boot_latency
        .record(report.latency_ms as f64 / 1000.0, &attrs);
}

// ── Create lifecycle ──

pub(crate) fn emit_create_started(sandbox_id: &str, tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(val::CREATE_STARTED, tenant_id);
    HOST_METRICS.create_events.inc(&attrs);

    let mut record = LogRecordBuilder::new(PKG_NAME, val::CREATE_STARTED, "sandbox create started")
        .severity(LogSeverity::Info)
        .operation(pico_telemetry::lifecycle::LifecycleOperation::Create);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::CREATE_STARTED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        "sandbox create started"
    );
}

pub(crate) fn emit_create_completed(sandbox_id: &str, latency_ms: u64, tenant_id: Option<&str>) {
    let latency_attrs = crate::metrics::latency_attrs(val::CREATE_COMPLETED, tenant_id);
    HOST_METRICS
        .create_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);

    let event_attrs = crate::metrics::event_attrs(val::CREATE_COMPLETED, tenant_id);
    HOST_METRICS.create_events.inc(&event_attrs);

    let mut record =
        LogRecordBuilder::new(PKG_NAME, val::CREATE_COMPLETED, "sandbox create completed")
            .severity(LogSeverity::Info)
            .operation(pico_telemetry::lifecycle::LifecycleOperation::Create)
            .outcome("success");
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::CREATE_COMPLETED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        latency_ms = latency_ms,
        "sandbox create completed"
    );
}

pub(crate) fn emit_create_failed(
    sandbox_id: &str,
    latency_ms: u64,
    reason: &str,
    tenant_id: Option<&str>,
) {
    let latency_attrs = crate::metrics::latency_attrs(val::CREATE_FAILED, tenant_id);
    HOST_METRICS
        .create_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);

    let event_attrs = crate::metrics::event_reason_attrs(val::CREATE_FAILED, reason, tenant_id);
    HOST_METRICS.create_events.inc(&event_attrs);

    let mut record = LogRecordBuilder::new(PKG_NAME, val::CREATE_FAILED, "sandbox create failed")
        .severity(LogSeverity::Error)
        .operation(pico_telemetry::lifecycle::LifecycleOperation::Create)
        .outcome("failed")
        .reason(reason);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::error!(
        event = val::CREATE_FAILED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        latency_ms = latency_ms,
        reason = %reason,
        "sandbox create failed"
    );
}

// ── Prepare lifecycle ──

pub(crate) fn emit_prepare_started(sandbox_id: &str, tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(val::PREPARE_STARTED, tenant_id);
    HOST_METRICS.prepare_events.inc(&attrs);

    let mut record =
        LogRecordBuilder::new(PKG_NAME, val::PREPARE_STARTED, "sandbox prepare started")
            .severity(LogSeverity::Info)
            .operation(pico_telemetry::lifecycle::LifecycleOperation::Prepare);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::PREPARE_STARTED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        "sandbox prepare started"
    );
}

pub(crate) fn emit_prepare_completed(sandbox_id: &str, latency_ms: u64, tenant_id: Option<&str>) {
    let latency_attrs = crate::metrics::latency_attrs(val::PREPARE_COMPLETED, tenant_id);
    HOST_METRICS
        .prepare_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);

    // Image-stage series for the `pico-image-cache` dashboard panel
    // "Image Prepare Latency by cache_result". Labels stay `unknown` until
    // host image-cache work reports real lookup results and image profiles,
    // so hit-filtered recording rules and alerts remain honestly empty.
    let image_latency_attrs = crate::metrics::image_prepare_latency_attrs(
        val::PREPARE_COMPLETED,
        val::CACHE_RESULT_UNKNOWN,
        val::IMAGE_PROFILE_UNKNOWN,
        tenant_id,
    );
    HOST_METRICS
        .image_prepare_latency
        .record(latency_ms as f64 / 1000.0, &image_latency_attrs);

    let event_attrs = crate::metrics::event_attrs(val::PREPARE_COMPLETED, tenant_id);
    HOST_METRICS.prepare_events.inc(&event_attrs);

    let mut record = LogRecordBuilder::new(
        PKG_NAME,
        val::PREPARE_COMPLETED,
        "sandbox prepare completed",
    )
    .severity(LogSeverity::Info)
    .operation(pico_telemetry::lifecycle::LifecycleOperation::Prepare)
    .outcome("success");
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::PREPARE_COMPLETED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        latency_ms = latency_ms,
        "sandbox prepare completed"
    );
}

pub(crate) fn emit_prepare_failed(
    sandbox_id: &str,
    latency_ms: u64,
    reason: &str,
    tenant_id: Option<&str>,
) {
    let latency_attrs = crate::metrics::latency_attrs(val::PREPARE_FAILED, tenant_id);
    HOST_METRICS
        .prepare_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);

    // Same image-stage mirror as the completed path. Failed prepares also
    // carry `unknown` cache labels until the host cache can classify them.
    let image_latency_attrs = crate::metrics::image_prepare_latency_attrs(
        val::PREPARE_FAILED,
        val::CACHE_RESULT_UNKNOWN,
        val::IMAGE_PROFILE_UNKNOWN,
        tenant_id,
    );
    HOST_METRICS
        .image_prepare_latency
        .record(latency_ms as f64 / 1000.0, &image_latency_attrs);

    let event_attrs = crate::metrics::event_reason_attrs(val::PREPARE_FAILED, reason, tenant_id);
    HOST_METRICS.prepare_events.inc(&event_attrs);

    let mut record = LogRecordBuilder::new(PKG_NAME, val::PREPARE_FAILED, "sandbox prepare failed")
        .severity(LogSeverity::Error)
        .operation(pico_telemetry::lifecycle::LifecycleOperation::Prepare)
        .outcome("failed")
        .reason(reason);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::error!(
        event = val::PREPARE_FAILED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        latency_ms = latency_ms,
        reason = %reason,
        "sandbox prepare failed"
    );
}

// ── Destroy lifecycle ──

pub(crate) fn emit_destroy_started(sandbox_id: &str, tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(val::DESTROY_STARTED, tenant_id);
    HOST_METRICS.destroy_events.inc(&attrs);

    let mut record =
        LogRecordBuilder::new(PKG_NAME, val::DESTROY_STARTED, "sandbox destroy started")
            .severity(LogSeverity::Info)
            .operation(pico_telemetry::lifecycle::LifecycleOperation::Destroy);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::DESTROY_STARTED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        "sandbox destroy started"
    );
}

pub(crate) fn emit_destroy_completed(sandbox_id: &str, latency_ms: u64, tenant_id: Option<&str>) {
    let latency_attrs = crate::metrics::latency_attrs(val::DESTROY_COMPLETED, tenant_id);
    HOST_METRICS
        .destroy_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);

    let event_attrs = crate::metrics::event_attrs(val::DESTROY_COMPLETED, tenant_id);
    HOST_METRICS.destroy_events.inc(&event_attrs);

    let mut record = LogRecordBuilder::new(
        PKG_NAME,
        val::DESTROY_COMPLETED,
        "sandbox destroy completed",
    )
    .severity(LogSeverity::Info)
    .operation(pico_telemetry::lifecycle::LifecycleOperation::Destroy)
    .outcome("success");
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::DESTROY_COMPLETED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        latency_ms = latency_ms,
        "sandbox destroy completed"
    );
}

pub(crate) fn emit_destroy_failed(
    sandbox_id: &str,
    latency_ms: u64,
    reason: &str,
    tenant_id: Option<&str>,
) {
    let latency_attrs = crate::metrics::latency_attrs(val::DESTROY_FAILED, tenant_id);
    HOST_METRICS
        .destroy_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);

    let event_attrs = crate::metrics::event_reason_attrs(val::DESTROY_FAILED, reason, tenant_id);
    HOST_METRICS.destroy_events.inc(&event_attrs);

    let mut record = LogRecordBuilder::new(PKG_NAME, val::DESTROY_FAILED, "sandbox destroy failed")
        .severity(LogSeverity::Error)
        .operation(pico_telemetry::lifecycle::LifecycleOperation::Destroy)
        .outcome("failed")
        .reason(reason);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::error!(
        event = val::DESTROY_FAILED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        latency_ms = latency_ms,
        reason = %reason,
        "sandbox destroy failed"
    );
}

// ── Fork lifecycle ──

#[expect(dead_code, reason = "emitted when fork lifecycle is implemented")]
pub(crate) fn emit_fork_started(sandbox_id: &str, tenant_id: Option<&str>) {
    let attrs = crate::metrics::event_attrs(val::FORK_STARTED, tenant_id);
    HOST_METRICS.fork_events.inc(&attrs);

    let mut record = LogRecordBuilder::new(PKG_NAME, val::FORK_STARTED, "sandbox fork started")
        .severity(LogSeverity::Info)
        .operation(pico_telemetry::lifecycle::LifecycleOperation::Fork);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::FORK_STARTED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        "sandbox fork started"
    );
}

#[expect(dead_code, reason = "emitted when fork lifecycle is implemented")]
pub(crate) fn emit_fork_completed(sandbox_id: &str, latency_ms: u64, tenant_id: Option<&str>) {
    let latency_attrs = crate::metrics::latency_attrs(val::FORK_COMPLETED, tenant_id);
    HOST_METRICS
        .fork_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);

    let event_attrs = crate::metrics::event_attrs(val::FORK_COMPLETED, tenant_id);
    HOST_METRICS.fork_events.inc(&event_attrs);

    let mut record = LogRecordBuilder::new(PKG_NAME, val::FORK_COMPLETED, "sandbox fork completed")
        .severity(LogSeverity::Info)
        .operation(pico_telemetry::lifecycle::LifecycleOperation::Fork)
        .outcome("success");
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::info!(
        event = val::FORK_COMPLETED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        latency_ms = latency_ms,
        "sandbox fork completed"
    );
}

#[expect(dead_code, reason = "emitted when fork lifecycle is implemented")]
pub(crate) fn emit_fork_failed(
    sandbox_id: &str,
    latency_ms: u64,
    reason: &str,
    tenant_id: Option<&str>,
) {
    let latency_attrs = crate::metrics::latency_attrs(val::FORK_FAILED, tenant_id);
    HOST_METRICS
        .fork_latency
        .record(latency_ms as f64 / 1000.0, &latency_attrs);

    let event_attrs = crate::metrics::event_reason_attrs(val::FORK_FAILED, reason, tenant_id);
    HOST_METRICS.fork_events.inc(&event_attrs);

    let mut record = LogRecordBuilder::new(PKG_NAME, val::FORK_FAILED, "sandbox fork failed")
        .severity(LogSeverity::Error)
        .operation(pico_telemetry::lifecycle::LifecycleOperation::Fork)
        .outcome("failed")
        .reason(reason);
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            record = record.tenant_id(tid);
        }
    } else {
        record = record.sandbox_id(sandbox_id);
    }
    record.build().emit();

    tracing::error!(
        event = val::FORK_FAILED,
        sandbox_id = %tracing_identity_label(sandbox_id, tenant_id),
        latency_ms = latency_ms,
        reason = %reason,
        "sandbox fork failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_boot_command() -> BootCommand {
        BootCommand {
            sandbox_id: "sbx_test01".into(),
            operation_id: OperationId::generate(),
            assigned_host_id: "host-1".into(),
            assigned_cell_id: "cell-a".into(),
            assignment_fencing_token: FencingToken::default(),
            policy_epoch: 1,
            timeout_secs: 60,
        }
    }

    fn test_boot_not_ready_report() -> BootReport {
        BootReport {
            sandbox_id: "sbx_test01".into(),
            operation_id: OperationId::generate(),
            status: BootStatus::NotReady,
            reason: Some(NonReadyReason::Protocol),
            observed_state: SandboxState::Failed,
            latency_ms: 1500,
            diagnostics: vec![],
        }
    }

    fn test_boot_ready_report() -> BootReport {
        BootReport {
            sandbox_id: "sbx_test01".into(),
            operation_id: OperationId::generate(),
            status: BootStatus::Ready,
            reason: None,
            observed_state: SandboxState::Running,
            latency_ms: 800,
            diagnostics: vec![],
        }
    }

    #[test]
    fn non_ready_reason_to_outcome_maps_all_variants() {
        assert_eq!(
            non_ready_reason_to_outcome(NonReadyReason::Image),
            "image_unavailable"
        );
        assert_eq!(
            non_ready_reason_to_outcome(NonReadyReason::Network),
            "network_setup_failed"
        );
        assert_eq!(
            non_ready_reason_to_outcome(NonReadyReason::Resource),
            "no_capacity"
        );
        assert_eq!(
            non_ready_reason_to_outcome(NonReadyReason::Backend),
            "runtime_start_failed"
        );
        assert_eq!(
            non_ready_reason_to_outcome(NonReadyReason::Protocol),
            "protocol_error"
        );
        assert_eq!(
            non_ready_reason_to_outcome(NonReadyReason::Timeout),
            "deadline_exceeded"
        );
        assert_eq!(
            non_ready_reason_to_outcome(NonReadyReason::Cleanup),
            "cleanup_incomplete"
        );
    }

    #[test]
    fn boot_not_ready_record_json_has_all_correlation_ids() {
        let sandbox_id = "sbx_test01";
        let operation_id = "opr_test01";

        let log_record = LogRecordBuilder::new(
            PKG_NAME,
            val::BOOT_NOT_READY,
            "sandbox boot did not become ready",
        )
        .severity(LogSeverity::Error)
        .sandbox_id(sandbox_id)
        .operation_id(operation_id)
        .lifecycle_state("Failed")
        .outcome("protocol_error")
        .reason("protocol")
        .build();

        let json = log_record.to_json();

        assert!(json.contains(&format!("\"sandbox_id\":\"{}\"", sandbox_id)));
        assert!(json.contains(&format!("\"operation_id\":\"{}\"", operation_id)));
        assert!(json.contains(r#""outcome":"protocol_error""#));
        assert!(json.contains(r#""reason":"protocol""#));
        assert!(json.contains(r#""lifecycle_state":"Failed""#));
        assert_eq!(log_record.severity, LogSeverity::Error);
    }

    #[test]
    fn boot_ready_structured_log_has_success_outcome() {
        let report = test_boot_ready_report();

        let log_record = LogRecordBuilder::new(PKG_NAME, val::BOOT_READY, "sandbox boot completed")
            .severity(LogSeverity::Info)
            .sandbox_id(&report.sandbox_id)
            .operation_id(report.operation_id.as_str())
            .lifecycle_state("Running")
            .outcome("success")
            .build();

        let json = log_record.to_json();
        assert!(json.contains(r#""outcome":"success""#));
        assert_eq!(log_record.severity, LogSeverity::Info);
    }

    #[test]
    fn boot_not_ready_emits_error_severity() {
        let report = test_boot_not_ready_report();
        let log_record = LogRecordBuilder::new(
            PKG_NAME,
            val::BOOT_NOT_READY,
            "sandbox boot did not become ready",
        )
        .severity(LogSeverity::Error)
        .sandbox_id(&report.sandbox_id)
        .operation_id(report.operation_id.as_str())
        .lifecycle_state("Failed")
        .outcome("protocol_error")
        .reason("protocol")
        .build();

        assert_eq!(log_record.severity, LogSeverity::Error);
        assert_eq!(log_record.severity_num, 17);
    }

    #[test]
    fn lifecycle_non_ready_outcome_includes_both_sandbox_and_operation_id() {
        let report = test_boot_not_ready_report();
        let log_record = LogRecordBuilder::new(
            PKG_NAME,
            val::BOOT_NOT_READY,
            "sandbox boot did not become ready",
        )
        .severity(LogSeverity::Error)
        .sandbox_id(&report.sandbox_id)
        .operation_id(report.operation_id.as_str())
        .outcome("protocol_error")
        .reason("protocol")
        .build();

        assert!(log_record.sandbox_id.is_some());
        assert!(log_record.operation_id.is_some());
        assert!(log_record.outcome.is_some());
        assert!(log_record.reason.is_some());
    }

    #[test]
    fn structured_log_does_not_leak_secret_patterns() {
        let log_record = LogRecordBuilder::new(
            PKG_NAME,
            val::BOOT_NOT_READY,
            "sandbox boot did not become ready",
        )
        .severity(LogSeverity::Error)
        .sandbox_id("sbx_test01")
        .operation_id("opr_test01")
        .outcome("protocol_error")
        .reason("protocol")
        .build();

        let json = log_record.to_json();

        assert!(!json.contains("token"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("password"));
        assert!(!json.contains("private_key"));
        assert!(!json.contains("api_key"));
        assert!(json.contains("sbx_test01"));
        assert!(json.contains("opr_test01"));
    }

    #[test]
    fn all_lifecycle_events_can_be_emitted_without_panic() {
        let command = test_boot_command();
        let report = test_boot_ready_report();
        let not_ready = test_boot_not_ready_report();

        emit_boot_start(&command, None);
        emit_boot_ready(&report, None);
        emit_boot_not_ready(&not_ready, None);
        emit_boot_cleanup(&report, None);

        emit_create_started("sbx_test02", None);
        emit_create_completed("sbx_test02", 100, None);
        emit_create_failed("sbx_test02", 200, "internal_error", None);

        emit_prepare_started("sbx_test03", None);
        emit_prepare_completed("sbx_test03", 150, None);
        emit_prepare_failed("sbx_test03", 250, "image_unavailable", None);

        emit_destroy_started("sbx_test04", None);
        emit_destroy_completed("sbx_test04", 300, None);
        emit_destroy_failed("sbx_test04", 400, "cleanup_incomplete", None);
    }
}
