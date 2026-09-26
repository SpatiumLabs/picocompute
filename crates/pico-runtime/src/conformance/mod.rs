//! Backend conformance test suite for [`RuntimeBackend`] implementations.
//!
//! Every backend must pass these tests to satisfy the PicoCompute lifecycle
//! semantics. The suite covers:
//!
//! - Capability declarations (no silent skips)
//! - Lifecycle operations (prepare, boot, attach, wait-ready, exec)
//! - State machine guards (wrong-state rejection on every method)
//! - Optional suspend/resume/fork
//! - Destroy and cleanup idempotency
//! - Restart reconciliation after partial failure
//! - Resource accounting
//! - Network port exposure and address resolution
//! - Observability (stats, health, diagnostics)
//! - Error taxonomy (typed failures, stable non-ready reasons)
//! - SSH metadata consistency
//!
//! # Quick start
//!
//! ```rust,ignore
//! use pico_runtime::conformance::{run_lifecycle_suite, ConformanceReport};
//!
//! let report = run_lifecycle_suite(&backend, &profile).await.unwrap();
//! assert!(report.passed, "suite did not pass: {:?}", report.failures());
//! ```

mod capabilities;
mod error_taxonomy;
mod idempotency;
mod lifecycle;
mod network;
mod observability;
mod reconciliation;
mod render;
mod ssh;
mod state_guards;

use std::fmt;
use std::time::Instant;

use pico_core::{
    BackendCapabilities, BackendCapability, BackendError, BackendOperation, BackendResult,
    ExecRequest, SandboxConfig, WorkloadClass,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use render::{render_json, render_text};

/// Inputs used by the backend conformance runner.
#[derive(Debug, Clone)]
pub struct ConformanceProfile {
    /// Sandbox configuration used for prepare.
    pub sandbox: SandboxConfig,
    /// Request used to verify exec handoff.
    pub exec: ExecRequest,
    /// Optional child sandbox configuration for fork testing.
    pub fork_child: Option<SandboxConfig>,
}

impl ConformanceProfile {
    /// Creates a minimal profile for unit-test backends.
    #[must_use]
    pub fn unit_default() -> Self {
        Self {
            sandbox: SandboxConfig {
                id: "sbx_conformance".into(),
                memory_limit_bytes: 512 * 1024 * 1024,
                network_isolated: true,
                ..Default::default()
            },
            exec: ExecRequest {
                command: "true".into(),
                args: Vec::new(),
                env: None,
                working_dir: None,
                timeout_secs: Some(1),
            },
            fork_child: None,
        }
    }

    /// Creates a profile with a fork child target.
    #[must_use]
    pub fn with_fork_child(mut self, child_id: impl Into<String>) -> Self {
        let mut child = self.sandbox.clone();
        child.id = child_id.into();
        self.fork_child = Some(child);
        self
    }
}

/// Structured representation of one conformance check outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceCheck {
    /// Human-readable check name (e.g. "state-guard/prepare-requires-pending").
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Explanation when the check fails.
    pub message: Option<String>,
    /// Wall-clock duration of the check in milliseconds.
    pub latency_ms: u64,
}

impl ConformanceCheck {
    /// Creates a passing check result.
    #[must_use]
    pub fn pass(name: impl Into<String>, latency_ms: u64) -> Self {
        Self {
            name: name.into(),
            passed: true,
            message: None,
            latency_ms,
        }
    }

    /// Creates a failing check result.
    #[must_use]
    pub fn fail(name: impl Into<String>, message: impl Into<String>, latency_ms: u64) -> Self {
        Self {
            name: name.into(),
            passed: false,
            message: Some(message.into()),
            latency_ms,
        }
    }
}

/// Summary of resource identities observed during conformance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceAccounting {
    /// Distinct resource classes observed in prepare receipts.
    pub resource_classes: Vec<String>,
    /// Total number of resource receipts returned across all operations.
    pub total_receipts: usize,
    /// Resources left in `remaining` after destroy or cleanup.
    pub remaining_after_destroy: Vec<String>,
}

/// Complete conformance testing report for one backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    /// Overall pass/fail status.
    pub passed: bool,
    /// Total wall-clock duration of the entire suite in milliseconds.
    pub total_latency_ms: u64,
    /// Checks executed in order.
    pub checks: Vec<ConformanceCheck>,
    /// Capabilities the backend declares it does not implement.
    pub unsupported_capabilities: Vec<BackendCapability>,
    /// Capabilities that are required but not declared (fatal).
    pub missing_capabilities: Vec<BackendCapability>,
    /// Resource accounting summary.
    pub resource_accounting: ResourceAccounting,
}

impl ConformanceReport {
    /// Creates a new empty report with a given pass/fail initial state.
    #[must_use]
    pub fn new(passed: bool, total_latency_ms: u64) -> Self {
        Self {
            passed,
            total_latency_ms,
            checks: Vec::new(),
            unsupported_capabilities: Vec::new(),
            missing_capabilities: Vec::new(),
            resource_accounting: ResourceAccounting::default(),
        }
    }

    /// Adds a check result and updates the overall `passed` flag.
    pub fn add_check(&mut self, check: ConformanceCheck) {
        if !check.passed {
            self.passed = false;
        }
        self.checks.push(check);
    }

    /// Returns all failing checks.
    #[must_use]
    pub fn failures(&self) -> Vec<&ConformanceCheck> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    /// Renders the report as a JSON value.
    ///
    /// This is a convenience method that delegates to [`render_json`].
    #[must_use]
    pub fn to_json(&self) -> Value {
        render_json(self)
    }
}

impl fmt::Display for ConformanceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Conformance Report ===")?;
        writeln!(f, "Status: {}", if self.passed { "PASS" } else { "FAIL" })?;
        writeln!(f, "Total latency: {} ms", self.total_latency_ms)?;

        let passed = self.checks.iter().filter(|c| c.passed).count();
        let failed = self.checks.len() - passed;
        writeln!(
            f,
            "Checks: {passed} passed, {failed} failed ({} total)",
            self.checks.len()
        )?;

        if !self.missing_capabilities.is_empty() {
            let names: Vec<String> = self
                .missing_capabilities
                .iter()
                .map(|c| format!("{c:?}"))
                .collect();
            writeln!(f, "Missing capabilities: {}", names.join(", "))?;
        }

        if !self.unsupported_capabilities.is_empty() {
            let names: Vec<String> = self
                .unsupported_capabilities
                .iter()
                .map(|c| format!("{c:?}"))
                .collect();
            writeln!(f, "Unsupported capabilities: {}", names.join(", "))?;
        }

        let acct = &self.resource_accounting;
        writeln!(
            f,
            "Resources: {} classes ({:?}), {} receipts, {} remaining",
            acct.resource_classes.len(),
            acct.resource_classes,
            acct.total_receipts,
            acct.remaining_after_destroy.len(),
        )?;

        for check in &self.checks {
            let mark = if check.passed { "PASS" } else { "FAIL" };
            match &check.message {
                Some(msg) => writeln!(
                    f,
                    "  [{mark}] {name} ({latency}ms): {msg}",
                    name = check.name,
                    latency = check.latency_ms
                )?,
                None => writeln!(
                    f,
                    "  [{mark}] {name} ({latency}ms)",
                    name = check.name,
                    latency = check.latency_ms
                )?,
            }
        }

        Ok(())
    }
}

/// Returns the minimum capability set a backend must declare to pass
/// conformance for the given workload class.
///
/// All profiles require `Boot`, `GuestTransport`, `Exec`, `Stats`, `Health`,
/// and `Diagnostics`. Public-untrusted (and compatibility/Kubernetes) profiles
/// additionally require `GuestReadiness` because hardware-VM backends must
/// prove guest-agent readiness on the attached transport.
///
/// The trusted-fast-path profile omits `GuestReadiness` by design: gVisor
/// proves liveness via `runsc exec` probes during boot and declares no
/// guest-agent handshake, so requiring the capability would reject a
/// correctly-scoped backend.
///
/// Note on `KubernetesIntegrated`: it intentionally keeps the strict set
/// (with `GuestReadiness`). Selection for this class is VM-only and never
/// admits gVisor, so the strict set always composes with selection.
/// Trusted tenants that want gVisor on a Kubernetes cell request
/// `TrustedFastPath` and are validated against that profile instead.
#[must_use]
pub fn required_capabilities_for_workload_class(class: WorkloadClass) -> BackendCapabilities {
    match class {
        WorkloadClass::TrustedFastPath => BackendCapabilities::from([
            BackendCapability::Boot,
            BackendCapability::GuestTransport,
            BackendCapability::Exec,
            BackendCapability::Stats,
            BackendCapability::Health,
            BackendCapability::Diagnostics,
        ]),
        WorkloadClass::PublicUntrusted
        | WorkloadClass::CompatibilityVm
        | WorkloadClass::KubernetesIntegrated => BackendCapabilities::from([
            BackendCapability::Boot,
            BackendCapability::GuestTransport,
            BackendCapability::GuestReadiness,
            BackendCapability::Exec,
            BackendCapability::Stats,
            BackendCapability::Health,
            BackendCapability::Diagnostics,
        ]),
    }
}

/// Runs the full backend conformance suite.
///
/// This is the public-untrusted profile entry point: it requires
/// `GuestReadiness`. Trusted-fast-path backends such as gVisor should use
/// [`run_lifecycle_suite_for_workload_class`] with
/// `WorkloadClass::TrustedFastPath` instead. See that function for
/// fail-fast and error semantics.
pub async fn run_lifecycle_suite(
    backend: &dyn pico_core::RuntimeBackend,
    profile: &ConformanceProfile,
) -> BackendResult<ConformanceReport> {
    run_lifecycle_suite_for_workload_class(backend, profile, WorkloadClass::PublicUntrusted).await
}

/// Runs the full backend conformance suite for an explicit workload class.
///
/// This is the profile-aware entry point. The required
/// capability set comes from [`required_capabilities_for_workload_class`], so
/// a trusted-fast-path backend without `GuestReadiness` (gVisor) can pass
/// while public-untrusted backends must still declare it. It exercises every
/// capability-gated operation, validates state machine guards, checks
/// resource accounting, and verifies error taxonomy.
///
/// # Fail-fast behavior
///
/// The lifecycle phase (`run_lifecycle`) uses early returns on prepare and
/// boot failures because later operations (stats, health, diagnostics, destroy,
/// cleanup) depend on a running runtime. This is intentional: a backend that
/// cannot boot is not conformance-eligible, and skipping dependent steps
/// avoids cascading noise in the report.
///
/// Phase-level checks that operate independently (destroy idempotency, cleanup
/// idempotency, error taxonomy, network behavior, SSH metadata) run regardless
/// of lifecycle outcome, so a backend that fails early still gets a partial
/// report.
///
/// # Errors
///
/// Returns `BackendError` only when the suite itself encounters a setup failure
/// that cannot be attributed to the backend under test. All backend-specific
/// failures are captured in the report.
pub async fn run_lifecycle_suite_for_workload_class(
    backend: &dyn pico_core::RuntimeBackend,
    profile: &ConformanceProfile,
    workload_class: WorkloadClass,
) -> BackendResult<ConformanceReport> {
    let start = Instant::now();

    let metadata = backend.metadata();
    let required = required_capabilities_for_workload_class(workload_class);

    let missing: Vec<BackendCapability> = metadata.capabilities.missing(&required);
    let all_caps = all_capabilities();

    let mut unsupported: Vec<BackendCapability> = Vec::new();
    for cap in &all_caps {
        if !metadata.capabilities.contains(*cap) {
            unsupported.push(*cap);
        }
    }

    let mut report = ConformanceReport::new(missing.is_empty(), 0);
    report.missing_capabilities = missing;
    report.unsupported_capabilities = unsupported;

    if !report.passed {
        report.total_latency_ms = start.elapsed().as_millis() as u64;
        return Ok(report);
    }

    capabilities::test_capability_declarations(backend, &mut report).await;
    state_guards::test_state_guards(backend, profile, &mut report).await;

    {
        let _ =
            lifecycle::run_lifecycle(backend, profile, &metadata.capabilities, &mut report).await;
    }

    idempotency::test_destroy_idempotency(backend, &mut report).await;
    idempotency::test_cleanup_idempotency(backend, &mut report).await;
    reconciliation::test_restart_reconciliation(backend, profile, &mut report).await;
    error_taxonomy::test_error_taxonomy(backend, profile, &mut report).await;
    network::test_network_behavior(backend, &mut report);
    ssh::test_ssh_metadata(backend, &mut report);
    observability::test_observability(backend, &mut report).await;

    report.total_latency_ms = start.elapsed().as_millis() as u64;
    Ok(report)
}

/// Returns the full set of all declared BackendCapability variants.
fn all_capabilities() -> Vec<BackendCapability> {
    vec![
        BackendCapability::Boot,
        BackendCapability::GuestTransport,
        BackendCapability::GuestReadiness,
        BackendCapability::Exec,
        BackendCapability::Suspend,
        BackendCapability::Resume,
        BackendCapability::Fork,
        BackendCapability::Stats,
        BackendCapability::Health,
        BackendCapability::Diagnostics,
        BackendCapability::BackendManagedPortForwarding,
        BackendCapability::SnapshotRestore,
        BackendCapability::EbpFNetworking,
    ]
}

/// Runs the backward-compatible single-lifecycle conformance runner.
///
/// This is the original contract from `mock.rs` preserved for existing callers.
/// New code should prefer [`run_lifecycle_suite`] for comprehensive reporting.
///
/// This is the public-untrusted profile entry point: it requires
/// `GuestReadiness`. Trusted-fast-path callers should use
/// [`run_backend_conformance_for_workload_class`] instead.
pub async fn run_backend_conformance(
    backend: &dyn pico_core::RuntimeBackend,
    profile: &ConformanceProfile,
) -> BackendResult<Vec<BackendOperation>> {
    run_backend_conformance_for_workload_class(backend, profile, WorkloadClass::PublicUntrusted)
        .await
}

/// Runs the backward-compatible single-lifecycle runner for an explicit
/// workload class.
///
/// The required capability set comes from
/// [`required_capabilities_for_workload_class`]. When the backend does not
/// declare `GuestReadiness` (trusted-fast-path without a guest-agent
/// handshake), the `wait_ready` step is skipped rather than failed, mirroring
/// [`lifecycle`](self) behavior in [`run_lifecycle_suite_for_workload_class`].
pub async fn run_backend_conformance_for_workload_class(
    backend: &dyn pico_core::RuntimeBackend,
    profile: &ConformanceProfile,
    workload_class: WorkloadClass,
) -> BackendResult<Vec<BackendOperation>> {
    let required = required_capabilities_for_workload_class(workload_class);
    let metadata = backend.metadata();
    if let Some(capability) = metadata.capabilities.first_missing(&required) {
        return Err(BackendError::Unsupported { capability });
    }

    let mut completed = Vec::new();
    backend.prepare(&profile.sandbox).await?;
    completed.push(BackendOperation::Prepare);
    backend.boot().await?;
    completed.push(BackendOperation::Boot);
    let transport = backend.attach_transport().await?;
    completed.push(BackendOperation::AttachTransport);
    if metadata
        .capabilities
        .contains(BackendCapability::GuestReadiness)
    {
        backend.wait_ready(&transport).await?;
        completed.push(BackendOperation::WaitReady);
    }
    backend.exec(profile.exec.clone()).await?;
    completed.push(BackendOperation::Exec);
    backend.stats().await?;
    completed.push(BackendOperation::Stats);
    backend.health().await?;
    completed.push(BackendOperation::Health);
    backend.diagnostics().await?;
    completed.push(BackendOperation::Diagnostics);

    if metadata.capabilities.contains(BackendCapability::Suspend) {
        backend.suspend().await?;
        completed.push(BackendOperation::Suspend);
    }
    if metadata.capabilities.contains(BackendCapability::Resume) {
        backend.resume().await?;
        completed.push(BackendOperation::Resume);
    }
    if metadata.capabilities.contains(BackendCapability::Fork) {
        let mut child = profile.sandbox.clone();
        child.id = format!("{}-child", child.id);
        backend.fork(&child).await?;
        completed.push(BackendOperation::Fork);
    }

    backend.destroy().await?;
    completed.push(BackendOperation::Destroy);
    backend.cleanup().await?;
    completed.push(BackendOperation::Cleanup);

    Ok(completed)
}
