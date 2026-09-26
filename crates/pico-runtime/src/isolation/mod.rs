//! Isolation boundary validation suite for runtime backends.
//!
//! Every backend must pass these tests to prove that intended filesystem,
//! process, network, resource, credential, virtualization, and data-sharing
//! boundaries hold before production launch.
//!
//! ## Scope and limitations
//!
//! When `live_boundary_tests` is `false` (the default in CI), the suite
//! validates **policy, configuration, metadata assertions, and backend
//! classification invariants**. These checks confirm that boundary
//! mechanisms are declared and correctly configured — they do not test
//! runtime enforcement against actual VM or container backends.
//!
//! Checks that require live hardware (side-channel observables, process
//! signal isolation, PID namespace isolation) are marked `Skipped` when
//! not in live mode. Skipped checks do not affect the overall pass/fail
//! status. To run live boundary probing, set `live_boundary_tests: true`
//! and provide a real backend (Firecracker, gVisor, QEMU).
//!
//! ## Covered boundaries
//!
//! - Filesystem read/write/mount boundary behavior
//! - Process visibility and signal isolation (live-mode only)
//! - Network allow/deny policy and DNS/egress behavior
//! - Resource-control enforcement
//! - Credential and snapshot exclusion
//! - Backend-specific boundary differences
//! - VM and sandbox escape-resistance assumptions
//! - Safe data sharing between parent/child sandboxes, host, guest, and exports
//! - Timing, resource, and cache-observable side effects (live-mode only)
//!
//! # Quick start
//!
//! ```rust,ignore
//! use pico_runtime::isolation::{run_isolation_suite, IsolationReport};
//!
//! let report = run_isolation_suite(&backend, &profile).await.unwrap();
//! assert!(report.passed, "suite did not pass: {:?}", report.failures());
//! ```

mod backend;
mod credentials;
mod data_sharing;
mod filesystem;
mod network;
mod process;
mod render;
mod resources;
mod side_channels;

use std::fmt;
use std::time::Instant;

use pico_core::backend_selection::IsolationFloor;
use pico_core::{BackendResult, RuntimeBackend};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use render::{render_json, render_text};

const ISOLATION_REPORT_SCHEMA_VERSION: u32 = 1;

/// Configuration for the isolation boundary validation run.
#[derive(Debug, Clone)]
pub struct IsolationProfile {
    /// Inputs shared with the conformance profile.
    pub conformance: crate::conformance::ConformanceProfile,
    /// Expected isolation floor for the backend under test.
    pub expected_isolation_floor: IsolationFloor,
    /// Whether to run live-boundary tests that require real infrastructure.
    ///
    /// When `false` (default), checks that require live hardware verification
    /// are marked `Skipped` rather than auto-passing. Set to `true` when
    /// running against a real backend (Firecracker, gVisor, QEMU) with actual
    /// VM/container isolation to exercise enforcement.
    pub live_boundary_tests: bool,
    /// When `true`, side-channel probes on non-x86_64 or non-Linux platforms
    /// produce `Fail` rather than passing with platform-limitation notes.
    ///
    /// Default `false` (lenient) is appropriate for CI and development. Set
    /// to `true` in production validation profiles where reduced isolation
    /// assurance on non-x86 / non-Linux must be surfaced as a hard failure.
    pub requires_strong_side_channel_validation: bool,
}

impl IsolationProfile {
    /// Creates a unit-test profile with Firecracker (microVM) expectations.
    #[must_use]
    pub fn unit_firecracker() -> Self {
        Self {
            conformance: crate::conformance::ConformanceProfile::unit_default(),
            expected_isolation_floor: IsolationFloor::MicroVm,
            live_boundary_tests: false,
            requires_strong_side_channel_validation: false,
        }
    }

    /// Creates a unit-test profile with gVisor (container) expectations.
    #[must_use]
    pub fn unit_gvisor() -> Self {
        Self {
            conformance: crate::conformance::ConformanceProfile::unit_default(),
            expected_isolation_floor: IsolationFloor::Container,
            live_boundary_tests: false,
            requires_strong_side_channel_validation: false,
        }
    }

    /// Creates a unit-test profile with QEMU (VM) expectations.
    #[must_use]
    pub fn unit_qemu() -> Self {
        Self {
            conformance: crate::conformance::ConformanceProfile::unit_default(),
            expected_isolation_floor: IsolationFloor::Vm,
            live_boundary_tests: false,
            requires_strong_side_channel_validation: false,
        }
    }
}

/// Terminal outcome of a boundary check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckOutcome {
    /// The check executed and passed.
    Pass,
    /// The check executed and failed.
    Fail,
    /// The check was skipped because it requires live hardware or a
    /// backend capability not available in the current environment.
    /// Skipped checks do not affect the overall pass/fail status.
    Skipped,
}

impl CheckOutcome {
    /// Returns true when the check definitively passed.
    pub fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Returns true when the check definitively failed.
    pub fn is_fail(self) -> bool {
        matches!(self, Self::Fail)
    }

    /// Returns true when the check was skipped (not run).
    pub fn is_skipped(self) -> bool {
        matches!(self, Self::Skipped)
    }
}

impl fmt::Display for CheckOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Skipped => write!(f, "SKIP"),
        }
    }
}

/// Structured representation of one isolation boundary check outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryCheck {
    /// Human-readable check name (e.g. "filesystem/read-boundary").
    pub name: String,
    /// Terminal outcome of this check.
    pub outcome: CheckOutcome,
    /// Explanation when the check fails or is skipped.
    pub message: Option<String>,
    /// Wall-clock duration of the check in milliseconds.
    pub latency_ms: u64,
    /// Category this check belongs to.
    pub category: BoundaryCategory,
}

impl BoundaryCheck {
    /// Creates a passing check result.
    #[must_use]
    pub fn pass(name: impl Into<String>, category: BoundaryCategory, latency_ms: u64) -> Self {
        Self {
            name: name.into(),
            outcome: CheckOutcome::Pass,
            message: None,
            latency_ms,
            category,
        }
    }

    /// Creates a failing check result.
    #[must_use]
    pub fn fail(
        name: impl Into<String>,
        category: BoundaryCategory,
        message: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        Self {
            name: name.into(),
            outcome: CheckOutcome::Fail,
            message: Some(message.into()),
            latency_ms,
            category,
        }
    }

    /// Creates a skipped check result.
    ///
    /// Skipped checks do not count toward the overall pass/fail status
    /// but appear in the report so that reviewers can see which
    /// boundaries were not exercised.
    #[must_use]
    pub fn skip(
        name: impl Into<String>,
        category: BoundaryCategory,
        reason: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        Self {
            name: name.into(),
            outcome: CheckOutcome::Skipped,
            message: Some(reason.into()),
            latency_ms,
            category,
        }
    }
}

/// Boundary validation category for grouping and filtering checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundaryCategory {
    /// Filesystem read/write/mount boundary tests.
    Filesystem,
    /// Process visibility and signal isolation tests.
    Process,
    /// Network allow/deny and egress policy tests.
    Network,
    /// Resource control limit enforcement tests.
    Resources,
    /// Credential and snapshot exclusion tests.
    Credentials,
    /// Backend-specific containment tests.
    Backend,
    /// Data sharing boundary tests (parent/child, host/guest, exports).
    DataSharing,
    /// Side-channel observable tests.
    SideChannels,
}

impl fmt::Display for BoundaryCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filesystem => write!(f, "filesystem"),
            Self::Process => write!(f, "process"),
            Self::Network => write!(f, "network"),
            Self::Resources => write!(f, "resources"),
            Self::Credentials => write!(f, "credentials"),
            Self::Backend => write!(f, "backend"),
            Self::DataSharing => write!(f, "data-sharing"),
            Self::SideChannels => write!(f, "side-channels"),
        }
    }
}

/// Collection of evidence artefacts gathered during boundary validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Filesystem boundary assertions that were validated.
    pub filesystem_assertions: Vec<String>,
    /// Process boundary assertions that were validated.
    pub process_assertions: Vec<String>,
    /// Network boundary assertions that were validated.
    pub network_assertions: Vec<String>,
    /// Resource control boundary assertions that were validated.
    pub resource_assertions: Vec<String>,
    /// Credential boundary assertions that were validated.
    pub credential_assertions: Vec<String>,
    /// Backend-specific boundary assertions that were validated.
    pub backend_assertions: Vec<String>,
    /// Data sharing boundary assertions that were validated.
    pub data_sharing_assertions: Vec<String>,
    /// Side channel boundary assertions that were validated.
    pub side_channel_assertions: Vec<String>,
    /// Backend metadata collected during the run.
    pub backend_metadata: Option<Value>,
}

/// Complete isolation boundary validation report for one backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationReport {
    /// Schema version for forward compatibility of the report format.
    pub schema_version: u32,
    /// Overall pass/fail status.
    ///
    /// Set to `false` when any check has outcome `Fail`. Skipped checks
    /// do not affect this flag.
    pub passed: bool,
    /// Total wall-clock duration of the entire suite in milliseconds.
    pub total_latency_ms: u64,
    /// Checks executed in order.
    pub checks: Vec<BoundaryCheck>,
    /// Expected isolation floor for the backend under test.
    pub expected_isolation_floor: IsolationFloor,
    /// Backend's declared isolation floor (derived from RuntimeType).
    pub actual_isolation_floor: Option<IsolationFloor>,
    /// Whether isolation floor assertion passed.
    pub isolation_floor_assertion_passed: bool,
    /// Evidence bundle gathered during the run.
    pub evidence: EvidenceBundle,
}

impl IsolationReport {
    /// Creates a new empty report.
    #[must_use]
    pub fn new(passed: bool, total_latency_ms: u64) -> Self {
        Self {
            schema_version: ISOLATION_REPORT_SCHEMA_VERSION,
            passed,
            total_latency_ms,
            checks: Vec::new(),
            expected_isolation_floor: IsolationFloor::MicroVm,
            actual_isolation_floor: None,
            isolation_floor_assertion_passed: false,
            evidence: EvidenceBundle::default(),
        }
    }

    /// Adds a check result and updates the overall `passed` flag.
    ///
    /// Only `Fail` outcomes flip `passed` to `false`. `Skipped` checks
    /// are recorded but do not affect the overall status.
    pub fn add_check(&mut self, check: BoundaryCheck) {
        if check.outcome.is_fail() {
            self.passed = false;
        }
        self.checks.push(check);
    }

    /// Returns all failing checks.
    #[must_use]
    pub fn failures(&self) -> Vec<&BoundaryCheck> {
        self.checks.iter().filter(|c| c.outcome.is_fail()).collect()
    }

    /// Returns all skipped checks.
    #[must_use]
    pub fn skipped(&self) -> Vec<&BoundaryCheck> {
        self.checks
            .iter()
            .filter(|c| c.outcome.is_skipped())
            .collect()
    }

    /// Returns failing checks filtered by category.
    #[must_use]
    pub fn failures_by_category(&self, category: BoundaryCategory) -> Vec<&BoundaryCheck> {
        self.checks
            .iter()
            .filter(|c| c.outcome.is_fail() && c.category == category)
            .collect()
    }

    /// Returns counts by category.
    #[must_use]
    pub fn category_counts(&self) -> Vec<(BoundaryCategory, usize, usize, usize)> {
        use hashbrown::HashMap;
        let mut counts: HashMap<BoundaryCategory, (usize, usize, usize)> = HashMap::new();
        for check in &self.checks {
            let entry = counts.entry(check.category).or_default();
            match check.outcome {
                CheckOutcome::Pass => entry.0 += 1,
                CheckOutcome::Fail => entry.1 += 1,
                CheckOutcome::Skipped => entry.2 += 1,
            }
        }
        let mut results: Vec<(BoundaryCategory, usize, usize, usize)> = counts
            .into_iter()
            .map(|(cat, (pass, fail, skip))| (cat, pass, fail, skip))
            .collect();
        results.sort_by_key(|(cat, _, _, _)| category_ordinal(*cat));
        results
    }

    /// Renders the report as a JSON value.
    #[must_use]
    pub fn to_json(&self) -> Value {
        render_json(self)
    }
}

impl fmt::Display for IsolationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Isolation Boundary Validation Report ===")?;
        writeln!(f, "Schema version: {}", self.schema_version)?;
        writeln!(f, "Status: {}", if self.passed { "PASS" } else { "FAIL" })?;
        writeln!(f, "Total latency: {} ms", self.total_latency_ms)?;

        let passed = self.checks.iter().filter(|c| c.outcome.is_pass()).count();
        let failed = self.checks.iter().filter(|c| c.outcome.is_fail()).count();
        let skipped = self.checks.len() - passed - failed;
        writeln!(
            f,
            "Checks: {passed} passed, {failed} failed, {skipped} skipped ({} total)",
            self.checks.len()
        )?;

        if let Some(actual) = self.actual_isolation_floor {
            writeln!(
                f,
                "Isolation floor: expected {}, actual {} - {}",
                isolation_floor_as_stable_str(self.expected_isolation_floor),
                isolation_floor_as_stable_str(actual),
                if self.isolation_floor_assertion_passed {
                    "PASS"
                } else {
                    "FAIL"
                }
            )?;
        }

        for (category, pass, fail, skip) in self.category_counts() {
            if skip > 0 {
                writeln!(f, "  {category}: {pass} pass, {fail} fail, {skip} skip")?;
            } else {
                writeln!(f, "  {category}: {pass} pass, {fail} fail")?;
            }
        }

        for check in &self.checks {
            match &check.message {
                Some(msg) => writeln!(
                    f,
                    "  [{outcome}] {name} [{cat}] ({latency}ms): {msg}",
                    outcome = check.outcome,
                    name = check.name,
                    cat = check.category,
                    latency = check.latency_ms
                )?,
                None => writeln!(
                    f,
                    "  [{outcome}] {name} [{cat}] ({latency}ms)",
                    outcome = check.outcome,
                    name = check.name,
                    cat = check.category,
                    latency = check.latency_ms
                )?,
            }
        }

        Ok(())
    }
}

/// Returns a stable string representation for an isolation floor.
///
/// Unlike the Debug format, this string is a stable API contract
/// safe for JSON rendering and cross-tool comparison.
#[must_use]
pub fn isolation_floor_as_stable_str(floor: IsolationFloor) -> &'static str {
    match floor {
        IsolationFloor::Container => "container",
        IsolationFloor::MicroVm => "microvm",
        IsolationFloor::Vm => "vm",
    }
}

/// Runs the full isolation boundary validation suite.
///
/// Exercises filesystem, process, network, resource, credential, backend,
/// data-sharing, and side-channel boundary assertions. Returns a structured
/// [`IsolationReport`] suitable for CI reporting and security launch gate review.
///
/// When `profile.live_boundary_tests` is `false`, checks that require live
/// hardware verification (process isolation, side-channel observables) are
/// marked `Skipped` rather than auto-passing. To run full enforcement testing,
/// set `live_boundary_tests: true` with a real backend.
///
/// # Errors
///
/// Returns `BackendError` only when the suite itself encounters a setup failure
/// that cannot be attributed to the backend under test. All backend-specific
/// failures are captured in the report.
pub async fn run_isolation_suite(
    backend: &dyn RuntimeBackend,
    profile: &IsolationProfile,
) -> BackendResult<IsolationReport> {
    let start = Instant::now();

    let metadata = backend.metadata();
    let mut report = IsolationReport::new(true, 0);
    report.expected_isolation_floor = profile.expected_isolation_floor;
    report.evidence.backend_metadata = Some(serde_json::to_value(&metadata).unwrap_or_default());

    validate_isolation_floor(
        &metadata.runtime,
        profile.expected_isolation_floor,
        &mut report,
    );

    filesystem::validate_filesystem_boundaries(backend, profile, &mut report).await;
    process::validate_process_boundaries(backend, profile, &mut report).await;
    network::validate_network_boundaries(backend, profile, &mut report).await;
    resources::validate_resource_boundaries(backend, profile, &mut report).await;
    credentials::validate_credential_boundaries(backend, profile, &mut report).await;
    backend::validate_backend_boundaries(backend, profile, &mut report).await;
    data_sharing::validate_data_sharing_boundaries(backend, profile, &mut report).await;
    side_channels::validate_side_channel_boundaries(backend, profile, &mut report).await;

    report.total_latency_ms = start.elapsed().as_millis() as u64;
    Ok(report)
}

/// Validates that the backend's isolation floor meets or exceeds the expected minimum.
fn validate_isolation_floor(
    runtime: &pico_core::RuntimeType,
    expected: IsolationFloor,
    report: &mut IsolationReport,
) {
    let t0 = Instant::now();
    let actual = isolation_floor_for_runtime(runtime);
    report.actual_isolation_floor = Some(actual);

    let passed = actual >= expected;
    report.isolation_floor_assertion_passed = passed;

    if passed {
        report.add_check(BoundaryCheck::pass(
            "isolation-floor/assertion",
            BoundaryCategory::Backend,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "isolation-floor/assertion",
            BoundaryCategory::Backend,
            format!(
                "expected at least {} isolation, got {} from {:?}",
                isolation_floor_as_stable_str(expected),
                isolation_floor_as_stable_str(actual),
                runtime
            ),
            t0.elapsed().as_millis() as u64,
        ));
    }
}

/// Maps a runtime type to the isolation floor it provides.
fn isolation_floor_for_runtime(runtime: &pico_core::RuntimeType) -> IsolationFloor {
    use pico_core::RuntimeType;
    match runtime {
        RuntimeType::Firecracker | RuntimeType::RemoteFirecracker => IsolationFloor::MicroVm,
        RuntimeType::Qemu => IsolationFloor::Vm,
        RuntimeType::GVisor => IsolationFloor::Container,
    }
}

fn category_ordinal(cat: BoundaryCategory) -> u8 {
    match cat {
        BoundaryCategory::Filesystem => 0,
        BoundaryCategory::Process => 1,
        BoundaryCategory::Network => 2,
        BoundaryCategory::Resources => 3,
        BoundaryCategory::Credentials => 4,
        BoundaryCategory::Backend => 5,
        BoundaryCategory::DataSharing => 6,
        BoundaryCategory::SideChannels => 7,
    }
}
