//! Validation report types.
//!
//! A `ValidationReport` collects the outcome of every validation check run
//! against a PicoCompute guest image manifest and associated artifacts.

use serde::{Deserialize, Serialize};

/// A structured validation report for a PicoCompute guest image.
///
/// Can be serialized as JSON, attached as OCI referrer evidence, and used
/// as an automated promotion gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Schema version of the report format itself.
    pub report_schema: String,

    /// The image being validated.
    pub image_id: String,

    /// Release version of the image.
    pub release_version: String,

    /// UTC timestamp when validation was performed (epoch seconds).
    pub validated_at: i64,

    /// Whether all checks passed.
    pub all_checks_passed: bool,

    /// Total number of checks run.
    pub total_checks: usize,

    /// Number of passing checks.
    pub passed_checks: usize,

    /// Number of failing checks.
    pub failed_checks: usize,

    /// Individual check results.
    pub checks: Vec<CheckResult>,
}

/// Result of a single validation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Human-readable name of the check.
    pub name: String,

    /// Outcome of the check.
    pub outcome: CheckOutcome,
}

/// Outcome of a single validation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "message", rename_all = "snake_case")]
pub enum CheckOutcome {
    /// Check passed.
    Pass,
    /// Check failed with an error message.
    Fail(String),
    /// Check was skipped (e.g., not applicable to this variant).
    Skip(String),
}

impl ValidationReport {
    /// Create a new, empty validation report for the given image.
    pub fn new(image_id: String, release_version: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            report_schema: "1.0".into(),
            image_id,
            release_version,
            validated_at: now,
            all_checks_passed: true,
            total_checks: 0,
            passed_checks: 0,
            failed_checks: 0,
            checks: Vec::new(),
        }
    }

    /// Add a check result and update aggregate counts.
    pub fn add_check(&mut self, check: CheckResult) {
        match &check.outcome {
            CheckOutcome::Pass => self.passed_checks += 1,
            CheckOutcome::Fail(_) => {
                self.failed_checks += 1;
                self.all_checks_passed = false;
            }
            CheckOutcome::Skip(_) => { /* skipped checks don't affect pass/fail */ }
        }
        self.total_checks += 1;
        self.checks.push(check);
    }

    /// Returns true if all checks passed (no failures).
    pub fn all_passed(&self) -> bool {
        self.all_checks_passed
    }

    /// Returns the number of passing checks.
    pub fn passed_count(&self) -> usize {
        self.passed_checks
    }

    /// Returns the number of failing checks.
    pub fn failed_count(&self) -> usize {
        self.failed_checks
    }

    /// Returns a list of failed check results.
    pub fn failed_checks(&self) -> Vec<&CheckResult> {
        self.checks
            .iter()
            .filter(|c| matches!(c.outcome, CheckOutcome::Fail(_)))
            .collect()
    }

    /// Returns names of failed checks.
    pub fn failed_check_names(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|c| matches!(c.outcome, CheckOutcome::Fail(_)))
            .map(|c| c.name.as_str())
            .collect()
    }

    /// Returns a summary string suitable for logging.
    pub fn summary(&self) -> String {
        format!(
            "{}: {}/{} passed, {} failed",
            if self.all_checks_passed {
                "PASS"
            } else {
                "FAIL"
            },
            self.passed_checks,
            self.total_checks,
            self.failed_checks
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_report_has_empty_checks() {
        let report = ValidationReport::new("test".into(), "1.0".into());
        assert_eq!(report.total_checks, 0);
        assert_eq!(report.passed_count(), 0);
        assert_eq!(report.failed_count(), 0);
        assert!(report.all_passed());
    }

    #[test]
    fn add_pass_keeps_all_passed() {
        let mut report = ValidationReport::new("test".into(), "1.0".into());
        report.add_check(CheckResult {
            name: "check-1".into(),
            outcome: CheckOutcome::Pass,
        });
        assert!(report.all_passed());
        assert_eq!(report.passed_count(), 1);
        assert_eq!(report.failed_count(), 0);
    }

    #[test]
    fn add_fail_sets_all_passed_to_false() {
        let mut report = ValidationReport::new("test".into(), "1.0".into());
        report.add_check(CheckResult {
            name: "check-1".into(),
            outcome: CheckOutcome::Fail("error".into()),
        });
        assert!(!report.all_passed());
        assert_eq!(report.failed_count(), 1);
    }

    #[test]
    fn skip_does_not_affect_counts() {
        let mut report = ValidationReport::new("test".into(), "1.0".into());
        report.add_check(CheckResult {
            name: "check-1".into(),
            outcome: CheckOutcome::Skip("not applicable".into()),
        });
        assert!(report.all_passed());
        assert_eq!(report.total_checks, 1);
        assert_eq!(report.passed_count(), 0);
        assert_eq!(report.failed_count(), 0);
    }

    #[test]
    fn failed_check_names_returns_names() {
        let mut report = ValidationReport::new("test".into(), "1.0".into());
        report.add_check(CheckResult {
            name: "pass".into(),
            outcome: CheckOutcome::Pass,
        });
        report.add_check(CheckResult {
            name: "fail-1".into(),
            outcome: CheckOutcome::Fail("err".into()),
        });
        report.add_check(CheckResult {
            name: "fail-2".into(),
            outcome: CheckOutcome::Fail("err2".into()),
        });

        let names = report.failed_check_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"fail-1"));
        assert!(names.contains(&"fail-2"));
    }

    #[test]
    fn summary_reflects_state() {
        let mut report = ValidationReport::new("test".into(), "1.0".into());
        report.add_check(CheckResult {
            name: "pass".into(),
            outcome: CheckOutcome::Pass,
        });
        let s = report.summary();
        assert!(s.contains("PASS"));
        assert!(s.contains("1/1"));

        report.add_check(CheckResult {
            name: "fail".into(),
            outcome: CheckOutcome::Fail("err".into()),
        });
        let s = report.summary();
        assert!(s.contains("FAIL"));
        assert!(s.contains("1/2"));
    }

    #[test]
    fn report_json_roundtrip() {
        let mut report = ValidationReport::new("img-1".into(), "0.1.0".into());
        report.add_check(CheckResult {
            name: "schema".into(),
            outcome: CheckOutcome::Pass,
        });
        report.add_check(CheckResult {
            name: "kernel".into(),
            outcome: CheckOutcome::Fail("missing".into()),
        });
        report.add_check(CheckResult {
            name: "optional".into(),
            outcome: CheckOutcome::Skip("not applicable".into()),
        });

        let json = serde_json::to_string_pretty(&report).unwrap();

        let parsed: ValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.image_id, "img-1");
        assert!(!parsed.all_passed());
        assert_eq!(parsed.total_checks, 3);
        assert_eq!(parsed.passed_count(), 1);
        assert_eq!(parsed.failed_count(), 1);
        assert_eq!(parsed.checks.len(), 3);

        let fail_check = &parsed.checks[1];
        match &fail_check.outcome {
            CheckOutcome::Fail(msg) => assert_eq!(msg, "missing"),
            other => panic!("expected Fail, got {:?}", other),
        }

        let skip_check = &parsed.checks[2];
        match &skip_check.outcome {
            CheckOutcome::Skip(msg) => assert_eq!(msg, "not applicable"),
            other => panic!("expected Skip, got {:?}", other),
        }
    }
}
