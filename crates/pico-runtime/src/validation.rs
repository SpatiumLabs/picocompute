//! Shared validation report infrastructure for conformance and isolation suites.
//!
//! Both suites produce reports that aggregate check results with pass/fail
//! status, latency tracking, and JSON/text rendering. This module provides
//! the common type-level foundation so each suite focuses on its domain logic.

use std::fmt;

use serde::Serialize;
use serde_json::Value;

/// A single check result shared across validation suites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub message: Option<String>,
    pub latency_ms: u64,
}

impl CheckResult {
    #[must_use]
    pub fn pass(name: impl Into<String>, latency_ms: u64) -> Self {
        Self {
            name: name.into(),
            passed: true,
            message: None,
            latency_ms,
        }
    }

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

/// Renders a collection of check results as a JSON value.
///
/// Each suite provides its own report wrapper via this function.
pub fn checks_json<C>(checks: &[C]) -> Value
where
    C: Serialize,
{
    serde_json::to_value(checks).unwrap_or_default()
}

/// Renders a collection of check results as a text table.
pub fn checks_text(
    header: &str,
    passed: bool,
    total_latency_ms: u64,
    passed_count: usize,
    failed_count: usize,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    writeln!(f, "=== {header} ===")?;
    writeln!(f, "Status: {}", if passed { "PASS" } else { "FAIL" })?;
    writeln!(f, "Total latency: {} ms", total_latency_ms)?;
    writeln!(
        f,
        "Checks: {passed_count} passed, {failed_count} failed ({} total)",
        passed_count + failed_count
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_pass_has_correct_fields() {
        let check = CheckResult::pass("test-check", 42);
        assert_eq!(check.name, "test-check");
        assert!(check.passed);
        assert_eq!(check.latency_ms, 42);
        assert!(check.message.is_none());
    }

    #[test]
    fn check_result_fail_has_correct_fields() {
        let check = CheckResult::fail("test-check", "something broke", 17);
        assert_eq!(check.name, "test-check");
        assert!(!check.passed);
        assert_eq!(check.message.unwrap(), "something broke");
        assert_eq!(check.latency_ms, 17);
    }

    #[test]
    fn checks_json_serializes_correctly() {
        let checks = vec![CheckResult::pass("a", 1), CheckResult::fail("b", "err", 2)];
        let json = checks_json(&checks);
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["name"], "a");
        assert_eq!(arr[1]["passed"], false);
    }
}
