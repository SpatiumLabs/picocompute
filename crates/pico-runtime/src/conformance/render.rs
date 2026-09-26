use serde_json::Value;

use super::ConformanceReport;

/// Renders a conformance report as a JSON value.
#[must_use]
pub fn render_json(report: &ConformanceReport) -> Value {
    serde_json::to_value(report)
        .unwrap_or_else(|e| serde_json::json!({"error": format!("serialization failed: {}", e)}))
}

/// Renders a conformance report as a human-readable text block.
#[must_use]
pub fn render_text(report: &ConformanceReport) -> String {
    report.to_string()
}
