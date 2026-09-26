use serde_json::Value;

use super::{IsolationReport, isolation_floor_as_stable_str};

pub fn render_json(report: &IsolationReport) -> Value {
    serde_json::json!({
        "schema_version": report.schema_version,
        "passed": report.passed,
        "total_latency_ms": report.total_latency_ms,
        "expected_isolation_floor": isolation_floor_as_stable_str(report.expected_isolation_floor),
        "actual_isolation_floor": report.actual_isolation_floor.map(isolation_floor_as_stable_str),
        "isolation_floor_assertion_passed": report.isolation_floor_assertion_passed,
        "checks": report.checks.iter().map(|c| {
            serde_json::json!({
                "name": c.name,
                "outcome": format!("{}", c.outcome),
                "message": c.message,
                "latency_ms": c.latency_ms,
                "category": format!("{}", c.category),
            })
        }).collect::<Vec<_>>(),
        "evidence": {
            "filesystem_assertions": &report.evidence.filesystem_assertions,
            "process_assertions": &report.evidence.process_assertions,
            "network_assertions": &report.evidence.network_assertions,
            "resource_assertions": &report.evidence.resource_assertions,
            "credential_assertions": &report.evidence.credential_assertions,
            "backend_assertions": &report.evidence.backend_assertions,
            "data_sharing_assertions": &report.evidence.data_sharing_assertions,
            "side_channel_assertions": &report.evidence.side_channel_assertions,
            "backend_metadata": &report.evidence.backend_metadata,
        },
    })
}

pub fn render_text(report: &IsolationReport) -> String {
    report.to_string()
}
