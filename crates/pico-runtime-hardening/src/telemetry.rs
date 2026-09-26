use pico_telemetry::events::SecurityEvent;

use crate::anomaly::AnomalyEvent;
use crate::fim::FimAlert;
use crate::namespaces::NamespaceConfig;

pub fn emit_namespace_isolation(config: &NamespaceConfig) {
    SecurityEvent::namespace_isolation_applied(format!(
        "mount={} pid={} uts={} ipc={} net={}",
        config.mount, config.pid, config.uts, config.ipc, config.net
    ))
    .emit();
}

pub fn emit_behavioral_anomaly(event: &AnomalyEvent) {
    SecurityEvent::behavioral_anomaly(
        &event.sandbox_id,
        &event.sandbox_type,
        event.anomaly_type.as_str(),
        event.severity.as_str(),
        event.confidence,
        &event.syscall_name,
        &event.detail,
        event.timestamp_ns,
    )
    .emit();
}

pub fn emit_file_integrity_alert(alert: &FimAlert) {
    SecurityEvent::file_integrity_violation(
        &alert.sandbox_id,
        &alert.path,
        alert.hook.as_str(),
        alert.mode.as_str(),
        alert.pid,
        alert.tid,
        alert.uid,
        alert.gid,
        alert.denied,
        alert.timestamp_ns,
        &alert.detail,
    )
    .emit();
}
