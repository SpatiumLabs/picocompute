use std::time::SystemTime;

use tracing::info;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityEvent {
    pub event: String,
    pub component: String,
    pub detail: String,
    pub timestamp: SystemTime,
    pub profile_version: Option<String>,
}

impl SecurityEvent {
    pub fn new(
        event: impl Into<String>,
        component: impl Into<String>,
        detail: impl Into<String>,
        profile_version: Option<String>,
    ) -> Self {
        Self {
            event: event.into(),
            component: component.into(),
            detail: detail.into(),
            timestamp: SystemTime::now(),
            profile_version,
        }
    }

    pub fn profile_installed(
        component: impl Into<String>,
        profile: impl Into<String>,
        profile_version: Option<String>,
    ) -> Self {
        Self::new(
            "seccomp_profile_installed",
            component,
            profile,
            profile_version,
        )
    }

    pub fn capabilities_dropped(
        component: impl Into<String>,
        profile_version: Option<String>,
    ) -> Self {
        Self::new("capabilities_dropped", component, "", profile_version)
    }

    pub fn violation(
        component: impl Into<String>,
        detail: impl Into<String>,
        profile_version: Option<String>,
    ) -> Self {
        Self::new("seccomp_violation", component, detail, profile_version)
    }

    pub fn namespace_isolation_applied(detail: impl Into<String>) -> Self {
        Self::new(
            "namespace_isolation_applied",
            "runtime-hardening",
            detail,
            None,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "syscall audit event carries hardware-level trace data that belongs together as a single structured record"
    )]
    pub fn syscall_audit_event(
        sandbox_id: impl Into<String>,
        syscall: impl Into<String>,
        pid: u32,
        tid: u32,
        uid: u32,
        gid: u32,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        retval: i64,
        timestamp_ns: u64,
        string_arg: Option<String>,
        is_enter: bool,
    ) -> Self {
        let sandbox_id = sandbox_id.into();
        let syscall = syscall.into();
        let phase = if is_enter { "enter" } else { "exit" };
        let mut detail = format!(
            "sandbox={sandbox_id} syscall={syscall} pid={pid} tid={tid} uid={uid} gid={gid} arg0={arg0:#x} arg1={arg1:#x} arg2={arg2:#x} arg3={arg3:#x} ts={timestamp_ns} phase={phase}",
        );
        if !is_enter {
            let _ = std::fmt::Write::write_fmt(&mut detail, format_args!(" retval={retval}"));
        }
        if let Some(s) = string_arg {
            let _ = std::fmt::Write::write_fmt(&mut detail, format_args!(" path={s}"));
        }
        Self::new("syscall_audit", "runtime-hardening", detail, None)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "anomaly audit records need sandbox, type, severity, and confidence together"
    )]
    pub fn behavioral_anomaly(
        sandbox_id: impl Into<String>,
        sandbox_type: impl Into<String>,
        anomaly_type: impl Into<String>,
        severity: impl Into<String>,
        confidence: f64,
        syscall: impl Into<String>,
        detail: impl Into<String>,
        timestamp_ns: u64,
    ) -> Self {
        let sandbox_id = sandbox_id.into();
        let sandbox_type = sandbox_type.into();
        let anomaly_type = anomaly_type.into();
        let severity = severity.into();
        let syscall = syscall.into();
        let detail = detail.into();
        let record = format!(
            "sandbox={sandbox_id} type={sandbox_type} anomaly={anomaly_type} severity={severity} confidence={confidence:.3} syscall={syscall} ts={timestamp_ns} detail={detail}"
        );
        Self::new("behavioral_anomaly", "runtime-hardening", record, None)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "FIM alerts need path, process identity, and mode for audit correlation"
    )]
    pub fn file_integrity_violation(
        sandbox_id: impl Into<String>,
        path: impl Into<String>,
        hook: impl Into<String>,
        mode: impl Into<String>,
        pid: u32,
        tid: u32,
        uid: u32,
        gid: u32,
        denied: bool,
        timestamp_ns: u64,
        detail: impl Into<String>,
    ) -> Self {
        let sandbox_id = sandbox_id.into();
        let path = path.into();
        let hook = hook.into();
        let mode = mode.into();
        let detail = detail.into();
        let record = format!(
            "sandbox={sandbox_id} path={path} hook={hook} mode={mode} pid={pid} tid={tid} uid={uid} gid={gid} denied={denied} ts={timestamp_ns} detail={detail}"
        );
        Self::new(
            "file_integrity_violation",
            "runtime-hardening",
            record,
            None,
        )
    }

    pub fn emit(&self) {
        if let Some(ref version) = self.profile_version {
            info!(
                event = %self.event,
                component = %self.component,
                detail = %self.detail,
                profile_version = %version,
                "security event"
            );
        } else {
            info!(
                event = %self.event,
                component = %self.component,
                detail = %self.detail,
                "security event"
            );
        }
    }
}
