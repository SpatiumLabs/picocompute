pub use pico_telemetry::events::SecurityEvent;

fn profile_version() -> Option<String> {
    Some(crate::PICO_PROFILE_VERSION.to_string())
}

pub fn profile_installed(
    component: impl Into<String>,
    profile: impl Into<String>,
) -> SecurityEvent {
    SecurityEvent::profile_installed(component, profile, profile_version())
}

pub fn capabilities_dropped(component: impl Into<String>) -> SecurityEvent {
    SecurityEvent::capabilities_dropped(component, profile_version())
}

pub fn violation(component: impl Into<String>, detail: impl Into<String>) -> SecurityEvent {
    SecurityEvent::violation(component, detail, profile_version())
}
