pub mod capabilities;
pub mod error;
pub mod profile;
pub mod telemetry;

pub use capabilities::{
    CapabilitySet, drop_all_capabilities, drop_capabilities, keep_capabilities,
};
pub use error::{ProfileError, ProfileResult};
pub use profile::{
    ComponentProfile, ProfileInstallConfig, ProfileManager, SeccompProfile, SyscallArg,
    SyscallEntry, install_profile, install_profile_for_component,
};
pub use telemetry::SecurityEvent;

pub const PICO_PROFILE_VERSION: &str = "0.1.0";

pub fn init() {
    tracing::info!(
        version = PICO_PROFILE_VERSION,
        "pico-seccomp library initialized"
    );
}

pub fn init_profile_for_component(
    component: ComponentProfile,
    keep_caps: &CapabilitySet,
    set_no_new_privs: bool,
) -> ProfileResult<()> {
    init_profile_for_component_with_strictness(component, keep_caps, set_no_new_privs, false)
}

pub fn init_profile_for_component_with_strictness(
    component: ComponentProfile,
    keep_caps: &CapabilitySet,
    set_no_new_privs: bool,
    strict: bool,
) -> ProfileResult<()> {
    let result = try_init_profile(component, keep_caps, set_no_new_privs);

    if strict {
        result
    } else {
        if let Err(ref e) = result {
            tracing::warn!(
                component = component.profile_name(),
                error = %e,
                "seccomp profile initialization failed, continuing without seccomp"
            );
        }
        Ok(())
    }
}

fn try_init_profile(
    component: ComponentProfile,
    keep_caps: &CapabilitySet,
    set_no_new_privs: bool,
) -> ProfileResult<()> {
    let mut manager = ProfileManager::new()?;
    manager.load_embedded_profile(component)?;

    if set_no_new_privs {
        capabilities::set_no_new_privs()?;
    }

    if !keep_caps.is_empty() {
        keep_capabilities(keep_caps)?;
    } else {
        drop_all_capabilities()?;
    }

    manager.install_profile(component, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ComponentProfile;

    #[test]
    fn embedded_profiles_are_valid_toml() {
        for profile in [
            ComponentProfile::HostAgent,
            ComponentProfile::Sandboxd,
            ComponentProfile::GuestAgent,
            ComponentProfile::RuntimeFirecracker,
            ComponentProfile::RuntimeQemu,
            ComponentProfile::RuntimeGvisor,
            ComponentProfile::NetworkAgent,
        ] {
            let toml_str = crate::profile::get_embedded_profile(profile);
            let json_value: serde_json::Value = toml::from_str(toml_str).unwrap_or_else(|e| {
                panic!("{} embedded TOML should parse: {e}", profile.profile_name())
            });
            let json_str = serde_json::to_string(&json_value).unwrap_or_else(|e| {
                panic!(
                    "{} TOML should serialize to JSON: {e}",
                    profile.profile_name()
                )
            });

            let parsed: serde_json::Value = serde_json::from_str(&json_str)
                .unwrap_or_else(|e| panic!("{} JSON should be valid: {e}", profile.profile_name()));
            assert!(
                parsed.is_object(),
                "{}: profile should be a JSON object",
                profile.profile_name()
            );
            let main_thread = parsed.get("main_thread").unwrap_or_else(|| {
                panic!(
                    "{}: profile should have main_thread key",
                    profile.profile_name()
                )
            });
            assert!(
                main_thread.get("match_action").is_some(),
                "{}: profile should have match_action",
                profile.profile_name()
            );
            assert!(
                main_thread.get("filter").is_some(),
                "{}: profile should have filter",
                profile.profile_name()
            );
            let filter = main_thread
                .get("filter")
                .unwrap()
                .as_array()
                .unwrap_or_else(|| panic!("{}: filter should be an array", profile.profile_name()));
            assert!(
                !filter.is_empty(),
                "{}: profile filter should not be empty",
                profile.profile_name()
            );
        }
    }

    #[test]
    fn profile_manager_can_init() {
        let manager = ProfileManager::new();
        assert!(manager.is_ok(), "ProfileManager::new() should succeed");
    }

    #[test]
    fn get_embedded_profile_returns_non_empty() {
        for profile in [
            ComponentProfile::HostAgent,
            ComponentProfile::Sandboxd,
            ComponentProfile::GuestAgent,
        ] {
            let content = crate::profile::get_embedded_profile(profile);
            assert!(
                !content.is_empty(),
                "{} embedded profile should not be empty",
                profile.profile_name()
            );
            assert!(
                content.contains("main_thread"),
                "{} embedded profile should contain main_thread",
                profile.profile_name()
            );
        }
    }

    #[test]
    fn component_profile_has_distinct_names() {
        let mut names: Vec<&str> = [
            ComponentProfile::HostAgent,
            ComponentProfile::Sandboxd,
            ComponentProfile::GuestAgent,
            ComponentProfile::RuntimeFirecracker,
            ComponentProfile::RuntimeQemu,
            ComponentProfile::RuntimeGvisor,
            ComponentProfile::NetworkAgent,
        ]
        .iter()
        .map(|p| p.profile_name())
        .collect();
        let original_len = names.len();
        names.sort();
        names.dedup();
        assert_eq!(
            names.len(),
            original_len,
            "all profiles should have unique names"
        );
    }

    #[test]
    fn guest_agent_profile_does_not_permit_mount() {
        // The guest agent's secrets path is mounted by `/init`, not by the
        // agent, precisely because this filter cannot permit `mount(2)`. If a
        // future change widens the profile to allow it, the agent's Exec path
        // would also inherit the widened filter for every tenant command, so
        // this invariant should fail loudly rather than silently.
        let toml_str = crate::profile::get_embedded_profile(ComponentProfile::GuestAgent);
        let parsed: serde_json::Value = toml::from_str(toml_str)
            .unwrap_or_else(|e| panic!("guest-agent profile should parse: {e}"));
        let filter = parsed["main_thread"]["filter"]
            .as_array()
            .expect("guest-agent profile must have a filter array");
        assert!(!filter.is_empty(), "guest-agent filter should not be empty");

        let permitted = |name: &str| {
            filter
                .iter()
                .any(|e| e.get("syscall").and_then(|s| s.as_str()) == Some(name))
        };
        for syscall in ["mount", "umount", "umount2"] {
            assert!(
                !permitted(syscall),
                "guest-agent profile must not permit {syscall}: the secrets tmpfs is mounted by \
                 /init, and widening this filter would widen it for Exec'd tenant commands"
            );
        }
        // Sanity: the filter really is the syscall allowlist we think it is,
        // and the agent can still spawn Exec'd commands.
        assert!(
            permitted("execve") || permitted("execveat"),
            "guest-agent must still be able to spawn Exec'd commands"
        );
        // The file primitives the secrets path depends on must remain allowed.
        for syscall in ["openat", "unlinkat", "mkdirat", "write"] {
            assert!(
                permitted(syscall),
                "guest-agent needs {syscall} to manage credential files"
            );
        }
    }

    #[test]
    fn init_profile_for_component_with_strictness_logs_on_failure() {
        let result = init_profile_for_component_with_strictness(
            ComponentProfile::HostAgent,
            &CapabilitySet::host_agent(),
            false,
            false,
        );
        // On non-Linux this should succeed (no-op), on Linux it may fail gracefully
        assert!(result.is_ok(), "non-strict mode should always return Ok");
    }
}
