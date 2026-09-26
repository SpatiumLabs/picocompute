use std::path::Path;

use crate::ProfileResult;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SeccompProfile {
    pub name: String,
    pub description: String,
    pub version: String,
    pub match_action: String,
    pub mismatch_action: String,
    pub syscalls: Vec<SyscallEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyscallEntry {
    pub syscall: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<SyscallArg>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyscallArg {
    pub index: u32,
    #[serde(rename = "type")]
    pub arg_type: String,
    pub op: String,
    pub val: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentProfile {
    HostAgent,
    Sandboxd,
    GuestAgent,
    RuntimeFirecracker,
    RuntimeGvisor,
    RuntimeQemu,
    NetworkAgent,
}

impl ComponentProfile {
    pub fn profile_name(&self) -> &'static str {
        match self {
            ComponentProfile::HostAgent => "host-agent",
            ComponentProfile::Sandboxd => "sandboxd",
            ComponentProfile::GuestAgent => "guest-agent",
            ComponentProfile::RuntimeFirecracker => "runtime-firecracker",
            ComponentProfile::RuntimeGvisor => "runtime-gvisor",
            ComponentProfile::RuntimeQemu => "runtime-qemu",
            ComponentProfile::NetworkAgent => "network-agent",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ComponentProfile::HostAgent => "Host Agent",
            ComponentProfile::Sandboxd => "Sandboxd Supervisor",
            ComponentProfile::GuestAgent => "Guest Agent",
            ComponentProfile::RuntimeFirecracker => "Firecracker Runtime",
            ComponentProfile::RuntimeGvisor => "gVisor Runtime",
            ComponentProfile::RuntimeQemu => "QEMU Runtime",
            ComponentProfile::NetworkAgent => "Network Agent",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProfileInstallConfig {
    pub profile: ComponentProfile,
    pub drop_all_caps: bool,
    pub keep_caps: Vec<String>,
    pub set_no_new_privs: bool,
    pub strict_mode: bool,
}

impl Default for ProfileInstallConfig {
    fn default() -> Self {
        Self {
            profile: ComponentProfile::HostAgent,
            drop_all_caps: true,
            keep_caps: Vec::new(),
            set_no_new_privs: true,
            strict_mode: true,
        }
    }
}

pub struct ProfileManager {
    inner: ProfileManagerImpl,
}

#[cfg(target_os = "linux")]
mod inner {
    use hashbrown::HashMap;
    use std::path::Path;
    use std::time::Instant;

    use seccompiler::{BpfProgram, TargetArch};
    use tracing::{error, info};

    use super::ComponentProfile;
    use crate::ProfileError;
    use crate::ProfileResult;
    use crate::telemetry;

    pub(super) struct ProfileManagerImpl {
        compiled_profiles: HashMap<ComponentProfile, BpfProgram>,
        target_arch: TargetArch,
    }

    impl ProfileManagerImpl {
        pub(super) fn new() -> ProfileResult<Self> {
            let arch_str = std::env::consts::ARCH;
            let target_arch: TargetArch = match arch_str {
                "x86_64" => TargetArch::x86_64,
                "aarch64" => TargetArch::aarch64,
                other => {
                    return Err(ProfileError::UnsupportedArch {
                        arch: other.to_string(),
                    });
                }
            };

            Ok(Self {
                compiled_profiles: HashMap::new(),
                target_arch,
            })
        }

        pub(super) fn load_from_toml(
            &mut self,
            profile: ComponentProfile,
            toml_str: &str,
        ) -> ProfileResult<()> {
            info!(
                component = profile.profile_name(),
                "loading seccomp profile from TOML"
            );

            let json_value: serde_json::Value =
                toml::from_str(toml_str).map_err(|e| ProfileError::Compilation(e.to_string()))?;

            let json_str = serde_json::to_string(&json_value)
                .map_err(|e| ProfileError::Compilation(e.to_string()))?;

            let bpf_map = seccompiler::compile_from_json(json_str.as_bytes(), self.target_arch)
                .map_err(|e| ProfileError::Compilation(e.to_string()))?;

            let program = bpf_map.get("main_thread").cloned().unwrap_or_default();
            self.compiled_profiles.insert(profile, program);

            info!(
                component = profile.profile_name(),
                "seccomp profile compiled successfully"
            );
            Ok(())
        }

        pub(super) fn load_from_file(
            &mut self,
            profile: ComponentProfile,
            path: &Path,
        ) -> ProfileResult<()> {
            info!(
                component = profile.profile_name(),
                path = %path.display(),
                "loading seccomp profile from file"
            );

            let content = std::fs::read_to_string(path).map_err(|e| ProfileError::FileRead {
                path: path.display().to_string(),
                source: e,
            })?;

            self.load_from_toml(profile, &content)
        }

        pub(super) fn install_profile(
            &self,
            profile: ComponentProfile,
            block_other_threads: bool,
        ) -> ProfileResult<()> {
            let program = self.compiled_profiles.get(&profile).ok_or_else(|| {
                ProfileError::ProfileNotFound {
                    component: profile.profile_name().to_string(),
                }
            })?;

            let start = Instant::now();
            let component_name = profile.display_name();
            let profile_name = profile.profile_name();

            let install_result = if block_other_threads {
                seccompiler::apply_filter_all_threads(program)
            } else {
                seccompiler::apply_filter(program)
            };

            match install_result {
                Ok(()) => {
                    let elapsed = start.elapsed();
                    info!(
                        component = component_name,
                        profile = profile_name,
                        duration_ms = elapsed.as_millis(),
                        "seccomp profile installed"
                    );

                    telemetry::profile_installed(component_name, profile_name).emit();
                    Ok(())
                }
                Err(e) => {
                    error!(
                        component = component_name,
                        profile = profile_name,
                        error = %e,
                        "failed to install seccomp profile"
                    );

                    telemetry::violation(
                        component_name,
                        format!("seccomp profile install failed: {}", e),
                    )
                    .emit();

                    Err(ProfileError::FilterApplication(e.to_string()))
                }
            }
        }

        pub(super) fn all_profiles(&self) -> Vec<ComponentProfile> {
            self.compiled_profiles.keys().copied().collect()
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod inner {
    use hashbrown::HashMap;
    use std::path::Path;

    use tracing::info;

    use super::ComponentProfile;

    use crate::ProfileResult;
    use crate::telemetry;

    pub(super) struct ProfileManagerImpl {
        profiles: HashMap<ComponentProfile, ()>,
    }

    impl ProfileManagerImpl {
        pub(super) fn new() -> ProfileResult<Self> {
            info!("pico-seccomp: running on non-Linux platform, seccomp profiles disabled");
            Ok(Self {
                profiles: HashMap::new(),
            })
        }

        pub(super) fn load_from_toml(
            &mut self,
            profile: ComponentProfile,
            _toml_str: &str,
        ) -> ProfileResult<()> {
            info!(
                component = profile.profile_name(),
                "seccomp profile loading skipped (non-Linux)"
            );
            self.profiles.insert(profile, ());
            Ok(())
        }

        pub(super) fn load_from_file(
            &mut self,
            profile: ComponentProfile,
            _path: &Path,
        ) -> ProfileResult<()> {
            info!(
                component = profile.profile_name(),
                "seccomp profile loading skipped (non-Linux)"
            );
            self.profiles.insert(profile, ());
            Ok(())
        }

        pub(super) fn install_profile(
            &self,
            profile: ComponentProfile,
            _block_other_threads: bool,
        ) -> ProfileResult<()> {
            info!(
                component = profile.display_name(),
                "seccomp profile installation skipped (non-Linux)"
            );
            telemetry::profile_installed(
                profile.display_name(),
                format!("{} (non-Linux no-op)", profile.profile_name()),
            )
            .emit();
            Ok(())
        }

        pub(super) fn all_profiles(&self) -> Vec<ComponentProfile> {
            self.profiles.keys().copied().collect()
        }
    }
}

use inner::ProfileManagerImpl;

impl ProfileManager {
    pub fn new() -> ProfileResult<Self> {
        Ok(Self {
            inner: ProfileManagerImpl::new()?,
        })
    }

    pub fn load_from_toml(
        &mut self,
        profile: ComponentProfile,
        toml_str: &str,
    ) -> ProfileResult<()> {
        self.inner.load_from_toml(profile, toml_str)
    }

    pub fn load_from_file(&mut self, profile: ComponentProfile, path: &Path) -> ProfileResult<()> {
        self.inner.load_from_file(profile, path)
    }

    pub fn install_profile(
        &self,
        profile: ComponentProfile,
        block_other_threads: bool,
    ) -> ProfileResult<()> {
        self.inner.install_profile(profile, block_other_threads)
    }

    pub fn all_profiles(&self) -> Vec<ComponentProfile> {
        self.inner.all_profiles()
    }

    pub fn load_embedded_profile(&mut self, profile: ComponentProfile) -> ProfileResult<()> {
        let profile_toml = get_embedded_profile(profile);
        self.load_from_toml(profile, profile_toml)
    }
}

pub(crate) fn get_embedded_profile(profile: ComponentProfile) -> &'static str {
    match profile {
        ComponentProfile::HostAgent => include_str!("../profiles/host-agent.toml"),
        ComponentProfile::Sandboxd => include_str!("../profiles/sandboxd.toml"),
        ComponentProfile::GuestAgent => include_str!("../profiles/guest-agent.toml"),
        ComponentProfile::RuntimeFirecracker => {
            include_str!("../profiles/runtime-firecracker.toml")
        }
        ComponentProfile::RuntimeQemu => include_str!("../profiles/runtime-qemu.toml"),
        ComponentProfile::RuntimeGvisor => include_str!("../profiles/runtime-gvisor.toml"),
        ComponentProfile::NetworkAgent => include_str!("../profiles/network-agent.toml"),
    }
}

pub fn install_profile(manager: &ProfileManager, profile: ComponentProfile) -> ProfileResult<()> {
    manager.install_profile(profile, true)
}

pub fn install_profile_for_component(
    manager: &ProfileManager,
    profile: ComponentProfile,
    block_other_threads: bool,
) -> ProfileResult<()> {
    manager.install_profile(profile, block_other_threads)
}
