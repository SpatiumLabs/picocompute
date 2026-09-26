//! Runtime backend registry that maps `RuntimeType` to factory functions.

use std::sync::Arc;

use hashbrown::HashMap;
use pico_core::RuntimeType;
use pico_core::runtime::{BackendCapabilities, RuntimeBackend};
use pico_runtime::firecracker::FirecrackerAdapter;
use pico_runtime::gvisor::GVisorAdapter;
use pico_runtime::qemu::QemuAdapter;
use pico_runtime::remote_firecracker::RemoteFirecrackerAdapter;

/// Factory that produces a fresh backend handle for one sandbox prepare.
pub type BackendFactory = Arc<dyn Fn() -> Arc<dyn RuntimeBackend> + Send + Sync>;

/// Maps runtime families to in-process backend constructors.
#[derive(Clone)]
pub struct AdapterRegistry {
    factories: Arc<HashMap<RuntimeType, BackendFactory>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self {
            factories: Arc::new(HashMap::from([
                (
                    RuntimeType::Firecracker,
                    backend_factory(|| Arc::new(FirecrackerAdapter::new())),
                ),
                (
                    RuntimeType::RemoteFirecracker,
                    backend_factory(|| Arc::new(RemoteFirecrackerAdapter::new())),
                ),
                (
                    RuntimeType::Qemu,
                    backend_factory(|| Arc::new(QemuAdapter::new())),
                ),
                (
                    RuntimeType::GVisor,
                    backend_factory(|| Arc::new(GVisorAdapter::new())),
                ),
            ])),
        }
    }
}

impl AdapterRegistry {
    /// Creates an empty registry with no backends registered.
    #[must_use]
    pub fn new() -> Self {
        Self {
            factories: Arc::new(HashMap::new()),
        }
    }

    /// Registers or replaces the factory for `runtime`.
    pub fn register<F>(&mut self, runtime: RuntimeType, factory: F)
    where
        F: Fn() -> Arc<dyn RuntimeBackend> + Send + Sync + 'static,
    {
        let factories = Arc::make_mut(&mut self.factories);
        factories.insert(runtime, Arc::new(factory));
    }

    /// Returns a new backend instance when `runtime` is registered.
    #[must_use]
    pub fn get(&self, runtime: RuntimeType) -> Option<Arc<dyn RuntimeBackend>> {
        self.factories.get(&runtime).map(|f| f())
    }

    /// Creates a backend or returns [`pico_core::SandboxError::NotImplemented`].
    ///
    /// # Errors
    ///
    /// Returns an error when no factory is registered for `runtime`.
    pub fn create(
        &self,
        runtime: RuntimeType,
    ) -> Result<Arc<dyn RuntimeBackend>, pico_core::SandboxError> {
        self.get(runtime)
            .ok_or_else(|| missing_runtime_error(runtime))
    }

    /// Sorted list of registered runtime families.
    #[must_use]
    pub fn supported_backends(&self) -> Vec<RuntimeType> {
        let mut backends: Vec<RuntimeType> = self.factories.keys().copied().collect();
        backends.sort();
        backends
    }

    /// Registered runtimes whose capabilities cover `required`.
    #[must_use]
    pub fn matching_backends(&self, required: &BackendCapabilities) -> Vec<RuntimeType> {
        let mut backends = self
            .factories
            .iter()
            .filter_map(|(runtime, factory)| {
                factory()
                    .metadata()
                    .capabilities
                    .supports_all(required)
                    .then_some(*runtime)
            })
            .collect::<Vec<_>>();
        backends.sort();
        backends
    }
}

fn missing_runtime_error(runtime: RuntimeType) -> pico_core::SandboxError {
    pico_core::SandboxError::NotImplemented(match runtime {
        RuntimeType::Firecracker => "Firecracker runtime is not registered",
        RuntimeType::RemoteFirecracker => "Remote Firecracker runtime is not registered",
        RuntimeType::Qemu => "QEMU runtime is not registered",
        RuntimeType::GVisor => "gVisor runtime is not registered",
    })
}

fn backend_factory<F, B>(factory: F) -> BackendFactory
where
    F: Fn() -> Arc<B> + Send + Sync + 'static,
    B: RuntimeBackend + 'static,
{
    Arc::new(move || -> Arc<dyn RuntimeBackend> { factory() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_core::BackendCapability;
    use pico_runtime::mock::{MockBackend, MockBackendConfig};

    #[test]
    fn default_registry_has_builtin_adapters() {
        let registry = AdapterRegistry::default();
        let backends = registry.supported_backends();
        assert!(backends.contains(&RuntimeType::Firecracker));
        assert!(backends.contains(&RuntimeType::RemoteFirecracker));
        assert!(backends.contains(&RuntimeType::Qemu));
        assert!(backends.contains(&RuntimeType::GVisor));
    }

    #[test]
    fn empty_registry_returns_error() {
        let registry = AdapterRegistry::new();
        match registry.create(RuntimeType::Firecracker) {
            Ok(_) => panic!("expected missing runtime to return an error"),
            Err(err) => assert!(matches!(err, pico_core::SandboxError::NotImplemented(_))),
        }
    }

    #[test]
    fn custom_factory_registration() {
        let mut registry = AdapterRegistry::new();
        registry.register(RuntimeType::Qemu, || Arc::new(MockBackend::default()));
        assert_eq!(registry.supported_backends(), vec![RuntimeType::Qemu]);
    }

    #[test]
    fn capability_matching_filters_registered_backends() {
        let mut registry = AdapterRegistry::new();
        registry.register(
            RuntimeType::Firecracker,
            || Arc::new(MockBackend::default()),
        );
        registry.register(RuntimeType::Qemu, || {
            Arc::new(MockBackend::new(MockBackendConfig {
                capabilities: BackendCapabilities::from([BackendCapability::Boot]),
                runtime: RuntimeType::Qemu,
                ..MockBackendConfig::default()
            }))
        });

        let required =
            BackendCapabilities::from([BackendCapability::Boot, BackendCapability::GuestTransport]);
        assert_eq!(
            registry.matching_backends(&required),
            vec![RuntimeType::Firecracker]
        );
    }
}
