//! Tenant model and registry.
//!
//! Defines the tenant entity, its lifecycle status, default quotas,
//! workload class authorization, and an in-memory registry for tenant lookup.

use hashbrown::HashMap;
use std::sync::Arc;

use crate::backend_selection::WorkloadClass;
use crate::identity::TenantId;
use crate::runtime::RuntimeType;

/// Tenant lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    Active,
    Suspended,
    Deleted,
}

impl TenantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
        }
    }
}

/// A PicoCompute tenant.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: TenantId,
    pub name: String,
    pub status: TenantStatus,
    pub allowed_runtimes: Vec<RuntimeType>,
    /// Workload classes authorized for this tenant.
    pub allowed_workload_classes: Vec<WorkloadClass>,
    /// Monotonic policy configuration epoch.
    pub policy_epoch: Option<u64>,
}

impl Tenant {
    /// Returns true when the tenant is authorized for the given workload class.
    #[must_use]
    pub fn is_authorized_for_class(&self, class: WorkloadClass) -> bool {
        self.allowed_workload_classes.contains(&class)
    }
}

/// In-memory tenant registry loaded from configuration at startup.
#[derive(Debug, Default)]
pub struct TenantRegistry {
    tenants: HashMap<TenantId, Arc<Tenant>>,
}

impl TenantRegistry {
    pub fn new() -> Self {
        Self {
            tenants: HashMap::new(),
        }
    }

    pub fn register(&mut self, tenant: Tenant) {
        self.tenants.insert(tenant.id.clone(), Arc::new(tenant));
    }

    pub fn get(&self, id: &TenantId) -> Option<Arc<Tenant>> {
        self.tenants.get(id).cloned()
    }

    pub fn exists(&self, id: &TenantId) -> bool {
        self.tenants.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_registry_register_and_lookup() {
        let mut reg = TenantRegistry::new();
        let tid = TenantId::generate();
        let tenant = Tenant {
            id: tid.clone(),
            name: "test-tenant".into(),
            status: TenantStatus::Active,
            allowed_runtimes: vec![RuntimeType::Firecracker],
            allowed_workload_classes: vec![],
            policy_epoch: None,
        };
        reg.register(tenant);
        let found = reg.get(&tid).unwrap();
        assert_eq!(found.name, "test-tenant");
        assert_eq!(found.status, TenantStatus::Active);
        assert!(reg.exists(&tid));
    }

    #[test]
    fn tenant_registry_missing_returns_none() {
        let reg = TenantRegistry::new();
        let tid = TenantId::generate();
        assert!(reg.get(&tid).is_none());
        assert!(!reg.exists(&tid));
    }

    #[test]
    fn tenant_registry_suspended_tenant() {
        let mut reg = TenantRegistry::new();
        let tid = TenantId::generate();
        let tenant = Tenant {
            id: tid.clone(),
            name: "suspended-tenant".into(),
            status: TenantStatus::Suspended,
            allowed_runtimes: vec![],
            allowed_workload_classes: vec![],
            policy_epoch: None,
        };
        reg.register(tenant);
        let found = reg.get(&tid).unwrap();
        assert_eq!(found.status, TenantStatus::Suspended);
    }
}
