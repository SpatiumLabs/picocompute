//! Agent wrapper that admits through policy + quota and issues access leases.
//!
//! Intercepts `SandboxService` methods to add admission-time quota checks,
//! Cedar-backed policy evaluation, and signed lease issuance. Data-plane
//! enforcers (edge, host) verify the lease artifact.
//!
//! When tenant-context middleware is integrated,
//! the per-request tenant/principal extraction will replace the
//! constructor-provided defaults.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use pico_core::{
    AccessLease, Admission, AdmitRequest, AuditEventBuilder, AuditEventDetails, AuditEventKind,
    AuditEventSink, ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest, Hlc,
    JobOutcome, JobPauseSignal, JobResumeSignal, LeaseAction, LeaseAuthority, LeaseScope,
    PolicyAction, PolicyEngine, PortForwardEndpoint, PortForwardRequest, PortForwardResponse,
    PrincipalId, QuotaEngine, Result, SandboxError, SandboxId, SandboxInfo, SandboxService,
    SandboxSpec, SshInfo, TaskEvent, TaskInfo, TaskRequest, TenantId, new_ulid,
};
use tokio::sync::broadcast;

use crate::placement::{HostCapacityReport, PlacementGate};

/// Wraps a [`SandboxService`] and enforces quota + policy on every call.
///
/// The wrapper also implements the narrow [`pico_core::SandboxFacade`] for
/// lifecycle consumers that do not need data-plane capabilities.
pub struct PolicyEnforcingAgent {
    inner: Arc<dyn SandboxService>,
    admission: Arc<Admission>,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    audit_sink: Option<Arc<dyn AuditEventSink>>,
    hlc: Arc<Hlc>,
    reservations: Mutex<HashMap<String, (u32, u64)>>,
    placement: Option<Arc<PlacementGate>>,
}

impl PolicyEnforcingAgent {
    pub fn new(
        inner: Arc<dyn SandboxService>,
        quota: Arc<QuotaEngine>,
        policy: Arc<PolicyEngine>,
        tenant_id: TenantId,
        principal_id: PrincipalId,
    ) -> Self {
        Self::with_admission(
            inner,
            Arc::new(Admission::new(policy, quota, LeaseAuthority::generate())),
            tenant_id,
            principal_id,
        )
    }

    /// Wraps an agent with a shared admission module.
    pub fn with_admission(
        inner: Arc<dyn SandboxService>,
        admission: Arc<Admission>,
        tenant_id: TenantId,
        principal_id: PrincipalId,
    ) -> Self {
        Self {
            inner,
            admission,
            tenant_id,
            principal_id,
            audit_sink: None,
            hlc: Arc::new(Hlc::new()),
            reservations: Mutex::new(HashMap::new()),
            placement: None,
        }
    }

    /// Attaches scheduler-backed placement admission to the create path.
    ///
    /// When set, `create` runs `RegionalScheduler` then `CellScheduler`
    /// after policy and quota, refreshes `HostInventory` from host-agent
    /// capacity reports (TTL 60s), and fails closed with a retryable
    /// throttled error on `InsufficientCapacity`/`PressureSaturated`
    /// without silent backend fallback.
    pub fn with_placement(mut self, gate: Arc<PlacementGate>) -> Self {
        self.placement = Some(gate);
        self
    }

    /// Returns the attached placement gate, if any.
    pub fn placement(&self) -> Option<&Arc<PlacementGate>> {
        self.placement.as_ref()
    }

    /// Ingests a host-agent capacity report into the placement registry.
    ///
    /// Multi-host deployments call this when a host-agent pushes capacity;
    /// the report refreshes `HostInventory` with a 60s TTL and releases the
    /// overlay entries it supersedes. No-op when no placement gate is
    /// attached.
    pub fn report_capacity(&self, report: &HostCapacityReport) {
        if let Some(ref gate) = self.placement {
            gate.report_host(report, time::OffsetDateTime::now_utc());
        }
    }

    fn release_quota(&self, sandbox_id: &str) {
        let reserved = self.reservations.lock().remove(sandbox_id);
        if let Some((vcpus, memory_mb)) = reserved {
            self.admission
                .quota()
                .release(&self.tenant_id, vcpus, memory_mb);
        }
    }

    /// Returns the admission module used to issue leases.
    pub fn admission(&self) -> &Admission {
        &self.admission
    }

    /// Set an audit event sink for emitting policy and quota events.
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditEventSink>, hlc: Arc<Hlc>) -> Self {
        self.audit_sink = Some(sink);
        self.hlc = hlc;
        self
    }

    fn emit_audit(&self, event: pico_core::AuditEvent) {
        if let Some(ref sink) = self.audit_sink {
            let _ = sink.emit(event);
        }
    }

    fn issue_lease(
        &self,
        sandbox_id: &str,
        action: LeaseAction,
        scope: LeaseScope,
    ) -> Result<AccessLease> {
        self.admission.admit(AdmitRequest {
            tenant_id: self.tenant_id.clone(),
            principal: self.principal_id.clone(),
            sandbox_id: SandboxId::from_string(sandbox_id),
            action,
            scope,
            ttl_secs: None,
            quota: None,
        })
    }

    fn check_policy(&self, action: PolicyAction) -> Result<()> {
        let decision =
            self.admission
                .policy()
                .evaluate(&self.principal_id, &self.tenant_id, action);

        let outcome_str = match &decision.outcome {
            pico_core::PolicyOutcome::Allow => "allow",
            pico_core::PolicyOutcome::Deny { .. } => "deny",
        };
        let reason = match &decision.outcome {
            pico_core::PolicyOutcome::Deny { reason } => Some(reason.clone()),
            _ => None,
        };

        self.emit_audit(
            AuditEventBuilder::new(Arc::clone(&self.hlc), AuditEventKind::PolicyDecision)
                .tenant_id(self.tenant_id.clone())
                .principal(self.principal_id.clone())
                .details(AuditEventDetails::PolicyDecision {
                    decision_id: decision.decision_id.as_str().to_string(),
                    action: action.as_str().to_string(),
                    outcome: outcome_str.to_string(),
                    policy_epoch: decision.policy_epoch,
                    reason,
                })
                .build(),
        );

        match decision.outcome {
            pico_core::PolicyOutcome::Allow => Ok(()),
            pico_core::PolicyOutcome::Deny { reason } => Err(SandboxError::PolicyDenied { reason }),
        }
    }
}

#[async_trait]
impl SandboxService for PolicyEnforcingAgent {
    #[tracing::instrument(skip(self, spec), fields(tenant_id = %self.tenant_id, sandbox_id = %spec.id.as_deref().unwrap_or("")))]
    async fn create(&self, mut spec: SandboxSpec) -> Result<SandboxInfo> {
        let vcpus = spec.vcpus.unwrap_or(2);
        let memory_mb = spec.memory_mb.unwrap_or(512);

        self.check_policy(PolicyAction::Create)?;

        let quota_decision = self
            .admission
            .quota()
            .check_create(&self.tenant_id, vcpus, memory_mb);

        if !quota_decision.allowed {
            let resource = quota_decision.resource.clone().unwrap_or_default();
            self.emit_audit(
                AuditEventBuilder::new(Arc::clone(&self.hlc), AuditEventKind::QuotaRejection)
                    .tenant_id(self.tenant_id.clone())
                    .principal(self.principal_id.clone())
                    .details(AuditEventDetails::QuotaRejection {
                        decision_id: quota_decision.decision_id.as_str().to_string(),
                        resource: resource.clone(),
                        limit: quota_decision.limit,
                        current: quota_decision.current,
                    })
                    .build(),
            );
            return Err(SandboxError::QuotaExceeded {
                resource,
                limit: quota_decision.limit,
                current: quota_decision.current,
            });
        }

        if spec.credential_request.is_some() && spec.id.is_none() {
            spec.id = Some(new_ulid("sbx"));
        }

        // Scheduler-backed placement admission. Runs after policy and quota
        // so production admits use the calibrated packing math. Refreshes
        // HostInventory from host-agent capacity reports (TTL 60s) inside
        // the gate, then calls RegionalScheduler followed by CellScheduler.
        // InsufficientCapacity and PressureSaturated fail closed as
        // retryable throttled errors; quota releases and no silent backend
        // fallback is attempted.
        if let Some(ref gate) = self.placement {
            if spec.id.is_none() {
                spec.id = Some(new_ulid("sbx"));
            }
            let sandbox_id = spec.id.clone().unwrap_or_default();
            let image = spec
                .image_id
                .clone()
                .or_else(|| spec.image_digest.clone())
                .unwrap_or_else(|| "default-image".into());
            match gate.admit(
                &sandbox_id,
                &self.tenant_id,
                vcpus,
                memory_mb,
                spec.runtime,
                &image,
            ) {
                Ok(decision) => {
                    tracing::info!(
                        cell_id = %decision.cell_id.as_str(),
                        host_id = %decision.host_id.as_str(),
                        regional_reason = %decision.regional_reason,
                        cell_reason = %decision.cell_reason,
                        "create placement admitted"
                    );
                    // Pin the resolved backend explicitly so the downstream
                    // host does not silently fall back to a different
                    // runtime under pressure.
                    if spec.runtime.is_none() {
                        spec.runtime = Some(gate.default_runtime());
                    }
                }
                Err(err) => {
                    tracing::warn!(reason = %err, "create placement rejected");
                    self.admission
                        .quota()
                        .release(&self.tenant_id, vcpus, memory_mb);
                    return Err(SandboxError::from(err));
                }
            }
        }

        if spec.credential_request.is_some() {
            let sandbox_id = spec.id.clone().unwrap_or_default();
            let credential_types = spec
                .credential_request
                .as_ref()
                .map(|c| c.credential_types.clone())
                .unwrap_or_default();
            let lease = match self.issue_lease(
                &sandbox_id,
                LeaseAction::CredentialAccess,
                LeaseScope {
                    ports: vec![],
                    paths: vec![],
                    egress_cidrs: vec![],
                    credential_types: credential_types.clone(),
                },
            ) {
                Ok(lease) => lease,
                Err(err) => {
                    self.admission
                        .quota()
                        .release(&self.tenant_id, vcpus, memory_mb);
                    return Err(err);
                }
            };
            if let Some(cred) = spec.credential_request.as_mut() {
                cred.tenant_id = self.tenant_id.clone();
                cred.lease_id = lease.lease_id.clone();
                cred.policy_decision_id = Some(lease.policy_decision_id.clone());
                cred.lease = Some(self.admission.encode(&lease)?);
            }
        }

        match self.inner.create(spec).await {
            Ok(info) => {
                self.reservations
                    .lock()
                    .insert(info.id.clone(), (vcpus, memory_mb));
                Ok(info)
            }
            Err(err) => {
                self.admission
                    .quota()
                    .release(&self.tenant_id, vcpus, memory_mb);
                Err(err)
            }
        }
    }

    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
        self.inner.list(limit, cursor).await
    }

    async fn get(&self, id: &str) -> Result<SandboxInfo> {
        self.inner.get(id).await
    }

    #[tracing::instrument(skip(self), fields(sandbox_id = %id))]
    async fn destroy(&self, id: &str) -> Result<()> {
        self.check_policy(PolicyAction::Destroy)?;
        self.inner.destroy(id).await?;
        self.release_quota(id);
        Ok(())
    }

    async fn purge(&self, id: &str) -> Result<()> {
        self.check_policy(PolicyAction::Destroy)?;
        self.inner.purge(id).await?;
        self.release_quota(id);
        Ok(())
    }

    async fn stop(&self, id: &str) -> Result<()> {
        self.check_policy(PolicyAction::Stop)?;
        self.inner.stop(id).await
    }

    async fn suspend(&self, id: &str) -> Result<()> {
        self.check_policy(PolicyAction::Suspend)?;
        self.inner.suspend(id).await
    }

    async fn resume(&self, id: &str) -> Result<()> {
        self.check_policy(PolicyAction::Resume)?;
        self.inner.resume(id).await
    }

    async fn pause_job(&self, signal: JobPauseSignal) -> Result<JobOutcome> {
        signal.validate()?;
        self.check_policy(PolicyAction::Suspend)?;
        self.inner.pause_job(signal).await
    }

    async fn resume_job(&self, signal: JobResumeSignal) -> Result<JobOutcome> {
        signal.validate()?;
        self.check_policy(PolicyAction::Resume)?;
        self.inner.resume_job(signal).await
    }

    async fn keepalive(&self, id: &str) -> Result<()> {
        self.inner.keepalive(id).await
    }

    #[tracing::instrument(skip(self, req), fields(sandbox_id = %id))]
    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse> {
        self.check_policy(PolicyAction::Exec)?;
        self.inner.exec(id, req).await
    }

    async fn file_read(&self, id: &str, path: &str) -> Result<FileReadResponse> {
        self.check_policy(PolicyAction::FileAccess)?;
        self.inner.file_read(id, path).await
    }

    async fn file_write(&self, id: &str, req: FileWriteRequest) -> Result<FileInfo> {
        self.check_policy(PolicyAction::FileAccess)?;
        self.inner.file_write(id, req).await
    }

    async fn file_list(&self, id: &str, dir: &str, recursive: bool) -> Result<Vec<FileInfo>> {
        self.check_policy(PolicyAction::FileAccess)?;
        self.inner.file_list(id, dir, recursive).await
    }

    async fn task_start(&self, id: &str, req: TaskRequest) -> Result<TaskInfo> {
        self.inner.task_start(id, req).await
    }

    async fn task_get(&self, id: &str, task_id: &str) -> Result<TaskInfo> {
        self.inner.task_get(id, task_id).await
    }

    async fn task_cancel(&self, id: &str, task_id: &str) -> Result<()> {
        self.inner.task_cancel(id, task_id).await
    }

    fn task_subscribe(&self, id: &str, task_id: &str) -> Result<broadcast::Receiver<TaskEvent>> {
        self.inner.task_subscribe(id, task_id)
    }

    async fn ssh_info(&self, id: &str) -> Result<SshInfo> {
        self.inner.ssh_info(id).await
    }

    async fn expose_port(
        &self,
        id: &str,
        mut req: PortForwardRequest,
    ) -> Result<PortForwardEndpoint> {
        self.check_policy(PolicyAction::PortForward)?;
        let lease = self.issue_lease(
            id,
            LeaseAction::PortForward,
            LeaseScope {
                ports: vec![req.guest_port],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![],
            },
        )?;
        req.tenant_id = self.tenant_id.clone();
        req.lease_id = lease.lease_id.clone();
        req.lease = Some(self.admission.encode(&lease)?);
        self.inner.expose_port(id, req).await
    }

    async fn issue_access_lease(
        &self,
        sandbox_id: &str,
        action: LeaseAction,
        scope: LeaseScope,
    ) -> Result<AccessLease> {
        let _ = self.inner.get(sandbox_id).await?;
        self.issue_lease(sandbox_id, action, scope)
    }

    async fn revoke_port(&self, id: &str, endpoint_id: &str) -> Result<PortForwardResponse> {
        self.check_policy(PolicyAction::PortForward)?;
        self.inner.revoke_port(id, endpoint_id).await
    }

    async fn list_ports(&self, id: &str) -> Result<Vec<PortForwardEndpoint>> {
        self.inner.list_ports(id).await
    }
}

#[async_trait]
impl pico_core::SandboxFacade for PolicyEnforcingAgent {
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxInfo> {
        SandboxService::create(self, spec).await
    }

    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
        SandboxService::list(self, limit, cursor).await
    }

    async fn get(&self, id: &str) -> Result<SandboxInfo> {
        SandboxService::get(self, id).await
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        SandboxService::destroy(self, id).await
    }

    async fn purge(&self, id: &str) -> Result<()> {
        SandboxService::purge(self, id).await
    }

    async fn stop(&self, id: &str) -> Result<()> {
        SandboxService::stop(self, id).await
    }

    async fn keepalive(&self, id: &str) -> Result<()> {
        SandboxService::keepalive(self, id).await
    }

    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse> {
        SandboxService::exec(self, id, req).await
    }

    async fn suspend(&self, id: &str) -> Result<()> {
        SandboxService::suspend(self, id).await
    }

    async fn resume(&self, id: &str) -> Result<()> {
        SandboxService::resume(self, id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::placement::PlacementRegistry;
    use hashbrown::HashMap;
    use parking_lot::Mutex;
    use pico_core::{HostHealth, HostPressure, RuntimeType};

    fn test_tenant() -> (TenantId, PrincipalId) {
        (TenantId::generate(), PrincipalId::new("test-principal"))
    }

    struct MockAgent {
        items: Mutex<HashMap<String, SandboxInfo>>,
        last_cred_tenant: Mutex<Option<TenantId>>,
        last_cred_lease: Mutex<Option<String>>,
        last_runtime: Mutex<Option<RuntimeType>>,
        fail_create: Mutex<bool>,
        lifecycle_calls: Mutex<Vec<&'static str>>,
    }
    impl MockAgent {
        fn new() -> Self {
            Self {
                items: Mutex::new(HashMap::new()),
                last_cred_tenant: Mutex::new(None),
                last_cred_lease: Mutex::new(None),
                last_runtime: Mutex::new(None),
                fail_create: Mutex::new(false),
                lifecycle_calls: Mutex::new(Vec::new()),
            }
        }
    }
    #[async_trait]
    impl SandboxService for MockAgent {
        async fn create(&self, s: SandboxSpec) -> Result<SandboxInfo> {
            if *self.fail_create.lock() {
                return Err(SandboxError::Other("backend unavailable".into()));
            }
            *self.last_runtime.lock() = s.runtime;
            if let Some(ref cred) = s.credential_request {
                *self.last_cred_tenant.lock() = Some(cred.tenant_id.clone());
                *self.last_cred_lease.lock() = cred.lease.clone();
            }
            let id = s.id.clone().unwrap_or_else(|| pico_core::new_ulid("sbx"));
            let info = SandboxInfo {
                id: id.clone(),
                state: pico_core::SandboxState::Running,
                ports: s.ports.unwrap_or_default(),
                container_id: None,
                created_at: "2026-06-09T00:00:00Z".into(),
                last_activity_at: "2026-06-09T00:00:00Z".into(),
                ssh_port: Some(22),
                ssh_public_key: Some("ssh-ed25519 test-key".into()),
            };
            self.items.lock().insert(id, info.clone());
            Ok(info)
        }
        async fn list(
            &self,
            _l: usize,
            _c: Option<String>,
        ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
            Ok((vec![], None))
        }
        async fn get(&self, id: &str) -> Result<SandboxInfo> {
            self.items
                .lock()
                .get(id)
                .cloned()
                .ok_or(pico_core::SandboxError::SandboxNotFound(id.into()))
        }
        async fn destroy(&self, id: &str) -> Result<()> {
            self.items.lock().remove(id);
            Ok(())
        }
        async fn purge(&self, id: &str) -> Result<()> {
            self.destroy(id).await
        }
        async fn stop(&self, _: &str) -> Result<()> {
            Ok(())
        }
        async fn suspend(&self, _: &str) -> Result<()> {
            self.lifecycle_calls.lock().push("suspend");
            Ok(())
        }
        async fn resume(&self, _: &str) -> Result<()> {
            self.lifecycle_calls.lock().push("resume");
            Ok(())
        }
        async fn keepalive(&self, _: &str) -> Result<()> {
            Ok(())
        }
        async fn exec(&self, _: &str, _: ExecRequest) -> Result<ExecResponse> {
            unimplemented!()
        }
        async fn file_read(&self, _: &str, _: &str) -> Result<FileReadResponse> {
            unimplemented!()
        }
        async fn file_write(&self, _: &str, _: FileWriteRequest) -> Result<FileInfo> {
            unimplemented!()
        }
        async fn file_list(&self, _: &str, _: &str, _: bool) -> Result<Vec<FileInfo>> {
            unimplemented!()
        }
        async fn task_start(&self, _: &str, _: TaskRequest) -> Result<TaskInfo> {
            unimplemented!()
        }
        async fn task_get(&self, _: &str, _: &str) -> Result<TaskInfo> {
            unimplemented!()
        }
        async fn task_cancel(&self, _: &str, _: &str) -> Result<()> {
            unimplemented!()
        }
        fn task_subscribe(&self, _: &str, _: &str) -> Result<broadcast::Receiver<TaskEvent>> {
            unimplemented!()
        }
        async fn ssh_info(&self, _: &str) -> Result<SshInfo> {
            unimplemented!()
        }
    }

    #[test]
    fn policy_agent_exposes_the_narrow_facade() {
        fn assert_facade<T: pico_core::SandboxFacade>() {}
        assert_facade::<PolicyEnforcingAgent>();
    }

    #[tokio::test]
    async fn under_quota_allows_create() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let (tid, pid) = test_tenant();
        let agent = PolicyEnforcingAgent::new(mock, quota, policy, tid, pid);

        let spec = SandboxSpec {
            runtime: None,
            id: Some("sbx_test".into()),
            ports: Some(vec![3000]),
            env: None,
            memory_mb: Some(128),
            vcpus: Some(1),
            idle_timeout_secs: None,
            ssh_public_key: None,
            ssh_key_type: None,
            image_id: None,
            image_digest: None,
            credential_request: None,
        };

        let result = agent.create(spec).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn delegates_list_to_inner() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        let (tid, pid) = test_tenant();
        let agent = PolicyEnforcingAgent::new(mock, quota, policy, tid, pid);

        let (items, cursor) = agent.list(10, None).await.unwrap();
        assert!(items.is_empty());
        assert!(cursor.is_none());
    }

    #[tokio::test]
    async fn suspend_and_resume_are_policy_gated_and_delegate() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let (tid, pid) = test_tenant();
        let agent =
            PolicyEnforcingAgent::new(Arc::<MockAgent>::clone(&mock), quota, policy, tid, pid);

        agent.suspend("sbx_lifecycle").await.unwrap();
        agent.resume("sbx_lifecycle").await.unwrap();
        assert_eq!(
            mock.lifecycle_calls.lock().as_slice(),
            ["suspend", "resume"]
        );
    }

    #[tokio::test]
    async fn policy_denied_blocks_create() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies(
                r#"
forbid(
    principal,
    action == PicoCompute::Action::"Create",
    resource
) when { true };
"#,
            )
            .unwrap();
        let (tid, pid) = test_tenant();
        let agent = PolicyEnforcingAgent::new(mock, quota, policy, tid, pid);

        let spec = SandboxSpec {
            runtime: None,
            id: Some("sbx_test".into()),
            ports: None,
            env: None,
            memory_mb: Some(128),
            vcpus: Some(1),
            idle_timeout_secs: None,
            ssh_public_key: None,
            ssh_key_type: None,
            image_id: None,
            image_digest: None,
            credential_request: None,
        };

        let result = agent.create(spec).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SandboxError::PolicyDenied { .. }
        ));
    }

    #[tokio::test]
    async fn quota_exceeded_blocks_create() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let (tid, pid) = test_tenant();
        quota.set_limits(
            tid.clone(),
            pico_core::QuotaLimits {
                max_sandboxes: 0,
                max_vcpus: 0,
                max_memory_mb: 0,
                ..Default::default()
            },
        );
        let agent = PolicyEnforcingAgent::new(mock, quota, policy, tid, pid);

        let spec = SandboxSpec {
            runtime: None,
            id: Some("sbx_test".into()),
            ports: None,
            env: None,
            memory_mb: Some(128),
            vcpus: Some(1),
            idle_timeout_secs: None,
            ssh_public_key: None,
            ssh_key_type: None,
            image_id: None,
            image_digest: None,
            credential_request: None,
        };

        let result = agent.create(spec).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SandboxError::QuotaExceeded { .. }
        ));
    }

    #[tokio::test]
    async fn create_rewrites_credential_request_tenant() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let (tid, pid) = test_tenant();
        let agent = PolicyEnforcingAgent::new(
            Arc::<MockAgent>::clone(&mock),
            quota,
            policy,
            tid.clone(),
            pid,
        );

        let smuggled = TenantId::generate();
        let spec = SandboxSpec {
            runtime: None,
            id: Some("sbx_test".into()),
            ports: None,
            env: None,
            memory_mb: Some(128),
            vcpus: Some(1),
            idle_timeout_secs: None,
            ssh_public_key: None,
            ssh_key_type: None,
            image_id: None,
            image_digest: None,
            credential_request: Some(pico_core::CredentialRequestSpec {
                tenant_id: smuggled.clone(),
                lease_id: pico_core::LeaseId::generate(),
                policy_decision_id: None,
                credential_types: vec!["aws".into()],
                lease: None,
            }),
        };

        let result = agent.create(spec).await;
        assert!(result.is_ok());
        assert_eq!(mock.last_cred_tenant.lock().clone(), Some(tid));
        assert!(mock.last_cred_lease.lock().is_some());
        assert_ne!(mock.last_cred_tenant.lock().clone(), Some(smuggled));
    }

    fn tight_quota_spec(id: &str) -> SandboxSpec {
        SandboxSpec {
            runtime: None,
            id: Some(id.into()),
            ports: None,
            env: None,
            memory_mb: Some(128),
            vcpus: Some(1),
            idle_timeout_secs: None,
            ssh_public_key: None,
            ssh_key_type: None,
            image_id: None,
            image_digest: None,
            credential_request: None,
        }
    }

    #[tokio::test]
    async fn destroy_releases_quota() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let (tid, pid) = test_tenant();
        quota.set_limits(
            tid.clone(),
            pico_core::QuotaLimits {
                max_sandboxes: 1,
                max_vcpus: 2,
                max_memory_mb: 512,
                ..Default::default()
            },
        );
        let agent = PolicyEnforcingAgent::new(mock, quota, policy, tid, pid);

        assert!(agent.create(tight_quota_spec("sbx_a")).await.is_ok());
        assert!(matches!(
            agent.create(tight_quota_spec("sbx_b")).await.unwrap_err(),
            SandboxError::QuotaExceeded { .. }
        ));
        agent.destroy("sbx_a").await.unwrap();
        assert!(agent.create(tight_quota_spec("sbx_b")).await.is_ok());
    }

    #[tokio::test]
    async fn failed_create_rolls_back_quota() {
        let mock = Arc::new(MockAgent::new());
        *mock.fail_create.lock() = true;
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let (tid, pid) = test_tenant();
        quota.set_limits(
            tid.clone(),
            pico_core::QuotaLimits {
                max_sandboxes: 1,
                max_vcpus: 2,
                max_memory_mb: 512,
                ..Default::default()
            },
        );
        let agent =
            PolicyEnforcingAgent::new(Arc::<MockAgent>::clone(&mock), quota, policy, tid, pid);

        assert!(agent.create(tight_quota_spec("sbx_a")).await.is_err());
        *mock.fail_create.lock() = false;
        assert!(agent.create(tight_quota_spec("sbx_a")).await.is_ok());
    }

    fn placement_gate_with_host(health: HostHealth, pressure: HostPressure) -> Arc<PlacementGate> {
        use pico_core::{
            CacheLocality, CellCapacity, CellHealth, CellId, CellInfo, HostCacheState,
            HostCapacity, RegionId, RuntimeType, SnapshotTimingHint,
        };
        let registry = Arc::new(PlacementRegistry::new());
        registry.upsert_cell(CellInfo {
            cell_id: CellId::from_string("cel_1"),
            region_id: RegionId::from_string("rgn_1"),
            health: CellHealth::Healthy,
            capacity: CellCapacity {
                total_vcpus: 64,
                allocated_vcpus: 0,
                total_memory_mb: 262_144,
                allocated_memory_mb: 0,
                max_sandboxes: 100,
                current_sandboxes: 0,
            },
            supported_runtimes: vec![RuntimeType::Firecracker],
            failure_domain: "fd-cel_1".into(),
            cache: CacheLocality {
                cached_images: Vec::new(),
                cached_snapshots: Vec::new(),
            },
            admission_pressure: 0.0,
            snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
        });
        registry.report_host(
            &HostCapacityReport {
                host_id: "hst_1".into(),
                cell_id: "cel_1".into(),
                region: Some("rgn_1".into()),
                health,
                capacity: HostCapacity {
                    total_vcpus: 32,
                    allocated_vcpus: 0,
                    total_memory_mb: 131_072,
                    allocated_memory_mb: 0,
                    total_disk_mb: 1_000_000,
                    used_disk_mb: 0,
                    total_network_mbps: 10_000,
                    allocated_network_mbps: 0,
                    max_process_slots: 1000,
                    used_process_slots: 0,
                },
                pressure,
                supported_runtimes: vec![RuntimeType::Firecracker],
                cache: Some(HostCacheState {
                    cached_images: Vec::new(),
                    cached_snapshots: Vec::new(),
                }),
                current_sandboxes: 0,
                snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
            },
            time::OffsetDateTime::now_utc(),
        );
        Arc::new(PlacementGate::new(registry))
    }

    #[tokio::test]
    async fn placement_admits_healthy_capacity_and_pins_runtime() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let (tid, pid) = test_tenant();
        let gate = placement_gate_with_host(
            HostHealth::Healthy,
            HostPressure {
                in_flight_creates: 0,
                in_flight_restores: 0,
                max_concurrent_creates: 8,
                max_concurrent_restores: 8,
            },
        );
        let agent = PolicyEnforcingAgent::with_admission(
            Arc::<MockAgent>::clone(&mock),
            Arc::new(pico_core::Admission::new(
                policy,
                quota,
                pico_core::LeaseAuthority::generate(),
            )),
            tid,
            pid,
        )
        .with_placement(gate);
        // `None` runtime must resolve explicitly, not silently fall back later.
        let mut spec = tight_quota_spec("sbx_place_ok");
        spec.runtime = None;
        let info = agent.create(spec).await.expect("healthy must place");
        assert_eq!(info.id, "sbx_place_ok");
        assert_eq!(
            *mock.last_runtime.lock(),
            Some(RuntimeType::Firecracker),
            "admission must pin the resolved backend explicitly"
        );
    }

    #[tokio::test]
    async fn placement_pressure_fails_closed_and_releases_quota() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let (tid, pid) = test_tenant();
        quota.set_limits(
            tid.clone(),
            pico_core::QuotaLimits {
                max_sandboxes: 1,
                max_vcpus: 2,
                max_memory_mb: 512,
                ..Default::default()
            },
        );
        let gate = placement_gate_with_host(
            HostHealth::Healthy,
            HostPressure {
                in_flight_creates: 8,
                in_flight_restores: 0,
                max_concurrent_creates: 8,
                max_concurrent_restores: 8,
            },
        );
        let quota_clone = Arc::clone(&quota);
        let agent = PolicyEnforcingAgent::with_admission(
            mock,
            Arc::new(pico_core::Admission::new(
                policy,
                quota_clone,
                pico_core::LeaseAuthority::generate(),
            )),
            tid.clone(),
            pid,
        )
        .with_placement(gate);
        let err = agent
            .create(tight_quota_spec("sbx_place_hot"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::PlacementThrottled { .. }),
            "pressure must fail closed throttled, got {err}"
        );
        // Quota released: with max_sandboxes 1, a leaked reservation would
        // block the follow-up create, so its success proves the release.
        let healthy_gate = placement_gate_with_host(
            HostHealth::Healthy,
            HostPressure {
                in_flight_creates: 0,
                in_flight_restores: 0,
                max_concurrent_creates: 8,
                max_concurrent_restores: 8,
            },
        );
        // Swap gate by rebuilding agent sharing the same quota engine.
        let mock2 = Arc::new(MockAgent::new());
        let policy2 = Arc::new(PolicyEngine::new());
        policy2
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let agent2 = PolicyEnforcingAgent::with_admission(
            mock2,
            Arc::new(pico_core::Admission::new(
                policy2,
                quota,
                pico_core::LeaseAuthority::generate(),
            )),
            tid,
            PrincipalId::new("test-principal"),
        )
        .with_placement(healthy_gate);
        assert!(
            agent2
                .create(tight_quota_spec("sbx_place_ok2"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn placement_unsupported_runtime_rejects_without_fallback() {
        let mock = Arc::new(MockAgent::new());
        let quota = Arc::new(QuotaEngine::new());
        let policy = Arc::new(PolicyEngine::new());
        policy
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let (tid, pid) = test_tenant();
        let gate = placement_gate_with_host(
            HostHealth::Healthy,
            HostPressure {
                in_flight_creates: 0,
                in_flight_restores: 0,
                max_concurrent_creates: 8,
                max_concurrent_restores: 8,
            },
        );
        let agent = PolicyEnforcingAgent::with_admission(
            mock,
            Arc::new(pico_core::Admission::new(
                policy,
                quota,
                pico_core::LeaseAuthority::generate(),
            )),
            tid,
            pid,
        )
        .with_placement(gate);
        let mut spec = tight_quota_spec("sbx_place_bad_rt");
        spec.runtime = Some(RuntimeType::GVisor);
        let err = agent.create(spec).await.unwrap_err();
        assert!(
            matches!(err, SandboxError::Unprocessable(_)),
            "unsupported runtime must reject, got {err}"
        );
    }
}
