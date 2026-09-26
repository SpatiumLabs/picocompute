//! Snapshot metadata repository.
//!
//! Defines the persistence abstraction for snapshot metadata records.
//! Implementations may store records in SQLite, a key-value store, or
//! a distributed metadata service.
//!
//! # Audit decorator
//!
//! [`AuditLoggedSnapshotRepository`] wraps any [`SnapshotRepository`]
//! and emits audit events for every `get_snapshot` and `list_snapshots`
//! call. Use this in production to satisfy the metadata access
//! audit requirement.

use async_trait::async_trait;
use std::sync::Arc;

use crate::event_bus::{AuditEventSink, emit_snapshot_metadata_access};
use crate::identity::{Hlc, PrincipalId, SnapshotId, TenantId};

use super::error::SnapshotResult;
use super::metadata::SnapshotMetadata;
use super::purpose::SnapshotPurpose;
use super::state::SnapshotState;

/// Result page returned from a paginated `list_snapshots` query.
#[derive(Debug, Clone)]
pub struct SnapshotListPage {
    /// The matching snapshots in this page.
    pub snapshots: Vec<SnapshotMetadata>,
    /// An opaque cursor for fetching the next page, or `None` if this is the last page.
    pub next_cursor: Option<String>,
}

/// Persistence operations for snapshot metadata records.
///
/// The repository is the authoritative store for snapshot metadata.
/// Restore and fork operations load metadata from the repository
/// before validating compatibility and retrieving blobs.
///
/// # Audit enforcement
///
/// **All production access paths** MUST wrap the concrete repository
/// implementation with [`AuditLoggedSnapshotRepository`] to satisfy
/// the metadata access audit requirement. Any code path that
/// calls `get_snapshot` or `list_snapshots` on an unwrapped repository
/// bypasses audit logging.
///
/// Recommended wiring pattern:
///
/// ```ignore
/// use pico_core::snapshot::repository::AuditLoggedSnapshotRepository;
///
/// let repo = AuditLoggedSnapshotRepository::new(
///     inner_repo,        // Arc<dyn SnapshotRepository>
///     audit_sink,        // Arc<dyn AuditEventSink>
///     hlc,               // Arc<Hlc>
///     "service-name",    // e.g. "api", "host-agent"
///     Some(principal),   // authenticated caller, if known
/// );
/// ```
#[async_trait]
pub trait SnapshotRepository: Send + Sync {
    /// Retrieves snapshot metadata by ID.
    ///
    /// Returns `SnapshotNotFound` if the snapshot does not exist.
    async fn get_snapshot(&self, id: &SnapshotId) -> SnapshotResult<SnapshotMetadata>;

    /// Stores a new snapshot metadata record.
    ///
    /// Returns `SnapshotAlreadyExists` if a snapshot with this ID already exists.
    async fn store_snapshot(&self, metadata: &SnapshotMetadata) -> SnapshotResult<()>;

    /// Updates an existing snapshot metadata record.
    ///
    /// The `expected_version` enables optimistic concurrency control.
    /// Returns an error if the version does not match.
    async fn update_snapshot(
        &self,
        metadata: &SnapshotMetadata,
        expected_version: u64,
    ) -> SnapshotResult<()>;

    /// Lists snapshots for a tenant with pagination and optional filters.
    ///
    /// `limit` controls the maximum number of snapshots per page (1-250).
    /// `cursor` is an opaque page cursor from a previous response, or `None`
    /// to fetch the first page.
    async fn list_snapshots(
        &self,
        tenant_id: &TenantId,
        purpose: Option<SnapshotPurpose>,
        state: Option<SnapshotState>,
        limit: usize,
        cursor: Option<String>,
    ) -> SnapshotResult<SnapshotListPage>;

    /// Deletes a snapshot metadata record.
    ///
    /// This is a hard delete; prefer `revoke()` on the metadata record
    /// for soft deletion with a recovery window.
    async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()>;
}

/// Decorator that wraps a [`SnapshotRepository`] and emits audit events
/// for every `get_snapshot` and `list_snapshots` call.
///
/// **Required for production.** All code paths that access snapshot metadata
/// MUST use this wrapper. Unwrapped `get_snapshot`/`list_snapshots` calls
/// bypass audit logging and violate.
///
/// Pass-through methods (`store_snapshot`, `update_snapshot`, `delete_snapshot`)
/// are forwarded without audit events — they are covered by existing
/// snapshot operation audit events in the restore orchestrator.
///
/// # Audit fields
///
/// Each emitted event includes:
/// - The **principal** or **service** that initiated the access
/// - The **snapshot ID** (for reads) and **tenant ID**
/// - The **operation type** ("read" or "list")
/// - A wall-clock **timestamp** (HLC for causal ordering)
/// - The **outcome** (success or failure)
///
/// # Construction
///
/// Provide a `service` name (e.g. "host-agent", "api") that identifies the
/// calling component. Optionally provide a [`PrincipalId`] when the
/// authenticated caller is known (e.g. from an API request context).
pub struct AuditLoggedSnapshotRepository {
    inner: Arc<dyn SnapshotRepository>,
    sink: Arc<dyn AuditEventSink>,
    hlc: Arc<Hlc>,
    /// The service component making the access (e.g. "host-agent", "api").
    service: String,
    /// The authenticated principal, if known at construction time.
    principal: Option<PrincipalId>,
}

impl AuditLoggedSnapshotRepository {
    /// Creates a new audit-logging repository wrapper.
    ///
    /// # Parameters
    ///
    /// * `inner` — The repository to wrap.
    /// * `sink` — Audit event sink for emitting access events.
    /// * `hlc` — Hybrid logical clock for event timestamps.
    /// * `service` — Name of the service component making the access
    ///   (included in audit events as the `producer` field).
    /// * `principal` — Optional authenticated principal identity to
    ///   record in audit events.
    pub fn new(
        inner: Arc<dyn SnapshotRepository>,
        sink: Arc<dyn AuditEventSink>,
        hlc: Arc<Hlc>,
        service: impl Into<String>,
        principal: Option<PrincipalId>,
    ) -> Self {
        Self {
            inner,
            sink,
            hlc,
            service: service.into(),
            principal,
        }
    }

    /// Creates a new audit-logging wrapper without a specific principal.
    ///
    /// Equivalent to `new(inner, sink, hlc, service, None)`.
    pub fn service_only(
        inner: Arc<dyn SnapshotRepository>,
        sink: Arc<dyn AuditEventSink>,
        hlc: Arc<Hlc>,
        service: impl Into<String>,
    ) -> Self {
        Self::new(inner, sink, hlc, service, None)
    }
}

#[async_trait]
impl SnapshotRepository for AuditLoggedSnapshotRepository {
    async fn get_snapshot(&self, id: &SnapshotId) -> SnapshotResult<SnapshotMetadata> {
        let id_str = id.to_string();
        let result = self.inner.get_snapshot(id).await;

        let (outcome, tid, reason) = match &result {
            Ok(meta) => ("success", Some(meta.tenant_id.to_string()), None),
            Err(e) => ("failed", None, Some(e.to_string())),
        };

        emit_snapshot_metadata_access(
            &*self.sink,
            &self.hlc,
            "read",
            outcome,
            Some(&id_str),
            tid.as_deref(),
            None,
            None,
            &self.service,
            self.principal.as_ref(),
            reason.as_deref(),
        );

        result
    }

    async fn store_snapshot(&self, metadata: &SnapshotMetadata) -> SnapshotResult<()> {
        self.inner.store_snapshot(metadata).await
    }

    async fn update_snapshot(
        &self,
        metadata: &SnapshotMetadata,
        expected_version: u64,
    ) -> SnapshotResult<()> {
        self.inner.update_snapshot(metadata, expected_version).await
    }

    async fn list_snapshots(
        &self,
        tenant_id: &TenantId,
        purpose: Option<SnapshotPurpose>,
        state: Option<SnapshotState>,
        limit: usize,
        cursor: Option<String>,
    ) -> SnapshotResult<SnapshotListPage> {
        let tid = tenant_id.to_string();
        let filter_desc = build_list_filter_desc(purpose, state, limit, cursor.as_deref());
        let result = self
            .inner
            .list_snapshots(tenant_id, purpose, state, limit, cursor)
            .await;

        let (outcome, count, reason) = match &result {
            Ok(page) => ("success", Some(page.snapshots.len()), None),
            Err(e) => ("failed", None, Some(e.to_string())),
        };

        emit_snapshot_metadata_access(
            &*self.sink,
            &self.hlc,
            "list",
            outcome,
            None,
            Some(&tid),
            Some(&filter_desc),
            count,
            &self.service,
            self.principal.as_ref(),
            reason.as_deref(),
        );

        result
    }

    async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()> {
        self.inner.delete_snapshot(id).await
    }
}

/// Builds a human-readable filter description for list audit events.
fn build_list_filter_desc(
    purpose: Option<SnapshotPurpose>,
    state: Option<SnapshotState>,
    limit: usize,
    cursor: Option<&str>,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref p) = purpose {
        parts.push(format!("purpose={}", p.as_str()));
    }
    if let Some(ref s) = state {
        parts.push(format!("state={}", s.as_str()));
    }
    parts.push(format!("limit={}", limit));
    if cursor.is_some() {
        parts.push("has_cursor=true".into());
    }
    if parts.is_empty() {
        "no filter".into()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_bus::InMemoryAuditSink;
    use crate::identity::{
        AuditEventDetails, AuditEventKind, Hlc, OperationId, PrincipalId, SandboxId,
    };
    use crate::snapshot::profile::SnapshotProfile;
    use crate::snapshot::purpose::{LineageType, SnapshotPurpose};
    use crate::snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};
    use crate::snapshot::state::SnapshotState;
    use crate::snapshot::{SnapshotError, SnapshotListPage, SnapshotMetadata, SnapshotResult};
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::sync::Arc;

    // In-memory test repository.
    struct MemRepo {
        snapshots: Mutex<Vec<SnapshotMetadata>>,
    }

    impl MemRepo {
        fn new() -> Self {
            Self {
                snapshots: Mutex::new(Vec::new()),
            }
        }

        fn add(&self, meta: SnapshotMetadata) {
            self.snapshots.lock().push(meta);
        }
    }

    #[async_trait]
    impl SnapshotRepository for MemRepo {
        async fn get_snapshot(&self, id: &SnapshotId) -> SnapshotResult<SnapshotMetadata> {
            self.snapshots
                .lock()
                .iter()
                .find(|m| m.id == *id)
                .cloned()
                .ok_or_else(|| SnapshotError::SnapshotNotFound { id: id.to_string() })
        }

        async fn store_snapshot(&self, metadata: &SnapshotMetadata) -> SnapshotResult<()> {
            self.snapshots.lock().push(metadata.clone());
            Ok(())
        }

        async fn update_snapshot(
            &self,
            metadata: &SnapshotMetadata,
            _expected_version: u64,
        ) -> SnapshotResult<()> {
            let mut guard = self.snapshots.lock();
            if let Some(existing) = guard.iter_mut().find(|m| m.id == metadata.id) {
                *existing = metadata.clone();
                Ok(())
            } else {
                Err(SnapshotError::SnapshotNotFound {
                    id: metadata.id.to_string(),
                })
            }
        }

        async fn list_snapshots(
            &self,
            _tenant_id: &TenantId,
            _purpose: Option<SnapshotPurpose>,
            _state: Option<SnapshotState>,
            _limit: usize,
            _cursor: Option<String>,
        ) -> SnapshotResult<SnapshotListPage> {
            let snapshots = self.snapshots.lock().clone();
            Ok(SnapshotListPage {
                snapshots,
                next_cursor: None,
            })
        }

        async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()> {
            self.snapshots.lock().retain(|m| m.id != *id);
            Ok(())
        }
    }

    fn make_test_metadata(id: Option<SnapshotId>, tenant: Option<TenantId>) -> SnapshotMetadata {
        SnapshotMetadata::new(
            id.unwrap_or_else(SnapshotId::generate),
            tenant.unwrap_or_else(|| TenantId::from_string("tnt_test")),
            SandboxId::generate(),
            None,
            LineageType::Root,
            SnapshotPurpose::Session,
            SnapshotProfile::Filesystem,
            OperationId::generate(),
            "img_test".into(),
            BackendRecord {
                backend_type: "firecracker".into(),
                backend_version: "1.10.0".into(),
                protocol_version: "2.0".into(),
                guest_agent_version: Some("0.5.0".into()),
            },
            CpuShape::new("x86_64"),
            MemoryShape {
                memory_mb: 2048,
                vcpus: 2,
            },
            DeviceModel::new("q35"),
        )
    }

    #[tokio::test]
    async fn audit_logged_get_snapshot_emits_event_on_success() {
        let inner = Arc::new(MemRepo::new());
        let sink = Arc::new(InMemoryAuditSink::new());
        let hlc = Arc::new(Hlc::new());
        let meta = make_test_metadata(None, None);
        let id = meta.id.clone();
        inner.add(meta);

        let wrapper = AuditLoggedSnapshotRepository::service_only(
            inner,
            Arc::<InMemoryAuditSink>::clone(&sink),
            hlc,
            "test-service",
        );

        let result = wrapper.get_snapshot(&id).await;
        assert!(result.is_ok());

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, AuditEventKind::SnapshotMetadataAccess);

        let details = events[0].details.as_ref().unwrap();
        if let AuditEventDetails::SnapshotMetadataAccess {
            operation,
            outcome,
            snapshot_id,
            tenant_id,
            result_count,
            ..
        } = details
        {
            assert_eq!(operation, "read");
            assert_eq!(outcome, "success");
            assert_eq!(snapshot_id.as_deref(), Some(id.to_string()).as_deref());
            assert!(tenant_id.is_some());
            assert_eq!(*result_count, None);
        } else {
            panic!("expected SnapshotMetadataAccess details");
        }

        assert_eq!(events[0].producer.as_deref(), Some("test-service"));
        assert!(events[0].principal.is_none());
    }

    #[tokio::test]
    async fn audit_logged_get_snapshot_emits_event_on_failure() {
        let inner = Arc::new(MemRepo::new());
        let sink = Arc::new(InMemoryAuditSink::new());
        let hlc = Arc::new(Hlc::new());
        let id = SnapshotId::generate();

        let wrapper = AuditLoggedSnapshotRepository::new(
            inner,
            Arc::<InMemoryAuditSink>::clone(&sink),
            hlc,
            "test-service",
            Some(PrincipalId::new("user:alice")),
        );

        let result = wrapper.get_snapshot(&id).await;
        assert!(result.is_err());

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, AuditEventKind::SnapshotMetadataAccess);
        assert_eq!(events[0].outcome.as_deref(), Some("failed"));
        assert_eq!(
            events[0].principal.as_ref().map(|p| p.as_str()),
            Some("user:alice")
        );
    }

    #[tokio::test]
    async fn audit_logged_list_snapshots_emits_event() {
        let inner = Arc::new(MemRepo::new());
        let sink = Arc::new(InMemoryAuditSink::new());
        let hlc = Arc::new(Hlc::new());
        let tenant = TenantId::from_string("tnt_list");
        let meta1 = make_test_metadata(None, Some(tenant.clone()));
        let meta2 = make_test_metadata(None, Some(tenant.clone()));
        inner.add(meta1);
        inner.add(meta2);

        let wrapper = AuditLoggedSnapshotRepository::service_only(
            inner,
            Arc::<InMemoryAuditSink>::clone(&sink),
            hlc,
            "list-service",
        );

        let page = wrapper
            .list_snapshots(&tenant, None, None, 50, None)
            .await
            .unwrap();
        assert_eq!(page.snapshots.len(), 2);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, AuditEventKind::SnapshotMetadataAccess);

        let details = events[0].details.as_ref().unwrap();
        if let AuditEventDetails::SnapshotMetadataAccess {
            operation,
            outcome,
            snapshot_id,
            result_count,
            filter,
            ..
        } = details
        {
            assert_eq!(operation, "list");
            assert_eq!(outcome, "success");
            assert!(snapshot_id.is_none());
            assert_eq!(*result_count, Some(2));
            assert!(filter.as_deref().unwrap().contains("limit=50"));
        } else {
            panic!("expected SnapshotMetadataAccess details");
        }
    }

    #[tokio::test]
    async fn audit_logged_list_snapshots_failure_emits_event() {
        // A repo that always fails on list.
        struct FailingRepo;

        #[async_trait]
        impl SnapshotRepository for FailingRepo {
            async fn get_snapshot(&self, _: &SnapshotId) -> SnapshotResult<SnapshotMetadata> {
                Err(SnapshotError::SnapshotNotFound { id: "never".into() })
            }
            async fn store_snapshot(&self, _: &SnapshotMetadata) -> SnapshotResult<()> {
                Ok(())
            }
            async fn update_snapshot(&self, _: &SnapshotMetadata, _: u64) -> SnapshotResult<()> {
                Ok(())
            }
            async fn list_snapshots(
                &self,
                _: &TenantId,
                _: Option<SnapshotPurpose>,
                _: Option<SnapshotState>,
                _: usize,
                _: Option<String>,
            ) -> SnapshotResult<SnapshotListPage> {
                Err(SnapshotError::SnapshotNotFound {
                    id: "list_fail".into(),
                })
            }
            async fn delete_snapshot(&self, _: &SnapshotId) -> SnapshotResult<()> {
                Ok(())
            }
        }

        let inner = Arc::new(FailingRepo);
        let sink = Arc::new(InMemoryAuditSink::new());
        let hlc = Arc::new(Hlc::new());
        let tenant = TenantId::from_string("tnt_fail");

        let wrapper = AuditLoggedSnapshotRepository::service_only(
            inner,
            Arc::<InMemoryAuditSink>::clone(&sink),
            hlc,
            "fail-service",
        );

        let result = wrapper.list_snapshots(&tenant, None, None, 10, None).await;
        assert!(result.is_err());

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome.as_deref(), Some("failed"));
    }

    #[tokio::test]
    async fn audit_logged_repo_passes_through_store_and_delete() {
        let inner = Arc::new(MemRepo::new());
        let sink = Arc::new(InMemoryAuditSink::new());
        let hlc = Arc::new(Hlc::new());
        let meta = make_test_metadata(None, None);
        let id = meta.id.clone();

        let wrapper = AuditLoggedSnapshotRepository::service_only(
            Arc::<MemRepo>::clone(&inner),
            sink,
            hlc,
            "passthrough",
        );

        // store should pass through without audit
        wrapper.store_snapshot(&meta).await.unwrap();
        assert!(inner.get_snapshot(&id).await.is_ok());

        // delete should pass through without audit
        wrapper.delete_snapshot(&id).await.unwrap();
        assert!(inner.get_snapshot(&id).await.is_err());
    }

    #[test]
    fn build_list_filter_desc_with_filters() {
        let desc = build_list_filter_desc(
            Some(SnapshotPurpose::Base),
            Some(SnapshotState::Ready),
            25,
            Some("cursor_abc"),
        );
        assert!(desc.contains("purpose=base"));
        assert!(desc.contains("state=ready"));
        assert!(desc.contains("limit=25"));
        assert!(desc.contains("has_cursor=true"));
    }

    #[test]
    fn build_list_filter_desc_no_filters() {
        let desc = build_list_filter_desc(None, None, 100, None);
        assert_eq!(desc, "limit=100");
    }

    #[test]
    fn audit_logged_snapshot_repository_new_with_principal() {
        let inner = Arc::new(MemRepo::new());
        let sink = Arc::new(InMemoryAuditSink::new());
        let hlc = Arc::new(Hlc::new());

        let wrapper = AuditLoggedSnapshotRepository::new(
            inner,
            sink,
            hlc,
            "custom-service",
            Some(PrincipalId::new("user:bob")),
        );

        assert_eq!(wrapper.service, "custom-service");
        assert_eq!(
            wrapper.principal.as_ref().map(|p| p.as_str()),
            Some("user:bob")
        );
    }
}
