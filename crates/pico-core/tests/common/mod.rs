use async_trait::async_trait;
use parking_lot::Mutex;
use pico_core::identity::{SnapshotId, TenantId};
use pico_core::snapshot::{
    SnapshotError, SnapshotListPage, SnapshotMetadata, SnapshotPurpose, SnapshotRepository,
    SnapshotResult, SnapshotState,
};

pub(crate) struct InMemorySnapshotRepo {
    snapshots: Mutex<Vec<SnapshotMetadata>>,
}

impl InMemorySnapshotRepo {
    pub(crate) fn new() -> Self {
        Self {
            snapshots: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn store(&self, meta: &SnapshotMetadata) {
        self.snapshots.lock().push(meta.clone());
    }
}

#[async_trait]
impl SnapshotRepository for InMemorySnapshotRepo {
    async fn get_snapshot(&self, id: &SnapshotId) -> SnapshotResult<SnapshotMetadata> {
        self.snapshots
            .lock()
            .iter()
            .find(|m| m.id == *id)
            .cloned()
            .ok_or_else(|| SnapshotError::SnapshotNotFound { id: id.to_string() })
    }

    async fn store_snapshot(&self, metadata: &SnapshotMetadata) -> SnapshotResult<()> {
        self.store(metadata);
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
        Ok(SnapshotListPage {
            snapshots: self.snapshots.lock().clone(),
            next_cursor: None,
        })
    }

    async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()> {
        self.snapshots.lock().retain(|m| m.id != *id);
        Ok(())
    }
}
