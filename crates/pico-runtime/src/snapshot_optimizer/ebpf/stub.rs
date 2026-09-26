use std::path::Path;

use crate::snapshot_optimizer::{
    CgroupId, DirtyPageEvent, IoHeatmapEvent, SnapshotOptimizationError,
};

pub(super) struct StubBackend {
    _private: (),
}

impl StubBackend {
    #[must_use]
    pub(super) fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for StubBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::snapshot_optimizer::SnapshotOptimizationBackend for StubBackend {
    fn register_sandbox(
        &self,
        _sandbox_id: &str,
        _cgroup_id: CgroupId,
        _cgroup_path: &Path,
    ) -> Result<(), SnapshotOptimizationError> {
        Ok(())
    }

    fn unregister_sandbox(&self, _sandbox_id: &str) -> Result<(), SnapshotOptimizationError> {
        Ok(())
    }

    fn drain_dirty_page_events(&self) -> Vec<DirtyPageEvent> {
        Vec::new()
    }

    fn drain_io_events(&self) -> Vec<IoHeatmapEvent> {
        Vec::new()
    }

    fn is_available(&self) -> bool {
        false
    }
}
