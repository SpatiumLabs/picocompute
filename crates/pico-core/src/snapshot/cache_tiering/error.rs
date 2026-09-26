use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CacheTierError {
    #[error("reference already exists for snapshot {snapshot_id}")]
    ReferenceAlreadyExists { snapshot_id: String },

    #[error("reference not found for snapshot {snapshot_id}")]
    ReferenceNotFound { snapshot_id: String },

    #[error(
        "cannot evict snapshot {snapshot_id}: still referenced by {ref_count} active holder(s)"
    )]
    SnapshotReferenced { snapshot_id: String, ref_count: u64 },

    #[error(
        "cache tier {tier} has no capacity for snapshot {snapshot_id} (used: {used_bytes}, max: {max_bytes})"
    )]
    TierFull {
        tier: String,
        snapshot_id: String,
        used_bytes: u64,
        max_bytes: u64,
    },

    #[error("snapshot {snapshot_id} not found in cache tier {tier}")]
    SnapshotNotCached { snapshot_id: String, tier: String },

    #[error("snapshot {snapshot_id} not found in any tier")]
    SnapshotNotFound { snapshot_id: String },

    #[error("retention period has not elapsed for snapshot {snapshot_id}")]
    RetentionActive { snapshot_id: String },

    #[error("GC cannot proceed: no live references for snapshot {snapshot_id} found in repository")]
    NoReferencesFound { snapshot_id: String },

    #[error("cache tier {tier} is not eligible for eviction policy {policy}")]
    TierNotEligible { tier: String, policy: String },

    #[error("I/O error during cache operation: {reason}")]
    IoError { reason: String },
}

pub type CacheTierResult<T> = std::result::Result<T, CacheTierError>;
