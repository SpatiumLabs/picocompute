//! Snapshot cache tiering, eviction, and garbage collection.
//!
//! Implements: a three-tier snapshot cache (host-local, cell cache,
//! regional object store) with configurable eviction policies, reference-aware
//! garbage collection, and OTLP metrics emission.
//!
//! ## Tier ordering
//!
//! Tiers are ordered by proximity: `HostLocal` (fastest, smallest) ->
//! `CellCache` (shared within a cell) -> `RegionalObjectStore` (durable,
//! highest capacity).  The `TieredCacheManager::lookup` method searches tiers
//! in registration order; register them from fastest to slowest.
//!
//! ## Reference sources
//!
//! The `SnapshotRefTracker` tracks references from:
//! - `ActiveSandbox` — running sandboxes that hold a live reference to a snapshot
//! - `ImageWarmPool` — pre-warmed base snapshots kept ready for fast cold starts
//! - `ForkLineage` — child snapshots that depend on a parent via fork lineage
//! - `ExternalRestore` — external systems performing a restore
//!
//! ## Core invariant: never delete live data
//!
//! Every eviction path checks `SnapshotRefTracker::is_referenced()` before
//! removing a cached entry.  The GC `find_gc_candidates` filter additionally
//! checks: the snapshot is not in a terminal state, has no live descendants in
//! the `LineageGraph`, and the retention period has elapsed.  Pinned entries
//! in a cache tier are also protected from eviction.
//!
//! ## Concurrency model
//!
//! `CacheTierStore`, `EvictionEngine`, `CacheGarbageCollector`, and
//! `SnapshotRefTracker` are all `&mut self` structures.  They are designed to
//! be owned by a single async task (e.g. a background GC worker or the
//! restore coordinator) and accessed sequentially.  If shared across tasks,
//! wrap the entire `CacheIntegration` in `Arc<tokio::sync::Mutex<...>>`.
//! The check-then-evict pattern is not atomic — callers running concurrent
//! eviction + insert must serialise access.
//!
//! ## Eviction complexity
//!
//! `eviction_candidates()` does a full O(n) scan of all unpinned entries
//! followed by a sort by last-access time, access count, or size.  This is
//! acceptable for caches under ~10k entries (typical of a single host).
//! Beyond that, replace the sort with a `BTreeMap`-backed LRU index or
//! a min-heap for LFU.
//!
//! ## Back-pressure
//!
//! `CacheTierStore::insert` calls `enforce_eviction_policy` before admitting a
//! new entry.  If the policy cannot free enough bytes or slots, `TierFull` is
//! returned.  Callers can pre-flight with `eviction_candidates()` to decide
//! whether to cache at all.  Pinned entries are never evicted.

pub mod error;
pub mod eviction;
pub mod gc;
pub mod integration;
pub mod policy;
pub mod reference;
pub mod tier;

pub use error::*;
pub use eviction::*;
pub use gc::*;
pub use integration::*;
pub use policy::*;
pub use reference::*;
pub use tier::*;
