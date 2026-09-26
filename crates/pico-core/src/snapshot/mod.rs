//! Snapshot metadata model.
//!
//! Defines the durable snapshot metadata record, state machine, purpose
//! classification, state profile, lineage graph, compatibility validation,
//! integrity references, typed errors, blob storage abstraction, metadata
//! repository, and restore coordination.
//!
//! This module implements: Snapshot Metadata Model and:
//! Base Snapshot Restore, and: Prototype copy-on-write workspace
//! branching, following the consistency contract defined in ADR-0007.

pub mod blob;
pub mod cache_tiering;
pub mod compatibility;
pub mod cow;
pub mod credential_policy;
pub mod encryption;
pub mod error;
pub mod integrity;
pub mod lineage;
pub mod metadata;
pub mod profile;
pub mod purpose;
pub mod repository;
pub mod restore;
pub mod restore_executor;
pub mod shape;
pub mod state;

pub use blob::*;
pub use compatibility::*;
pub use cow::*;
pub use credential_policy::*;
pub use encryption::*;
pub use error::*;
pub use integrity::*;
pub use lineage::*;
pub use metadata::*;
pub use profile::*;
pub use purpose::*;
pub use repository::*;
pub use restore::*;
pub use restore_executor::*;
pub use shape::*;
pub use state::*;

// cache_tiering module is intentionally not re-exported via wildcard.
// Its types (CacheTier, GcPolicy, CacheGarbageCollector, etc.) are
// accessed through snapshot::cache_tiering::<Type> to avoid namespace
// collisions and to signal that the module is a distinct subsystem.
