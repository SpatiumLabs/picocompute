//! Shared contracts and data types used by the API, host agent, and runtimes.

pub mod admission;
pub mod audit;
pub mod availability;
pub mod backend_selection;
pub mod capacity;
mod cell_scheduler;
pub mod cgroups;
pub mod cost_model;
pub mod cpu_isolation;
mod create;
pub mod crypto;
mod emergency_rebuild;
pub mod error;
pub mod event_bus;
mod fs_retry;
mod host_quarantine;
pub mod identity;
pub mod image_cache;
pub mod in_flight;
pub mod lease_token;
pub mod leases;
mod lifecycle;
pub mod metadata;
pub mod metrics;
pub mod mount;
mod observation;
mod operator;
pub mod overcommit;
pub mod overcommit_p1;
pub mod placement_engine;
pub mod policy;
pub mod preemption;
mod quota;
pub mod restore_capacity;
pub mod runtime;
mod sandbox_facade;
mod scheduler;
pub mod secrets;
pub mod slo_validation;
pub mod snapshot;
pub mod tenant;
pub mod types;
pub mod workspace;

pub use admission::*;
pub use audit::*;
pub use backend_selection::*;
pub use cell_scheduler::{
    CellBackpressureSignal, CellScheduler, CellSchedulerError, CellSchedulerRequest,
    CellSchedulerResponse, CellScoringWeights, HostCacheState, HostCapacity, HostHealth, HostInfo,
    HostInventory, HostPlacementReason, HostPressure, HostRejection, HostScoreBreakdown,
    HostScoreComponent, HostScoreDimension, PlacementMetrics, RejectionCount,
};
pub use create::*;
pub use emergency_rebuild::{
    EmergencyError, EmergencyExercise, EmergencyStage, REQUIRED_DRAIN_AUDIT_KIND,
    REQUIRED_REBUILD_AUDIT_KIND, REQUIRED_REVOKE_AUDIT_KIND,
};
pub use error::{PLACEMENT_RETRY_AFTER_SECS, Result, SandboxError};
pub use event_bus::*;
pub use fs_retry::{
    TRANSIENT_FS_BASE_DELAY, TRANSIENT_FS_MAX_ATTEMPTS, TRANSIENT_FS_MAX_DELAY,
    TransientFsRetryPolicy, is_transient_fs_error, retry_transient_fs_op,
    retry_transient_fs_op_with,
};
pub use host_quarantine::{
    AlertCondition, AlertSeverity, AlertStateManager, HostAlert, HostAlertEvaluation,
};
pub use identity::*;
pub use in_flight::{
    DEFAULT_IN_FLIGHT_MAX_ENTRIES, DEFAULT_IN_FLIGHT_TTL_SECS, InFlightOverlay, InFlightReservation,
};
pub use lease_token::*;
pub use leases::*;
pub use lifecycle::{
    ensure_destroy_precondition, ensure_purge_precondition, ensure_stop_precondition,
};
pub use metadata::*;
pub use metrics::CORE_METRICS;
pub use observation::{
    CoherenceDecision, ObservationCoherence, ObservationEpoch, SshObservation,
    merge_ssh_observation,
};
pub use operator::{
    AcknowledgeEvidence, DrainEvidence, FencedCleanupEvidence, LedgerInspectEvidence,
    LedgerInspectQuery, OperatorError, OperatorTicket, ReadmitChecks, ResolveEvidence,
    UNDRAIN_NOT_SUPPORTED, parse_condition, validate_acknowledge, validate_drain,
    validate_fenced_cleanup, validate_ledger_inspect, validate_readmit, validate_resolve,
    validate_ticket,
};
pub use overcommit::{
    BE_CPU_WEIGHT, BE_MEMORY_HIGH_FRACTION, BalloonDriver, BalloonPolicy, BalloonTarget,
    BaseSharingMode, CoreSchedSupport, LS_CPU_WEIGHT, LS_MEMORY_HIGH_FRACTION,
    MAX_OVERCOMMIT_RATIO, MAX_SHARED_BASE_MB, OvercommitPolicy, SchedPolicy, ServiceClass,
    ServiceClassControls, apply_sched_policy_to_pid, apply_service_class_sched_policy,
    balloon_target, controls_for_class, effective_capacity_for_class, effective_memory_request,
    idle_reclaim_plan, is_sched_permission_denied, probe_core_scheduling, resolve_service_class,
    sched_policy_for_class,
};
pub use overcommit_p1::{
    BeBitRecord, BeBitVerdict, CoreSchedBranch, DSEC_SMT_INFLATION_HIGH_PCT,
    DSEC_SMT_INFLATION_LOW_PCT, ExecKneeComparison, LsBaselineVerdict, NoisyVerdict,
    OvercommitSweepPoint, P1Mechanism, ReclaimComparison, SmtInflationBand, SoakVerdict,
    SweepSummary, bit_record_from_response, check_noisy_holds, check_soak_holds,
    classify_smt_inflation, compare_exec_knees, compare_ls_warning_max, core_sched_branch,
    graduation_for_mechanism, measure_reclaim_freed_bytes, smt_inflation_pct, summarize_sweep,
    sweep_mode_order_ok, verify_be_overcommit_bits,
};
pub use placement_engine::{
    ConstraintResult, PlacementBackpressure, PlacementOutcome, PlacementOutcomeWithBreakdown,
    ScoredCandidate, ScoredWithBreakdown, SelectionDetail, SelectionMode, place,
    place_sampled_with_breakdown, place_with_breakdown,
};
pub use policy::*;
pub use preemption::*;
pub use quota::*;
pub use runtime::*;
pub use sandbox_facade::*;
pub use scheduler::*;
pub use snapshot::*;
pub use tenant::*;
pub use types::*;
pub use workspace::{reject_traversal, validate_sandbox_id};

#[cfg(any(test, feature = "mock-backend"))]
pub mod mock;
