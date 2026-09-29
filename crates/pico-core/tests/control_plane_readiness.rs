//! Integrated control-plane production readiness validation.
//!
//! This suite validates the Control Plane as an integrated subsystem rather
//! than as isolated API, metadata, policy, scheduler, lease, and audit
//! components. Each test composes at least two control-plane modules through
//! their public APIs and asserts the contract that holds between them.
//!
//! Validation areas (see):
//! - A: Lifecycle API contract compatibility.
//! - B: Metadata state machine correctness under retry and concurrency.
//! - C: Secure time and identity binding behavior.
//! - D: Policy and quota enforcement behavior.
//! - E: Access lease issue, expiry, renewal, and revocation behavior.
//! - F: Regional and cell scheduler placement behavior.
//! - G: Lifecycle audit ordering and correlation.
//! - H: Control-plane degradation and recovery behavior.
//! - I: Scheduler-on-create integrated path.
//! - J: Stale-operation convergence and idempotent retry.
//!
//! Known boundaries pinned (not fixed) by this suite:
//! - `SandboxFacade` is the narrow lifecycle seam; `SandboxService` carries
//!   the API data-plane operations. Suspend/resume policy is enforced by the
//!   API wrapper, while state validity is checked by the host backend.
//! - Destroy auto-revokes leases (issue 140): the destroy flow revokes all
//!   active leases for the sandbox with `RevocationReason::ResourceRemoved`
//!   between the `Destroying` commit and `Destroyed`, carrying the
//!   destroying operation identity onto each `LeaseRevoked` event.
//! - Offline lease enforcement (`enforce_blob`) does not consult the
//!   manager's revocation set; revocation-aware edge enforcement must use
//!   `enforce_blob_revocable` or re-validate against the manager.
//! - Scheduler-on-create carries trace, operation, and idempotency
//!   identity into placement and lifecycle audit events. Standalone
//!   scheduler calls without a create context still emit
//!   `trace_id=None` by contract.

use pico_core::{
    AccessLease, Admission, AdmitRequest, AuditEventBuilder, AuditEventDetails, AuditEventKind,
    AuditEventSink, CacheLocality, CellCapacity, CellHealth, CellId, CellInfo, CellScheduler,
    CellSchedulerError, CellSchedulerRequest, ChannelAuditSink, CreateError, CreateOrchestrator,
    CreateRequest, DEFAULT_PERMIT_POLICY, DestroyRevocationContext, EnforceContext, FencingToken,
    Hlc, HostCacheState, HostCapacity, HostHealth, HostId, HostInfo, HostPressure,
    IdempotencyStore, InMemoryAuditSink, LeaseAction, LeaseAuthority, LeaseManager, LeaseScope,
    LeaseValidationError, OperationId, PlacementReason, PolicyAction, PolicyDecision,
    PolicyDecisionId, PolicyEngine, PolicyOutcome, PrincipalId, QuotaAdmit, QuotaEngine,
    QuotaLimits, ReconcileAction, RegionId, RegionalScheduler, ResourceLimits, RevocationReason,
    RuntimeType, SandboxError, SandboxId, SandboxMetadata, SandboxState, ScheduleTraceContext,
    SchedulerError, SchedulerRequest, ServiceClass, SnapshotTimingHint, TenantId, TransitionError,
    apply_transition, apply_transition_with_audit, check_policy_epoch, is_lease_expired,
    is_ordered_chronologically, is_valid_idempotency_key, validate_causal_chain,
    validate_policy_epoch,
};
use std::sync::Arc;

// ---- Shared fixtures ----

fn test_tenant() -> TenantId {
    TenantId::from_string("tnt_readiness")
}

fn other_tenant() -> TenantId {
    TenantId::from_string("tnt_readiness_other")
}

fn test_principal() -> PrincipalId {
    PrincipalId::new("user:readiness")
}

fn sandbox(suffix: &str) -> SandboxId {
    SandboxId::from_string(format!("sbx_readiness_{suffix}"))
}

fn new_metadata(suffix: &str) -> SandboxMetadata {
    SandboxMetadata::new(
        sandbox(suffix),
        test_tenant(),
        "img:readiness".into(),
        Some(RuntimeType::Firecracker),
        ResourceLimits::default(),
        None,
    )
}

fn permit_policy() -> Arc<PolicyEngine> {
    let policy = Arc::new(PolicyEngine::new());
    policy.load_policies(DEFAULT_PERMIT_POLICY).unwrap();
    policy
}

fn fresh_admission() -> Admission {
    Admission::new(
        permit_policy(),
        Arc::new(QuotaEngine::new()),
        LeaseAuthority::generate(),
    )
}

fn allow_decision(epoch: u64) -> PolicyDecision {
    PolicyDecision {
        decision_id: PolicyDecisionId::generate(),
        outcome: PolicyOutcome::Allow,
        policy_epoch: epoch,
    }
}

fn deny_policy_text(action: &str) -> String {
    format!(
        r#"forbid(principal, action == PicoCompute::Action::"{action}", resource) when {{ true }};"#
    )
}

fn admit_exec(admission: &Admission, sbx: &SandboxId) -> AccessLease {
    admission
        .admit(AdmitRequest {
            tenant_id: test_tenant(),
            principal: test_principal(),
            sandbox_id: sbx.clone(),
            action: LeaseAction::Exec,
            scope: LeaseScope::unbounded(),
            ttl_secs: Some(300),
            quota: None,
        })
        .expect("permit policy must admit exec")
}

fn healthy_cell(id: &str, region: &str, failure_domain: &str) -> CellInfo {
    CellInfo {
        cell_id: CellId::from_string(id),
        region_id: RegionId::from_string(region),
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
        failure_domain: failure_domain.into(),
        cache: CacheLocality {
            cached_images: vec![],
            cached_snapshots: vec![],
        },
        admission_pressure: 0.0,
        snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    }
}

fn sched_request(sbx: &str) -> SchedulerRequest {
    SchedulerRequest {
        tenant_id: test_tenant(),
        vcpus: 2,
        memory_mb: 512,
        runtime: Some(RuntimeType::Firecracker),
        image: "img:readiness".into(),
        snapshot_id: None,
        preferred_region: None,
        avoid_failure_domains: vec![],
        sandbox_id: sbx.into(),
    }
}

fn healthy_host(id: &str) -> HostInfo {
    HostInfo {
        host_id: HostId::from_string(id),
        health: HostHealth::Healthy,
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
        supported_runtimes: vec![RuntimeType::Firecracker],
        cache: HostCacheState {
            cached_images: vec![],
            cached_snapshots: vec![],
        },
        pressure: HostPressure {
            in_flight_creates: 0,
            in_flight_restores: 0,
            max_concurrent_creates: 8,
            max_concurrent_restores: 8,
        },
        current_sandboxes: 0,
        snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    }
}

fn cell_request(sbx: &str) -> CellSchedulerRequest {
    CellSchedulerRequest {
        sandbox_id: sbx.into(),
        vcpus: 2,
        memory_mb: 512,
        disk_mb: 1024,
        runtime: Some(RuntimeType::Firecracker),
        image: "img:readiness".into(),
        snapshot_id: None,
        is_restore: false,
        service_class: ServiceClass::LatencySensitive,
    }
}

/// Full create-to-destroy walk through the desired-state mutation API.
fn full_lifecycle() -> Vec<(SandboxState, SandboxState)> {
    vec![
        (SandboxState::Pending, SandboxState::Scheduled),
        (SandboxState::Scheduled, SandboxState::Preparing),
        (SandboxState::Preparing, SandboxState::Booting),
        (SandboxState::Booting, SandboxState::Running),
        (SandboxState::Running, SandboxState::Suspending),
        (SandboxState::Suspending, SandboxState::Suspended),
        (SandboxState::Suspended, SandboxState::Resuming),
        (SandboxState::Resuming, SandboxState::Running),
        (SandboxState::Running, SandboxState::Destroying),
        (SandboxState::Destroying, SandboxState::Destroyed),
    ]
}

// ---- A: Lifecycle API contract compatibility ----

#[test]
fn lifecycle_contract_twelve_states_stable() {
    // The 12-state model from ADR-0001 is the wire contract for status
    // flows; adding, removing, or renaming a state breaks API consumers.
    assert_eq!(SandboxState::ALL.len(), 12);
    let names: Vec<&str> = SandboxState::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "Pending",
            "Scheduled",
            "Preparing",
            "Booting",
            "Running",
            "Suspending",
            "Suspended",
            "Resuming",
            "Stopped",
            "Destroying",
            "Destroyed",
            "Failed",
        ]
    );

    // Serde contract is PascalCase; every state must round-trip.
    for state in SandboxState::ALL {
        let json = serde_json::to_string(state).unwrap();
        assert_eq!(json, format!("\"{}\"", state.as_str()));
        let back: SandboxState = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, state);
    }

    // Exactly the transitory states must resolve or escalate; Destroyed is
    // the only terminal state.
    assert_eq!(SandboxState::TRANSITORY.len(), 5);
    assert!(SandboxState::Destroyed.is_terminal());
    for state in SandboxState::ALL {
        assert_eq!(
            state.is_terminal(),
            matches!(state, SandboxState::Destroyed),
            "{state:?} terminal classification changed"
        );
    }
}

#[test]
fn lifecycle_commit_walk_create_to_destroy() {
    // End-to-end create, suspend, resume, destroy, and status flows pass
    // against the integrated desired-state path (`commit`), which is the
    // only mutation path for regional desired lifecycle state.
    let mut meta = new_metadata("commit_walk");
    assert_eq!(meta.state, SandboxState::Pending);
    assert_eq!(meta.version, 1);

    for (step, (from, to)) in full_lifecycle().into_iter().enumerate() {
        meta.commit(from, to, None)
            .unwrap_or_else(|e| panic!("step {step}: {from:?} -> {to:?} must commit: {e}"));
        assert_eq!(meta.state, to, "step {step}: state must advance");
        // Optimistic concurrency: every commit bumps exactly one version.
        assert_eq!(meta.version, (step as u64) + 2, "step {step}: version bump");
        // Commit stamps durable write evidence.
        assert!(
            meta.timestamps.committed_at.is_some(),
            "step {step}: committed_at"
        );
        // Status flow surface stays consistent with the committed state.
        assert_eq!(meta.user_facing_state(), to, "step {step}: status surface");
    }
    assert_eq!(meta.state, SandboxState::Destroyed);
}

#[test]
fn lifecycle_commit_rejects_stale_and_terminal_writes() {
    let mut meta = new_metadata("commit_guards");

    // A stale writer that still believes the record is Pending cannot skip
    // ahead once another writer advanced it.
    meta.commit(SandboxState::Pending, SandboxState::Scheduled, None)
        .unwrap();
    let err = meta
        .commit(SandboxState::Pending, SandboxState::Preparing, None)
        .unwrap_err();
    assert!(
        matches!(err, TransitionError::UnexpectedState { .. }),
        "stale from-state must fail, got {err}"
    );
    assert_eq!(meta.state, SandboxState::Scheduled);
    assert_eq!(meta.version, 2);

    // Illegal jumps are rejected even with a fresh from-state.
    let err = meta
        .commit(SandboxState::Scheduled, SandboxState::Running, None)
        .unwrap_err();
    assert!(
        matches!(err, TransitionError::InvalidTransition { .. }),
        "jump must fail, got {err}"
    );

    // Terminal state is terminal: no transition out of Destroyed.
    meta.commit(SandboxState::Scheduled, SandboxState::Destroying, None)
        .unwrap();
    meta.commit(SandboxState::Destroying, SandboxState::Destroyed, None)
        .unwrap();
    let err = meta
        .commit(SandboxState::Destroyed, SandboxState::Destroying, None)
        .unwrap_err();
    assert!(
        matches!(err, TransitionError::TerminalState(_)),
        "terminal write must fail, got {err}"
    );
}

#[test]
fn lifecycle_failure_and_reconcile_paths() {
    // Any non-terminal state can escalate to Failed with structured info;
    // retryable failures stay recoverable while internal errors do not.
    let mut meta = new_metadata("failure_paths");
    meta.commit(SandboxState::Pending, SandboxState::Scheduled, None)
        .unwrap();
    meta.commit(SandboxState::Scheduled, SandboxState::Preparing, None)
        .unwrap();
    meta.commit(SandboxState::Preparing, SandboxState::Booting, None)
        .unwrap();
    meta.commit(SandboxState::Booting, SandboxState::Failed, None)
        .unwrap();
    meta.failure = Some(pico_core::FailureInfo {
        code: pico_core::FailureCode::BootTimeout,
        message: "guest agent did not answer".into(),
        component: Some("host-agent".into()),
        retryable: true,
        occurred_at: pico_core::types::now_iso(),
    });
    assert!(!meta.looks_unrecoverable());
    assert_eq!(
        meta.reconcile_action(SandboxState::Running),
        Some(ReconcileAction::EvaluateFailure)
    );
    assert!(
        !meta.diagnostic_reason().is_empty(),
        "failed status must carry a reason"
    );

    // Failed is a sink for execution: the record cannot resume work, but it
    // can be torn down. Recovery of a retryable failure means evaluating
    // (EvaluateFailure), destroying the failed record, and re-preparing a
    // new one - never reviving the failed record in place.
    assert_eq!(
        meta.reconcile_action(SandboxState::Destroying),
        Some(ReconcileAction::Destroy)
    );
    meta.commit(SandboxState::Failed, SandboxState::Destroying, None)
        .unwrap();
    // Leaving Failed clears the failure record on the teardown commit.
    assert!(meta.failure.is_none());
    meta.commit(SandboxState::Destroying, SandboxState::Destroyed, None)
        .unwrap();
    assert_eq!(meta.state, SandboxState::Destroyed);

    // Force-destroy is reachable from active states for operator cleanup.
    let mut active = new_metadata("force_destroy");
    active
        .commit(SandboxState::Pending, SandboxState::Scheduled, None)
        .unwrap();
    active
        .commit(SandboxState::Scheduled, SandboxState::Preparing, None)
        .unwrap();
    active
        .commit(SandboxState::Preparing, SandboxState::Booting, None)
        .unwrap();
    active
        .commit(SandboxState::Booting, SandboxState::Running, None)
        .unwrap();
    active
        .commit(SandboxState::Running, SandboxState::Destroying, None)
        .unwrap();
    active
        .commit(SandboxState::Destroying, SandboxState::Destroyed, None)
        .unwrap();
    assert_eq!(active.state, SandboxState::Destroyed);
}

// ---- B: Metadata retry and concurrency ----

#[test]
fn concurrent_transitions_single_winner() {
    // Concurrent writers racing on the same expected version must resolve
    // to exactly one winner; losers observe VersionConflict and must
    // re-read before retrying.
    use std::sync::Mutex;

    let meta = Arc::new(Mutex::new(new_metadata("race")));
    let winners = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let conflicts = Arc::new(std::sync::atomic::AtomicU64::new(0));

    std::thread::scope(|scope| {
        for _ in 0..16 {
            let meta = Arc::clone(&meta);
            let winners = Arc::clone(&winners);
            let conflicts = Arc::clone(&conflicts);
            scope.spawn(move || {
                let mut guard = meta.lock().unwrap();
                match apply_transition(&mut guard, SandboxState::Scheduled, 1) {
                    Ok(()) => {
                        winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(TransitionError::VersionConflict { .. }) => {
                        conflicts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(e) => panic!("unexpected transition error: {e}"),
                }
            });
        }
    });

    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(conflicts.load(std::sync::atomic::Ordering::SeqCst), 15);
    let guard = meta.lock().unwrap();
    assert_eq!(guard.state, SandboxState::Scheduled);
    assert_eq!(guard.version, 2);
}

#[test]
fn version_conflict_retry_converges_after_reread() {
    // The prescribed retry loop (conflict -> re-read version -> retry)
    // converges instead of wedging the record.
    let mut meta = new_metadata("retry_converges");
    let stale_version = meta.version;

    // Another writer advances the record first.
    apply_transition(&mut meta, SandboxState::Scheduled, stale_version).unwrap();

    // Stale retry fails closed ...
    let err = apply_transition(&mut meta, SandboxState::Preparing, stale_version).unwrap_err();
    let actual = match err {
        TransitionError::VersionConflict { actual, .. } => actual,
        e => panic!("expected version conflict, got {e}"),
    };

    // ... and the re-read retry succeeds exactly once.
    apply_transition(&mut meta, SandboxState::Preparing, actual).unwrap();
    assert_eq!(meta.state, SandboxState::Preparing);
    assert_eq!(meta.version, 3);
}

#[test]
fn completed_operation_retry_is_idempotent() {
    // Retrying an already-applied transition (same from/to after success)
    // surfaces AlreadyInState rather than duplicating the effect: the
    // version does not move and the state does not change.
    let mut meta = new_metadata("retry_idempotent");
    apply_transition(&mut meta, SandboxState::Scheduled, 1).unwrap();
    let version_after_first = meta.version;

    let err =
        apply_transition(&mut meta, SandboxState::Scheduled, version_after_first).unwrap_err();
    assert!(
        matches!(err, TransitionError::AlreadyInState(_)),
        "replayed transition must be AlreadyInState, got {err}"
    );
    assert_eq!(meta.version, version_after_first);
    assert_eq!(meta.state, SandboxState::Scheduled);
}

#[test]
fn stuck_transitory_state_escalates_to_failed() {
    // A transitory state that outlives its timeout is detectable via
    // `is_stuck` + `transitory_timeout` and can escalate to Failed.
    let mut meta = new_metadata("stuck_boot");
    meta.commit(SandboxState::Pending, SandboxState::Scheduled, None)
        .unwrap();
    meta.commit(SandboxState::Scheduled, SandboxState::Preparing, None)
        .unwrap();
    meta.commit(SandboxState::Preparing, SandboxState::Booting, None)
        .unwrap();

    let timeout = meta
        .transitory_timeout()
        .expect("Booting must declare a timeout");
    assert!(timeout > 0);

    // Fresh record is not stuck; a record whose heartbeat is older than the
    // timeout is stuck.
    assert!(!meta.is_stuck(timeout, &pico_core::types::now_iso()));
    meta.updated_at = "2020-01-01T00:00:00Z".into();
    assert!(meta.is_stuck(timeout, &pico_core::types::now_iso()));

    // Escalation itself is a legal transition any operator can commit.
    meta.commit(SandboxState::Booting, SandboxState::Failed, None)
        .unwrap();
    assert_eq!(meta.state, SandboxState::Failed);
}

// ---- C: Secure time and identity binding ----

#[test]
fn hlc_timestamps_are_monotonic_across_rapid_events() {
    // Secure time base: even back-to-back events from one HLC domain carry
    // strictly increasing timestamps so audit ordering never depends on
    // wall-clock granularity.
    let hlc = Hlc::new();
    let mut last = None;
    for _ in 0..50 {
        let ts = hlc.next_timestamp();
        if let Some(prev) = last {
            assert!(ts > prev, "HLC must advance monotonically");
        }
        last = Some(ts);
    }
}

#[test]
fn fencing_epoch_bump_invalidates_stale_holders() {
    // Identity binding via fencing: the record stores the newest token it
    // has seen; any holder of an older epoch/sequence fails closed.
    let mut meta = new_metadata("fencing_bump");
    let epoch1 = FencingToken::new(1);
    meta.commit(SandboxState::Pending, SandboxState::Scheduled, Some(epoch1))
        .unwrap();
    assert_eq!(meta.fencing_token, Some(epoch1));

    // Same token re-presented is not stale (equal is not older).
    meta.commit(
        SandboxState::Scheduled,
        SandboxState::Preparing,
        Some(epoch1),
    )
    .unwrap();

    // A newer epoch takes over ...
    let epoch2 = FencingToken::new(2);
    meta.commit(SandboxState::Preparing, SandboxState::Booting, Some(epoch2))
        .unwrap();

    // ... and the previous holder is now stale and cannot write.
    let err = meta
        .commit(SandboxState::Booting, SandboxState::Running, Some(epoch1))
        .unwrap_err();
    assert!(
        matches!(err, TransitionError::StaleFencingToken { .. }),
        "stale fencing holder must fail, got {err}"
    );
    assert_eq!(meta.state, SandboxState::Booting);
}

#[test]
fn stale_policy_epoch_is_rejected_before_side_effects() {
    // Stale policy scenario: a request admitted under an older policy epoch
    // must be rejected once the control plane has moved on.
    assert!(validate_policy_epoch(Some(2), Some(2)).is_ok());
    assert!(validate_policy_epoch(None, Some(2)).is_ok());
    assert!(validate_policy_epoch(Some(1), None).is_ok());
    let err = validate_policy_epoch(Some(1), Some(2)).unwrap_err();
    assert!(
        matches!(err, TransitionError::StalePolicyEpoch { .. }),
        "older request epoch must be stale, got {err}"
    );
    assert!(check_policy_epoch(Some(1), 2).is_err());
    assert!(check_policy_epoch(Some(2), 2).is_ok());
}

#[test]
fn lease_expiry_on_enforcement_path_is_bare_iso_compare() {
    // Production expiry (`has_lease_expired` / `LeaseManager::validate`)
    // is `expires_at <= now` with no skew window. `is_lease_expired` is a
    // standalone helper and is not on this path - pin that so the report
    // does not claim skew is enforced.
    let manager = LeaseManager::new();
    let sbx = sandbox("expiry_bare");
    let lease = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &allow_decision(1),
        0,
    );
    let err = manager
        .validate(&lease.lease_id, &sbx, &test_tenant(), LeaseAction::Exec, 1)
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::Expired { .. }),
        "ttl=0 must expire on the enforcement path, got {err}"
    );
    // Helper exists and is skew-aware, but unused by validate/enforce_blob.
    assert!(!is_lease_expired(1_000, 1_029, 30));
    assert!(is_lease_expired(1_000, 1_031, 30));
}

#[test]
fn actor_identity_is_stored_but_not_copied_onto_lifecycle_audit() {
    // Actor identity persists on the metadata record. `apply_transition_with_audit`
    // does not copy it onto the emitted event (`principal=None`) - pin the
    // gap the same way scheduler outcomes pin `trace_id=None`.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let mut meta = new_metadata("actor_binding");
    meta.actor_identity = Some(test_principal());

    apply_transition_with_audit(&mut meta, SandboxState::Scheduled, 1, sink.as_ref(), &hlc)
        .unwrap();

    assert_eq!(meta.actor_identity, Some(test_principal()));
    let events = sink.events_for_sandbox(&meta.id);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sandbox_id, Some(meta.id.clone()));
    assert_eq!(events[0].tenant_id, Some(test_tenant()));
    assert!(
        events[0].principal.is_none(),
        "lifecycle audit pins principal=None until apply_transition_with_audit copies actor_identity"
    );
}

// ---- D: Policy and quota enforcement ----

#[test]
fn admission_permit_issues_enforceable_lease() {
    // Integrated policy + lease path: one Admission call evaluates policy
    // and returns a signed lease blob that the offline enforce seam
    // accepts for the same epoch.
    let admission = fresh_admission();
    let sbx = sandbox("admit_enforce");
    let lease = admit_exec(&admission, &sbx);
    assert!(lease.signature.is_some());
    assert_eq!(lease.policy_epoch, admission.policy_epoch());

    let blob = admission.encode(&lease).unwrap();
    let ctx = EnforceContext {
        sandbox_id: &sbx,
        tenant_id: &test_tenant(),
        action: LeaseAction::Exec,
        scope: &LeaseScope::unbounded(),
        policy_epoch: admission.policy_epoch(),
    };
    let decoded = admission.authority().enforce_blob(&blob, &ctx).unwrap();
    assert_eq!(decoded.lease_id, lease.lease_id);
}

#[test]
fn policy_deny_blocks_admission_without_consuming_quota() {
    // Deny precedence: a policy denial must not mint a lease and must not
    // consume quota reservations.
    let policy = Arc::new(PolicyEngine::new());
    policy.load_policies(&deny_policy_text("Exec")).unwrap();
    let quota = Arc::new(QuotaEngine::new());
    quota.set_limits(
        test_tenant(),
        QuotaLimits {
            max_sandboxes: 10,
            max_vcpus: 20,
            max_memory_mb: 8192,
            ..Default::default()
        },
    );
    let admission = Admission::new(policy, Arc::clone(&quota), LeaseAuthority::generate());

    let err = admission
        .admit(AdmitRequest {
            tenant_id: test_tenant(),
            principal: test_principal(),
            sandbox_id: sandbox("deny_no_quota"),
            action: LeaseAction::Exec,
            scope: LeaseScope::unbounded(),
            ttl_secs: Some(300),
            quota: Some(QuotaAdmit {
                vcpus: 1,
                memory_mb: 128,
            }),
        })
        .unwrap_err();
    assert!(
        matches!(err, SandboxError::PolicyDenied { .. }),
        "deny must surface, got {err}"
    );
    assert_eq!(
        quota.get_counters(&test_tenant()),
        (0, 0, 0),
        "denied admission must not consume quota"
    );
}

#[test]
fn quota_exceeded_blocks_admission_without_minting_lease() {
    // Quota path: exhausted tenants fail with QuotaExceeded and no lease is
    // minted (no credential/lease artifact escapes a rejected admission).
    let quota = Arc::new(QuotaEngine::new());
    quota.set_limits(
        test_tenant(),
        QuotaLimits {
            max_sandboxes: 0,
            max_vcpus: 0,
            max_memory_mb: 0,
            ..Default::default()
        },
    );
    let admission = Admission::new(permit_policy(), quota, LeaseAuthority::generate());

    let err = admission
        .admit(AdmitRequest {
            tenant_id: test_tenant(),
            principal: test_principal(),
            sandbox_id: sandbox("quota_blocked"),
            action: LeaseAction::Exec,
            scope: LeaseScope::unbounded(),
            ttl_secs: Some(300),
            quota: Some(QuotaAdmit {
                vcpus: 1,
                memory_mb: 128,
            }),
        })
        .unwrap_err();
    assert!(
        matches!(err, SandboxError::QuotaExceeded { .. }),
        "exhaustion must surface, got {err}"
    );
}

#[test]
fn concurrent_create_admission_respects_quota_limit() {
    // Concurrent create storm: exactly `max_sandboxes` admissions win and
    // the rest observe QuotaExceeded; no lease escapes for losers.
    let quota = Arc::new(QuotaEngine::new());
    quota.set_limits(
        test_tenant(),
        QuotaLimits {
            max_sandboxes: 3,
            max_vcpus: 100,
            max_memory_mb: 100_000,
            ..Default::default()
        },
    );
    let admission = Arc::new(Admission::new(
        permit_policy(),
        quota,
        LeaseAuthority::generate(),
    ));

    let admitted = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let rejected = Arc::new(std::sync::atomic::AtomicU64::new(0));
    std::thread::scope(|scope| {
        for i in 0..12 {
            let admission = Arc::clone(&admission);
            let admitted = Arc::clone(&admitted);
            let rejected = Arc::clone(&rejected);
            scope.spawn(move || {
                let result = admission.admit(AdmitRequest {
                    tenant_id: test_tenant(),
                    principal: test_principal(),
                    sandbox_id: SandboxId::generate(),
                    action: LeaseAction::Exec,
                    scope: LeaseScope::unbounded(),
                    ttl_secs: Some(300),
                    quota: Some(QuotaAdmit {
                        vcpus: 1,
                        memory_mb: 128,
                    }),
                });
                match result {
                    Ok(lease) => {
                        assert!(lease.signature.is_some());
                        admitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(SandboxError::QuotaExceeded { .. }) => {
                        rejected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(e) => panic!("thread {i}: unexpected admission error: {e}"),
                }
            });
        }
    });
    assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(rejected.load(std::sync::atomic::Ordering::SeqCst), 9);
}

#[test]
fn invalid_policy_push_preserves_last_good_epoch() {
    // Degradation: a malformed policy push must not take down admission;
    // the previous policy version and epoch keep serving.
    let policy = permit_policy();
    let epoch_before = policy.get_epoch();
    assert!(epoch_before >= 1);

    let err = policy.load_policies("this is not ( valid cedar {{{");
    assert!(err.is_err(), "malformed policy must be rejected");
    assert_eq!(
        policy.get_epoch(),
        epoch_before,
        "failed push must not bump the epoch"
    );

    let decision = policy.evaluate(&test_principal(), &test_tenant(), PolicyAction::Exec);
    assert!(matches!(decision.outcome, PolicyOutcome::Allow));
    assert_eq!(decision.policy_epoch, epoch_before);
}

// ---- E: Access lease lifecycle ----

#[test]
fn lease_issue_expiry_renew_revocation_lifecycle() {
    // Full lease lifecycle through one manager: issue -> validate -> renew
    // (old revoked, new valid) -> revoke -> denied -> expired pruned.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let sink_dyn: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);
    let manager = LeaseManager::with_audit_sink(sink_dyn, hlc);
    let sbx = sandbox("lease_lifecycle");
    let decision = allow_decision(7);

    let lease = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &decision,
        3600,
    );
    assert_eq!(lease.policy_epoch, 7);
    manager
        .validate(&lease.lease_id, &sbx, &test_tenant(), LeaseAction::Exec, 7)
        .expect("fresh lease must validate");

    // Renewal mints a successor and retires the predecessor.
    let successor = manager
        .renew(&lease.lease_id, &allow_decision(8), 3600)
        .expect("renew must succeed");
    assert_ne!(successor.lease_id, lease.lease_id);
    assert_eq!(successor.policy_epoch, 8);
    assert!(manager.is_revoked(&lease.lease_id));
    let err = manager
        .validate(&lease.lease_id, &sbx, &test_tenant(), LeaseAction::Exec, 8)
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::Revoked { .. }),
        "renewed-away lease must be revoked, got {err}"
    );
    manager
        .validate(
            &successor.lease_id,
            &sbx,
            &test_tenant(),
            LeaseAction::Exec,
            8,
        )
        .expect("successor must validate");

    // Explicit revocation denies future use ...
    manager
        .revoke(&successor.lease_id, RevocationReason::AdminAction)
        .unwrap();
    // ... and double revocation is a conflict, not a silent no-op.
    assert!(
        manager
            .revoke(&successor.lease_id, RevocationReason::AdminAction)
            .is_err()
    );

    // Zero-TTL leases are born expired and the reaper prunes them.
    let short = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &allow_decision(8),
        0,
    );
    let err = manager
        .validate(&short.lease_id, &sbx, &test_tenant(), LeaseAction::Exec, 8)
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::Expired { .. }),
        "ttl=0 must be expired, got {err}"
    );
    assert!(manager.cleanup_expired() >= 1);
    let err = manager
        .validate(&short.lease_id, &sbx, &test_tenant(), LeaseAction::Exec, 8)
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::NotFound { .. }),
        "pruned lease must be not-found, got {err}"
    );

    // The audit trail records every step of the lifecycle in order.
    // Note the renewal contract: `renew` retires the predecessor with
    // `LeaseRevoked{PolicyChanged}` and mints the successor with
    // `LeaseIssued` - there is no separate `LeaseRenewed` event on this
    // path, so successor/predecessor linkage is by sandbox/action/scope.
    let kinds: Vec<AuditEventKind> = sink
        .events_for_sandbox(&sbx)
        .iter()
        .map(|e| e.kind)
        .collect();
    for expected in [
        AuditEventKind::LeaseIssued,
        AuditEventKind::LeaseEnforced,
        AuditEventKind::LeaseRevoked,
        AuditEventKind::LeaseDenied,
        AuditEventKind::LeaseExpired,
    ] {
        assert!(
            kinds.contains(&expected),
            "lease audit trail must contain {expected:?}, got {kinds:?}"
        );
    }
}

#[test]
fn policy_update_invalidates_stale_leases() {
    // Stale policy scenario end to end: a lease admitted under epoch N is
    // rejected once the policy engine advances past N, on both the
    // manager path and the offline blob path.
    let policy = permit_policy();
    let epoch1 = policy.get_epoch();
    let admission = Admission::new(
        Arc::clone(&policy),
        Arc::new(QuotaEngine::new()),
        LeaseAuthority::generate(),
    );
    let sbx = sandbox("stale_policy");
    let lease = admit_exec(&admission, &sbx);

    // Tighten the policy: epoch advances.
    policy.load_policies(&deny_policy_text("Exec")).unwrap();
    let epoch2 = policy.get_epoch();
    assert!(epoch2 > epoch1);

    // New admissions under the tightened policy are denied ...
    assert!(matches!(
        admission
            .admit(AdmitRequest {
                tenant_id: test_tenant(),
                principal: test_principal(),
                sandbox_id: SandboxId::generate(),
                action: LeaseAction::Exec,
                scope: LeaseScope::unbounded(),
                ttl_secs: Some(300),
                quota: None,
            })
            .unwrap_err(),
        SandboxError::PolicyDenied { .. }
    ));

    // ... and the pre-update lease is stale on the offline enforce path.
    let blob = admission.encode(&lease).unwrap();
    let ctx = EnforceContext {
        sandbox_id: &sbx,
        tenant_id: &test_tenant(),
        action: LeaseAction::Exec,
        scope: &LeaseScope::unbounded(),
        policy_epoch: epoch2,
    };
    let err = admission.authority().enforce_blob(&blob, &ctx).unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::StalePolicyEpoch { .. }),
        "pre-update lease must be stale, got {err}"
    );

    // Same staleness through the manager path.
    let manager = LeaseManager::new();
    let managed = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &allow_decision(epoch1),
        3600,
    );
    let err = manager
        .validate(
            &managed.lease_id,
            &sbx,
            &test_tenant(),
            LeaseAction::Exec,
            epoch2,
        )
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::StalePolicyEpoch { .. }),
        "manager must see stale epoch, got {err}"
    );
}

#[test]
fn revocation_takes_precedence_over_staleness() {
    // Ordering pin: revocation is checked before expiry staleness, so an
    // explicitly revoked lease reports Revoked (actionable: stop using it)
    // rather than StalePolicyEpoch even after a policy update.
    let manager = LeaseManager::new();
    let sbx = sandbox("revoke_precedence");
    let lease = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &allow_decision(1),
        3600,
    );
    manager
        .revoke(&lease.lease_id, RevocationReason::PolicyChanged)
        .unwrap();
    let err = manager
        .validate(&lease.lease_id, &sbx, &test_tenant(), LeaseAction::Exec, 99)
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::Revoked { .. }),
        "revocation must win over staleness, got {err}"
    );
}

#[test]
fn offline_enforcement_requires_revocable_path_for_revocation() {
    // TTL/revocation boundary pin: a signed blob carries no revocation
    // state, so plain `enforce_blob` cannot see a manager-side revoke.
    // Edge enforcers that need revocation visibility must use
    // `enforce_blob_revocable` (short TTLs bound the exposure otherwise).
    let authority = LeaseAuthority::generate();
    let manager = LeaseManager::new();
    let sbx = sandbox("offline_revoke");
    let mut lease = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &allow_decision(3),
        3600,
    );
    authority.sign(&mut lease).unwrap();
    let blob = pico_core::lease_token::encode_lease_blob(&lease).unwrap();
    let ctx = EnforceContext {
        sandbox_id: &sbx,
        tenant_id: &test_tenant(),
        action: LeaseAction::Exec,
        scope: &LeaseScope::unbounded(),
        policy_epoch: 3,
    };

    manager
        .revoke(&lease.lease_id, RevocationReason::AdminAction)
        .unwrap();
    // Plain offline enforcement still passes: revocation lives in the
    // manager, not in the blob.
    assert!(authority.enforce_blob(&blob, &ctx).is_ok());
    // The revocable path observes the manager's revocation set.
    let err = authority
        .enforce_blob_revocable(&blob, &ctx, |id| manager.is_revoked(id))
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::Revoked { .. }),
        "revocable path must deny, got {err}"
    );
}

#[test]
fn lease_wrong_binding_is_rejected() {
    // Stale lease scenario: a lease presented for the wrong sandbox,
    // tenant, or action is rejected with a typed error.
    let manager = LeaseManager::new();
    let sbx = sandbox("lease_binding");
    let lease = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &allow_decision(1),
        3600,
    );

    let err = manager
        .validate(
            &lease.lease_id,
            &sandbox("lease_binding_other"),
            &test_tenant(),
            LeaseAction::Exec,
            1,
        )
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::WrongSandbox { .. }),
        "got {err}"
    );

    let err = manager
        .validate(&lease.lease_id, &sbx, &other_tenant(), LeaseAction::Exec, 1)
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::WrongTenant { .. }),
        "got {err}"
    );

    let err = manager
        .validate(
            &lease.lease_id,
            &sbx,
            &test_tenant(),
            LeaseAction::PortForward,
            1,
        )
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::WrongAction { .. }),
        "got {err}"
    );
}

#[test]
fn destroy_revokes_all_sandbox_leases() {
    // issue 140 contract: the destroy flow revokes every active lease bound
    // to the sandbox with `ResourceRemoved` between `Destroying` and
    // `Destroyed`. After destroy completes no lease for the sandbox
    // validates, revokes carry the destroying operation identity, and
    // foreign-sandbox leases are untouched.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let sink_dyn: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);
    let manager = LeaseManager::with_audit_sink(Arc::clone(&sink_dyn), Arc::clone(&hlc));

    let sbx = sandbox("destroy_revoke");
    let other_sbx = sandbox("destroy_revoke_other");
    let exec_lease = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &allow_decision(1),
        3600,
    );
    let cred_scope = LeaseScope {
        ports: vec![],
        paths: vec![],
        egress_cidrs: vec![],
        credential_types: vec!["aws".into()],
    };
    let cred_lease = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::CredentialAccess,
        cred_scope.clone(),
        &allow_decision(1),
        3600,
    );
    let other_lease = manager.issue(
        test_tenant(),
        test_principal(),
        other_sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &allow_decision(1),
        3600,
    );

    let destroy_op = OperationId::generate();
    let mut meta = new_metadata("destroy_revoke");
    meta.actor_identity = Some(test_principal());
    meta.operation_id = Some(destroy_op.clone());
    apply_transition_with_audit(&mut meta, SandboxState::Destroying, 1, sink.as_ref(), &hlc)
        .unwrap();

    // Standard destroy identity: operation_id correlates the revoke with
    // the lifecycle commit, principal stays None so each revoke keeps
    // the lease subject.
    let ctx = DestroyRevocationContext {
        operation_id: Some(destroy_op.clone()),
        principal: None,
    };
    let revoked = manager.revoke_for_sandbox_with_context(
        &sbx,
        RevocationReason::ResourceRemoved,
        Some(&ctx),
    );
    assert_eq!(revoked.len(), 2);
    assert!(revoked.contains(&exec_lease.lease_id));
    assert!(revoked.contains(&cred_lease.lease_id));

    apply_transition_with_audit(&mut meta, SandboxState::Destroyed, 2, sink.as_ref(), &hlc)
        .unwrap();
    assert_eq!(meta.state, SandboxState::Destroyed);

    for (id, action) in [
        (&exec_lease.lease_id, LeaseAction::Exec),
        (&cred_lease.lease_id, LeaseAction::CredentialAccess),
    ] {
        let err = manager
            .validate(id, &sbx, &test_tenant(), action, 1)
            .unwrap_err();
        assert!(
            matches!(err, LeaseValidationError::Revoked { .. }),
            "destroyed lease must be revoked, got {err}"
        );
    }
    // Credential scope path also fails closed with Revoked (precedence over scope).
    let err = manager
        .validate_with_scope(
            &cred_lease.lease_id,
            &sbx,
            &test_tenant(),
            LeaseAction::CredentialAccess,
            &cred_scope,
            1,
        )
        .unwrap_err();
    assert!(
        matches!(err, LeaseValidationError::Revoked { .. }),
        "got {err}"
    );

    // Foreign sandbox leases survive destroy of another sandbox.
    manager
        .validate(
            &other_lease.lease_id,
            &other_sbx,
            &test_tenant(),
            LeaseAction::Exec,
            1,
        )
        .expect("other sandbox lease must survive");
    assert!(manager.active_leases_for_sandbox(&sbx).is_empty());
    assert_eq!(manager.active_leases_for_sandbox(&other_sbx).len(), 1);

    // Audit: two LeaseRevoked events carry the destroying operation identity,
    // are sandbox-correlated, keep the lease subject as principal, and the
    // per-sandbox trail stays HLC-ordered across lifecycle + revoke.
    let revokes = sink.events_by_kind(AuditEventKind::LeaseRevoked);
    assert_eq!(revokes.len(), 2);
    for e in &revokes {
        assert_eq!(e.sandbox_id.as_ref(), Some(&sbx));
        assert_eq!(e.operation_id.as_ref(), Some(&destroy_op));
        assert_eq!(e.principal.as_ref(), Some(&test_principal()));
    }
    let trail = sink.events_for_sandbox(&sbx);
    assert!(is_ordered_chronologically(&trail));
}

#[test]
fn concurrent_destroy_and_lease_use_is_fail_closed() {
    // issue 140 concurrency: lease validation racing destroy revocation is
    // single-winner (Ok before revoke, Revoked after) and fail-closed
    // (no validation succeeds after destroy completes). The race window
    // itself is best-effort: with 800 validates against 1 revoke overlap
    // is near-certain but not guaranteed, so only the final fail-closed
    // assertion is deterministic; the in-race counters only prove no
    // third outcome appears.
    let manager = Arc::new(LeaseManager::new());
    let sbx = sandbox("destroy_race");
    let lease = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::CredentialAccess,
        LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        },
        &allow_decision(1),
        3600,
    );

    let ok = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let revoked = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let unexpected = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let start = Arc::new(std::sync::Barrier::new(9));

    std::thread::scope(|scope| {
        for _ in 0..8 {
            let manager = Arc::clone(&manager);
            let sbx = sbx.clone();
            let lease_id = lease.lease_id.clone();
            let tenant = test_tenant();
            let ok = Arc::clone(&ok);
            let revoked = Arc::clone(&revoked);
            let unexpected = Arc::clone(&unexpected);
            let start = Arc::clone(&start);
            scope.spawn(move || {
                start.wait();
                for _ in 0..100 {
                    match manager.validate(
                        &lease_id,
                        &sbx,
                        &tenant,
                        LeaseAction::CredentialAccess,
                        1,
                    ) {
                        Ok(_) => ok.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                        Err(LeaseValidationError::Revoked { .. }) => {
                            revoked.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        }
                        Err(_) => unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    };
                }
            });
        }
        let manager = Arc::clone(&manager);
        let sbx = sbx.clone();
        let start = Arc::clone(&start);
        scope.spawn(move || {
            start.wait();
            manager.revoke_for_sandbox(&sbx, RevocationReason::ResourceRemoved);
        });
    });

    assert_eq!(
        unexpected.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "race must only produce Ok or Revoked"
    );
    // After destroy completes, validation always fails closed.
    let err = manager
        .validate(
            &lease.lease_id,
            &sbx,
            &test_tenant(),
            LeaseAction::CredentialAccess,
            1,
        )
        .unwrap_err();
    assert!(matches!(err, LeaseValidationError::Revoked { .. }));
}

// ---- F: Scheduler placement ----

#[test]
fn regional_scheduler_places_on_healthy_cell_with_evidence() {
    // Placement carries evidence: reason, per-candidate scores, placement
    // identity for the metadata record, backpressure, and an audit event.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let sink_dyn: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);
    let scheduler = RegionalScheduler::new().with_audit_sink(sink_dyn, Arc::clone(&hlc));
    let cells = vec![
        healthy_cell("cel_readiness_a", "rgn_1", "fd-1"),
        healthy_cell("cel_readiness_b", "rgn_1", "fd-2"),
        healthy_cell("cel_readiness_c", "rgn_1", "fd-3"),
    ];

    let resp = scheduler
        .schedule(&sched_request("sbx_place_healthy"), &cells)
        .expect("healthy region must place");
    assert!(resp.scheduled);
    let placement = resp.placement.expect("placement identity must be set");
    assert!(placement.cell.is_some());
    assert!(matches!(
        resp.reason,
        PlacementReason::BestScore | PlacementReason::OnlyCandidate
    ));
    assert_eq!(resp.candidate_scores.len(), 3);
    assert!(resp.score_breakdown.is_some());
    assert_eq!(resp.backpressure.total_cells, 3);
    assert_eq!(resp.backpressure.eligible_cells, 3);
    assert!(!resp.backpressure.should_throttle);

    let outcomes = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(outcomes.len(), 1);
    match &outcomes[0].details {
        Some(AuditEventDetails::PlacementOutcome {
            cell_id,
            host_id,
            reason,
            score,
            candidates_evaluated,
            sampled,
            sample_size,
            eligible,
            overlay_adjusted,
        }) => {
            assert!(cell_id.is_some());
            assert!(host_id.is_none(), "regional stage selects cells, not hosts");
            assert!(!reason.is_empty());
            assert!(score.is_some());
            assert_eq!(*candidates_evaluated, 3);
            assert!(!sampled, "default scheduler takes the full best");
            assert_eq!(*sample_size, 3);
            assert_eq!(*eligible, 3);
            assert!(!overlay_adjusted);
        }
        d => panic!("placement outcome details missing, got {d:?}"),
    }
}

#[test]
fn regional_scheduler_degrades_and_recovers() {
    // Degradation: degraded cells still admit, unavailable cells never get
    // selected, total loss fails closed with a typed error and a reject
    // audit event. Recovery: restored cells take placements again.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let sink_dyn: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);
    let scheduler = RegionalScheduler::new().with_audit_sink(sink_dyn, Arc::clone(&hlc));

    let mut cells = vec![
        healthy_cell("cel_deg_a", "rgn_1", "fd-1"),
        healthy_cell("cel_deg_b", "rgn_1", "fd-2"),
    ];

    // Degraded still admits: a region with only a degraded cell must place
    // on it (a mixed healthy+degraded region can hide this by picking healthy).
    let only_degraded = vec![{
        let mut cell = healthy_cell("cel_deg_only", "rgn_1", "fd-1");
        cell.health = CellHealth::Degraded;
        cell
    }];
    let resp = scheduler
        .schedule(&sched_request("sbx_deg"), &only_degraded)
        .expect("degraded cell must still admit");
    assert!(resp.scheduled);
    assert_eq!(
        resp.cell_id.as_ref().map(|c| c.as_str()),
        Some("cel_deg_only")
    );

    // Unavailable is never selected while a survivor exists.
    cells[0].health = CellHealth::Unavailable;
    let resp = scheduler
        .schedule(&sched_request("sbx_failover"), &cells)
        .expect("survivor must take the load");
    assert_eq!(
        resp.cell_id.as_ref().map(|c| c.as_str()),
        Some("cel_deg_b"),
        "failed cell must never be selected"
    );

    // Total loss fails closed with a typed rejection, not a placement.
    cells[1].health = CellHealth::Unavailable;
    let err = scheduler
        .schedule(&sched_request("sbx_total_loss"), &cells)
        .unwrap_err();
    assert!(
        matches!(
            err,
            SchedulerError::NoCellSatisfiesConstraints { .. } | SchedulerError::NoCellsAvailable
        ),
        "total loss must fail closed, got {err}"
    );

    // Reject audit events exist for the failure (admit AND reject are
    // observable).
    let outcomes = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert!(
        outcomes.len() >= 3,
        "every schedule call must emit an outcome, got {}",
        outcomes.len()
    );

    // Recovery: restored cells resume placements without further action.
    cells[0].health = CellHealth::Healthy;
    let resp = scheduler
        .schedule(&sched_request("sbx_recovered"), &cells)
        .expect("restored cell must resume");
    assert!(resp.scheduled);
    assert_eq!(resp.cell_id.as_ref().map(|c| c.as_str()), Some("cel_deg_a"));
}

#[test]
fn regional_scheduler_rejection_taxonomy_is_typed() {
    // Stale/unsupported placement scenarios surface as typed rejection
    // reasons that callers can map to traces and audit without parsing.
    let scheduler = RegionalScheduler::new();
    let cells = vec![healthy_cell("cel_tax_a", "rgn_1", "fd-1")];

    // Unsupported backend.
    let mut req = sched_request("sbx_tax_runtime");
    req.runtime = Some(RuntimeType::Qemu);
    let err = scheduler.schedule(&req, &cells).unwrap_err();
    assert!(
        matches!(err, SchedulerError::UnsupportedRuntime { .. }),
        "unsupported runtime must be typed, got {err}"
    );

    // Insufficient capacity.
    let mut req = sched_request("sbx_tax_capacity");
    req.vcpus = 1_000_000;
    req.memory_mb = 1_000_000_000;
    let err = scheduler.schedule(&req, &cells).unwrap_err();
    assert!(
        matches!(err, SchedulerError::InsufficientCapacity { .. }),
        "exhaustion must be typed, got {err}"
    );

    // Draining fleet.
    let mut draining = vec![healthy_cell("cel_tax_d", "rgn_1", "fd-1")];
    draining[0].health = CellHealth::Draining;
    let err = scheduler
        .schedule(&sched_request("sbx_tax_drain"), &draining)
        .unwrap_err();
    assert!(
        matches!(err, SchedulerError::NoCellSatisfiesConstraints { .. }),
        "draining fleet must reject, got {err}"
    );

    // Empty region.
    let err = scheduler
        .schedule(&sched_request("sbx_tax_empty"), &[])
        .unwrap_err();
    assert!(
        matches!(err, SchedulerError::NoCellsAvailable),
        "empty region must fail closed, got {err}"
    );
}

#[test]
fn cell_scheduler_places_on_healthy_host_with_rejections() {
    // Cell stage selects hosts and reports per-candidate rejection causes
    // so operators can see why each host was skipped.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let sink_dyn: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);
    let scheduler = CellScheduler::new().with_audit_sink(sink_dyn, Arc::clone(&hlc));

    let mut hosts = vec![healthy_host("hst_cell_a"), healthy_host("hst_cell_b")];
    hosts[1].health = HostHealth::Draining;

    let resp = scheduler
        .schedule(&cell_request("sbx_cell_place"), &hosts)
        .expect("healthy host must take the placement");
    assert!(resp.placed);
    assert_eq!(
        resp.host_id.as_ref().map(|h| h.as_str()),
        Some("hst_cell_a")
    );
    assert!(
        !resp.rejections.is_empty(),
        "filtered hosts must appear in rejections"
    );

    let outcomes = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(outcomes.len(), 1);
    match &outcomes[0].details {
        Some(AuditEventDetails::PlacementOutcome { host_id, .. }) => {
            assert!(host_id.is_some(), "cell stage must record the host");
        }
        d => panic!("placement outcome details missing, got {d:?}"),
    }
}

#[test]
fn cell_scheduler_quarantine_and_recovery() {
    // Host-level degradation: quarantine overlays reject, draining fleets
    // fail closed with a typed error, and recovery resumes placement.
    let scheduler = CellScheduler::new();
    let mut hosts = vec![healthy_host("hst_q_a"), healthy_host("hst_q_b")];

    hosts[0].health = hosts[0].health.with_quarantine(true);
    assert_eq!(hosts[0].health, HostHealth::Quarantined);
    let resp = scheduler
        .schedule(&cell_request("sbx_quarantine"), &hosts)
        .expect("survivor must take the load");
    assert_eq!(
        resp.host_id.as_ref().map(|h| h.as_str()),
        Some("hst_q_b"),
        "quarantined host must never be selected"
    );

    // Quarantine never rewrites an operator drain.
    assert_eq!(
        HostHealth::Draining.with_quarantine(true),
        HostHealth::Draining
    );

    hosts[1].health = HostHealth::Draining;
    let err = scheduler
        .schedule(&cell_request("sbx_cell_drain"), &hosts)
        .unwrap_err();
    assert!(
        matches!(
            err,
            CellSchedulerError::AllHostsDraining
                | CellSchedulerError::NoHostSatisfiesConstraints { .. }
        ),
        "drained cell must fail closed, got {err}"
    );

    hosts[0].health = HostHealth::Healthy;
    let resp = scheduler
        .schedule(&cell_request("sbx_cell_recovered"), &hosts)
        .expect("restored host must resume");
    assert!(resp.placed);
}

#[test]
fn two_stage_placement_regional_then_cell() {
    // The integrated placement chain: regional selection feeds the cell
    // stage, and both outcomes land in one ordered audit stream joined by
    // sandbox identity; the chain is recorded on the metadata record.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let regional_sink: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);
    let cell_sink: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);
    let regional = RegionalScheduler::new().with_audit_sink(regional_sink, Arc::clone(&hlc));
    let cell = CellScheduler::new().with_audit_sink(cell_sink, Arc::clone(&hlc));

    let sbx_id = sandbox("two_stage");
    let sbx_key = sbx_id.as_str().to_string();
    let cells = vec![
        healthy_cell("cel_stage_a", "rgn_1", "fd-1"),
        healthy_cell("cel_stage_b", "rgn_1", "fd-2"),
    ];
    let regional_resp = regional
        .schedule(
            &SchedulerRequest {
                sandbox_id: sbx_key.clone(),
                ..sched_request("ignored")
            },
            &cells,
        )
        .expect("regional stage must place");
    let chosen_cell = regional_resp.cell_id.expect("cell must be chosen");

    let hosts = vec![healthy_host("hst_stage_1"), healthy_host("hst_stage_2")];
    let cell_resp = cell
        .schedule(
            &CellSchedulerRequest {
                sandbox_id: sbx_key.clone(),
                ..cell_request("ignored")
            },
            &hosts,
        )
        .expect("cell stage must place");

    // Record the chain on the metadata record and advance to Scheduled.
    let mut meta = new_metadata("two_stage");
    meta.placement = Some(pico_core::PlacementInfo {
        region: Some("rgn_1".into()),
        cell: Some(chosen_cell.as_str().to_string()),
        host: cell_resp.host_id.as_ref().map(|h| h.as_str().to_string()),
        runtime_backend: Some(RuntimeType::Firecracker),
        network_identity: None,
    });
    meta.commit(SandboxState::Pending, SandboxState::Scheduled, None)
        .unwrap();
    let placement = meta.placement.expect("placement must be recorded");
    assert!(placement.cell.is_some());
    assert!(placement.host.is_some());

    // Both stage outcomes are present, ordered, and joined by sandbox id.
    let outcomes = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(outcomes.len(), 2);
    assert!(is_ordered_chronologically(
        &sink.events_for_sandbox(&sbx_id)
    ));
    for event in &outcomes {
        assert_eq!(
            event.sandbox_id.as_ref().map(|s| s.as_str()),
            Some(sbx_key.as_str())
        );
    }
}

#[test]
fn scheduler_audit_sink_failure_does_not_fail_placement() {
    // Degradation: a saturated audit channel must not fail or delay the
    // placement decision itself (emission is best-effort by contract).
    let (sink, _receiver) = ChannelAuditSink::new(1);
    let hlc = Arc::new(Hlc::new());
    // Saturate the channel: first emit buffers, second observes ChannelFull.
    sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PlacementOutcome)
            .sandbox_id(sandbox("saturate"))
            .build(),
    )
    .unwrap();
    assert!(
        sink.emit(
            AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PlacementOutcome)
                .sandbox_id(sandbox("saturate"))
                .build(),
        )
        .is_err()
    );

    let sink_dyn: Arc<dyn AuditEventSink> = Arc::new(sink);
    let scheduler = RegionalScheduler::new().with_audit_sink(sink_dyn, Arc::clone(&hlc));
    let cells = vec![healthy_cell("cel_sat_a", "rgn_1", "fd-1")];
    let resp = scheduler
        .schedule(&sched_request("sbx_sat"), &cells)
        .expect("placement must survive audit backpressure");
    assert!(resp.scheduled);
}

// ---- G: Audit ordering and correlation ----

#[test]
fn full_control_plane_chain_is_ordered_and_correlated() {
    // The test-plan centerpiece: policy decision -> regional
    // placement -> cell placement -> lifecycle transitions -> lease
    // issue/enforce/revoke/deny through one HLC domain and one sink form
    // a single chronologically ordered, sandbox-correlated trail.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let sink_dyn: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);

    let sbx = sandbox("full_chain");
    let sbx_key = sbx.as_str().to_string();

    // 1. Policy decision is injected: `Admission::admit` evaluates policy
    // and issues a lease but does not emit `PolicyDecision` (that lives on
    // `PolicyEnforcingAgent` in pico-api). The trail is a composed seam,
    // not one control-plane call stack.
    let admission = fresh_admission();
    let lease = admit_exec(&admission, &sbx);
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
            .sandbox_id(sbx.clone())
            .tenant_id(test_tenant())
            .principal(test_principal())
            .details(AuditEventDetails::PolicyDecision {
                decision_id: lease.policy_decision_id.as_str().to_string(),
                action: PolicyAction::Exec.as_str().to_string(),
                outcome: "Allow".to_string(),
                policy_epoch: lease.policy_epoch,
                reason: None,
            })
            .epoch(lease.policy_epoch)
            .build(),
    );

    // 2. Regional + cell placement through the real schedulers.
    let regional =
        RegionalScheduler::new().with_audit_sink(Arc::clone(&sink_dyn), Arc::clone(&hlc));
    let cell = CellScheduler::new().with_audit_sink(Arc::clone(&sink_dyn), Arc::clone(&hlc));
    let cells = vec![
        healthy_cell("cel_chain_a", "rgn_1", "fd-1"),
        healthy_cell("cel_chain_b", "rgn_1", "fd-2"),
    ];
    regional
        .schedule(
            &SchedulerRequest {
                sandbox_id: sbx_key.clone(),
                ..sched_request("ignored")
            },
            &cells,
        )
        .expect("regional placement must succeed");
    cell.schedule(
        &CellSchedulerRequest {
            sandbox_id: sbx_key.clone(),
            ..cell_request("ignored")
        },
        &[healthy_host("hst_chain_1")],
    )
    .expect("cell placement must succeed");

    // 3. Lifecycle transitions with audit on every commit.
    let mut meta = new_metadata("full_chain");
    for (version, (_, to)) in (meta.version..).zip(full_lifecycle()) {
        apply_transition_with_audit(&mut meta, to, version, sink.as_ref(), &hlc).unwrap();
    }
    assert_eq!(meta.state, SandboxState::Destroyed);

    // 4. Lease lifecycle events through a manager sharing the sink/HLC.
    let lease_sink: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);
    let manager = LeaseManager::with_audit_sink(lease_sink, Arc::clone(&hlc));
    let chain_lease = manager.issue(
        test_tenant(),
        test_principal(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &allow_decision(admission.policy_epoch()),
        3600,
    );
    manager
        .validate(
            &chain_lease.lease_id,
            &sbx,
            &test_tenant(),
            LeaseAction::Exec,
            admission.policy_epoch(),
        )
        .unwrap();
    manager
        .revoke(&chain_lease.lease_id, RevocationReason::PolicyChanged)
        .unwrap();
    let _ = manager.validate(
        &chain_lease.lease_id,
        &sbx,
        &test_tenant(),
        LeaseAction::Exec,
        admission.policy_epoch(),
    );

    // The whole per-sandbox trail is chronologically ordered ...
    let trail = sink.events_for_sandbox(&sbx);
    assert!(
        trail.len() >= 1 + 2 + full_lifecycle().len() + 3,
        "trail must contain every stage, got {} events",
        trail.len()
    );
    assert!(
        is_ordered_chronologically(&trail),
        "cross-subsystem trail must be HLC-ordered"
    );

    // ... every event carries the sandbox correlation key ...
    for event in &trail {
        assert_eq!(event.sandbox_id.as_ref(), Some(&sbx));
    }

    // ... lifecycle events form a valid causal chain ...
    let lifecycle: Vec<_> = trail
        .iter()
        .filter(|e| e.kind == AuditEventKind::LifecycleTransition)
        .cloned()
        .collect();
    assert_eq!(lifecycle.len(), full_lifecycle().len());
    validate_causal_chain(&lifecycle).expect("lifecycle must be causal");

    // ... and the lease denial references the revoked lease.
    let denied: Vec<_> = trail
        .iter()
        .filter(|e| e.kind == AuditEventKind::LeaseDenied)
        .collect();
    assert_eq!(denied.len(), 1);
    match &denied[0].details {
        Some(AuditEventDetails::LeaseOperation { lease_id, .. }) => {
            assert_eq!(*lease_id, chain_lease.lease_id.as_str());
        }
        d => panic!("lease denial must carry lease identity, got {d:?}"),
    }
}

#[test]
fn placement_and_lifecycle_share_sandbox_identity() {
    // Correlation review: the join keys an operator (or audit pipeline)
    // needs - sandbox id on every event, tenant on regional/policy,
    // cell on regional, host on cell, from/to on lifecycle - are present
    // on events produced by the real components, not hand-built fixtures.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let sink_dyn: Arc<dyn AuditEventSink> = Arc::<InMemoryAuditSink>::clone(&sink);

    let sbx = sandbox("join_keys");
    let sbx_key = sbx.as_str().to_string();
    RegionalScheduler::new()
        .with_audit_sink(Arc::clone(&sink_dyn), Arc::clone(&hlc))
        .schedule(
            &SchedulerRequest {
                sandbox_id: sbx_key.clone(),
                ..sched_request("ignored")
            },
            &[healthy_cell("cel_join_a", "rgn_1", "fd-1")],
        )
        .unwrap();
    CellScheduler::new()
        .with_audit_sink(sink_dyn, Arc::clone(&hlc))
        .schedule(
            &CellSchedulerRequest {
                sandbox_id: sbx_key.clone(),
                ..cell_request("ignored")
            },
            &[healthy_host("hst_join_1")],
        )
        .unwrap();

    let mut meta = new_metadata("join_keys");
    apply_transition_with_audit(&mut meta, SandboxState::Scheduled, 1, sink.as_ref(), &hlc)
        .unwrap();

    let trail = sink.events_for_sandbox(&sbx);
    assert_eq!(trail.len(), 3);
    let regional = trail
        .iter()
        .find(|e| {
            matches!(
                &e.details,
                Some(AuditEventDetails::PlacementOutcome { host_id: None, .. })
            )
        })
        .expect("regional outcome must be present");
    assert!(regional.tenant_id.is_some(), "regional carries tenant");
    let cell = trail
        .iter()
        .find(|e| {
            matches!(
                &e.details,
                Some(AuditEventDetails::PlacementOutcome {
                    host_id: Some(_),
                    ..
                })
            )
        })
        .expect("cell outcome must be present");
    assert!(
        cell.tenant_id.is_none(),
        "cell stage pins tenant=None (known gap)"
    );
    let lifecycle = trail
        .iter()
        .find(|e| e.kind == AuditEventKind::LifecycleTransition)
        .expect("lifecycle event must be present");
    match &lifecycle.details {
        Some(AuditEventDetails::LifecycleTransition { .. }) => {}
        d => panic!("lifecycle details missing, got {d:?}"),
    }
    // Known boundary: real scheduler events carry no trace/operation
    // context (: schedulers are not on the API create path, so no
    // request trace flows into placement). Pin it so the gap stays visible.
    for event in &trail {
        if event.kind == AuditEventKind::PlacementOutcome {
            assert!(
                event.trace_id.is_none(),
                "scheduler outcomes pin trace_id=None until 130"
            );
        }
    }
}

// ---- H: Degradation and recovery ----

#[test]
fn quota_reservations_release_on_destroy() {
    // Recovery: destroy frees the reservation so a tenant at quota can
    // create again; double release never drives counters negative.
    let quota = Arc::new(QuotaEngine::new());
    quota.set_limits(
        test_tenant(),
        QuotaLimits {
            max_sandboxes: 1,
            max_vcpus: 2,
            max_memory_mb: 512,
            ..Default::default()
        },
    );
    let tenant = test_tenant();
    assert!(quota.check_create(&tenant, 1, 128).allowed);
    assert!(!quota.check_create(&tenant, 1, 128).allowed);

    quota.release(&tenant, 1, 128);
    assert_eq!(quota.get_counters(&tenant), (0, 0, 0));
    assert!(quota.check_create(&tenant, 1, 128).allowed);

    quota.release(&tenant, 1, 128);
    quota.release(&tenant, 1, 128);
    assert_eq!(quota.get_counters(&tenant), (0, 0, 0));
}

#[test]
fn operation_identity_rejects_replay() {
    // Replay protection helper: an operation id already recorded as
    // completed is recognized on re-presentation.
    let op = pico_core::OperationId::generate();
    assert!(!pico_core::identity::is_replayed_operation(&op, &[]));
    assert!(pico_core::identity::is_replayed_operation(
        &op,
        std::slice::from_ref(&op)
    ));
    assert!(!pico_core::identity::is_replayed_operation(
        &pico_core::OperationId::generate(),
        &[op]
    ));
}

#[test]
fn stale_record_detection_guards_read_modify_write() {
    // `commit` carries no version comparison: its only concurrency guard
    // is the expected-state precondition. Writers racing on one shared
    // record resolve to a single winner; losers observe UnexpectedState
    // and must re-read before retrying. (A detached copy cannot be
    // guarded - staleness is a property of the shared record, which is
    // why `is_stale` exists for holders of copied versions.)
    use std::sync::Mutex;

    let meta = Arc::new(Mutex::new(new_metadata("stale_guard")));
    meta.lock()
        .unwrap()
        .commit(SandboxState::Pending, SandboxState::Scheduled, None)
        .unwrap();
    assert!(meta.lock().unwrap().is_stale(99));
    assert!(!meta.lock().unwrap().is_stale(2));

    let winners = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stale = Arc::new(std::sync::atomic::AtomicU64::new(0));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let meta = Arc::clone(&meta);
            let winners = Arc::clone(&winners);
            let stale = Arc::clone(&stale);
            scope.spawn(move || {
                let result = meta.lock().unwrap().commit(
                    SandboxState::Scheduled,
                    SandboxState::Preparing,
                    None,
                );
                match result {
                    Ok(()) => winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    Err(TransitionError::UnexpectedState { .. }) => {
                        stale.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    }
                    Err(e) => panic!("unexpected commit error: {e}"),
                };
            });
        }
    });
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(stale.load(std::sync::atomic::Ordering::SeqCst), 7);
    let guard = meta.lock().unwrap();
    assert_eq!(guard.state, SandboxState::Preparing);
    assert_eq!(guard.version, 3);
}

// ---- I: Scheduler-on-create integrated path ----

fn create_fixtures() -> (
    CreateOrchestrator,
    Arc<InMemoryAuditSink>,
    Arc<Hlc>,
    Arc<QuotaEngine>,
    Arc<IdempotencyStore>,
) {
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let quota = Arc::new(QuotaEngine::new());
    let dedup = Arc::new(IdempotencyStore::new());
    let orchestrator = CreateOrchestrator::new(
        permit_policy(),
        Arc::clone(&quota),
        Arc::<InMemoryAuditSink>::clone(&sink),
        Arc::clone(&hlc),
        Arc::clone(&dedup),
    );
    (orchestrator, sink, hlc, quota, dedup)
}

fn create_request(suffix: &str, op: OperationId, key: Option<String>) -> CreateRequest {
    CreateRequest {
        tenant_id: test_tenant(),
        principal: test_principal(),
        sandbox_id: sandbox(&format!("create_{suffix}")),
        image: "img:readiness".into(),
        runtime: Some(RuntimeType::Firecracker),
        vcpus: 2,
        memory_mb: 512,
        disk_mb: 1024,
        snapshot_id: None,
        preferred_region: None,
        avoid_failure_domains: vec![],
        trace_id: Some(format!("trace-create-{suffix}")),
        operation_id: op,
        idempotency_key: key,
        fencing_token: None,
        service_class: None,
    }
}

fn schedulers_with_sink(
    sink: &Arc<InMemoryAuditSink>,
    hlc: &Arc<Hlc>,
) -> (RegionalScheduler, CellScheduler) {
    let regional = RegionalScheduler::new()
        .with_audit_sink(Arc::<InMemoryAuditSink>::clone(sink), Arc::clone(hlc));
    let cell = CellScheduler::new()
        .with_audit_sink(Arc::<InMemoryAuditSink>::clone(sink), Arc::clone(hlc));
    (regional, cell)
}

#[test]
fn create_path_places_with_persisted_placement_and_trace_audit() {
    // Integrated create: policy plus quota plus regional plus cell plus
    // Pending to Scheduled commit through one sink and HLC domain. Placement
    // decisions and the lifecycle commit carry trace, operation, and
    // idempotency identity so operators join them without parsing.
    let (orchestrator, sink, hlc, quota, _dedup) = create_fixtures();
    let (regional, cell) = schedulers_with_sink(&sink, &hlc);
    let cells = vec![
        healthy_cell("cel_create_a", "rgn_1", "fd-1"),
        healthy_cell("cel_create_b", "rgn_1", "fd-2"),
    ];
    let hosts = vec![healthy_host("hst_create_1"), healthy_host("hst_create_2")];
    let op = OperationId::generate();
    let req = create_request("happy", op.clone(), Some("create-happy-001".into()));

    let outcome = orchestrator
        .create(&req, &regional, &cells, &cell, &|_| hosts.clone())
        .expect("healthy capacity must place on the create path");
    assert!(!outcome.replayed);
    assert_eq!(outcome.metadata.state, SandboxState::Scheduled);
    assert_eq!(outcome.metadata.version, 2);
    let placement = outcome
        .metadata
        .placement
        .clone()
        .expect("placement persisted");
    assert_eq!(placement.cell.as_deref(), Some(outcome.cell_id.as_str()));
    assert_eq!(placement.host.as_deref(), Some(outcome.host_id.as_str()));
    assert_eq!(placement.runtime_backend, Some(RuntimeType::Firecracker));
    assert!(!outcome.regional_reason.is_empty());
    assert!(!outcome.cell_reason.is_empty());
    assert_eq!(outcome.metadata.operation_id.as_ref(), Some(&op));
    assert_eq!(
        outcome.metadata.idempotency_key.as_deref(),
        Some("create-happy-001")
    );
    assert_eq!(quota.get_counters(&test_tenant()), (1, 2, 512));

    let trail = sink.events_for_sandbox(&req.sandbox_id);
    assert!(
        trail.len() >= 4,
        "trail must hold policy plus two placements plus lifecycle, got {}",
        trail.len()
    );
    assert!(is_ordered_chronologically(&trail));
    let placements: Vec<_> = trail
        .iter()
        .filter(|e| e.kind == AuditEventKind::PlacementOutcome)
        .collect();
    assert_eq!(placements.len(), 2);
    for event in &placements {
        assert_eq!(event.trace_id.as_deref(), req.trace_id.as_deref());
        assert_eq!(event.operation_id.as_ref(), Some(&op));
        assert_eq!(event.idempotency_key.as_deref(), Some("create-happy-001"));
    }
    let lifecycle: Vec<_> = trail
        .iter()
        .filter(|e| e.kind == AuditEventKind::LifecycleTransition)
        .collect();
    assert_eq!(lifecycle.len(), 1);
    assert_eq!(lifecycle[0].trace_id.as_deref(), req.trace_id.as_deref());
    assert_eq!(lifecycle[0].operation_id.as_ref(), Some(&op));
}

#[test]
fn create_path_rejection_is_typed_and_audited_with_quota_release() {
    // Rejection path: draining cells fail closed with a typed error, the
    // reject is visible in audit with trace context, and quota releases so
    // a later healthy create still admits.
    let (orchestrator, sink, hlc, quota, _) = create_fixtures();
    let (regional, cell) = schedulers_with_sink(&sink, &hlc);
    let mut cells = vec![healthy_cell("cel_reject_a", "rgn_1", "fd-1")];
    cells[0].health = CellHealth::Draining;
    let hosts = vec![healthy_host("hst_reject_1")];
    let req = create_request(
        "reject",
        OperationId::generate(),
        Some("create-reject-001".into()),
    );

    let err = orchestrator
        .create(&req, &regional, &cells, &cell, &|_| hosts.clone())
        .unwrap_err();
    assert!(
        matches!(err, CreateError::Regional(_) | CreateError::Cell(_)),
        "rejection must stay typed, got {err}"
    );
    assert_eq!(
        quota.get_counters(&test_tenant()),
        (0, 0, 0),
        "rejected create must release quota"
    );

    let outcomes = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(outcomes.len(), 1, "reject must still emit an outcome");
    assert_eq!(outcomes[0].trace_id.as_deref(), req.trace_id.as_deref());
    assert_eq!(outcomes[0].operation_id.as_ref(), Some(&req.operation_id));
    match &outcomes[0].details {
        Some(AuditEventDetails::PlacementOutcome { reason, .. }) => {
            assert!(!reason.is_empty(), "reject reason must be recorded");
        }
        d => panic!("placement outcome details missing, got {d:?}"),
    }

    let cells = vec![healthy_cell("cel_reject_ok", "rgn_1", "fd-1")];
    let ok_req = create_request(
        "reject_ok",
        OperationId::generate(),
        Some("create-reject-002".into()),
    );
    orchestrator
        .create(&ok_req, &regional, &cells, &cell, &|_| hosts.clone())
        .expect("quota release must admit a later create");
    assert_eq!(quota.get_counters(&test_tenant()), (1, 2, 512));
}

#[test]
fn create_path_audit_sink_failure_does_not_fail_placement() {
    // Degradation: a saturated audit channel never fails the create path.
    // Placement still succeeds; emission is best-effort by contract.
    let (sink, _receiver) = ChannelAuditSink::new(1);
    let hlc = Arc::new(Hlc::new());
    sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PlacementOutcome)
            .sandbox_id(sandbox("saturate_create"))
            .build(),
    )
    .unwrap();
    assert!(
        sink.emit(
            AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PlacementOutcome)
                .sandbox_id(sandbox("saturate_create"))
                .build(),
        )
        .is_err()
    );

    let channel: Arc<dyn AuditEventSink> = Arc::new(sink);
    let quota = Arc::new(QuotaEngine::new());
    let orchestrator = CreateOrchestrator::new(
        permit_policy(),
        Arc::clone(&quota),
        Arc::clone(&channel),
        Arc::clone(&hlc),
        Arc::new(IdempotencyStore::new()),
    );
    let regional = RegionalScheduler::new().with_audit_sink(Arc::clone(&channel), Arc::clone(&hlc));
    let cell = CellScheduler::new().with_audit_sink(channel, hlc);
    let cells = vec![healthy_cell("cel_sat_create", "rgn_1", "fd-1")];
    let hosts = vec![healthy_host("hst_sat_create")];
    let req = create_request(
        "saturated",
        OperationId::generate(),
        Some("create-sat-001".into()),
    );

    let outcome = orchestrator
        .create(&req, &regional, &cells, &cell, &|_| hosts.clone())
        .expect("create must survive audit backpressure");
    assert_eq!(outcome.metadata.state, SandboxState::Scheduled);
}

#[test]
fn create_idempotent_retry_converges_to_single_outcome() {
    // Partition retry: same key and body with a fresh operation id after a
    // crash converges to the stored outcome. No second quota reservation,
    // no second placement, no version move.
    let (orchestrator, sink, hlc, quota, _) = create_fixtures();
    let (regional, cell) = schedulers_with_sink(&sink, &hlc);
    let cells = vec![healthy_cell("cel_part_a", "rgn_1", "fd-1")];
    let hosts = vec![healthy_host("hst_part_1")];
    let key = Some("create-partition-001".into());

    let first_op = OperationId::generate();
    let first_req = create_request("partition", first_op.clone(), key.clone());
    let first = orchestrator
        .create(&first_req, &regional, &cells, &cell, &|_| hosts.clone())
        .expect("first create must place");
    assert!(!first.replayed);
    assert_eq!(quota.get_counters(&test_tenant()), (1, 2, 512));
    let placements_before = sink.events_by_kind(AuditEventKind::PlacementOutcome).len();

    let retry_op = OperationId::generate();
    assert_ne!(first_op, retry_op);
    let retry_req = create_request("partition", retry_op, key);
    let retry = orchestrator
        .create(&retry_req, &regional, &cells, &cell, &|_| hosts.clone())
        .expect("partition retry must converge");
    assert!(retry.replayed);
    assert_eq!(retry.cell_id, first.cell_id);
    assert_eq!(retry.host_id, first.host_id);
    assert_eq!(retry.metadata.version, first.metadata.version);
    assert_eq!(retry.metadata.placement, first.metadata.placement);
    assert_eq!(quota.get_counters(&test_tenant()), (1, 2, 512));
    assert_eq!(
        sink.events_by_kind(AuditEventKind::PlacementOutcome).len(),
        placements_before,
        "replay must not place again"
    );
}

#[test]
fn create_idempotency_conflict_and_stale_operation() {
    // Same key with a different body is a conflict, not a second sandbox.
    // Reusing an operation id for a different key is stale and never
    // double-applies. Invalid keys fail before any side effect.
    let (orchestrator, sink, hlc, quota, _) = create_fixtures();
    let (regional, cell) = schedulers_with_sink(&sink, &hlc);
    let cells = vec![healthy_cell("cel_conf_a", "rgn_1", "fd-1")];
    let hosts = vec![healthy_host("hst_conf_1")];

    let op = OperationId::generate();
    let req = create_request("conflict", op.clone(), Some("create-conflict-001".into()));
    orchestrator
        .create(&req, &regional, &cells, &cell, &|_| hosts.clone())
        .expect("first create must place");

    let mut different = create_request(
        "conflict",
        OperationId::generate(),
        Some("create-conflict-001".into()),
    );
    different.memory_mb = 4096;
    let err = orchestrator
        .create(&different, &regional, &cells, &cell, &|_| hosts.clone())
        .unwrap_err();
    assert!(
        matches!(err, CreateError::IdempotencyConflict { .. }),
        "different body with same key must conflict, got {err}"
    );
    assert_eq!(quota.get_counters(&test_tenant()), (1, 2, 512));

    let reuse = create_request("conflict_other", op, Some("create-conflict-002".into()));
    let err = orchestrator
        .create(&reuse, &regional, &cells, &cell, &|_| hosts.clone())
        .unwrap_err();
    assert!(
        matches!(err, CreateError::StaleOperation { .. }),
        "operation reuse across keys must be stale, got {err}"
    );

    let bad = create_request("bad", OperationId::generate(), Some("has spaces".into()));
    assert!(!is_valid_idempotency_key("has spaces"));
    let err = orchestrator
        .create(&bad, &regional, &cells, &cell, &|_| hosts.clone())
        .unwrap_err();
    assert!(
        matches!(err, CreateError::InvalidIdempotencyKey { .. }),
        "invalid key must fail fast, got {err}"
    );
    assert_eq!(quota.get_counters(&test_tenant()), (1, 2, 512));
}

#[test]
fn commit_with_operation_converges_after_partition() {
    // Metadata stale-operation plumbing: the first writer wins, replays of
    // the completed operation are idempotent, fresh retries of a completed
    // transition converge without a version move, and operation reuse across
    // transitions fails closed with StaleOperation instead of double-applying.
    let mut meta = new_metadata("op_converge");
    let op1 = OperationId::generate();
    meta.commit_with_operation(
        SandboxState::Pending,
        SandboxState::Scheduled,
        None,
        Some(op1.clone()),
        Some("op-key-1".into()),
    )
    .expect("first commit must win");
    assert_eq!(meta.version, 2);
    assert_eq!(meta.operation_id.as_ref(), Some(&op1));

    let err = meta
        .commit_with_operation(
            SandboxState::Pending,
            SandboxState::Scheduled,
            None,
            Some(op1.clone()),
            Some("op-key-1".into()),
        )
        .unwrap_err();
    assert!(
        matches!(err, TransitionError::AlreadyInState(_)),
        "same operation replay must be idempotent, got {err}"
    );
    assert_eq!(meta.version, 2);

    let op2 = OperationId::generate();
    let err = meta
        .commit_with_operation(
            SandboxState::Pending,
            SandboxState::Scheduled,
            None,
            Some(op2.clone()),
            Some("op-key-1".into()),
        )
        .unwrap_err();
    assert!(
        matches!(err, TransitionError::AlreadyInState(_)),
        "fresh retry of a completed transition must converge without a version move, got {err}"
    );
    assert_eq!(meta.version, 2);

    let err = meta
        .commit_with_operation(
            SandboxState::Scheduled,
            SandboxState::Preparing,
            None,
            Some(op1.clone()),
            None,
        )
        .unwrap_err();
    assert!(
        matches!(err, TransitionError::StaleOperation { .. }),
        "operation reuse across transitions must be stale, got {err}"
    );

    meta.commit_with_operation(
        SandboxState::Scheduled,
        SandboxState::Preparing,
        None,
        Some(op2),
        None,
    )
    .expect("fresh operation on the current state must advance");
    assert_eq!(meta.state, SandboxState::Preparing);
    assert_eq!(meta.version, 3);
}

#[test]
fn placement_with_context_carries_trace_operation_and_key() {
    // Trace contract for the create path: placement outcomes carry the
    // request trace, operation, and idempotency key. Standalone calls
    // without context still pin trace_id=None.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let (regional, cell) = schedulers_with_sink(&sink, &hlc);
    let cells = vec![healthy_cell("cel_trace_a", "rgn_1", "fd-1")];
    let hosts = vec![healthy_host("hst_trace_1")];
    let op = OperationId::generate();
    let context = ScheduleTraceContext {
        trace_id: Some("trace-142".into()),
        operation_id: Some(op.clone()),
        idempotency_key: Some("trace-key-001".into()),
    };

    regional
        .schedule_with_context(&sched_request("sbx_trace_regional"), &cells, Some(&context))
        .expect("regional with context must place");
    cell.schedule_with_context(&cell_request("sbx_trace_cell"), &hosts, Some(&context))
        .expect("cell with context must place");

    let outcomes = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(outcomes.len(), 2);
    for event in &outcomes {
        assert_eq!(event.trace_id.as_deref(), Some("trace-142"));
        assert_eq!(event.operation_id.as_ref(), Some(&op));
        assert_eq!(event.idempotency_key.as_deref(), Some("trace-key-001"));
    }

    sink.clear();
    regional
        .schedule(&sched_request("sbx_trace_bare"), &cells)
        .expect("standalone regional must place");
    let bare = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(bare.len(), 1);
    assert!(
        bare[0].trace_id.is_none(),
        "standalone placement pins trace_id=None"
    );
}

#[test]
fn create_keyless_same_operation_replays_without_duplicate() {
    // Keyless creates have no client key, so the operation id is the
    // dedup identity. Re-presenting the same operation converges without
    // a second quota reservation or placement.
    let (orchestrator, sink, hlc, quota, _) = create_fixtures();
    let (regional, cell) = schedulers_with_sink(&sink, &hlc);
    let cells = vec![healthy_cell("cel_keyless_a", "rgn_1", "fd-1")];
    let hosts = vec![healthy_host("hst_keyless_1")];
    let op = OperationId::generate();
    let mut req = create_request("keyless", op.clone(), None);
    req.sandbox_id = sandbox("create_keyless");

    let first = orchestrator
        .create(&req, &regional, &cells, &cell, &|_| hosts.clone())
        .expect("first keyless create must place");
    assert!(!first.replayed);
    assert_eq!(quota.get_counters(&test_tenant()), (1, 2, 512));
    let placements_before = sink.events_by_kind(AuditEventKind::PlacementOutcome).len();

    let retry = orchestrator
        .create(&req, &regional, &cells, &cell, &|_| hosts.clone())
        .expect("same-operation retry must converge");
    assert!(retry.replayed);
    assert_eq!(retry.metadata.version, first.metadata.version);
    assert_eq!(retry.metadata.placement, first.metadata.placement);
    assert_eq!(quota.get_counters(&test_tenant()), (1, 2, 512));
    assert_eq!(
        sink.events_by_kind(AuditEventKind::PlacementOutcome).len(),
        placements_before,
        "replay must not place again"
    );
}

#[test]
fn create_concurrent_same_key_single_winner() {
    // Concurrent creates with the same key resolve to one winner. Losers
    // observe StaleOperation while the winner is in flight, then converge
    // to replay once the winner completes. No duplicate quota or placement
    // escapes.
    let (orchestrator, sink, hlc, quota, _) = create_fixtures();
    let (regional, cell) = schedulers_with_sink(&sink, &hlc);
    let orchestrator = Arc::new(orchestrator);
    let regional = Arc::new(regional);
    let cell = Arc::new(cell);
    let cells = Arc::new(vec![healthy_cell("cel_race_a", "rgn_1", "fd-1")]);
    let hosts = Arc::new(vec![healthy_host("hst_race_1")]);

    let fresh = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let replayed = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stale = Arc::new(std::sync::atomic::AtomicU64::new(0));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let orchestrator = Arc::clone(&orchestrator);
            let regional = Arc::clone(&regional);
            let cell = Arc::clone(&cell);
            let cells = Arc::clone(&cells);
            let hosts = Arc::clone(&hosts);
            let fresh = Arc::clone(&fresh);
            let replayed = Arc::clone(&replayed);
            let stale = Arc::clone(&stale);
            scope.spawn(move || {
                let req = create_request(
                    "race",
                    OperationId::generate(),
                    Some("create-race-001".into()),
                );
                match orchestrator.create(&req, &regional, &cells, &cell, &|_| (*hosts).clone()) {
                    Ok(outcome) if outcome.replayed => {
                        replayed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Ok(_) => {
                        fresh.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(CreateError::StaleOperation { .. }) => {
                        stale.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(e) => panic!("unexpected race error: {e}"),
                }
            });
        }
    });
    assert_eq!(fresh.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        fresh.load(std::sync::atomic::Ordering::SeqCst)
            + replayed.load(std::sync::atomic::Ordering::SeqCst)
            + stale.load(std::sync::atomic::Ordering::SeqCst),
        8
    );
    assert_eq!(quota.get_counters(&test_tenant()), (1, 2, 512));
    assert_eq!(
        sink.events_by_kind(AuditEventKind::PlacementOutcome).len(),
        2,
        "only the winner places"
    );
}
