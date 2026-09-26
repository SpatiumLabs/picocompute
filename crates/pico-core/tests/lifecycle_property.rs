//! Lifecycle state-machine property tests.
//!
//! Covers the invariants cited as detective controls for lifecycle safety:
//! no illegal jumps, terminal states stay terminal, fencing and policy epoch
//! freshness, optimistic-concurrency single-winner semantics, and
//! operation-identity idempotence.
//!
//! Run with:
//! ```bash
//! cargo nextest run -p pico-core --test lifecycle_property
//! ```

use pico_core::metadata::{
    SandboxState, TransitionError, apply_transition, can_transition, validate_policy_epoch,
};
use pico_core::{FencingToken, OperationId, ResourceLimits, SandboxId, SandboxMetadata, TenantId};
use proptest::prelude::*;

fn arb_state() -> impl Strategy<Value = SandboxState> {
    prop_oneof![
        Just(SandboxState::Pending),
        Just(SandboxState::Scheduled),
        Just(SandboxState::Preparing),
        Just(SandboxState::Booting),
        Just(SandboxState::Running),
        Just(SandboxState::Suspending),
        Just(SandboxState::Suspended),
        Just(SandboxState::Resuming),
        Just(SandboxState::Stopped),
        Just(SandboxState::Destroying),
        Just(SandboxState::Destroyed),
        Just(SandboxState::Failed),
    ]
}

fn arb_token() -> impl Strategy<Value = FencingToken> {
    (0..5u64, 0..5u64).prop_map(|(epoch, sequence)| FencingToken { epoch, sequence })
}

fn test_metadata_in(state: SandboxState) -> SandboxMetadata {
    let mut meta = SandboxMetadata::new(
        SandboxId::from_string("sbx_property"),
        TenantId::from_string("tnt_property"),
        "img_property".into(),
        None,
        ResourceLimits::default(),
        None,
    );
    meta.state = state;
    meta.version = 1;
    meta
}

fn is_already_in_state(result: &Result<(), TransitionError>) -> bool {
    matches!(result, Err(TransitionError::AlreadyInState(_)))
}

fn is_terminal_state(result: &Result<(), TransitionError>) -> bool {
    matches!(result, Err(TransitionError::TerminalState(_)))
}

fn is_version_conflict(result: &Result<(), TransitionError>) -> bool {
    matches!(result, Err(TransitionError::VersionConflict { .. }))
}

fn is_stale_epoch(result: &Result<(), TransitionError>) -> bool {
    matches!(result, Err(TransitionError::StalePolicyEpoch { .. }))
}

fn is_stale_operation(result: &Result<(), TransitionError>) -> bool {
    matches!(result, Err(TransitionError::StaleOperation { .. }))
}

fn is_stale_fencing(result: &Result<(), TransitionError>) -> bool {
    matches!(result, Err(TransitionError::StaleFencingToken { .. }))
}

fn is_replay_converged(result: &Result<(), TransitionError>) -> bool {
    matches!(
        result,
        Err(TransitionError::AlreadyInState(_) | TransitionError::StaleOperation { .. })
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Destroyed is the only terminal state: no exit except self-loop handling.
    #[test]
    fn destroyed_never_exits(from in Just(SandboxState::Destroyed), to in arb_state()) {
        let result = can_transition(from, to);
        if from == to {
            prop_assert!(is_already_in_state(&result));
        } else {
            prop_assert!(is_terminal_state(&result));
        }
    }

    /// Non-terminal self transitions are always idempotent errors, never Ok.
    #[test]
    fn self_transition_is_already_in_state(state in arb_state()) {
        let result = can_transition(state, state);
        prop_assert!(is_already_in_state(&result));
        if let Err(TransitionError::AlreadyInState(s)) = result {
            prop_assert_eq!(s, state);
        }
    }

    /// Legal transitions are exactly the documented allowlist plus the two
    /// global rules (force-destroy and fail). Any Ok must be in that set.
    #[test]
    fn only_allowlisted_transitions_succeed(from in arb_state(), to in arb_state()) {
        let result = can_transition(from, to);
        if from == to {
            prop_assert!(result.is_err());
            return Ok(());
        }
        if from.is_terminal() {
            prop_assert!(result.is_err());
            return Ok(());
        }
        let explicit = matches!(
            (from, to),
            (SandboxState::Pending, SandboxState::Scheduled)
            | (SandboxState::Scheduled, SandboxState::Preparing)
            | (SandboxState::Preparing, SandboxState::Booting)
            | (SandboxState::Booting, SandboxState::Running)
            | (SandboxState::Running, SandboxState::Suspending)
            | (SandboxState::Running, SandboxState::Stopped)
            | (SandboxState::Suspending, SandboxState::Suspended)
            | (SandboxState::Suspended, SandboxState::Resuming)
            | (SandboxState::Resuming, SandboxState::Running)
            | (SandboxState::Stopped, SandboxState::Running)
            | (SandboxState::Destroying, SandboxState::Destroyed)
        );
        let global = to == SandboxState::Destroying
            || (to == SandboxState::Failed && !from.is_terminal());
        if result.is_ok() {
            prop_assert!(explicit || global);
        } else {
            prop_assert!(!(explicit || global));
        }
    }

    /// Transitory/durable partition covers every state exactly once.
    #[test]
    fn transitory_durable_partition_covers_all(state in arb_state()) {
        prop_assert_ne!(state.is_transitory(), state.is_durable());
        prop_assert!(SandboxState::ALL.contains(&state));
    }

    /// Version mismatch never mutates state or version (single-winner stays safe).
    #[test]
    fn version_conflict_leaves_record_untouched(
        from in arb_state(),
        to in arb_state(),
        bad_version in 100..1000u64,
    ) {
        let mut meta = test_metadata_in(from);
        let before = meta.clone();
        let err = apply_transition(&mut meta, to, bad_version);
        prop_assert!(is_version_conflict(&err));
        prop_assert_eq!(meta.state, before.state);
        prop_assert_eq!(meta.version, before.version);
    }

    /// Successful transitions always bump the version by exactly one.
    #[test]
    fn successful_transition_bumps_version_once(
        (from, to) in arb_state().prop_flat_map(|from| (Just(from), arb_state()))
    ) {
        let mut meta = test_metadata_in(from);
        if can_transition(from, to).is_ok() {
            let before = meta.version;
            apply_transition(&mut meta, to, before).unwrap();
            prop_assert_eq!(meta.version, before + 1);
            prop_assert_eq!(meta.state, to);
        }
    }

    /// Fencing order is total and stale detection matches the ordering.
    #[test]
    fn fencing_stale_matches_order(
        a_epoch in 0..5u64, a_seq in 0..5u64,
        b_epoch in 0..5u64, b_seq in 0..5u64,
    ) {
        let a = FencingToken { epoch: a_epoch, sequence: a_seq };
        let b = FencingToken { epoch: b_epoch, sequence: b_seq };
        prop_assert_eq!(a.is_stale(&b), b.is_newer_than(&a));
        // Equal tokens are never stale.
        if a == b {
            prop_assert!(!a.is_stale(&b));
        }
    }

    /// Policy epoch validation: stale exactly when req < cur.
    #[test]
    fn policy_epoch_stale_iff_behind(req in 0..10u64, cur in 0..10u64) {
        let result = validate_policy_epoch(Some(req), Some(cur));
        if req < cur {
            prop_assert!(is_stale_epoch(&result));
        } else {
            prop_assert!(result.is_ok());
        }
        // Unset epochs never reject.
        prop_assert!(validate_policy_epoch(None, Some(cur)).is_ok());
        prop_assert!(validate_policy_epoch(Some(req), None).is_ok());
    }

    /// Operation-identity commit converges: replaying the same operation never
    /// moves the version twice (single-winner concurrency).
    #[test]
    fn commit_with_operation_is_idempotent_on_replay(
        token_epoch in 0..3u64, token_seq in 0..3u64,
    ) {
        let token = FencingToken { epoch: token_epoch, sequence: token_seq };
        let mut meta = test_metadata_in(SandboxState::Pending);
        let op = OperationId::generate();
        meta.commit_with_operation(
            SandboxState::Pending,
            SandboxState::Scheduled,
            Some(token),
            Some(op.clone()),
            None,
        )
        .unwrap();
        let version_after_first = meta.version;
        // Same operation replayed on the same transition converges.
        let replay = meta.commit_with_operation(
            SandboxState::Pending,
            SandboxState::Scheduled,
            Some(token),
            Some(op.clone()),
            None,
        );
        prop_assert!(is_replay_converged(&replay));
        prop_assert_eq!(meta.version, version_after_first);
        // Same operation for a different transition is stale.
        let cross = meta.commit_with_operation(
            SandboxState::Scheduled,
            SandboxState::Preparing,
            Some(token.next_sequence()),
            Some(op),
            None,
        );
        prop_assert!(is_stale_operation(&cross));
        prop_assert_eq!(meta.version, version_after_first);
    }

    /// Fencing-advancing commits store the newest token; stale retries fail closed.
    #[test]
    fn commit_rejects_stale_fencing_token(cur in arb_token(), req in arb_token()) {
        let mut meta = test_metadata_in(SandboxState::Pending);
        // Establish cur as the current token via a legal first commit.
        meta.commit(SandboxState::Pending, SandboxState::Scheduled, Some(cur)).unwrap();
        if req.is_stale(&cur) {
            let err = meta.commit(
                SandboxState::Scheduled,
                SandboxState::Preparing,
                Some(req),
            );
            prop_assert!(is_stale_fencing(&err));
            prop_assert_eq!(meta.state, SandboxState::Scheduled);
        }
    }
}
