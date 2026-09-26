//! Wire round-trip tests for host-agent <-> sandboxd proto messages.

use pico_sandboxd_proto::status::SupervisorErrorClass;
use pico_sandboxd_proto::v1::{
    CommandMeta, ForkRequest, HostShape, NonReadyReason, OperationKind, Outcome, OutcomeReason,
    OutcomeStatus, PortTarget, ResourceReceipt, RestoreRequest, RuntimeType, SandboxObservation,
    SandboxState, port_target,
};
use prost::Message;
use tonic::Code;

fn sample_meta() -> CommandMeta {
    CommandMeta {
        sandbox_id: "sbx_01hxyz".into(),
        operation_id: "op_01hxyz".into(),
        assignment_fencing_token: "fence-7".into(),
        policy_epoch: 3,
        deadline_unix_ms: 1_700_000_000_000,
    }
}

#[test]
fn command_meta_round_trip() {
    let original = sample_meta();
    let bytes = original.encode_to_vec();
    let decoded = CommandMeta::decode(bytes.as_slice()).expect("decode CommandMeta");
    assert_eq!(decoded, original);
}

#[test]
fn outcome_round_trip() {
    let original = Outcome {
        operation_id: "op_1".into(),
        sandbox_id: "sbx_1".into(),
        kind: OperationKind::Prepare as i32,
        status: OutcomeStatus::Succeeded as i32,
        reason_code: OutcomeReason::Completed as i32,
        non_ready_reason: NonReadyReason::Unspecified as i32,
        message: Some("ok".into()),
        resources: vec![ResourceReceipt {
            class: "vm".into(),
            name: "fc-sbx_1".into(),
            external_id: Some("pid:123".into()),
            owner: "runtime".into(),
        }],
        observed_state: SandboxState::Pending as i32,
        completed_at: "2026-07-23T00:00:00Z".into(),
    };
    let bytes = original.encode_to_vec();
    let decoded = Outcome::decode(bytes.as_slice()).expect("decode Outcome");
    assert_eq!(decoded, original);
    assert_eq!(decoded.resources.len(), 1);
    assert_eq!(decoded.resources[0].class, "vm");
}

#[test]
fn port_target_tcp_round_trip() {
    let original = PortTarget {
        guest_port: 8080,
        target: Some(port_target::Target::TcpAddr("10.0.0.2:8080".into())),
    };
    let bytes = original.encode_to_vec();
    let decoded = PortTarget::decode(bytes.as_slice()).expect("decode PortTarget");
    assert_eq!(decoded.guest_port, 8080);
    match decoded.target {
        Some(port_target::Target::TcpAddr(addr)) => assert_eq!(addr, "10.0.0.2:8080"),
        other => panic!("expected TcpAddr, got {other:?}"),
    }
}

#[test]
fn port_target_unsupported_round_trip() {
    let original = PortTarget {
        guest_port: 22,
        target: Some(port_target::Target::Unsupported(true)),
    };
    let bytes = original.encode_to_vec();
    let decoded = PortTarget::decode(bytes.as_slice()).expect("decode PortTarget");
    assert!(matches!(
        decoded.target,
        Some(port_target::Target::Unsupported(true))
    ));
}

#[test]
fn sandbox_observation_with_ports_round_trip() {
    let original = SandboxObservation {
        sandbox_id: "sbx_obs".into(),
        observed_state: SandboxState::Running as i32,
        generation: 9,
        host_boot_id: "boot-a".into(),
        guest_boot_id: "gboot-b".into(),
        backend: RuntimeType::Firecracker as i32,
        ports: vec![PortTarget {
            guest_port: 80,
            target: Some(port_target::Target::BackendManaged(true)),
        }],
        ssh: None,
        policy_epoch: 2,
        assignment_fencing_token: "fence-1".into(),
        updated_at: "2026-07-23T12:00:00Z".into(),
    };
    let bytes = original.encode_to_vec();
    let decoded = SandboxObservation::decode(bytes.as_slice()).expect("decode observation");
    assert_eq!(decoded.generation, 9);
    assert_eq!(decoded.ports.len(), 1);
    assert_eq!(decoded.observed_state, SandboxState::Running as i32);
}

#[test]
fn supervisor_error_class_codes_are_stable() {
    assert_eq!(
        SupervisorErrorClass::StaleFencingToken.tonic_code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        SupervisorErrorClass::RuntimeNotAttached.tonic_code(),
        Code::NotFound
    );
    assert_eq!(
        SupervisorErrorClass::Unauthenticated.tonic_code(),
        Code::Unauthenticated
    );
}

fn sample_host_shape() -> HostShape {
    HostShape {
        backend_type: "firecracker".into(),
        backend_version: "1.10.0".into(),
        protocol_version: "2.0".into(),
        cpu_arch: "x86_64".into(),
        memory_mb: 4096,
        vcpus: 4,
        machine_type: "q35".into(),
        disk_mb: 0,
    }
}

fn sample_restore() -> RestoreRequest {
    RestoreRequest {
        meta: Some(sample_meta()),
        snapshot_id: "snp_01hxyz".into(),
        request_tenant_id: "tnt_test".into(),
        requires_memory: false,
        runtime_type: RuntimeType::Firecracker as i32,
        host: Some(sample_host_shape()),
    }
}

fn sample_fork() -> ForkRequest {
    ForkRequest {
        meta: Some(sample_meta()),
        parent_snapshot_id: "snp_parent".into(),
        request_tenant_id: "tnt_test".into(),
        child_sandbox_id: "sbx_child".into(),
        requires_memory: false,
        runtime_type: RuntimeType::Firecracker as i32,
        host: Some(sample_host_shape()),
    }
}

#[test]
fn restore_request_round_trip() {
    let original = sample_restore();
    let bytes = original.encode_to_vec();
    let decoded = RestoreRequest::decode(bytes.as_slice()).expect("decode RestoreRequest");
    assert_eq!(decoded, original);
    assert_eq!(decoded.snapshot_id, "snp_01hxyz");
    assert_eq!(decoded.request_tenant_id, "tnt_test");
}

#[test]
fn fork_request_round_trip() {
    let original = sample_fork();
    let bytes = original.encode_to_vec();
    let decoded = ForkRequest::decode(bytes.as_slice()).expect("decode ForkRequest");
    assert_eq!(decoded, original);
    assert_eq!(decoded.parent_snapshot_id, "snp_parent");
    assert_eq!(decoded.child_sandbox_id, "sbx_child");
}

#[test]
fn restore_and_fork_kinds_are_distinct() {
    assert_ne!(OperationKind::Restore as i32, OperationKind::Fork as i32);
    assert_eq!(
        OperationKind::try_from(OperationKind::Restore as i32).unwrap(),
        OperationKind::Restore
    );
    assert_eq!(
        OutcomeReason::try_from(OutcomeReason::RestoreRejected as i32).unwrap(),
        OutcomeReason::RestoreRejected
    );
}

#[test]
fn host_shape_disk_mb_round_trips_once() {
    // Adding disk_mb touches HostShape once, not every Restore/Fork layer.
    let mut shape = sample_host_shape();
    shape.disk_mb = 10240;
    let restore = RestoreRequest {
        host: Some(shape.clone()),
        ..sample_restore()
    };
    let bytes = restore.encode_to_vec();
    let decoded = RestoreRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded.host.unwrap().disk_mb, 10240);

    let fork = ForkRequest {
        host: Some(shape),
        ..sample_fork()
    };
    let bytes = fork.encode_to_vec();
    let decoded = ForkRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded.host.unwrap().disk_mb, 10240);
}
