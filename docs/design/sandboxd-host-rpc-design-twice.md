# host-agent to sandboxd RPC: design it twice

**Status**: Chosen (Interface 1)
**Date**: 2026-07-23
**Depends on**: ADR-0002, ADR-0011, architecture grill (sole RuntimeBackend owner)

## Goal

One process boundary between host-agent and sandboxd:

- host-agent admits, fences, caches observations, binds port proxies, reaps via RPC
- sandboxd owns RuntimeBackend handles, guest session, host resources, ledger, streams

Transport: gRPC (tonic) over Unix domain socket. Auth: SO_PEERCRED + shared token in metadata.

---

## Interface 1: single `Sandboxd` service (chosen)

One service, operation envelope on every mutating RPC, streaming where needed.

### Why this shape

- Matches today's `CommandContext` + `OperationKind` mental model
- One intercept for auth, deadline, correlation
- Big-bang cutover maps almost 1:1 from `SandboxSupervisor` methods
- Fewer package seams while the binary is young

### Proto sketch

```protobuf
syntax = "proto3";
package pico.sandboxd.v1;

// Attached as gRPC metadata:
//   x-pico-sandboxd-token: <shared runtime token>
// Peer UID/GID checked against allowlist in sandboxd.
//
// Sketch only. Wire truth is
// crates/pico-sandboxd-proto/proto/pico/sandboxd/v1/sandboxd.proto.
// Kind/status/reason_code/observed_state are strings (not protobuf enums)
// so wire names stay aligned with ledger serde snake_case/PascalCase.

message CommandMeta {
  string sandbox_id = 1;
  string operation_id = 2;
  // "epoch.sequence" decimal u64s (FencingToken Display). Example: "7.3".
  string assignment_fencing_token = 3;
  uint64 policy_epoch = 4;
  int64 deadline_unix_ms = 5;
}

message Outcome {
  string operation_id = 1;
  string kind = 2;           // prepare|boot|exec|...
  string status = 3;         // succeeded|failed|canceled|timed_out|requires_review
  string reason_code = 4;
  string message = 5;
  repeated ResourceReceipt resources = 6;
  string observed_state = 7; // SandboxState name
}

message ResourceReceipt {
  string class = 1;
  string name = 2;
  optional string external_id = 3;
  string owner = 4;          // runtime|network|workspace|cgroup|...
}

message PrepareRequest {
  CommandMeta meta = 1;
  SandboxConfig config = 2;
  string runtime_type = 3;   // firecracker|qemu|gvisor|...
  // Host resource inputs (workspace root relative id, vcpus, memory, ...)
  HostResourceSpec host = 4;
}

message BootRequest {
  CommandMeta meta = 1;
  // Optional: image digest re-check, boot report fields
}

message ExecRequest {
  CommandMeta meta = 1;
  string command = 2;
  repeated string args = 3;
  map<string, string> env = 4;
  string working_dir = 5;
  optional int64 timeout_ms = 6;
  uint64 max_stdout_bytes = 7;
  uint64 max_stderr_bytes = 8;
}

message ExecEvent {
  oneof body {
    ExecStarted started = 1;
    ExecStdout stdout = 2;
    ExecStderr stderr = 3;
    ExecExited exited = 4;
    ExecFailed failed = 5;
  }
}

message ExecStarted { string guest_operation_id = 1; }
message ExecStdout { bytes data = 1; }
message ExecStderr { bytes data = 1; }
message ExecExited {
  int32 exit_code = 1;
  Outcome outcome = 2;
}
message ExecFailed {
  Outcome outcome = 1;
}

message CancelRequest {
  string operation_id = 1;
  string sandbox_id = 2;
}

message SuspendRequest { CommandMeta meta = 1; }
message ResumeRequest { CommandMeta meta = 1; }
message DestroyRequest { CommandMeta meta = 1; }

message FileReadRequest {
  CommandMeta meta = 1;
  string path = 2;
  uint64 max_bytes = 3; // 0 = server default; never silent truncate
}
message FileWriteRequest {
  CommandMeta meta = 1;
  string path = 2;
  bytes content = 3;
  // mode, create flags as needed
}
message FileListRequest {
  CommandMeta meta = 1;
  string dir = 2;
  bool recursive = 3;
}

message InjectSecretsRequest {
  CommandMeta meta = 1;
  // Lease-validated credential material or broker fetch handle
  // Prefer broker fetch inside sandboxd after host passes lease proof
  CredentialInjectSpec spec = 2;
}

message GetSandboxRequest { string sandbox_id = 1; }
message SandboxObservation {
  string sandbox_id = 1;
  string observed_state = 2;
  uint64 generation = 3;     // monotonic for cache invalidation
  string host_boot_id = 4;
  string guest_boot_id = 5;
  string backend = 6;
  repeated PortTarget ports = 7;
  optional SshObservation ssh = 8;
  uint64 policy_epoch = 9;
  string assignment_fencing_token = 10;
}

message PortTarget {
  uint32 guest_port = 1;
  oneof target {
    string tcp_addr = 2;     // host-reachable "ip:port"
    bool backend_managed = 3;
    bool unsupported = 4;
  }
}

message GetPortTargetRequest {
  string sandbox_id = 1;
  uint32 guest_port = 2;
}
message GetPortTargetResponse {
  PortTarget target = 1;
  uint64 generation = 2;
}

message WatchRequest {
  // empty = all sandboxes on this host; optional filter later
  repeated string sandbox_ids = 1;
}
message WatchEvent {
  oneof body {
    SandboxObservation upsert = 1;
    string removed_sandbox_id = 2;
    ReconcileStatus reconcile = 3;
  }
}

message ListSandboxesRequest {}
message ListSandboxesResponse {
  repeated SandboxObservation sandboxes = 1;
}

message HealthRequest {}
message HealthResponse {
  bool ready_for_work = 1;
  bool reconcile_complete = 2;
  uint64 review_findings = 3;
  string host_boot_id = 4;
}

service Sandboxd {
  rpc Prepare(PrepareRequest) returns (Outcome);
  rpc Boot(BootRequest) returns (Outcome);
  rpc Exec(ExecRequest) returns (stream ExecEvent);
  rpc Cancel(CancelRequest) returns (Outcome);
  rpc Suspend(SuspendRequest) returns (Outcome);
  rpc Resume(ResumeRequest) returns (Outcome);
  rpc Destroy(DestroyRequest) returns (Outcome);

  rpc FileRead(FileReadRequest) returns (FileReadResponse);
  rpc FileWrite(FileWriteRequest) returns (FileWriteResponse);
  rpc FileList(FileListRequest) returns (FileListResponse);
  rpc InjectSecrets(InjectSecretsRequest) returns (Outcome);

  rpc GetSandbox(GetSandboxRequest) returns (SandboxObservation);
  rpc ListSandboxes(ListSandboxesRequest) returns (ListSandboxesResponse);
  rpc GetPortTarget(GetPortTargetRequest) returns (GetPortTargetResponse);
  rpc Watch(WatchRequest) returns (stream WatchEvent);

  rpc Health(HealthRequest) returns (HealthResponse);
}
```

### Depth notes

- Interface is small relative to implementation (ledger, adapters, guest session, cgroup).
- Stream demux lives inside sandboxd; host only consumes `ExecEvent`.
- `generation` is the observation-cache invalidation key for port proxy.

### Risks

- Mega-service growth if snapshot/fork land as more RPCs without sub-packages
- Task attach may need `AttachExec` later (bidi) without redesigning the service name

---

## Interface 2: four services by responsibility

Split along ADR-0002 seams:

```text
LifecycleService   prepare/boot/suspend/resume/destroy/cancel
GuestIoService     exec stream, files, inject secrets, signal
ObservationService get/list/watch/health
IngressQueryService get_port_target only
```

### Why consider it

- Clearer module boundaries inside sandboxd
- Observation watchers do not share request deadlines with destroy
- Ingress query can be rate-limited separately
- Matches "ports stay on host" as a dedicated query surface

### Sketch

```protobuf
service Lifecycle {
  rpc Prepare(...) returns (Outcome);
  rpc Boot(...) returns (Outcome);
  rpc Suspend(...) returns (Outcome);
  rpc Resume(...) returns (Outcome);
  rpc Destroy(...) returns (Outcome);
  rpc Cancel(...) returns (Outcome);
}

service GuestIo {
  rpc Exec(...) returns (stream ExecEvent);
  rpc FileRead(...) returns (...);
  rpc FileWrite(...) returns (...);
  rpc FileList(...) returns (...);
  rpc InjectSecrets(...) returns (Outcome);
}

service Observation {
  rpc GetSandbox(...) returns (SandboxObservation);
  rpc ListSandboxes(...) returns (...);
  rpc Watch(...) returns (stream WatchEvent);
  rpc Health(...) returns (HealthResponse);
}

service IngressQuery {
  rpc GetPortTarget(...) returns (GetPortTargetResponse);
}
```

Same messages as Interface 1; different service packaging.

### Risks

- Four auth interceptors/client stubs during big-bang
- Cross-service consistency (destroy vs open exec stream) still needs one internal gate; split interface does not create depth by itself
- Easy to grow shallow facades that only forward to the same supervisor

---

## Comparison

| Criterion | Interface 1 (single service) | Interface 2 (four services) |
|-----------|------------------------------|-----------------------------|
| Locality of lifecycle bugs | High - one client surface | Split across clients |
| Leverage for big-bang | High - map from supervisor | Medium - more plumbing |
| Stream isolation | Same channel, different RPC | Same UDS, separate service API |
| Deletion test (delete service split) | N/A | Split would move complexity, not concentrate it yet |
| Fits sole RuntimeBackend owner | Yes | Yes |
| Future helper peel | RPCs stay; impl moves | Same |

## Choice

**Interface 1.**

Reasons:

1. Big-bang cutover needs one host client and one intercept story.
2. Internal sandboxd modules can still be deep (lifecycle coordinator, guest session, observation publisher) without multi-service packaging.
3. Interface 2 can be a pure rename/split later if Observation traffic dominates; no wire break if package paths are versioned (`pico.sandboxd.v1`).

## Host API mapping (stop/purge)

Host-agent public methods are not 1:1 with Sandboxd RPCs:

| Host-agent API | sandboxd RPC | Notes |
|----------------|--------------|-------|
| prepare/boot/exec/suspend/resume/destroy | same-named RPC | Direct |
| cancel (in-flight op) | `Cancel` | By `operation_id` + `sandbox_id` |
| `stop` | `Destroy` | Accepts `Running` and is idempotent on `Stopped`; tears down runtime and host records the host-local `Stopped` state. Workspace retention is policy inside sandboxd destroy, not a separate RPC. |
| `purge` | `Destroy` | Requires `Stopped`; rejects a live sandbox before issuing the destructive RPC. After workspace/cgroup cleanup is ledger-backed inside sandboxd, host still must not call RuntimeBackend. |

Do not add `Stop` or `Purge` RPCs unless destroy semantics split for real.

## Non-goals for v1 wire

- snapshot/fork RPCs (add when implemented)
- network provision as separate public service (internal to sandboxd)
- returning RuntimeBackend handles or guest TCP addresses for host to dial guest protocol
- separate Stop/Purge RPCs (map through Destroy; see table above)

## Auth metadata (both interfaces)

```text
x-pico-sandboxd-token: <shared secret>
```

sandboxd rejects if:

- peer UID not in allowlist, or
- token missing/mismatch

Socket path example: `/var/run/pico/sandboxd.sock` mode `0660`, group `picocompute`.
