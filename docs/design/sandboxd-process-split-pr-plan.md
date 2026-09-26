# PR plan: sandboxd process split (big-bang)

**Goal**: sandboxd is a privileged OS process; sole RuntimeBackend and guest-session owner; host-agent admits + observes + port-proxies over gRPC/UDS.

**Interface**: [sandboxd-host-rpc-design-twice.md](./sandboxd-host-rpc-design-twice.md) (Interface 1)
**Decisions**: [ADR-0011](../adr/0011-sandboxd-process-boundary-and-host-ingress.md)

Use Graphite-style stacked PRs. Each PR leaves `main` buildable and tested. No long dual-owner mode on main: land behind a compile-time or default-off binary path until the cut PR, then switch host-agent in one PR and delete the in-process supervisor path immediately after.

---

## Dependency DAG

```text
PR1 proto + types
  -> PR2 sandboxd binary + gRPC server (library supervisor)
    -> PR3 guest session moves into sandboxd
      -> PR4 host resources (workspace/cgroup) into sandboxd
        -> PR5 host-agent gRPC client + cutover (delete in-process)
          -> PR6 observation Watch + GetPortTarget + proxy wiring
            -> PR7 secrets inject + DNS attach in sandboxd
              -> PR8 restart/reconcile acceptance + docs polish
```

PRs 6 and 7 can partially parallelize after PR5 if carefully stacked; prefer sequential for sole-owner clarity.

---

## PR1: Proto and shared error mapping

**Branch**: `feat/sandboxd-grpc-proto`

**Scope**:

- New crate or path: `crates/pico-sandboxd-proto` (or `proto/` under sandboxd with build.rs)
- Interface 1 messages + `Sandboxd` service
- Map `SupervisorError`/`OutcomeStatus` to tonic `Status` codes
- Unit tests: proto round-trip for `CommandMeta`, `Outcome`, `PortTarget`

**Out of scope**: server binary, host client

**Done when**: `cargo test -p pico-sandboxd-proto` (or sandboxd build.rs tests) green

---

## PR2: sandboxd binary + gRPC server over existing supervisor

**Branch**: `feat/sandboxd-grpc-server`

**Scope**:

- `crates/pico-sandboxd` binary: `main.rs`, config (UDS path, token, ledger path, workspace root)
- tonic server on UDS; peercred + token intercept
- Implement Lifecycle RPCs by calling existing `SandboxSupervisor` (still receives `Arc<dyn RuntimeBackend>` **inside** sandboxd process via local `AdapterRegistry`)
- `Health` + `ListSandboxes`/`GetSandbox` from ledger
- systemd unit sample under `infra/` (optional)

**Out of scope**: host-agent changes; guest session still may be incomplete for Boot Ready

**Done when**:

- Manual or integration: start sandboxd, `Prepare`+`Destroy` with MockBackend over UDS
- Existing `pico-sandboxd` supervisor unit tests still pass

---

## PR3: Guest session owned by sandboxd

**Branch**: `feat/sandboxd-guest-session`

**Scope**:

- Move or share `GuestConnection`/handshake into a module sandboxd owns (extract from host-agent into `pico-runtime` or `pico-sandboxd` guest module)
- Boot path: attach transport + handshake **fail closed** (no soft ConnectionRefused -> Ready)
- `Exec` streaming RPC: sandboxd demuxes guest frames to `ExecEvent`
- `FileRead`/`FileWrite`/`FileList`/`Cancel`
- Delete JSON-RPC use from boot Ready path if still present on this code path

**Done when**:

- Integration test: mock guest + sandboxd Exec stream end-to-end
- Boot Outcome observed_state Running only with session established

---

## PR4: Host resource materialization in sandboxd

**Branch**: `feat/sandboxd-host-resources`

**Scope**:

- Workspace ensure, cgroup setup/teardown, CPU allocate/pin inside sandboxd prepare/destroy
- Resource receipts for workspace/cgroup classes in ledger
- Host-agent no longer creates cgroups for new sandboxes (still may read stats via RPC later)

**Done when**: prepare without host-side cgroup code on the new path; cleanup receipts covered by tests

---

## PR5: host-agent cutover (big-bang)

**Branch**: `feat/host-agent-sandboxd-client`

**Scope**:

- gRPC client module in host-agent
- Replace `SandboxEntry.adapter` with observation cache entry
- Mutate ops via RPC: Prepare/Boot/Exec/Suspend/Resume/Destroy/Cancel
- Host `stop` and `purge` both call Destroy RPC (no separate Stop/Purge RPCs; see design-twice host API mapping). After Destroy, host updates local observation/cache only.
- Reaper calls Destroy RPC
- Remove in-process `SandboxSupervisor` field from HostAgent
- AdapterRegistry lives only in sandboxd
- API handlers unchanged at trait level where possible

**Done when**:

- `cargo nextest run` for host-agent + api with mock sandboxd or test fixture
- No references to `entry.adapter.destroy`/`entry.adapter.exec`
- Default dev compose runs host-agent + sandboxd two processes

---

## PR6: Port targets, Watch, proxy invalidation

**Branch**: `feat/sandboxd-observation-watch`

**Scope**:

- `GetPortTarget` + `generation` on observations
- `Watch` server stream + host hybrid: Watch + periodic List reconcile
- PortProxyManager resolve uses GetPortTarget cache; fail-closed
- Invalidate on Watch upsert/remove and resume/destroy

**Done when**: unit tests for fail-closed proxy; resume updates generation and drops stale routes

---

## PR7: Secrets inject + DNS attach in sandboxd

**Branch**: `feat/sandboxd-secrets-dns`

**Status**: Implemented

**Scope**:

- `InjectSecrets` RPC; SecretsCoordinator (or subset) runs in sandboxd
- Host passes lease proof/credential request; sandboxd fetches broker if configured
- DNS proxy attach receipts provisioned from sandboxd (DNS proxy process location: sandboxd for now)
- Host removes guest_conn-based secrets inject

**Done when**: secrets integration tests retargeted at sandboxd; DNS attach receipts in ledger

---

## PR8: Restart acceptance + polish

**Branch**: `feat/sandboxd-restart-proof`

**Status**: Implemented

**Scope**:

- Acceptance tests (Linux CI or marked ignore without privileges):
  1. Boot Running sandbox; kill host-agent; new host-agent ListSandboxes sees it; Exec still works
  2. Kill sandboxd; host Health not ready; no silent dual create
  3. Destroy resumes cleanup from ledger after sandboxd restart mid-destroy
- Update ARCHITECTURE.md host runtime section
- CONTEXT.md already seeded; fix any term drift
- Point ADR-0002 status notes at ADR-0011 for process boundary

**Done when**: documented test commands in PR; restart scenarios 1-2 green in CI where feasible

**Residual risk**: the shipped harness runs the split in-process (supervisor open/drop simulates a daemon kill; a fresh `HostAgent` simulates an agent kill), so real binary lifecycle, signal handling, and socket rebind are not covered yet. Addressed in with binary-level acceptance tests using the `mock-backend` feature.

---

## Test strategy summary

| Layer | What |
|-------|------|
| Proto | Round-trip + golden fixtures |
| sandboxd unit | Supervisor + ledger (existing) + guest session |
| sandboxd integration | UDS client against binary with MockBackend |
| host-agent | Mock sandboxd gRPC (or in-process test server) |
| Acceptance | Multi-process restart proofs |

## Explicit non-goals (this plan)

- Peeling network/cgroup to separate privileged helper processes (ADR-0002 end state; later)
- Moving port proxy into sandboxd (ADR-0011 residual)
- Regional metadata store ownership (ADR-0001)
- Full guest JSON-RPC deletion on all adapter paths if not on Ready path (track separately if needed)

## Risk register

| Risk | Mitigation |
|------|------------|
| Big-bang PR5 too large | Keep PR3-4 complete first; PR5 is wiring only |
| Streaming backpressure | Bound channel sizes; ExecEvent max chunk; cancel on host drop |
| Privilege of sandboxd | Document interim in ADR-0011; seccomp profile on binary |
| Auth token in env | Same class as API bearer today; rotate via config reload later |
| Dual process local dx | mise/scripts `dev-host` starts both; document in README |

## Suggested ownership order for implementers

1. Someone strong on tonic/proto: PR1-2
2. Guest protocol: PR3
3. Host/cgroup: PR4
4. Host-agent integration: PR5-6
5. Secrets/DNS: PR7
6. Reliability: PR8
