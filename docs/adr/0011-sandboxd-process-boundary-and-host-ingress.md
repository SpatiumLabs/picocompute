# ADR-0011: sandboxd Process Boundary, Sole Runtime Ownership, and Host Ingress

**Status**: Accepted
**Date**: 2026-07-23
**Accepted**: 2026-08-18 (PR1-PR8 of the process-split plan landed; see
[sandboxd-process-split-pr-plan.md](../design/sandboxd-process-split-pr-plan.md))
**Milestone**: M0 - Host Runtime Process Split
**Depends on**:
[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md),
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md),
[ADR-0003](0003-host-guest-agent-protocol-contract.md),
[ADR-0005](0005-per-sandbox-networking-model.md)

## Context

[ADR-0002](0002-host-runtime-lifecycle-orchestration.md) defines host-agent as
lifecycle coordinator and sandboxd as durable local supervisor. The
implementation still embeds `SandboxSupervisor` in-process inside `HostAgent`,
and `SandboxEntry` holds a second `Arc<dyn RuntimeBackend>`. Destroy, stop, and
exec often call the adapter directly, bypassing the ledger. Guest operational
I/O (`GuestConnection`) also lives on host-agent.

Architecture review (2026-07-23) selected deepening **sole RuntimeBackend
ownership** with a full OS process split. This ADR records the concrete
boundary decisions so future reviews do not re-litigate them, including one
intentional residual: **ingress (port proxy) stays on host-agent**.

## Decision

### 1. sandboxd is a separate OS process

- Binary: `sandboxd` (crate `pico-sandboxd`)
- Listens on a Unix domain socket (default `/var/run/pico/sandboxd.sock`)
- Wire protocol: gRPC (tonic) per
  [docs/design/sandboxd-host-rpc-design-twice.md](../design/sandboxd-host-rpc-design-twice.md)
  (Interface 1: single `Sandboxd` service)
- Host-agent never links `SandboxSupervisor` as an in-process field after cutover
- Cutover is big-bang on main: no long-lived dual mode of in-process vs remote

### 2. Sole RuntimeBackend and guest-session ownership

Only the sandboxd process may:

- hold `Arc<dyn RuntimeBackend>`
- call prepare, boot, attach_transport, wait_ready, suspend, resume, destroy
- open and own the guest-agent transport and framed operational session
- supervise exec streams, cancellation, and deadlines for guest I/O

Host-agent must not dial the guest for protocol RPCs. Exec, file transfer,
secrets inject, and quiesce go host-agent -> sandboxd -> guest.

### 3. Host resources materialize under sandboxd

Workspace directories, cgroup setup, CPU pinning allocation, and related host
resource receipts are created and cleaned under sandboxd and recorded in the
sandboxd ledger. host-agent does not own cleanup of those resources.

### 4. host-agent residual responsibilities

host-agent owns:

- public/cell RPC surface and command admission (fencing, policy epoch checks)
- observation cache only (mirror of sandboxd observations; no invented transitions)
- **port proxy and access-lease validation for ingress** (binds host ports)
- idle reaper that issues Destroy RPCs only
- aggregate host health reporting to the cell (degraded until sandboxd reconcile completes)

Host public `stop` and `purge` map to sandboxd `Destroy` (no separate Stop/Purge
RPCs). The host contract still distinguishes intent: `stop` accepts `Running`
and is idempotent on `Stopped`, while `purge` requires `Stopped`; callers that
need force teardown use `destroy`. Suspend and resume are separately admitted as
`PolicyAction::Suspend` and `PolicyAction::Resume`, so custom Cedar policies
must permit those actions explicitly. See
[sandboxd-host-rpc-design-twice.md](../design/sandboxd-host-rpc-design-twice.md)
host API mapping.

Port upstream resolution uses sandboxd `GetPortTarget` (and observation
`generation`). Host hybrid invalidation: Watch stream + periodic full
reconcile; proxy fail-closed when the target is unknown (`NotFound`) or
generation mismatches.

### 5. Ingress on host (intentional residual)

Port proxy remains on host-agent for this milestone and is not considered a
violation of sole RuntimeBackend ownership.

Rationale:

- Ingress is lease-gated API-adjacent work; edge and host already validate leases
- Moving TCP bind/proxy into privileged sandboxd expands blast radius without
  fixing dual adapter ownership
- Port **targets** remain published by sandboxd so host never needs an adapter

Future work may move proxy into sandboxd or a dedicated ingress helper; that
requires a new ADR. Do not "fix" ingress-on-host in drive-by refactors.

### 6. Auth between host-agent and sandboxd

- Filesystem permissions on the UDS (group-restricted)
- Unix peer credentials allowlist
- Shared runtime token in gRPC metadata (`x-pico-sandboxd-token`)

### 7. Privilege interim (amends ADR-0002 timeline, not end state)

ADR-0002 targets unprivileged host-agent and sandboxd with narrow privileged
helpers. For the process-split milestone, **sandboxd may run privileged**
(or with broad capabilities) so TAP/cgroup/guest paths can move without also
landing the full helper matrix.

This is interim. Peeling network/cgroup/mount into helpers remains the ADR-0002
end state. New code should still return typed receipts suitable for helpers.

### 8. READY/Running semantics (host path)

sandboxd must not report observed state Running until:

- runtime backend start succeeded
- transport attached
- guest handshake completed (fail closed; no soft skip on connection refused)
- required guest capabilities present for admitted operations

Host-agent reports Running to the cell only from sandboxd observations, not from
local guesses.

### 9. Secrets inject

Secrets inject executes inside sandboxd (guest session owner). host-agent may
pass lease proof and request specs; it does not hold the guest connection.
Broker HTTP client may run in sandboxd until a secrets helper exists.

## Consequences

### Positive

- Single owner for destroy, exec, and restart reconciliation
- host-agent restart does not drop VMM supervision
- Ledger matches reality for runtime and host resources
- Clear gRPC interface for tests (mock sandboxd)

### Negative

- Two processes in local dev and packaging
- Big-bang cutover risk (mitigated by stacked PR plan)
- Interim privileged sandboxd increases host blast radius until helpers land
- Ingress still spans two processes (host proxy + sandboxd targets)

### Neutral

- Guest dual protocol (JSON-RPC vs framed) should still be collapsed; this ADR
  requires fail-closed framed session for Running but does not finish all
  adapter JSON cleanup by itself

## Implementation plan

See [docs/design/sandboxd-process-split-pr-plan.md](../design/sandboxd-process-split-pr-plan.md).

## Acceptance tests (minimum)

1. Running sandbox survives host-agent restart; new host-agent can Exec via
   sandboxd -
   `crates/pico-host-agent/tests/restart_acceptance.rs::running_sandbox_survives_host_agent_restart_and_still_execs`;
   guest-session fail-closed across daemon restart -
   `exec_fails_closed_until_runtime_reattaches_after_sandboxd_restart` (same file)
2. sandboxd restart classifies incomplete ops; host reports not ready until
   reconcile completes -
   `crates/pico-host-agent/tests/restart_acceptance.rs::sandboxd_outage_marks_host_not_ready_and_restart_never_dual_creates`,
   `crates/pico-sandboxd/tests/restart_acceptance.rs::destroy_resumes_cleanup_from_ledger_after_mid_destroy_restart`,
   `crates/pico-sandboxd/tests/restart_acceptance.rs::destroy_resume_with_leftover_host_resources_escalates_to_review`,
   `crates/pico-sandboxd/tests/restart_acceptance.rs::supervisor_health_is_not_ready_before_reconcile`
3. No host-agent code path calls RuntimeBackend methods directly - host-agent
   holds no `Arc<dyn RuntimeBackend>`; mutating ops are `SandboxdHandle` gRPC
   calls (enforced by construction since PR5)
4. Port proxy fails closed when GetPortTarget misses after destroy -
   `crates/pico-host-agent/src/port_target_cache.rs` tombstone and
   generation guard, covered by PR6 unit tests in `port_target_cache.rs` and
   `sandboxd_client.rs`
5. Binary-level restart acceptance - real OS processes, SIGKILL,
   socket rebind, real guest-agent handshake -
   `crates/pico-host-agent/tests/binary_restart_acceptance.rs::agent_restart_keeps_running_sandbox_execable`,
   `daemon_kill_marks_host_not_ready_and_no_dual_create`,
   `exec_fails_closed_until_new_session_after_daemon_restart`,
   `mid_destroy_cleanup_resumes_from_ledger_after_restart`

   Note: `exec_fails_closed_until_new_session_after_daemon_restart` proves
   fail-closed on the original id and that a *fresh* sandbox can still be
   booted after restart. Same-sandbox session reattach/re-handshake without
   destroy+recreate is explicitly out of scope for this milestone: a sandbox
   whose guest session died with the daemon stays quarantined until the
   control plane destroys and recreates it. If transparent same-id reattach
   becomes product-required, add a dedicated test that retries boot/attach on
   the original id.

## References

- Architecture grill session 2026-07-23 (candidate: sole RuntimeBackend owner)
- [CONTEXT.md](..../CONTEXT.md) domain terms
- [sandboxd-host-rpc-design-twice.md](../design/sandboxd-host-rpc-design-twice.md)
