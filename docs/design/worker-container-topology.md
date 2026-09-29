# Worker-Container Topology for Preemptible Training

## Background

Agent training moves the agent loop off preemptible trainers. The agent
sandbox plus a scaffold-agnostic worker container is the source of truth,
with no command-log replay. On RL pause the platform reclaims trainer
memory and restores on resume. This document records the deployment
pattern that makes that safe: the rollout owner lives outside the
preemptible pool, workers live inside it, and a job-scoped pause/resume
signal coordinates reclaim behind the suspend contract.

Jobs are single-tenant. A bulk signal whose members span tenants, or
whose `tenant_id` does not match a member's tenant, fails closed before
any pause or resume side effect.

## Topology

```text
reserved pool (on-demand)          preemptible pool (spot)
-------------------------          ----------------------
rollout owner                      worker containers
- job scheduler                    - agent sandboxes
- policy engine                    - trainer sidecars
- snapshot manager                 - suspend plus reclaim
- audit/event bus                  - resume plus restore
         |                                   |
         | job pause/resume signal           |
         +-----------------------------------+
```

The rollout owner never runs on preemptible capacity. It admits the job,
tracks desired state, issues fencing tokens and policy epochs, and emits
the bulk pause/resume signal. Workers only execute fenced commands and
report observations. A preemption event pauses the job, reclaims worker
memory, and leaves the rollout owner untouched so it can drive resume
when capacity returns.

## Pause path

1. Control plane admits `JobPauseSignal` with job id, member sandbox ids,
   base fencing token, current policy epoch, deadline, and reason.
2. Host fans out to one fenced `Suspend` per member through sandboxd.
   Each member enforces fencing monotonicity, policy-epoch monotonicity,
   absolute deadline, and operation identity.
3. Suspend follows the standard contract: operation fence, exec drain,
   cooperative quiesce, workspace freeze, `memory` profile capture.
4. Reclaim runs after suspend succeeds, and the outcome reports whether it
   actually freed host memory:
   - containers: `memory.high` throttle plus `memory.reclaim` written to
     the sandbox cgroup, with the frozen cgroup preserving execution
     state and `MADV_WILLNEED` prefetch on resume.
   - microVMs: the same cgroup writes apply to the paused VMM, which also
     lives in the sandbox cgroup. Terminate plus on-demand restore is
     driven by the snapshot path.
   - `JobMemberOutcome.reclaim_applied` is `true` only when the writes
     succeeded. A member can be `succeeded: true` with
     `reclaim_applied: false`, which means the sandbox is safely
     `Suspended` but preemptible capacity was not freed. That is the
     signal operators need, and `JobOutcome.succeeded_without_reclaim`
     lists those members.
5. Per-sandbox audit records each `Running` to `Suspended` transition with
   the job envelope (`job.pause`, `job.reclaim_container` or
   `job.reclaim_microvm`) for correlation.

## Resume path

1. Control plane admits `JobResumeSignal` with a newer fencing token and
   the current policy epoch (refresh, not restore).
2. Host fans out to one fenced `Resume` per member. Before any resume side
   effect, the member's resume contract is validated: the `memory` profile
   is required, and the target runtime must match the backend that recorded
   the paused state. A runtime swap between pause and resume is rejected as
   a cross-backend restore. Each member then passes the full
   restore-validation gate list: tenant, readiness, lineage, key,
   integrity, image, backend, kernel, guest-agent, protocol, CPU, device,
   memory, policy, exclusion, fresh epoch, fresh network, fresh
   credentials, `ResumeNotify`, health.
3. Resume rebuilds host-local state: boot identity, protocol session,
   network namespace and policy, leases, credentials, SSH keys.
4. Per-sandbox audit records each `Suspended` to `Running` transition with
   `job.resume`, `job.prefetch_container`, or `job.restore_microvm`.

## Contract guards

- Suspend and resume require the `memory` profile. A `filesystem` request
  fails instead of falling back to a boot path.
- Cross-backend restore is rejected. A Firecracker snapshot never restores
  on QEMU.
- Resume never reuses pre-pause authority: sessions, leases, credentials,
  DNS answers, flows, and port exposures are regenerated.
- The rollout owner stays outside the preemptible pool so a reclaim event
  cannot take down the component that drives recovery.

## Failure handling

- Malformed envelopes fail closed before any side effect.
- Mixed-tenant member sets, or a signal tenant that does not match a
  member, fail the whole job with `BadRequest` before any pause or
  resume runs. Jobs are single-tenant.
- Stale fencing tokens or policy epochs fail per member with
  `OperationStale`; other members still proceed and the outcome reports
  per-sandbox success plus failure detail.
- Suspend or resume timeouts move the member to `Failed` with typed
  reasons; the job outcome surfaces the failure without rolling back
  members that already transitioned.
- Partial reclaim (cgroup write failure, missing snapshot) leaves the
  sandbox suspended with a warning audit; execution state stays preserved.
- Reclaim runs sequentially per member to keep sandboxd load bounded.
  Worst-case wall time is `members * member deadline`, so the control
  plane should chunk large jobs rather than sending one envelope with
  the full member list.

## API

- `POST /v1/jobs/{job_id}/pause` with `JobPauseSignal` returns `JobOutcome`.
- `POST /v1/jobs/{job_id}/resume` with `JobResumeSignal` returns `JobOutcome`.
- Both routes require bearer auth and pass the existing suspend/resume
  policy gates.
- Response status is `200` when every member succeeded and reclaim was
  actually applied, and `207` when any member failed or when a pause
  suspended every member without reclaiming anything. A status-only caller
  therefore cannot mistake a partial application or a non-reclaiming pause
  for success. `deadline_secs: 0` means the default budget.
- Both envelopes accept an optional `tenant_id` used for the single-tenant
  scope check.
