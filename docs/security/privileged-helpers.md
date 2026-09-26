# Privileged Helper Operations per Backend

This document defines the privileged helper boundary for each PicoCompute runtime backend.
All privileged operations must be narrow, typed, and auditable.

## Firecracker

### Jailer (privileged helper binary)

The Firecracker jailer is the privileged helper. It applies kernel-level isolation
before executing the Firecracker VMM. PicoCompute configures the jailer via the
`JailerHardening` profile.

| Operation | Privilege Required | Purpose |
|---|---|---|
| `--uid` | `CAP_SETUID` | Drop VMM process UID (default: 65534/nobody) |
| `--gid` | `CAP_SETGID` | Drop VMM process GID (default: 65534/nobody) |
| `--chroot-base-dir` | `CAP_SYS_CHROOT` | Confine VMM filesystem visibility |
| `--seccomp-level` | `CAP_SYS_ADMIN` (seccomp filter) | Apply seccomp BPF to VMM (default: 2) |
| KVM device access | `/dev/kvm` | Virtualization |
| TAP device setup | `CAP_NET_ADMIN` | Network interface creation |

### Host-side hardening (applied by sandboxd/agent before jailer)

| Operation | Privilege Required | Purpose |
|---|---|---|
| seccomp filter install | `PR_SET_SECCOMP` | Restrict host process syscalls |
| capability bounding | `CAP_SETPCAP` | Minimize ambient capability set |
| `PR_SET_NO_NEW_PRIVS` | None (irreversible) | Prevent privilege escalation |

### Auditable boundary

- Jailer arguments are logged via tracing at INFO level before execution.
- UID/GID/chroot/seccomp-level values are configurable via environment variables:
  `PICO_JAILER_UID`, `PICO_JAILER_GID`, `PICO_JAILER_CHROOT_BASE_DIR`,
  `PICO_JAILER_SECCOMP_LEVEL`.
- Production default UID/GID is `65534` (nobody), not root.

## QEMU

### QEMU process (no dedicated jailer)

QEMU runs directly without an external jailer. Host-side hardening is applied
by the runtime adapter via `pico-runtime-hardening` before spawning QEMU.

| Operation | Privilege Required | Purpose |
|---|---|---|
| namespace unshare (mount, UTS, IPC) | `CAP_SYS_ADMIN` | Process-level namespace isolation |
| `PR_SET_NO_NEW_PRIVS` | None (irreversible) | Prevent privilege escalation |
| seccomp filter install | `PR_SET_SECCOMP` | Restrict host process syscalls |
| capability bounding | `CAP_SETPCAP` | Minimize ambient capability set |
| KVM accelerator access | `/dev/kvm` | Hardware virtualization |
| TAP device setup | `CAP_NET_ADMIN` | Network interface creation |

### Auditable boundary

- Namespace isolation configuration is logged via tracing at INFO level.
- Hardening is controlled by `PICO_QEMU_HARDENING_ENABLED` environment variable.
- QEMU command line arguments are logged at INFO level.

## gVisor

### runsc (gVisor sandbox runner)

The `runsc` binary is the privileged helper. The runtime adapter applies host-side
namespace isolation before delegating to `runsc`.

| Operation | Privilege Required | Purpose |
|---|---|---|
| namespace unshare (mount, UTS, IPC) | `CAP_SYS_ADMIN` | Process-level namespace isolation |
| `PR_SET_NO_NEW_PRIVS` | None (irreversible) | Prevent privilege escalation |
| seccomp filter install | `PR_SET_SECCOMP` | Restrict host process syscalls |
| capability bounding | `CAP_SETPCAP` | Minimize ambient capability set |

### OCI container hardening (applied by runsc)

| Operation | Privilege Required | Purpose |
|---|---|---|
| Namespace creation (pid, net, ipc, uts, mount) | `CAP_SYS_ADMIN` | Container namespace isolation |
| Seccomp profile application | `CAP_SYS_ADMIN` (seccomp filter) | Container syscall filtering |
| Capability whitelist | `CAP_SETPCAP` | Container capability minimization |
| Masked paths | Mount namespace | Prevent access to sensitive host paths |
| Readonly paths | Mount namespace | Prevent writes to sensitive host paths |

### Auditable boundary

- Host-side hardening is controlled by `PICO_GVISOR_HARDENING_ENABLED`.
- OCI config.json contains the full container specification and is accessible
  via the diagnostics endpoint.
- `runsc` command output is captured and logged.

## Namespace Model

`pico-runtime-hardening` applies `unshare(2)` on the calling process (the
adapter process) before spawning the VMM/container. This moves the adapter
into new mount, UTS, and IPC namespaces.

This is safe in PicoCompute's single-sandbox-per-process model. In a
multi-tenant model where a single adapter process manages multiple sandboxes,
`unshare` would affect all subsequent sandboxes. Multi-tenant namespace
isolation requires `clone(2)` with `CLONE_NEWNS` per VMM process or a
dedicated short-lived helper (tracked by).

### Common Hardening Operations

| API | Syscall | Purpose |
|---|---|---|
| `apply_standard_isolation` | `unshare(2)`, `prctl(2)` | Unshare mount/uts/ipc namespaces + set no_new_privs |

### Telemetry Events

| Event | Description |
|---|---|
| `namespace_isolation_applied` | Namespace isolation configuration applied |
| `runtime_hardening_violation` | Hardening boundary violation detected (pico-seccomp) |
| `syscall_audit` | Per-sandbox eBPF syscall enter/exit audit record |
| `behavioral_anomaly` | anomaly alert (severity + confidence) |
| `file_integrity_violation` | protected-path write/unlink alert |

### Behavioral anomaly detection

`pico-host-agent` wires audit registration automatically on prepare/restore
and unregisters on destroy via `SyscallAuditService`:

- type key = `sandbox_type_key(image_id, tenant_id|"default")`
- cgroup id = sandbox cgroup directory inode (`bpf_get_current_cgroup_id`)
- sample rate = `PICO_SYSCALL_AUDIT_SAMPLE_RATE` (default 10)
- disable with `PICO_SYSCALL_AUDIT=0`

Library callers outside the host agent should use:

```rust
use pico_runtime_hardening::{sandbox_type_key, ebpf::EbpfSyscallMonitor};

let type_key = sandbox_type_key(image_id, workload_label);
monitor.register_sandbox_audit(sandbox_id, cgroup_id, &type_key, true, sample_rate)?;
monitor.unregister_sandbox_audit(sandbox_id, cgroup_id)?;
```

Learning completes when either `min_events_for_baseline` (default 100) enter
events are seen **or** `learning_duration` (default 5 minutes) elapses. Warm-start
priors and per-type `DetectorConfig` overrides are supported on `AnomalyDetector`.

### File integrity monitoring

`FileIntegrityService` registers each sandbox cgroup with a protected-path
baseline (system defaults: `/etc/passwd`, `/etc/shadow`, `/usr/bin`, `/lib`,
and related system paths; optional image/SBOM path merge).

**Kernel requirements (LSM path):** Linux 5.7+, `CONFIG_BPF_LSM=y`, host BTF,
and `bpf` in `/sys/kernel/security/lsm` (boot `lsm=...,bpf`).

**Observation paths:**

1. ** bridge (always when audit consumer runs):** `SyscallAuditService`
   attaches `FileIntegrityService::syscall_observer` so `open`/`openat`
   write-intent events with path strings feed the userspace checker. This is
   the reliable production alert path when LSM path resolution fails.
2. **BPF LSM:** `file_open`, `inode_permission`, `inode_unlink`, cgroup-filtered.

**Enforcement scope (intentional, v1):**

- Kernel `-EPERM` only on path-bearing protected **`file_open`** matches when
  `bpf_d_path` succeeds.
- `inode_permission` `inode_unlink` are audit/correlation only (fail-open;
  never deny). Unlink of a protected path is not blocked by FIM v1.
- Path resolution uses a best-effort `struct file` layout; on failure the LSM
  path fails open and increments `path_resolution_failures` (see `FimStats`).

**Config:**

- Mode: `PICO_FIM_MODE=audit` (default) or `enforce`
- Disable: `PICO_FIM=0`
- Extra paths: `PICO_FIM_EXTRA_PATHS` (comma/colon list); image_id also
  merges guest-agent install paths via `integrity_paths_for_image`
- Per-sandbox BPF path cap: 64 entries; path key length 128 bytes (truncated)

```rust
use pico_runtime_hardening::fim::{FileIntegrityChecker, FimMode, IntegrityBaseline};

let checker = FileIntegrityChecker::with_defaults;
checker.register_sandbox(sandbox_id, cgroup_id, FimMode::Audit, None);
// optional: IntegrityBaseline::system_with_image_paths(sbom_paths)
let stats = checker.stats; // alerts, denied, path_resolution_failures,...
```
