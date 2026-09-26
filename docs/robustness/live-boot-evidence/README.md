# Live Isolation-Backend Boot Evidence

Parent readiness gate: [92](../backend-prod-readiness-report.md) (section 8.5).
Assurance claim: [C-01](../../security/assurance-case.md#c-01-sandbox-isolation-boundaries-hold-for-supported-backends).
Rollout evidence target: 67 (production rollout checklist).
CI job: `.github/workflows/live-boot-evidence.yaml`.

## Purpose

Conformance currently passes against `MockBackend`. This directory defines the
reproducible procedure for one live
prepare/boot/attach/wait-ready/exec/destroy walk (plus suspend/resume where
the backend actually pauses the guest) per preview backend on the candidate
host profile, and records the resulting bundles.

Harness: `crates/pico-runtime/tests/live_boot.rs` (three ignored tests).
Collector: `scripts/live-boot-evidence.sh` (preflight plus aggregation).

## What a passing bundle must contain

Each `<backend>.json` records (schema `live-boot-evidence/1`):

- Tested source revision plus dirty flag (`GITHUB_SHA` in CI, else `git rev-parse HEAD`)
- Host image identifier (`/etc/os-release` `PRETTY_NAME`, overridable via
  `LIVE_BOOT_HOST_IMAGE`), kernel release plus full `/proc/version`, OS, arch,
  CPU model, `/dev/kvm` and `/dev/vhost-vsock` presence
- VMM and jailer/runsc versions (`--version` output plus resolved paths)
- Guest kernel, rootfs (and initrd, when configured) paths plus sha256 digests
- Transport expected versus transport observed (vsock UDS, Unix, never TCP)
- Per-phase outcomes with latency: preflight, prepare, boot,
  attach_transport, wait-ready, exec probes, stats, health, diagnostics,
  suspend/resume per policy below, destroy, cleanup
- `stats`, `health`, and `diagnostics` payloads plus tails of the diagnostic
  log artifacts

`host-profile.json` (schema `live-boot-host-profile/1`) repeats the
revision, host image, `os-release` map, kernel release, and resolved VMM
versions for the run. `summary.json` (schema `live-boot-summary/1`)
aggregates per-backend status plus revision, required-backend list, host
image, and transport for one collector run.

`status` is `pass`, `blocked` (prerequisites missing, fail-closed), or
`failed` (a walk phase failed; diagnostics tails and destroy outcome are
still recorded).

## Candidate host profile

| Requirement | Firecracker | QEMU | gVisor |
|---|---|---|---|
| Linux host | yes | yes for KVM accel | yes |
| `/dev/kvm` | yes | yes when accelerator needs KVM | no |
| VMM binary | `firecracker` (plus `jailer` for confinement) | `qemu-system-x86_64` or `qemu-system-aarch64` | `runsc` |
| Guest assets | kernel `vmlinux`, `rootfs.ext4`, optional initrd | kernel `vmlinux`, `rootfs.ext4` | gVisor rootfs |
| Network | pre-provisioned TAP via network-agent, `CAP_NET_ADMIN` | user-mode networking; `/dev/vhost-vsock` for vsock mode | none |
| Guest agent | baked into rootfs, listening on the TAP-routed TCP port | baked into rootfs | host `runsc exec` path |

## Environment

Adapter defaults are resolved from the environment (see
`crates/pico-runtime/src/firecracker/config.rs`,
`src/qemu/config.rs`, `src/gvisor/config.rs`). The variables most relevant
to a live run:

| Variable | Backend | Meaning |
|---|---|---|
| `PICO_FIRECRACKER_BIN` | Firecracker | firecracker binary path |
| `PICO_FIRECRACKER_JAILER_BIN` | Firecracker | jailer binary path (unset means no jailer confinement) |
| `PICO_FIRECRACKER_KERNEL_PATH` | Firecracker | guest kernel image (default `/opt/pico/kernel/<arch>/vmlinux`) |
| `PICO_ROOTFS_PATH` | Firecracker/QEMU | guest rootfs image |
| `PICO_QEMU_BIN` | QEMU | QEMU binary path |
| `PICO_QEMU_KERNEL_PATH` | QEMU | guest kernel image |
| `PICO_QEMU_MODE` | QEMU | `production` enables vsock plus QMP by default. The collector sets this when unset. |
| `PICO_QEMU_ENABLE_VSOCK` | QEMU | explicit vsock opt-in/out |
| `PICO_QEMU_SERIAL_FALLBACK` | QEMU | gated virtio-serial Unix fallback when vsock is off |
| `PICO_QEMU_QMP_ENABLED` | QEMU | QMP stop/cont for real suspend/resume |
| `LIVE_BOOT_OUT_DIR` | collector | base output dir (default `target/live-boot-evidence`) |
| `LIVE_BOOT_BACKENDS` | collector | subset of `firecracker qemu gvisor` |
| `LIVE_BOOT_REQUIRED_BACKENDS` | collector | subset that must pass (default `firecracker qemu`); gVisor stays optional |
| `LIVE_BOOT_HOST_IMAGE` | collector/tests | host image override for release-candidate naming |
| `LIVE_BOOT_TIMEOUT_SECS` | collector/tests | outer timeout per walk (default 600) |

## How to run

```bash
# Full collection: preflight, mock baseline, one live walk per backend.
# Sets PICO_QEMU_MODE=production when unset so QEMU attaches vsock, not TCP.
# Exit 0 when the mock baseline and every required backend pass (Firecracker
# plus QEMU by default; optional gVisor blocked does not fail the gate).
# Exit 1 on mock failure or a failed walk. Exit 2 when required walks are blocked.
scripts/live-boot-evidence.sh

# Required-only run (skip the optional gVisor signal):
LIVE_BOOT_BACKENDS="firecracker qemu" scripts/live-boot-evidence.sh

# Single backend, ignored-only (nextest):
LIVE_BOOT_OUT_DIR=/tmp/live-boot cargo nextest run -p pico-runtime \
  --test live_boot --run-ignored ignored-only -E 'test(qemu_live_boot_evidence)'
```

On hosts without network-agent, the Firecracker walk needs its TAP device
pre-provisioned (production: network-agent owns this step; the adapter never
creates TAPs). Run the companion watcher alongside the collector so the TAP
exists before the boot attaches it:

```bash
bash scripts/live-boot-tap-watch.sh &
WATCHER_PID=$!
scripts/live-boot-evidence.sh
kill "$WATCHER_PID" 2>/dev/null || true
```

Guest kernel and rootfs images for a native Linux host come from
`scripts/build-linux-guest-assets.sh` (kernel build plus Alpine rootfs with
the musl guest agent and `scripts/guest-init.sh` as `/init`, installed under
`/opt/pico` by default). VMM binaries stay out of that script: install
Firecracker from its release tarball (verify the checksum) and QEMU from
your distro, and confirm the user can open `/dev/kvm` (and
`/dev/vhost-vsock` for QEMU vsock mode).

Output layout per run: `<stamp>-<host>/` holds `<backend>.json`,
`<backend>.test.log`, `<backend>.exit`, `host-profile.json`,
`host-profile.txt`, `mock-conformance.log`, and `summary.json`.

## CI wiring

`.github/workflows/live-boot-evidence.yaml` runs the collector on
`ubuntu-latest` (x86_64) and `ubuntu-26.04-arm` (arm64) for pull requests and
pushes touching the backends, harness, collector, or this doc, plus manual
`workflow_dispatch` with `backends` and `required_backends` inputs. Every run:

- records the tested revision (`GITHUB_SHA`), host image, kernel, VMM
  versions, guest digests, transport, and per-phase outcomes;
- uploads `target/live-boot-evidence/` as
  `live-boot-evidence-<arch>-<sha>` (90-day retention);
- appends `summary.json` to the step summary.

Stock GitHub runners have no VMM binaries or guest assets (though
`ubuntu-latest` does expose `/dev/kvm` and `/dev/vhost-vsock`), so required
walks record `status=blocked` and the job stays informational (exit
2 uploads without failing). A mock failure or a `failed` walk fails the job.

## KVM evidence job

`live-boot-kvm` (x86_64, `ubuntu-latest`) goes further: it installs QEMU
8.x plus Firecracker 1.17.0, builds or restores cached guest assets with
`scripts/build-linux-guest-assets.sh` (kernel cache keyed by version,
rootfs cache keyed by guest-agent sources), pre-provisions the Firecracker
TAP with `scripts/live-boot-tap-watch.sh`, and runs the required walks for
a real `pass`. Any non-zero collector exit fails the job, and the bundle
uploads as `live-boot-evidence-kvm-x86_64-<sha>`. Trial-host deviations,
all recorded in the bundle: no jailer confinement,
`PICO_QEMU_HARDENING_ENABLED=false`, and the QEMU kernel selected via
`PICO_QEMU_KERNEL_PATH` (bzImage; Firecracker x86_64 uses the ELF
`vmlinux` at the default path).

To gate releases on a passing run, keep this job required and point
`runs-on` at a self-hosted Linux KVM runner matching the candidate profile
below if stock-runner nested KVM ever stops being sufficient.

## Reproducible reruns for release candidates

Pin and record the same inputs on every candidate rerun:

1. Freeze the source revision (`git rev-parse HEAD`, clean tree) and pass it
   through (`GITHUB_SHA` in CI covers this automatically).
2. Freeze the host image identifier (`LIVE_BOOT_HOST_IMAGE` when the cloud
   image name is more precise than `/etc/os-release`), kernel release, VMM
   binary versions, and guest kernel/rootfs/initrd digests; all land in the
   bundle and `host-profile.json`. Build the guest images with
   `scripts/build-linux-guest-assets.sh` (or record an equivalent procedure)
   so the digests are reproducible, not hand-placed.
3. Rerun `scripts/live-boot-evidence.sh` with the same `LIVE_BOOT_BACKENDS`
   and `LIVE_BOOT_REQUIRED_BACKENDS`. CI uploads the run dir as a
   per-revision `live-boot-evidence-<arch>-<sha>` artifact (90-day
   retention); for manual runs, archive the run dir where the readiness
   report and C-01 table can cite an immutable path per revision.

## Transport policy (fail-closed)

The harness refuses a non-vsock/Unix transport as live evidence: Firecracker
attaches vsock only, QEMU requires `enable_vsock` or the gated serial
fallback, gVisor always asserts Unix. A config with neither enabled records
`status=blocked` instead of silently downgrading.

## Suspend/resume policy

- Firecracker: skipped. Suspend/resume is state-only (issue 135); there is no
  guest pause to prove, so the walk records `skipped` rather than a fake pause.
- QEMU: run only when `qmp_enabled` (real QMP `stop`/`cont`). Adapter exec
  after resume is skipped because direct adapter exec is not supported
  (guest sessions are owned by sandboxd). Otherwise skipped
  as state-only.
- gVisor: skipped (Suspend/Resume undeclared). The walk probes that suspend
  still returns `Unsupported` as an informational contract pin.

Direct adapter `exec` is not supported for Firecracker/QEMU. Production
vsock/serial configs never forward a guest-agent port for adapter use, so
those walks skip adapter exec and record `adapter-exec-owned-by-sandboxd`.
gVisor execs via `runsc exec`.

## Known boundary (read before claiming handshake proof)

Adapter `wait_ready` for `Vsock`/`Unix` transports is accept-only; the
production guest handshake over those transports is owned by
`sandboxd::establish_guest_session` (pinned by the sandboxd
`qemu_transport` integration test with a mock Unix guest). Adapter-level
exec is not supported for Firecracker/QEMU: those walks record lifecycle,
transport, and observability evidence and skip exec, while gVisor execs
via `runsc exec` as its liveness proof. End-to-end vsock handshake proof
against a vsock-serving guest agent remains follow-up work; the bundle states
exactly which path each phase used.

`status` is `pass`, `blocked` (prerequisites missing, fail-closed), or
`failed` (a walk phase failed; diagnostics tails and destroy outcome are
still recorded).

## Recorded runs

### 2026-09-18 - Linux KVM host, Firecracker (pass, required)

Collector run on `Ubuntu 24.04.5 LTS aarch64`, kernel `6.8.0-139-generic`,
`/dev/kvm` and `/dev/vhost-vsock` present, Firecracker v1.17.0 (no jailer;
`PICO_FIRECRACKER_JAILER_BIN` unset), guest kernel `6.18` plus Alpine
3.24.2 rootfs with the musl guest agent built from the tested revision.
Mock conformance baseline: 21 passed, 0 failed. Firecracker walk `pass`
(all 17 phases, vsock+UDS transport, exec probes verified); TAP device
pre-provisioned per the deterministic sandbox identity (network-agent owns
this step in production; a watcher script emulated it here).

- Revision: `a2d138d`, clean tree. Collector exit 0.

This run found and fixed three product bugs (all with regression coverage
or live-bundle pins): Firecracker `PUT /vsocks/{id}` corrected to
`PUT /vsock`, `pico_sandbox_id=` added to the per-boot kernel cmdline
(guest derived `unknown-sandbox` before, failing proof verification), and
a 240s fail-closed `wait_guest_agent` poll before exec probes (adapter
`wait_ready` is accept-only for vsock, so exec raced boot on slow hosts).

### 2026-09-18 - Linux KVM host, QEMU (pass, required)

Collector run on the same Ubuntu 24.04.5 LTS aarch64 host as the
Firecracker pass (QEMU 8.2.2, KVM accel, vhost-vsock). Mock conformance
baseline: 21 passed, 0 failed. QEMU walk `pass` over vsock, including a
real QMP `stop`/`cont` pause-resume cycle; adapter exec stays skipped by
design (TCP-only; production exec is sandboxd over vsock/Unix). Trial-host
notes, all recorded in the bundle: `PICO_QEMU_HARDENING_ENABLED=false`
(unshare needs privilege the dev user lacks) and no jailer confinement.

- Revision: `4437b15`, clean tree. Collector exit 0.

This run fixed two more product bugs: the allocated QMP port is now passed
on the command line (the `:0` placeholder left QMP unreachable), and QMP
dial retries fail-closed to a 30s deadline with fast exit when the VM is
gone (the walk dialed 4ms after spawn and mistook a booting VM for a broken
one). Both carry unit tests with a fake QMP server.

### 2026-09-18 - macOS dev host, QEMU (pass, serial fallback)

Collector run on `Darwin arm64` (QEMU 11.1.1 via Homebrew, hvf
accelerator, no `/dev/kvm`, no vhost-vsock) with the same guest kernel and
rootfs as the Linux run. Mock conformance baseline: 21 passed, 0 failed.
QEMU walk `pass` over the gated virtio-serial Unix fallback transport
(`PICO_QEMU_MODE=development`, `PICO_QEMU_SERIAL_FALLBACK=true`);
suspend/resume recorded skipped (`qmp_enabled=false`, state-only without
QMP) and adapter exec recorded skipped (TCP-only by design).

- Revision: `a2d138d`, clean tree. Collector exit 0.
- A Linux KVM QEMU `pass` (vsock plus QMP stop/cont) was recorded in a later
  run on the same host; the remaining step is wiring the same run into a
  self-hosted CI job rather than a manual collector run.

### 2026-09-16 - macOS dev host (blocked, as expected)

Collector run on `Darwin arm64` (no `/dev/kvm`, no firecracker/jailer/runsc,
QEMU 11.1.1 present via Homebrew, no guest assets). Mock conformance
baseline: 15 passed, 0 failed. Live walks: all three `blocked` with explicit
reasons; QEMU additionally refused the dev-default TCP transport.

- Firecracker: blocked - not Linux, no `/dev/kvm`, no firecracker binary, no
  guest kernel/rootfs.
- QEMU: blocked - no guest kernel/rootfs; TCP downgrade refused.
- gVisor: blocked - not Linux, no runsc binary, no rootfs.

(That run used an older schema version; current bundles also record source
revision, host image, and kernel release.) Rerun the collector procedure
above for current evidence.

## 67 attach checklist (for the passing candidate-host run)

Attach to 67 and link from the 92 readiness report and the 89
assurance case C-01 table:

- `firecracker.json` and `qemu.json` with `status=pass` (required);
  `gvisor.json` with `status=pass` when the trusted fast path is in scope,
  otherwise its blocked/optional outcome is informational
- `host-profile.json` plus host image identifier for the exact candidate host
- `summary.json` (with `source_revision` and `required_backends`) and the
  `mock-conformance.log` control run
- `<backend>-test.log` tails showing the executed lifecycle
- CI artifact name (`live-boot-evidence-<arch>-<sha>`) linking the bundle to
  the tested revision
