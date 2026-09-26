<p align="center">
  <img src="favicon.svg" alt="PicoCompute Logo" width="64" height="64" />
</p>

<h1 align="center">PicoCompute</h1>

<p align="center">
  <a href="https://github.com/SpatiumLabs/picocompute/actions/workflows/test.yaml"><img src="https://github.com/SpatiumLabs/picocompute/actions/workflows/test.yaml/badge.svg?branch=main&style=flat" alt="Test Status"></a>
  <a href="https://github.com/SpatiumLabs/picocompute/actions/workflows/audit.yaml"><img src="https://github.com/SpatiumLabs/picocompute/actions/workflows/audit.yaml/badge.svg?branch=main&style=flat" alt="Audit Status"></a>
  <a href="https://github.com/SpatiumLabs/picocompute/actions/workflows/semgrep.yaml"><img src="https://github.com/SpatiumLabs/picocompute/actions/workflows/semgrep.yaml/badge.svg?branch=main&style=flat" alt="Semgrep Status"></a>
  <a href="https://github.com/SpatiumLabs/picocompute/actions/workflows/release-cli.yaml"><img src="https://github.com/SpatiumLabs/picocompute/actions/workflows/release-cli.yaml/badge.svg?branch=main&style=flat" alt="Release CLI Status"></a>
</p>

**PicoCompute is a cloud compute layer for the Age of AI Agents.**

It provides secure, policy-controlled, observable sandboxes for AI agents and developer workloads: fast environment creation, safe command execution, preserved or forked state, controlled network access, and reliable cleanup.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the full system design, and `docs/adr/` for the normative decisions behind it.

## Quickstart

Install the CLI, then point it at an API endpoint and token:

```bash
curl -fsSL https://github.com/SpatiumLabs/picocompute/releases/latest/download/install-script | sh

# or from source
cargo install --path crates/pico-cli

export PICO_API_URL=http://localhost:8080
export PICO_API_TOKEN=...   # required
```

Create a sandbox, use it, then tear it down:

```bash
pc create --id sbx_1 --runtime qemu --memory-mb 2048 --vcpus 2
pc get sbx_1
pc exec sbx_1 -- uname -a
pc files write sbx_1 --path /workspace/notes.md --content "hello"
pc files read sbx_1 --path /workspace/notes.md
pc ssh sbx_1
pc stop sbx_1
pc destroy sbx_1
```

Port exposure is policy-controlled, so it needs a lease first:

```bash
pc lease issue sbx_1 --action port_forward --ports 8080
pc ports expose sbx_1 --tenant-id tnt_1 --lease-id lse_1 --guest-port 8080
```

Run `pc --help` for the full command set.

## Development

```bash
cargo build                # build the workspace
cargo nextest run          # run all tests
cargo fmt --all            # format
./scripts/lint-fix.sh      # lint
```

Local stacks run through [mise](https://mise.jdx.dev):

```bash
mise run dev-host           # host-agent + sandboxd as two local processes
mise run qemu:dev           # API server on the QEMU backend
mise run firecracker:dev    # API server on the Firecracker backend
mise run smoke_test         # end-to-end smoke test
```

Copy `.env.sample` to `.env` to configure local settings.

## Architecture at a glance

```text
Client/Agent Platform -> Public Platform API -> Regional Control Plane
                                                 -> Cell Control Plane
                                                 -> Compute Host (host-agent, sandboxd)
                                                 -> Sandbox Backend (Firecracker, gVisor, QEMU)
```

The control plane owns admission, policy, scheduling, and lifecycle state. The host runtime owns local execution and supervision. Backends own isolation. The regional metadata store stays authoritative; host processes hold only local observed state.

## Capabilities

| Area | Summary | Decision |
|---|---|---|
| Lifecycle | Explicit state machine from creation through suspend, resume, fork, and destroy | [ADR-0001](docs/adr/0001-control-plane-ownership-lifecycle-state-model.md) |
| Host runtime | Fenced boot commands, durable `sandboxd` supervision, idempotent cleanup | [ADR-0002](docs/adr/0002-host-runtime-lifecycle-orchestration.md) |
| Host/guest protocol | Versioned gRPC with mutual authentication, bounded messages and streams | [ADR-0003](docs/adr/0003-host-guest-agent-protocol-contract.md) |
| Isolation backends | Firecracker by default, gVisor trusted fast path, QEMU fallback | [ADR-0004](docs/adr/0004-default-isolation-backend-strategy.md) |
| Networking | Per-sandbox network namespaces, default-deny egress, lease-controlled access | [ADR-0005](docs/adr/0005-per-sandbox-networking-model.md) |
| Security | Threat model, production posture, assurance case, evidence-based gates | [ADR-0006](docs/adr/0006-production-security-posture-for-sandbox-isolation.md) |
| Snapshots | Filesystem-first snapshot, resume, and fork with copy-on-write workspaces | [ADR-0007](docs/adr/0007-snapshot-resume-fork-consistency-model.md) |
| Images | Reproducible OCI bundles with signing, SBOMs, and provenance | [ADR-0008](docs/adr/0008-guest-image-format-and-build-pipeline.md) |
| Observability | OpenTelemetry signals plus a separate durable audit plane | [ADR-0009](docs/adr/0009-observability-and-reliability-signals.md) |
| Scale | Phased load validation, capacity models, rollout gates | [ADR-0012](docs/adr/0012-production-scale-validation-strategy.md) |

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - system design and repository layout
- [API reference](docs/api/v2/openapi.yaml) with [examples](docs/api/v2/EXAMPLES.md)
- [Runbooks](docs/runbooks/README.md) - operational procedures
- [Threat model](docs/security/threat-model.md) and [production readiness](docs/security/production-readiness.md)
- [Robustness](docs/robustness/README.md) - protocol fuzzing and conformance tests
- [SLO and error budget policy](docs/observability/slo-error-budget-policy.md)
- [Capacity models](docs/capacity/active-sandbox-defaults.md)

## Repository layout

The workspace is a set of Rust crates under `crates/`, each with a focused responsibility (API, sandbox lifecycle, runtime, networking, image builds, telemetry). Tests live alongside their crate; infrastructure, CI, scripts, and docs sit at the top level.

See [ARCHITECTURE.md §16](ARCHITECTURE.md#16-repository-layout) for the full tree.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
