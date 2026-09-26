# Coverage Threshold and Candidate Evidence Bundle

**Status**: Proposed
**Date**: 2026-09-22
**Parent gates**: `G-16`, `G-17` in [production readiness](production-readiness.md)
**Assurance claim**: `C-06` in [assurance case](assurance-case.md)
**Config**: `../../.config/coverage.json`
**Collector**: `../../scripts/coverage.sh`
**CI**: `../../.github/workflows/coverage.yaml`

## Purpose

Tool presence is not proof. This document defines the required coverage
floors, what counts toward them, how CI collects a revision-pinned candidate
bundle for release review, and how a below-threshold candidate fails visibly.
Launch reviews cite the attached bundle for the candidate revision instead
of citing tool availability.

## What counts

- Primary metric is **line coverage** from `cargo-llvm-cov` JSON summaries.
  A line counts when LLVM marks it executable in `crates/*/src` output.
- **Region coverage** approximates branch coverage and is **warn-only**.
  It is reported in every bundle but never blocks. Function coverage is
  informational.
- Scope is workspace default members under `crates/*/src`. The path filter
  in `scripts/coverage.sh` aggregates only files containing `crates/` plus
  `/src/`, so `tests/`, `examples/`, and generated `OUT_DIR` output never
  inflate the number. eBPF crates stay excluded through the workspace
  `exclude` list and are out of scope for this gate. Workspace and per-crate
  floors all use this filtered scope. Unfiltered llvm-cov totals are kept in
  `gate.json` under `llvm_totals` for transparency but never gate.
- Critical-path intent per crate is documented through existing suites,
  not through a separate file list: lifecycle plus credential plus snapshot
  paths in `pico-core`, isolation plus backend conformance in
  `pico-runtime`, framing plus handshake plus compat in
  `pico-guest-protocol`, egress plus reconciliation plus eBPF policy in
  `pico-network-agent`. Targeted critical-path-only gating is future
  work after region variance stabilizes.

## Thresholds

Floors, not targets. Initial values are conservative starters with a
ratchet plan below.

| Scope | Line floor | Rationale |
|---|---|---|
| Workspace | 70.0% | Global backstop against untested growth |
| `pico-core` | 75.0% | Largest security surface: lifecycle, credentials, snapshot, SLO |
| `pico-runtime` | 65.0% | Backend adapters plus isolation; live paths need hardware CI |
| `pico-guest-protocol` | 80.0% | Small protocol-critical surface with fuzz plus property suites |
| `pico-network-agent` | information-only | Measured 35.27%; eBPF/netlink/tap/veth/dns_attachment at 0% until Linux hardware CI lands |

Warn-only: workspace region coverage below 60.0% raises a warning in the
bundle but passes the gate. Promotion of region coverage to a blocking
gate needs three consecutive green runs with variance under 2 points plus
Security owner approval.

Machine-readable source is `.config/coverage.json`. Human review uses the
table above; on conflict the JSON file controls CI behavior and this
document records the approval for the change.

Starter floors are unmeasured. If the first `main` runs fail, run once
with `COVERAGE_WARN_ONLY=1` to record the failing bundle without failing
the job, read observed values from `gate.json`, then set floors at or just
below observed values with a dated entry plus Security owner approval.
Never leave a red gate red without that entry.

## Gate behavior

- **Block**: `scripts/coverage.sh` exits 1 when workspace line coverage or
  any per-crate line floor fails. The CI `coverage` job fails on that exit.
  `COVERAGE_WARN_ONLY=1` overrides to exit 0 for calibration runs only; the
  failing verdict stays in `gate.json` and the bundle still uploads.
- The bundle uploads even on failure as
  `coverage-bundle-<sha>` (90-day retention) so triage keeps the failing
  numbers. The step summary shows the failing table.
- A failing run blocks `G-16` for the candidate revision. `G-17` cites the
  bundle verdict as assurance input; a missing or stale bundle blocks the
  launch review exactly like any other missing gate record.
- A dirty tree (`meta.json` `dirty: true`) is valid for local iteration
  but never counts as release evidence. Release review needs a clean tree
  at the recorded revision.

## Candidate bundle

Per run, `scripts/coverage.sh` writes
`target/coverage/bundle-<short-sha>/` with:

- `coverage.json`: full `cargo-llvm-cov` JSON for the revision
- `lcov.info`: line data for external viewers, generated with the same
  workspace and feature scope as `coverage.json` so both artifacts describe
  the same code set
- `gate.json`: workspace plus per-crate verdicts against floors,
  including filtered counts plus unfiltered `llvm_totals` for
  transparency; `status: information` marks crates with 0 floor
  (not gated)
- `meta.json` (schema `coverage-bundle/1`): revision, dirty flag,
  toolchain (`rustc --version`), timestamp, threshold snapshot, verdict
- `summary.md`: human table plus reproduce steps, also appended to the CI
  step summary

Artifact name is `coverage-bundle-<full-sha>`, linking the bundle to the
tested revision without manual naming. Retention is 90 days, matching live
boot evidence practice.

## How to run

```bash
# Validate thresholds without running tests
scripts/coverage.sh --check-config

# Full collection plus gate (workspace, all features, nextest)
scripts/coverage.sh

# Gate a prebuilt JSON without rerunning tests (testing seam)
scripts/coverage.sh --json /tmp/coverage.json --output-dir /tmp/cov-test
# The seam writes a marked synthetic lcov placeholder, never measured data
```

Calibration run without failing the job (first `main` runs only):

```bash
COVERAGE_WARN_ONLY=1 scripts/coverage.sh
```

CI installs `llvm-tools-preview`, `cargo-nextest`, and `cargo-llvm-cov`,
runs `./scripts/coverage.sh`, then uploads `target/coverage/bundle-*/`.
Prerequisites are stable toolchain plus `python3` for JSON aggregation;
no extra Python packages are required.

## Reproducibility

For the same revision the bundle is reproducible on the same runner:

1. Freeze the source revision (`git rev-parse HEAD`, clean tree).
2. Use the same stable toolchain pinned by CI (`llvm-tools-preview`
   plus matching `cargo-llvm-cov` release line) on `ubuntu-latest` x86_64.
3. Rerun `scripts/coverage.sh` with default flags.
4. Compare `coverage.json` line totals plus `meta.json` revision pins.
   CI disables nextest retries (`retries = 0` in `.config/nextest.toml`)
   so flaky tests fail fast instead of passing on retry; identical inputs
   still rerun deterministically barring flaky tests.

## Limitations

- Single-arch evidence: CI collects on `ubuntu-latest` x86_64 only.
  Arch-gated or OS-gated code that is covered on arm64 or another OS reads
  as uncovered in this bundle. The bundle is x86_64 evidence; launch review
  must not treat arch-specific gaps as global gaps without checking the
  other arch test results.
- `lcov.info` and `coverage.json` share the same workspace and feature
  scope by construction (see collector flags); if either command changes
  scope, both must change together.

## Test plan

- Lower coverage artificially and confirm the gate reacts: copy a passing
  `coverage.json`, scale down `covered` counts for one gated crate with
  `python3` or `jq`, then run
  `scripts/coverage.sh --json lowered.json --output-dir /tmp/cov-low`
  and confirm exit 1 plus a `fail` row for that crate in `gate.json`.
- Confirm reproducibility: run `scripts/coverage.sh` twice for the same
  clean revision and confirm identical line totals in `coverage.json`
  plus matching `meta.json` revision pins.

## Ratchet and ownership

- Raise a floor only after the new floor holds for three consecutive
  `main` runs. Record the date plus reason in this document.
- Never lower a floor without Security owner approval plus a dated entry
  here explaining scope, compensating controls, and re-tightening plan.
- Region coverage stays warn-only until the variance criterion above is
  met and this document promotes it explicitly.

## Approval

| Role | Date | Decision |
|---|---|---|
| Security owner | Pending | Review floors, scope, block behavior, ratchet rule |
| SRE owner | Pending | Review bundle retention, step summary, `G-16`/`G-17` wiring |

This document stays Proposed until both owners approve the floors plus the
review procedure above.
