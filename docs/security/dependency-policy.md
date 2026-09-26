# PicoCompute Dependency Policy (cargo-deny)

**Owner**: Security
**Review date**: 2027-01-01 or on new critical/high advisory
**Inputs**: `deny.toml`, `.github/workflows/deny.yaml`, `.cargo/audit.toml`

## Policy

`cargo deny check` must pass in CI for every PR and on weekly schedule.
It enforces four gates:

- **Licenses**: permissive-only allow-list in `deny.toml`. Copyleft
  (GPL/AGPL/LGPL/GFDL) is denied by omission.
- **Advisories**: pinned RustSec DB (`db-urls`), refreshed on every CI run.
  Yanked is denied; unmaintained and unsound fail including transitive deps.
- **Sources**: only `crates.io` registry allowed; git and unknown registries denied.
- **Bans**: `openssl`/`openssl-sys` denied (use `rustls`/`ring`/`boring`);
  wildcard versions denied; duplicates warn.

## How to run

```bash
cargo install cargo-deny --locked --version 0.20.2
cargo deny check
cargo deny check advisories --hide-inclusion-graph
cargo deny check licenses --hide-inclusion-graph
cargo deny check bans --hide-inclusion-graph
cargo deny check sources --hide-inclusion-graph
```

## Advisory DB pin and refresh

- Pinned source: `https://github.com/RustSec/advisory-db` in `deny.toml`.
- Refresh: CI fetches fresh on every run (no `--offline`); local runs fetch
  unless the DB is already current. Verify refresh with
  `cargo deny check advisories` after `rm -rf ~/.cargo/advisory-dbs`.

## Exception register

All exceptions live in `deny.toml` with justification and owner. This table
mirrors them for review.

| Exception | Justification | Owner | Next review |
|---|---|---|---|
| `RUSTSEC-2024-0388` (`derivative` 2.2.0 unmaintained, transitive via `pingora-core`) | No safe upgrade available; pingora has not migrated | Security | 2027-01-01 |
| `RUSTSEC-2023-0071` (`rsa` 0.9.10, parity with `.cargo/audit.toml`) | Unused transitive of `ssh-key`; currently not in deny graph, kept for future feature resolution | Security | 2027-01-01 |
| `RUSTSEC-2024-0437` (`protobuf` 2.x, parity with `.cargo/audit.toml`) | Pingora pins `prometheus` ^0.13 which pins `protobuf` 2.x; metrics-only use, not untrusted input | Security | 2027-01-01 |
| License `WTFPL` allowed globally | `tun` 0.8.14 (direct dep of `pico-network-agent`) is WTFPL-only; replace `tun` to narrow | Security | 2027-01-01 |
| `multiple-versions = warn` (43 duplicates) | Upstream-only duplicates from `pingora`/`hickory` trees; promote to `deny` after triage | Security | 2027-01-01 |
| `openssl`/`openssl-sys` banned | Security policy: use `rustls`/`ring`/`boring` instead | Security | 2027-01-01 |

`r-efi` declares `MIT OR Apache-2.0 OR LGPL-2.1-or-later` and satisfies the
license check via `MIT`/`Apache-2.0`. `LGPL` is not allowed globally.

## Banned-crate verification

To confirm the gate fails, use a scratch branch:

```bash
# Temporary: ban a crate that exists in the graph, then check
# Example (do not commit): add { crate = "tun", reason = "test" } to [bans] deny
cargo deny check bans
# Must exit non-zero with error[banned] for the test crate
```

The initial verification banned `serde` on a scratch branch and
confirmed `cargo deny check bans` failed, then reverted.

## CI evidence

- Workflow: `.github/workflows/deny.yaml` (PR, push to `main`, weekly
  `0 2 * * 0` matching `audit.yaml`, plus `workflow_dispatch`).
- G-16 citation: link the latest `Dependency Policy` run with the candidate
  revision. C-06 citation: `deny.toml` plus the same run.
