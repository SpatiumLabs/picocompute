# Guest Image Pipeline Production Readiness Report

**Date**: 2026-09-23
**Status**: Draft (pending Image Pipeline, Runtime, Security, and Architecture owner review)
**Strategy**: [ADR-0008](../adr/0008-guest-image-format-and-build-pipeline.md)
**Posture**: [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md)
**Readiness model**: [Production readiness](../security/production-readiness.md) gate `G-08`
**Assurance parent**: [Security assurance case](../security/assurance-case.md) residual risk `RR-07`

## Executive Summary

This report validates the PicoCompute guest image pipeline as an integrated
subsystem from build input to promoted artifact and optional warm snapshot,
before production rollout. Validation composes the image-format ADR, PicoCompute
manifest schema, reproducible rootfs generation, mount layout, kernel and
init profiles, guest-agent injection, static and negative validation, SBOM,
signing, provenance, host verification, and warm-snapshot lineage through
the existing automated suites.

**Overall verdict**: the image pipeline meets the G-08 evidence bar that can
be executed without a live Linux image-build host, with the exceptions in
section 11. On 2026-09-23 the evidence suite passed: 249 `pico-image`
tests. `cargo clippy -p pico-image --lib --tests --locked -- -D warnings`
is clean. Manifests carry rootfs, kernel/init, guest-agent, mount, protocol,
compatibility, SBOM, signature, and provenance metadata. Production-mode
host verification rejects unsigned images, unpinned signers, and mismatched
artifact bytes. Warm snapshot generation is validated with a mock backend for
profiles that require it. x86_64 kernel profile IDs now match the ADR and
the `{backend}-{arch}-v1` lookup used at manifest generation.

This report is not launch approval. ADR-0008 remains Proposed. Live
`mkfs.ext4` rendering, apk package install, OCI registry referrers,
vulnerability scanning, and signed promotion attestations are outside this
run. Owner sign-off is recorded as pending in Approval.

## How to Run the Evidence

```bash
cargo nextest run -p pico-image --lib --tests
cargo clippy -p pico-image --lib --tests --locked -- -D warnings
```

Suite mapping to validation areas:

| Validation area | Suite | Location |
|---|---|---|
| Image format and ownership | ADR-0008 | `docs/adr/0008-guest-image-format-and-build-pipeline.md` |
| Manifest schema and pipeline | pipeline | `crates/pico-image/tests/pipeline.rs`, `src/manifest.rs` |
| Static validation | validation_static | `crates/pico-image/tests/validation_static.rs`, `src/validation/` |
| Negative fixtures | negative_fixtures | `crates/pico-image/tests/negative_fixtures.rs` |
| Kernel and init profiles | kernel lib | `crates/pico-image/src/kernel.rs` |
| SBOM | sbom lib | `crates/pico-image/src/sbom.rs` |
| Provenance | provenance lib | `crates/pico-image/src/provenance.rs` |
| Signing | signature lib | `crates/pico-image/src/signature.rs` |
| Host verification | host_verify lib | `crates/pico-image/src/host_verify.rs` |
| Warm snapshot generation | warm_snapshot lib | `crates/pico-image/src/warm_snapshot/` |
| Backend consumption of local artifacts | runtime adapters | `crates/pico-runtime/src/firecracker/`, `qemu/`, `gvisor/` |
| Boot-to-handshake identity | host-agent handshake | `crates/pico-host-agent/src/handshake.rs` |
| Live VMM boot (ignored by default) | live boot | `crates/pico-runtime/tests/live_boot.rs`, `scripts/live-boot-evidence.sh` |

Related prior evidence (not duplicated here): backend readiness in
`docs/robustness/backend-prod-readiness-report.md`, protocol readiness in
`docs/robustness/guest-agent-proto-prod-readiness-report.md`, snapshot
readiness in `docs/robustness/snapshot-readiness-report.md`, threat model in
`docs/security/threat-model.md`.

Test counts on 2026-09-23:

| Suite | Tests |
|---|---|
| pipeline | 46 |
| validation_static | 45 |
| negative_fixtures | 50 |
| kernel | 14 |
| sbom | 8 |
| provenance | 7 |
| signature | 10 |
| host_verify | 11 |
| validation report | 7 |
| warm_snapshot (compat, config, error, generator, validation) | 51 |
| **Total** | **249** |

## 1. Ownership Boundaries

ADR-0008 assigns one owner to each image-pipeline decision:

| Concern | Owner |
|---|---|
| Manifest schema and compatibility semantics | Guest image pipeline with Runtime and Security review |
| Source and component build definitions | Build/Release |
| Backend profile requirements | Runtime and backend conformance |
| Protocol ranges and capabilities | ADR-0003 schema and guest-protocol owners |
| Mount classes and snapshot behavior | Mount contract with Storage and Security review |
| Supply-chain and vulnerability policy | Security and Build/Release |
| Promotion decision | Release policy with Runtime, Security, and Build/Release approval |
| Placement eligibility | Control plane using verified manifest and policy evidence |
| Final artifact and compatibility verification | Host before cache use and boot (`verify_for_host`) |
| Warm snapshot capture and restore | Snapshot pipeline under ADR-0007 |

Runtime adapters receive an already selected variant. They materialize and
attach declared artifacts. They do not choose components, broaden
compatibility, waive verification, or promote images.

## 2. Image Format and Manifest Schema

The PicoCompute guest image is a signed, content-addressed bundle. The
implemented PicoCompute JSON manifest uses media-type
`application/vnd.pico.guest.manifest.v1+json` fields from ADR-0008:

- `schema_version`, `image_id`, `release` (version, source_revision, build_epoch)
- `platform` (os, architecture)
- `artifacts` (rootfs, kernel, initrd, firmware, guest_agent)
- `protocol` (bootstrap, supported ranges, capabilities)
- `compatibility` (profile_id, backends, CPU/device/host features)
- `mount_contract`
- `snapshot` exclusions

`manifest_json_conforms_to_adr_schema` pins the required top-level keys.
`manifest_serialization_roundtrip` and `manifest_with_null_kernel_is_none`
pin optional kernel/initrd/firmware as JSON `null` rather than a sentinel
path. Schema major `0` and unknown required fields fail
`validate_static`. Readers reject an empty `image_id`, empty rootfs digest,
and a digest without a `sha256:` prefix.

The implemented artifact is a local directory of files (`manifest.json`,
`rootfs.ext4`, `sbom.cdx.json`, `provenance.json`, optional
`manifest.sig.json`). The OCI index, variant manifests, and referrer graph
in ADR-0008 are not assembled in this pipeline. That stays an open
limitation in section 11.

## 3. Reproducible Rootfs Generation

`RootfsBuilder::build` runs the ordered in-process phases: load definition,
create or load the package lock, fetch the pinned base archive, resolve the
guest-agent binary, normalize the tree, render ext4, generate the PicoCompute
manifest, SBOM, and provenance, run supply-chain validation, and optionally
sign.

Normalization (`normalize.rs`) extracts the pinned base, installs locked
packages when `apk` is present, injects the guest agent at
`/usr/local/bin/pico-agent`, embeds init and agent startup config,
strips machine-id and SSH host keys, sets timestamps to
`source_date_epoch`, and creates canonical mount directories. Secret mount
paths must be empty in the released tree.

`lock_file_reproducibility` pins that the same definition produces the same
lock. `compute_digest_consistent` pins SHA-256 of identical bytes.
`render_ext4` uses `mkfs.ext4` with a fixed label and UUID, then `e2fsck`.
This run does not invoke `mkfs.ext4` or `apk`. Those tools are required on
a Linux build host. `image.toml` still records `digest = "sha256:unresolved"`
for the Alpine base; a production lock must replace that with a real digest
before locked-mode builds.

Byte-identical ext4 across independent rebuilds is not claimed here. The
pipeline records the digest of whatever `mkfs.ext4` produced. Independent
rebuild evidence is a section 11 limitation.

## 4. Mount Layout

The image definition and generated manifest share the mount contract from
`pico_core::mount`. Required classes are workspace
(`/workspace`), runtime_tmp (`/run/pico/tmp`), secret
(`/run/pico/secrets`), and guest_logs (`/var/log/pico`).

Static checks fail on an empty contract, a missing required class, a
non-canonical path, duplicate paths or classes, empty snapshot exclusions,
and exclusion of a non-ephemeral class. `secret` and `runtime_tmp` must
appear in `snapshot.excluded_mount_classes`. Manifest generation derives
exclusions from the contract so the two views cannot drift.

Unknown mount classes fail at definition load
(`build_mount_contract_from_def`). Runtime adapters must not guess paths.

## 5. Kernel and Init Path

Production Firecracker and QEMU profiles exist for aarch64 and x86_64.
Each profile pins cmdline, virtio, vsock, ext4, and devtmpfs options.
Production variants omit debug kernel options. Cmdline policy requires
`init=/init`, `root=/dev/vda`, and `rw`, and rejects debug tokens
(`debug`, `earlyprintk`, `slub_debug`, high `loglevel`) on a production
variant.

Profile IDs follow `{backend}-{arch}-v1` with architecture `x86_64`,
matching ADR-0008 (`firecracker-x86_64-v1`, `qemu-x86_64-v1`). Historical
IDs that omitted the underscore (`firecracker-x8664-v1`) still resolve
through `find_profile` so existing definitions keep working.
`kernel_cmdline_x86_64_matches_canonical_profile` pins that
`kernel_cmdline("x86_64", "firecracker")` returns the profile cmdline
rather than the fallback string.

gVisor variants declare no kernel. A missing kernel descriptor with a
missing kernel definition is valid. A definition that declares a kernel
with a null manifest descriptor fails closed.

This suite does not compile a kernel or boot it. Cmdline and config-option
policy are in-process. Live kernel boot is the live-boot evidence path.

## 6. Guest-Agent Injection and Protocol Metadata

The guest agent is a first-class artifact. Workspace builds resolve
`pico-guest-agent` from the cargo target directory. Prebuilt sources
pin a path and digest. The binary is copied to
`/usr/local/bin/pico-agent` mode `0755`.

The manifest records guest-agent digest, size, version, protocol version,
and capabilities. Protocol `supported` ranges and `capabilities` must
match the guest-agent descriptor. Empty digest, zero size, missing
version, missing protocol version, and definition/manifest version
mismatch all fail validation. `guest_agent_digest_in_manifest_matches_input`
pins that the descriptor digest is the digest of the injected bytes.

Host/guest handshake still compares `image_id` strings
(`pico-host-agent` `validate_identity_mismatch_rejects_wrong_image_id`).
ADR-0008 also wants readiness to report root bundle, variant, PicoCompute
manifest, and guest-agent digests. That digest exchange is a section 11
limitation.

## 7. Image Validation Tests

`validate_static` runs schema, artifact, digest, protocol, backend,
cmdline, mount, snapshot, filesystem, secret-scan, production-variant, and
platform checks in one report. Failures are typed per check and do not
stop later checks, so `multiple_failures_all_reported` sees at least three
failures from one malformed manifest.

`validate_supply_chain` runs after SBOM and provenance generation and
blocks `RootfsBuilder::build` when coverage or provenance consistency
fails.

Negative fixtures cover missing guest-agent, bad schema, bad kernel
config, secrets in the manifest JSON, credential-bearing cmdline, empty
snapshot exclusions, unknown backends, architecture mismatch, and
duplicate backend families. A valid fixture passes every static check.

## 8. SBOM, Signing, Provenance, and Host Verification

### SBOM and provenance

`generate_sbom` writes CycloneDX 1.5 JSON (`sbom.cdx.json`) covering
rootfs, guest-agent, optional kernel/initrd/firmware, and locked packages,
each with a SHA-256 hash. `validate_sbom` fails when a locked package is
missing. ADR-0008 names SPDX 3.0.1; the implemented document is CycloneDX
1.5. That format gap is recorded in section 11.

`generate_provenance` writes SLSA-style JSON binding the image id, builder
identity, source revision, definition digest, lock digest, base rootfs
digest, guest-agent digest, and manifest digest. ADR-0008 names SLSA v1.2
in-toto Statement v1. The implemented document is a PicoCompute JSON
attestation, not an in-toto statement. That format gap is recorded in
section 11.

### Signing

Ed25519 detached signatures live in `manifest.sig.json`. The bundle
records schema, image id, manifest digest, algorithm, public key,
signature, signer identity, and time. Tampered manifests, tampered
bundles, and the wrong verifying key fail `verify_manifest`. Build-time
signing is optional: no key means the build succeeds without a signature.

### Host verification

`verify_for_host` is the production verification hook. In production mode
it requires a signature, an approved verifying key, and matching digest
and size for every materialized artifact the host presents.

| Test | Proves |
|---|---|
| `production_accepts_signed_matching_artifacts` | A signed layout with matching bytes is admitted |
| `production_rejects_unsigned_image` | Missing signature yields `UnsignedImageRejected` |
| `production_rejects_missing_trusted_key` | Production mode requires a pinned verifying key |
| `production_rejects_unapproved_signer` | A valid signature from another key is rejected |
| `production_rejects_tampered_manifest` | A mutated manifest fails signature verification |
| `production_rejects_rootfs_digest_mismatch` | Rootfs bytes that do not match the descriptor fail |
| `production_rejects_guest_agent_size_mismatch` | Guest-agent bytes that do not match the descriptor fail |
| `production_rejects_missing_rootfs_path` | Production mode requires the materialized rootfs |
| `production_rejects_signature_image_id_mismatch` | Signature bundle image id must match the manifest |
| `non_production_allows_unsigned_when_digests_match` | Debug builds may omit a signature |
| `non_production_still_rejects_digest_mismatch` | Integrity checks still run off production mode |

A valid cryptographic signature from an unapproved identity is not
sufficient. That matches the ADR production verification policy.

`pico-host-agent` and `pico-runtime` still consume configured
kernel and rootfs paths and check that those files exist. They do not yet
call `verify_for_host` on the prepare path. The library hook is the
contract those callers must use before production cache or boot. Wiring is
a section 11 limitation.

## 9. Warm Snapshot Generation and Lineage

Warm snapshots are separate artifacts derived from an exact image
manifest. They are not embedded in the guest bundle.
`WarmSnapshotGenerator` boots via a `WarmSnapshotBackend`, captures
filesystem blobs, records source image id, rootfs digest, kernel version,
and guest-agent version, excludes `secret` mounts, computes integrity, and
runs restore validation before promotion.

| Test | Proves |
|---|---|
| `generate_disabled_returns_error` | A profile with warm snapshot off cannot generate |
| `generate_produces_output_with_valid_config` | An enabled profile produces promotion-ready metadata |
| `generate_fails_on_boot_error` | Guest boot failure fails closed |
| `generate_sets_backend_compatibility` | Metadata records backend and guest-agent version |
| `generate_excludes_secret_mounts` | Secret class is excluded; credential policy is production |
| `generate_integrity_record_is_populated` | Blake3 integrity over blobs is required |
| Compatibility mismatch tests | Image id, backend, kernel, or guest-agent drift fails restore |

`RootfsBuilder::build` does not call the generator. Warm snapshot remains
a post-build step that needs a backend implementation and a live guest.
Mock-backend tests cover the pipeline logic. Live Firecracker/QEMU capture
and restore are outside this run.

## 10. Backend Consumption

Firecracker and QEMU adapters attach a kernel image and an ext4 rootfs
from configured paths. gVisor attaches an OCI filesystem directory. Path
existence is checked before start. A missing kernel or rootfs fails
prepare.

The adapters do not parse the PicoCompute manifest, do not verify signatures,
and do not select a variant. That matches ADR-0008: adapters attach
already-selected artifacts. Production safety depends on the caller
running `verify_for_host` first.

Live boot-to-handshake evidence for Firecracker and QEMU lives in
`crates/pico-runtime/tests/live_boot.rs` and
`scripts/live-boot-evidence.sh`. Those tests are ignored by default and
are recorded in `docs/robustness/live-boot-evidence/`. This report does
not rerun them.

## 11. Open Limitations

| Limitation | Why it remains open |
|---|---|
| ADR-0008 is Proposed | Owner approval of the model is a separate review. This report does not accept the ADR. |
| No OCI index, variant manifests, or referrer graph | The pipeline writes a local file set. Registry distribution and OCI 1.1 referrers are not implemented. |
| SBOM is CycloneDX 1.5, not SPDX 3.0.1 | Implemented generator matches current consumers. SPDX conversion is follow-up. |
| Provenance is PicoCompute JSON, not SLSA v1.2 in-toto | Builder, source, and input digests are recorded. The in-toto statement envelope is follow-up. |
| No vulnerability or secret-scan referrer | Manifest JSON is scanned for credential patterns. A scanner identity, database revision, and policy result are not produced. |
| No signed promotion attestation | Stages `built`/`validated`/`candidate`/`production` are not issued as referrers. |
| Signing is optional at build time | Host verification enforces signatures in production mode. CI must supply `PICO_SIGNING_KEY` or a key file for production artifacts. |
| `verify_for_host` is not yet called from host-agent or runtime prepare | The hook and tests exist. Prepare still checks path existence. |
| Handshake compares `image_id`, not bundle/manifest/guest-agent digests | Protocol readiness covers identity mismatch. Digest exchange remains follow-up. |
| Live `mkfs.ext4` / `apk` / `tar` render is not in the default suite | Rendering requires those tools on Linux. This run does not claim a live rootfs was built. |
| Alpine base digest in `image.toml` is `sha256:unresolved` | Locked-mode production builds must pin a real base digest. |
| No gVisor OCI filesystem renderer | VM variants render ext4. gVisor still consumes a configured rootfs path. |
| Warm snapshot is not wired into `RootfsBuilder::build` | Generator, mock backend, and promotion checks exist. Live capture needs a VMM backend. |
| No independent rebuild evidence | Digest is recorded per build. A second isolated rebuild is not compared in CI. |
| Owner approval | Section 12. |

## 12. Approval

Promotion past Draft requires all four approvals. Until they are recorded,
G-08 stays short of `pass` and this report is evidence, not a rollout
decision.

| Owner | Scope | Decision | Date |
|---|---|---|---|
| Image Pipeline | Manifest schema, rootfs pipeline, SBOM, signing, provenance | Pending | |
| Runtime | Backend consumption, host verification wiring, kernel/init profiles | Pending | |
| Security | Supply-chain policy, unsigned rejection, residual risk RR-07 | Pending | |
| Architecture | ADR-0008 consistency, compatibility allowlist | Pending | |
