# Composable Environment Layers: Base plus Workspace plus Toolkit

**Status**: Implemented
**Refs**: DSec 4.2/5.1/8.3; ADR-0008; ARCHITECTURE.md 10
**Scope**: Image manifest plus host prepare/boot path. No on-demand fetching, no Fn/GPU.

## Model

One composition binds independently versioned layers:

```text
base (bottom, read-only, released)
  -> workspace (middle, read-only, released)
    -> toolkits (top, read-only, released, sorted by name)
      -> local writable upper (per-sandbox, never promoted)
```

Implementation: `crates/pico-image/src/layers.rs`.

- `EnvironmentLayer` carries `name`, `kind`, `digest` (`sha256:`), `size`,
  `media_type`, plus optional per-layer `sbom_digest`, `provenance_digest`,
  and `signature_digest`.
- `EnvironmentComposition` binds base, workspace, toolkits, and a
  `CompositionCompatibility` allowlist with one `composition_digest`.
- `PicoComputeGuestManifest.environment` is `Option<EnvironmentComposition>`.
  `None` preserves monolithic manifests. When present, the manifest signature
  covers the composition bytes, so `verify_for_host` plus
  `verify_environment_layers` is a signed composition check before boot.
- `VerifiedImage` returns `composition_digest` and
  `composition_audit_record` for placement/host audit on READY.

## Overlay stack at prepare/boot

`plan_overlay_stack` orders lowerdirs base bottom, workspace middle,
toolkits top (sorted by name for determinism), with one per-sandbox writable
upper:

- Released lowers mount read-only. Only the upper is writable.
- Never mutate released layers: any post-release edit changes bytes and fails
  the digest check, so hosts must keep all writes in the upper.
- Whiteout semantics preserved by never merging down: deletions stay as
  `.wh.*` files and opaque markers (`trusted.overlay.opaque`) in the upper.
  Collapse carries them into the squashed layer.
- The `lowerdir=` mount option lists the topmost lower first (overlayfs
  convention) while `lowerdirs` stays in stack order for audit.

## Rebuild and promotion semantics

- Toolkit bump fast path: `with_rebuilt_toolkit` replaces one toolkit by
  name, preserves base/workspace digests byte-identical, and recomputes only
  the composition digest. `plan_rebuild` reports `toolkit_only` with the
  changed layer name. This turns O(m*N)/O(k*N) monolithic rebuilds into O(k).
- Base or workspace change is the slow path: `plan_rebuild` sets
  `base_or_workspace_changed`, requiring full revalidation.
- Promotion is monotonic evidence over one digest
  (`Built` -> `Validated` -> `Candidate` -> `Production`). It never rebuilds
  or mutates layers. `CompositionPromotion::advance` rejects skips,
  regressions, and digest changes.
- Per-layer supply-chain gates: `layers_missing_supply_chain_evidence`
  reports layers missing SBOM/provenance/signature digests. Production
  compositions must return empty. Host verification additionally checks
  per-layer digest/size of materialized bytes.

## Composition compatibility

`verify_composition_compatibility` enforces the ADR-0008 allowlist plus
ADR-0004 backend gates:

- composition `image_id` matches manifest `image_id`
- composition and manifest architecture match the host
- backend family/arch is in both the composition and manifest allowlists
- protocol major is in the composition allowlist
- composition and manifest snapshot exclusions agree (must cover `secret`
  and `runtime_tmp` so restore/fork/warm-snapshot cannot diverge by layer)

Broadening compatibility requires recomposition plus revalidation, never a
host-time substitution. Scheduler placement (manifest) and host boot
(composition) cannot diverge.

## Layer-collapse and threshold policy

- `MAX_ENVIRONMENT_LAYERS = 16` total released layers. Above this,
  composition construction and overlay planning fail closed.
- `COLLAPSE_THRESHOLD_LAYERS = 8` total layers. At or above this,
  `plan_overlay_stack` sets `collapse_recommended` and `collapse_advice`
  returns a reason.
- Collapse policy: squash the least-recently-changed toolkits into one new
  versioned toolkit layer with fresh digest, SBOM, provenance, and signature.
  Carry whiteouts (`.wh.*` and `trusted.overlay.opaque`) into the squashed
  layer. Recompose and revalidate. Never edit a released layer in place.
- Adding a toolkit to a composition at the threshold should collapse first.
  Adding beyond the max must collapse first.

## Audit

`format_composition_audit_record` emits JSON with `image_id`,
`composition_digest`, `manifest_digest`, `profile_id`, `architecture`, and
ordered layer name/kind/digest. Placement and host persist this record on
READY so audits prove which exact layer set booted without re-reading the
manifest.

## Tests

- Unit: `crates/pico-image/src/layers.rs` (ordering, rebuild, overlay,
  collapse, promotion, duplicate rejection)
- Integration: `crates/pico-image/tests/composable_layers.rs` (12 tests:
  toolkit-only rebuild, signed boot with audit, tamper rejection, per-layer
  gates, whiteouts, compatibility drift, collapse/max, monolithic compat,
  static validation, monotonic promotion)
- Static validation: `environment layer composition` check in
  `validate_static` (monolithic manifests pass, layered manifests bind
  image/profile/arch/snapshot)
