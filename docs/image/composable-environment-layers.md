# Composable Environment Layers: Base plus Workspace plus Toolkit

**Status**: Implemented
**Refs**: DSec 4.2/5.1/8.3; ADR-0008; ARCHITECTURE.md 10
**Scope**: Image manifest plus host prepare/boot path. No on-demand fetching, no Fn/GPU.

## Model

One composition binds independently versioned layers:

```text
base (bottom, read-only, released)
  -> workspace (middle, read-only, released)
    -> toolkits (top, read-only, released, in declared precedence)
      -> local writable upper (per-sandbox, never promoted)
```

Implementation: `crates/pico-image/src/layers.rs`.

- `EnvironmentLayer` carries `name`, `order`, `kind`, `digest` (`sha256:`),
  `size`, `media_type`, plus the per-layer `sbom_digest`,
  `provenance_digest`, and `signature_digest` evidence digests.
- `EnvironmentComposition` binds base, workspace, toolkits, and a
  `CompositionCompatibility` allowlist with one `composition_digest`.
- `PicoComputeGuestManifest.environment` is `Option<EnvironmentComposition>`.
  `None` preserves monolithic manifests. When present, the manifest signature
  covers the composition bytes, so `verify_for_host` plus
  `verify_environment_layers` is a signed composition check before boot.
- `VerifiedImage` returns `composition_digest` and
  `composition_audit_record` for placement/host audit on READY.

## Overlay precedence is explicit

`EnvironmentLayer.order` is assigned from declaration order and validated
against the stored array position, so shadowing order is signed data rather
than a side effect of naming. Renaming a toolkit cannot change which layer
wins. `order` is included in the composition digest, so two orderings of the
same layer set produce different digests because the merged view differs.

`[[environment.layers]]` in the image definition declares layers in
precedence order, with `role = "base" | "workspace" | "toolkit"`. Exactly one
base and one workspace are required.

## What the composition digest binds

`compute_composition_digest` hashes, per layer: `name`, `order`, `digest`,
`size`, `media_type`, `sbom_digest`, `provenance_digest`, and
`signature_digest`, plus the full compatibility block.

This matters for revocation: promotion and revocation decisions are keyed on
`composition_digest`, so binding the evidence digests means a decision also
pins the evidence it reviewed. Re-generating a layer SBOM changes the
composition digest.

`version` is deliberately excluded. It is a human release label, so relabelling
a layer must not change its identity.

## Overlay stack at prepare/boot

`plan_overlay_stack` orders lowerdirs base bottom, workspace middle, then
toolkits in declared precedence, with one per-sandbox writable upper:

- Released lowers mount read-only. Only the upper is writable.
- Never mutate released layers: any post-release edit changes bytes and fails
  the digest check, so hosts must keep all writes in the upper.
- Whiteout semantics are preserved structurally. Overlayfs itself creates and
  consumes whiteouts (`0/0` character devices in the upper) and opaque
  directories (`trusted.overlay.opaque=y`). Because Pico never merges the upper
  down into a released lower, it needs no whiteout parser and cannot
  accidentally drop a deletion. `OVERLAYFS_OPAQUE_XATTR` /
  `OVERLAYFS_OPAQUE_VALUE` are the documented markers the collapse policy must
  preserve.
- The `lowerdir=` mount option lists the topmost lower first (kernel doc:
  "stacked beginning from the rightmost one and going left"), so
  `lowerdir_option` is reversed while `lowerdirs` stays in stack order for
  audit and verification.

### Layer name safety

Hosts derive mount paths from the layer name and join them with `:` into the
`lowerdir=` option, so `validate_layer_name` restricts names to
`[A-Za-z0-9._-]`, rejects `.` and `..`, and caps length at 128 bytes. Without
this, a name like `toolkit-a:/etc` would inject an extra lower layer and
`../../etc` would escape the layer store. `plan_overlay_stack` additionally
validates `layer_mount_dir` (absolute, normalized, no `:`) and keeps an
inline containment guard at the sink so the name check dominates the path
join.

## Rebuild and promotion semantics

- Toolkit bump fast path: `with_rebuilt_toolkit` replaces one toolkit by
  name, preserves base/workspace digests byte-identical, and recomputes only
  the composition digest. `plan_rebuild` reports `toolkit_only` with the
  changed layer name. This turns O(m*N)/O(k*N) monolithic rebuilds into O(k).
  Both operands are validated first, so a malformed or stale composition
  cannot select the fast path.
- Base or workspace change is the slow path: `plan_rebuild` sets
  `base_or_workspace_changed`, requiring full revalidation.
- Promotion is monotonic evidence over one digest
  (`Built` -> `Validated` -> `Candidate` -> `Production`). It never rebuilds
  or mutates layers. `CompositionPromotion::advance` rejects skips,
  regressions, and digest changes.
- Per-layer supply-chain gates are enforced, not advisory. Every layer must
  carry SBOM, provenance, and signature digests. Enforced at build time by
  `check_environment_supply_chain` in `validate_supply_chain` (which
  `RootfsBuilder::build` runs and which blocks signing when it fails) and at
  boot time by `verify_environment_supply_chain`.

## Composition compatibility

`verify_composition_compatibility` enforces the ADR-0008 allowlist plus
ADR-0004 backend gates, cross-checking every claim the composition and the
manifest both record:

- composition `image_id` matches manifest `image_id`
- composition and manifest architecture match the host
- composition `profile_id` matches manifest `profile_id`
- backend family/arch is in both the composition and manifest allowlists
- protocol major is in both the composition and manifest allowlists
- composition and manifest snapshot exclusions agree (must cover `secret`
  and `runtime_tmp` so restore/fork/warm-snapshot cannot diverge by layer)

Broadening compatibility requires recomposition plus revalidation, never a
host-time substitution. Scheduler placement (manifest) and host boot
(composition) cannot disagree.

## Reader compatibility

`PicoComputeGuestManifest.required_features` lists features a reader must
understand. A manifest carrying an environment declares
`ENVIRONMENT_LAYER_FEATURE` (`environment-layers-v1`).

This exists because serde ignores unknown keys: a reader predating the
`environment` field would otherwise parse a layered manifest, ignore the
composition, and silently boot `artifacts.rootfs` instead of the layer stack.
`unknown_required_features` runs in both `validate_manifest` and
`verify_for_host`, so such a reader refuses the manifest rather than
downgrading it. Limitation: a reader predating `required_features` itself
cannot be made to fail closed, since it has no field to inspect. That needs a
schema major bump, which ADR-0008 requires explicit reader support for.

## Layer-collapse and threshold policy

- `MAX_ENVIRONMENT_LAYERS = 16` total released layers. Above this,
  composition construction and overlay planning fail closed.
  `plan_overlay_stack` checks the count before full validation, so an
  over-cap composition reports the typed `ImageError::TooManyLayers` rather
  than the generic composition error.
- `COLLAPSE_THRESHOLD_LAYERS = 8` total layers. At or above this,
  `plan_overlay_stack` sets `collapse_recommended` and `collapse_advice`
  returns a reason.
- Collapse policy: squash the least-recently-changed toolkits into one new
  versioned toolkit layer with fresh digest, SBOM, provenance, and signature.
  Preserve any overlayfs opaque-directory markers and whiteouts from the
  upper. Recompose and revalidate. Never edit a released layer in place.
- Adding a toolkit to a composition at the threshold should collapse first.
  Adding beyond the max must collapse first.

## Build pipeline integration

`RootfsBuilder::build` attaches the composition when the definition declares
`[[environment.layers]]`, via
`manifest::attach_environment_from_definition`. The environment is attached
before evidence generation, so:

- the SBOM gains one component per layer (`build_layer_component`), carrying
  the layer content digest and its declared evidence digests;
- `validate_sbom` fails when a declared layer has no SBOM component;
- provenance records each layer material and the composition digest as build
  inputs (`generate_provenance` takes the composition);
- the manifest signature covers the composition bytes.

## Audit

`format_composition_audit_record` emits JSON with `image_id`,
`composition_digest`, `manifest_digest`, `profile_id`, `architecture`,
`layer_count`, and ordered layer name/order/kind/digest. Placement and host
persist this record on READY so audits prove which exact layer set booted
without re-reading the manifest.

## Host prepare/boot admission

`pico-host-agent` verifies images before it admits a sandbox. The gate lives in
`crates/pico-host-agent/src/image_verify.rs` and runs inside `prepare_sandbox`
before any host resource exists, so a rejected image leaves nothing to roll
back.

Image admission is host policy, so it lives in the host agent's own
configuration rather than the `sandboxd` environment the runtime adapters read
(`host-agent` and `sandboxd` are separate processes per ADR-0011):

| Setting | Env | Meaning |
|---|---|---|
| `image_verification.image_dir` | `PICO_IMAGE_DIR` | Bundle directory: `manifest.json`, optional `manifest.sig.json`, artifact files, `<layer>.erofs` per layer |
| `image_verification.trusted_signing_key` | `PICO_IMAGE_TRUSTED_SIGNING_KEY` | Base64 Ed25519 public key pinning the approved signer |
| `image_verification.mode` | `PICO_IMAGE_VERIFICATION_MODE` | `production` or `development`; unknown values fail closed toward `production` |

`production` mode without a pinned key refuses to start. A host with no
`image_dir` configured performs no verification at all, which keeps existing
deployments working but means such a host boots whatever its adapter was
pointed at; operators must set `image_dir` for admission to mean anything.

On success the host records a `VerifiedImageRecord` (manifest digest, signer
identity, composition digest, layer count, composition audit record) on the
sandbox entry and emits it on the READY transition, so a placement or host
audit can answer "which layer set booted" without re-reading the manifest. A
rehydrated entry after a host restart carries no verification record, because
this process did not run the check.

### Backend layer support gate

A manifest may carry an environment composition, but booting it requires the
backend to actually present a merged layer stack. The host therefore requires
`BackendCapability::EnvironmentLayers` and refuses a layered manifest on a
backend that does not declare it, rather than silently booting the monolithic
`artifacts.rootfs`.

**No adapter declares this capability today**, and the host gate is what makes
that safe. See the open limitation below.

## Open limitation: no merged rootfs view yet

Overlaying layers inside a guest needs backend support that does not exist
today. Concretely, from a survey of the current code:

- **No guest-side mounting exists at all.** The `MountWorkspace` RPC handler in
  `crates/pico-guest-agent/src/mount.rs` validates its arguments and returns
  `Mounted(true)` without a single syscall. `/etc/pico/mount-contract.json` is
  written at build time and read by nothing. The only real `mount(2)` in the
  workspace is the secrets tmpfs.
- **`/init` mounts only proc, devtmpfs, and sysfs.** The four canonical mount
  directories are plain directories on the writable root ext4 image.
- **Neither backend exposes a shared-filesystem device.** Firecracker is
  virtio-blk only, with a single drive hardcoded as `is_root_device: true`; it
  has no virtio-fs endpoint in its API at all. QEMU emits one raw `-drive`,
  with no `-fsdev`, 9p, or virtiofs.
- **The guest kernel profiles compile none of the required drivers.** No
  `CONFIG_OVERLAY_FS`, `CONFIG_EROFS_FS`, or `CONFIG_SQUASHFS` appears in any
  of the four profiles in `crates/pico-image/src/kernel.rs`.
- **The guest seccomp profile does not allow `mount` or `umount2`.** The four
  host-side runtime profiles do.
- **The rootfs is mounted `rw`**, so ADR-0008's "the VM rootfs is immutable at
  runtime" invariant is not enforced by anything today.

Closing this needs a separate change touching kernel profiles, the seccomp
profile, per-sandbox kernel parameters, and at least one backend device
surface, plus a live-boot test to prove the guest actually sees the stack.
None of that is reachable from the image manifest, and none of it is covered
here. What this module does provide is the capability gate that makes the gap
safe: until a backend declares `EnvironmentLayers`, a layered manifest cannot
boot at all.

## Tests

- Unit (`layers.rs`): precedence preservation, order/digest binding, evidence
  binding, version exclusion, overlay planning, collapse advice, promotion
  monotonicity, duplicate rejection.
- Integration (`tests/composable_layers.rs`): toolkit-only rebuild, signed
  boot with audit, tamper rejection, per-layer gates, compatibility drift
  (backend/arch/protocol/profile/snapshot), required-feature rejection, name
  and layer-store-dir safety, collapse/max, monolithic compatibility, static
  validation, monotonic promotion.
- Pipeline (`tests/pipeline.rs`): `[[environment.layers]]` parsing, absent
  section, and fail-closed base/workspace arity.
- Static validation: `environment layer composition` and
  `security posture: no secrets in environment layers` in `validate_static`;
  `per-layer supply-chain evidence` in `validate_supply_chain`.

### Secret scanning

The whole-manifest secret scan excludes the `environment` block, because its
pattern list is deliberately broad and a legitimate layer name such as
`toolkit-tokenizer` would otherwise fail with a misleading error. Layer
`name` and `media_type` get a narrower assignment-shaped scan in
`check_environment_no_secrets` against the module-level
`LAYER_SECRET_PATTERNS` table (lowercase, compared without allocating).

`is_assignment_shaped` accepts a match when an explicit assignment follows the
keyword (`token=`, `api_key:`) or when the keyword stands alone at a field
boundary, and rejects a keyword embedded in a longer identifier. A pattern
that already ends in a separator, such as `bearer `, skips the
trailing-character check because the character after it begins the value
rather than a longer identifier.

Note that `name` is charset-restricted to `[A-Za-z0-9._-]`, so the
assignment branch is unreachable for `name` and only the bare-keyword branch
applies there; `media_type` is the free-text field where assignment-shaped
matches are actually reachable. The `name` scan is defense in depth against a
future relaxation of the charset rule.
