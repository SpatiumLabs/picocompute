# ADR-0008: Guest Image Format and Build Pipeline

**Status**: Proposed
**Date**: 2026-06-11
**Milestone**: M0 - Image Format ADR
**Depends on**:
[ADR-0003](0003-host-guest-agent-protocol-contract.md),
[ADR-0004](0004-default-isolation-backend-strategy.md),
[ADR-0006](0006-production-security-posture-for-sandbox-isolation.md),
[ADR-0007](0007-snapshot-resume-fork-consistency-model.md)

## Context

PicoCompute needs one guest image contract that can supply Firecracker, gVisor,
QEMU, and future approved backends without allowing each runtime adapter to
invent its own packaging, compatibility, or verification rules.

The guest image is a trusted platform artifact that contains or identifies:

- the immutable root filesystem
- the guest kernel and optional initrd
- optional firmware required by a backend profile
- the guest agent and its host/guest protocol support
- the mount and persistence contract
- scheduler and runtime compatibility metadata
- software bill of materials, build provenance, vulnerability results,
  signatures, and promotion evidence

The selected backends do not consume the same native artifact shape.
Firecracker requires an uncompressed Linux kernel and an ext4 root
filesystem. QEMU can use the same class of artifacts but may additionally
require firmware or a different disk representation. gVisor consumes an OCI
filesystem and runtime configuration rather than a guest kernel.

Treating those outputs as unrelated images would allow their package sets,
guest-agent builds, security evidence, and release status to drift. Composing
independently promoted rootfs, kernel, init, and guest-agent artifacts at boot
would move release engineering and compatibility decisions into the
scheduler or host runtime. A single opaque VM archive would keep components
together but would lose standard content-addressed distribution, deduplication,
and attachment of supply-chain evidence.

[ADR-0003](0003-host-guest-agent-protocol-contract.md) requires the host to
validate the image and guest-agent identity during readiness negotiation.
[ADR-0004](0004-default-isolation-backend-strategy.md) requires image,
kernel, architecture, backend, and protocol compatibility before backend
selection.
[ADR-0006](0006-production-security-posture-for-sandbox-isolation.md)
requires signed provenance, an SBOM, vulnerability results, immutable
distribution, and admission verification.
[ADR-0007](0007-snapshot-resume-fork-consistency-model.md) binds restore
compatibility to exact image and runtime artifacts and prohibits
cross-backend restore.

This ADR defines the artifact and release contract those systems consume. It
does not select the rootfs distribution, kernel configuration, build
orchestrator, OCI registry product, signing key service, vulnerability
scanner, or concrete Rust types.

## Decision

PicoCompute adopts a **signed, content-addressed PicoCompute Guest Image Bundle
distributed as an OCI image layout and OCI registry graph**.

The canonical identity is the digest of a root OCI image index. The index
references all released architecture and backend variants. A scheduler or
runtime always resolves and records the root bundle digest plus the selected
variant digest. Tags are discovery aliases only and are never production
identity or authorization.

Each variant carries one PicoCompute JSON manifest and immutable descriptors for
the artifacts needed by that variant. VM variants contain backend-ready
kernel, rootfs, initrd, and optional firmware blobs. gVisor variants reference
a standards-compliant OCI filesystem image. All rootfs renderings originate
from the same normalized filesystem tree and the same guest-agent artifact.

SBOMs, provenance, vulnerability results, signatures, validation reports, and
promotion attestations are attached to the root bundle digest through OCI
1.1 referrers. Promotion never rebuilds or mutates a bundle. It adds signed
evidence to the existing digest.

### Canonical OCI Graph

The canonical graph has these nodes:

| Node | Purpose | Identity |
|---|---|---|
| Root image index | Enumerates every released architecture and backend variant | Root bundle digest and canonical `image_id` |
| PicoCompute variant manifest | Groups one bootable or runnable backend profile | Variant manifest digest |
| PicoCompute JSON manifest | Defines component descriptors and compatibility policy | Content digest referenced as the variant config |
| Rootfs artifact | Ext4 image for VM profiles or OCI image manifest for gVisor | Content or manifest digest |
| Boot artifacts | Kernel, optional initrd, and optional firmware | Individual content digests |
| Guest-agent artifact | Exact executable injected into or referenced by the rootfs build | Content digest |
| Referrer artifacts | SBOM, provenance, vulnerability, validation, signature, and promotion evidence | Referrer manifest and payload digests |
| Warm snapshot artifact | Optional backend-bound warm state derived from the bundle | Separate signed artifact digest |

The root index is the release unit. A release may contain multiple
architectures and backend profiles, but every child descriptor must represent
the same logical package set, guest-agent source revision, mount contract, and
release policy unless the manifest explicitly records a profile-specific
difference.

Registry reachability never depends on parsing the custom PicoCompute JSON. Every
artifact descriptor named by the PicoCompute manifest must also be reachable
through standard OCI index or manifest descriptors. The PicoCompute manifest
provides typed meaning and policy, while the OCI graph provides distribution,
retention, and digest traversal. Validation rejects a missing, extra, or
mismatched descriptor between those views.

Root index descriptors include OCI platform fields and PicoCompute annotations
for:

- variant kind
- backend family
- architecture
- compatibility profile ID
- PicoCompute manifest media type and schema major

Clients must ignore unknown optional annotations. They must not use
annotations as authority when the signed PicoCompute manifest provides the
equivalent field.

### Variant Shapes

The initial variant shapes are:

| Backend profile | Required artifacts | Rootfs form |
|---|---|---|
| Firecracker | PicoCompute manifest, uncompressed kernel, ext4 rootfs, optional initrd | Deterministic ext4 image |
| QEMU | PicoCompute manifest, kernel, ext4 rootfs or an explicitly declared QEMU disk form, optional initrd and firmware | Deterministic ext4 by default |
| gVisor | PicoCompute manifest and OCI image manifest with config and filesystem layers | OCI image filesystem |
| Evaluation backend | Only artifacts explicitly approved by a later ADR and conformance profile | Must derive from the normalized filesystem tree |

The rootfs pipeline first produces a normalized filesystem tree. Backend
renderers consume that tree:

- the VM renderer creates a deterministic ext4 filesystem with fixed
  ownership, ordering, timestamps, filesystem features, labels, and UUID
  policy
- the OCI renderer creates deterministic OCI layers and config
- both renderers include the same intended package inventory, guest-agent
  digest, init behavior, non-secret configuration, and mount points

Byte identity is not required between different renderings. Semantic
equivalence is required and is checked through package inventory,
guest-agent identity, filesystem policy, mount contract, and backend
conformance tests.

The VM rootfs is immutable at runtime. A writable per-sandbox overlay or
separate writable drive is attached according to the mount contract. The
gVisor filesystem is also consumed by digest and receives writable mounts or
an overlay from the runtime. No backend mutates the released base artifact.

### PicoCompute Manifest

The PicoCompute manifest is UTF-8 JSON with media type
`application/vnd.pico.guest.manifest.v1+json`. JSON is selected because it
has broad tooling support, deterministic canonicalization options, and direct
compatibility with OCI descriptors and policy engines.

The manifest has these required top-level fields:

```json
{
  "schema_version": "1.0",
  "image_id": "pico-guest-standard",
  "release": {
    "version": "2026.06.0",
    "source_revision": "git-sha",
    "build_epoch": 1781170000
  },
  "platform": {
    "os": "linux",
    "architecture": "x86_64"
  },
  "artifacts": {
    "rootfs": {
      "format": "ext4",
      "media_type": "application/vnd.pico.rootfs.ext4",
      "digest": "sha256:...",
      "size": 0
    },
    "kernel": {
      "format": "linux-vmlinux",
      "media_type": "application/vnd.pico.kernel.vmlinux",
      "digest": "sha256:...",
      "size": 0,
      "version": "..."
    },
    "initrd": null,
    "firmware": null,
    "guest_agent": {
      "media_type": "application/vnd.pico.guest-agent",
      "digest": "sha256:...",
      "size": 0,
      "version": "..."
    }
  },
  "protocol": {
    "bootstrap": "pico.guest.bootstrap.v1",
    "supported": [
      {
        "major": 1,
        "min_minor": 0,
        "max_minor": 0
      }
    ],
    "capabilities":
  },
  "compatibility": {
    "profile_id": "firecracker-x86_64-v1",
    "backends":
    "required_cpu_features":
    "required_devices":
    "required_host_features":
  },
  "mount_contract": {
    "version": "1.0",
    "mounts":
  },
  "snapshot": {
    "filesystem": true,
    "memory": false,
    "excluded_mount_classes": [
      "secret",
      "runtime_tmp"
    ]
  }
}
```

Descriptors use OCI digest syntax and include media type, digest, and byte
size. A field that is not applicable is `null`; it is not replaced with a
sentinel path or empty digest.

The schema implemented by
 must additionally define:

- artifact format and compression
- immutable guest-agent installation path and execution identity
- kernel command-line policy and init entry point
- package inventory digest
- filesystem feature and read-only policy
- backend family and tested runtime version set
- machine type, device model, firmware, and boot method where applicable
- CPU vendor, template, and feature requirements where applicable
- required host kernel, KVM, filesystem, and runtime capabilities
- supported workload and conformance profile IDs
- protocol version ranges and required capabilities
- mount path, class, ownership, mode, persistence, and snapshot behavior
- declared unsupported features
- warm snapshot eligibility

The manifest never contains:

- credentials, authentication material, private keys, or bearer tokens
- mutable tags as component identity
- host-local paths
- tenant-specific policy
- an unbounded compatibility claim such as `latest`, `any`, or a minimum
  version without tested upper bounds
- embedded signatures that would make signing change the manifest digest

### Schema and Compatibility Versioning

`schema_version` uses `major.minor`.

- A minor schema revision is additive. Existing fields keep their meaning,
  required fields are not added for old readers, and unknown optional fields
  may be ignored.
- A major schema revision may change required fields or semantics and requires
  explicit reader support.
- A reader rejects an unknown major.
- A reader rejects an unknown field or value marked as required by the
  manifest's feature requirements.
- Field removal reserves the old name and meaning. A removed field is not
  reused for another purpose.

The bundle digest is the immutable release identity. Human release versions
are labels for operators and audit records. Reusing a release version for a
different bundle digest is prohibited.

Compatibility is an allowlist of tested profiles, not a prediction based on
semantic versions. Each backend entry records:

- backend family
- exact runtime version or explicitly tested bounded version set
- architecture
- machine and device profile
- rootfs and boot artifact requirements
- protocol range and required capabilities
- host kernel and CPU requirements
- conformance profile and validation report digest
- snapshot support and compatibility limits

Adding a newly tested backend or runtime version requires a new bundle
because it changes signed compatibility metadata. A promotion attestation may
advance an existing bundle through release stages, but it cannot broaden the
bundle's compatibility claim.

### Kernel, Init, and Guest-Agent Compatibility

The kernel, initrd, init configuration, rootfs, and guest agent form one
tested variant. The scheduler and runtime do not replace one component with a
newer compatible-looking artifact.

Compatibility follows these rules:

- the kernel and init path must boot the selected rootfs with the declared
  machine and device profile
- the guest agent digest in the manifest must match the binary measured in
  the normalized filesystem tree and the backend rendering
- protocol compatibility is determined by the ranges and capabilities
  required by ADR-0003, not by guest-agent release version alone
- a host must support the selected backend profile and every declared host
  feature before it downloads or boots the variant
- readiness must report the expected root bundle digest, variant digest,
  PicoCompute manifest digest, guest-agent digest, and protocol capabilities
- any identity or capability mismatch fails readiness and quarantines the
  local materialization

The scheduler may use verified manifest metadata to select eligible backend
and host profiles. The host independently verifies the same compatibility
contract before boot. A scheduler decision never waives host verification.

### Mount Contract

The manifest records the mount contract defined by
. Each mount entry includes:

- stable mount class and guest path
- expected filesystem or transport type
- ownership and mode
- read-only or writable behavior
- persistent, ephemeral, or secret lifetime
- snapshot inclusion or exclusion
- required or optional presence

The initial classes are:

| Class | Default path | Persistence | Snapshot behavior |
|---|---|---|---|
| Base rootfs | `/` | Immutable release artifact | Referenced by bundle digest |
| Workspace | `/workspace` | Per-sandbox persistent or copy-on-write state | Included according to snapshot profile |
| Runtime temporary | `/run/pico/tmp` | Per-boot ephemeral state | Excluded |
| Secret | `/run/pico/secrets` | Revocable non-persistent state | Excluded and proven absent |
| Guest logs | `/var/log/pico` | Policy-dependent | Explicitly declared |

Unknown required mount classes make the image incompatible. Runtime adapters
must not guess paths or silently omit required mounts.

### Build Pipeline

The canonical pipeline has these ordered phases:

1. **Resolve inputs**: Pin source revision, package repositories, packages,
   toolchains, base filesystem inputs, kernel source and configuration,
   guest-agent source, and build containers by digest.
2. **Build components**: Build the guest agent, kernel, init path, and other
   components in isolated builders with no production credentials.
3. **Normalize rootfs**: Install the pinned package set and guest agent, then
   normalize ownership, permissions, timestamps, ordering, caches, machine
   identity, logs, random seeds, and other nondeterministic state.
4. **Render variants**: Produce deterministic ext4 and OCI forms from the
   normalized tree and package required boot artifacts.
5. **Assemble bundle**: Generate PicoCompute manifests, variant manifests, and the
   root OCI index using content digests.
6. **Generate evidence**: Produce SBOM, SLSA provenance, vulnerability
   results, secret-scan results, and reproducibility evidence.
7. **Validate**: Run static, supply-chain, backend boot, readiness, and
   compatibility gates against the immutable bundle digest.
8. **Publish and promote**: Sign the bundle and add signed validation and
   promotion attestations without rebuilding it.

Builds use a fixed locale, timezone, umask, source date epoch, file ordering,
numeric ownership, and deterministic archive and filesystem options.
Generated machine IDs, SSH host keys, random seeds, boot secrets, network
identity, and tenant data are absent from the image.

Every declared output has a digest before the root index is assembled. The
build does not fetch unpinned inputs after digest calculation begins.
Reproducibility is evaluated on the rootfs tree, rendered artifacts, PicoCompute
manifest, variant manifests, and root index. A mismatch is a failed build
unless an approved, documented exception identifies the nondeterministic
field and a deterministic verification method.

### Supply-Chain Evidence

The root bundle has these required OCI referrers:

| Evidence | Required content |
|---|---|
| SPDX SBOM | SPDX 3.0.1 package, file, relationship, license, and checksum data for the released bundle |
| SLSA provenance | SLSA v1.2 build provenance in an in-toto Statement v1 binding all outputs to source, builder, invocation, and materials |
| Vulnerability result | Scanner identity and database revision, scan time, findings, severity, exploitability data when available, policy result, and approved exceptions |
| Secret-scan result | Scanner identity, ruleset revision, scanned subjects, and pass or reject outcome |
| Validation report | Schema, digest, filesystem, backend boot, protocol, mount, security, and conformance results |
| Signature | Signature over the root bundle digest using an approved PicoCompute image signing identity |
| Promotion attestation | Stage, bundle digest, policy revision, evidence digests, approver identity, decision time, and expiry or review time |

Evidence payloads use immutable subjects and are themselves addressed by
digest. The in-toto subject list covers the root index, variant manifests,
PicoCompute manifests, rootfs outputs, kernel, initrd, firmware, and guest-agent
artifacts produced by the build.

The production policy accepts only approved signing identities and trust
roots. Keyless signing, managed keys, or an offline release key may be used,
but identity, issuer, workflow, repository, and environment constraints are
verified explicitly. A valid cryptographic signature from an unapproved
identity is not sufficient.

The registry must support the OCI Distribution Specification 1.1 referrers
API or the specified referrers tag fallback. PicoCompute clients verify the
subject digest in every referrer and never accept evidence merely because it
shares a repository or tag prefix.

### Validation Gates

A bundle is validated only when all applicable gates pass:

1. **Graph and schema**: OCI graph traversal, media types, descriptor sizes,
   digests, PicoCompute schema, required fields, and absence of unknown required
   features.
2. **Artifact integrity**: Every descriptor resolves to bytes matching its
   digest and declared size; no mutable external reference is required.
3. **Reproducibility**: Independent or isolated rebuild evidence satisfies
   the current release policy.
4. **Filesystem policy**: Expected ownership and modes, no secrets or host
   identity, no undeclared setuid or setgid files, no prohibited devices,
   and package inventory matches the SBOM.
5. **Kernel and init policy**: Approved configuration, command line, init
   entry point, module policy, architecture, and required device support.
6. **Guest-agent policy**: Expected digest, installation path, execution
   identity, bootstrap service, protocol ranges, and required capabilities.
7. **Mount policy**: Required mount classes, paths, permissions,
   persistence, and snapshot exclusions are complete and non-conflicting.
8. **Backend boot**: Each declared backend profile boots the exact variant
   and reaches the authenticated ADR-0003 handshake within its test budget.
9. **Compatibility**: Host, backend, protocol, CPU, device, and snapshot
   claims are covered by current conformance evidence.
10. **Supply chain**: Provenance, SBOM, vulnerability, secret scan,
    signatures, and policy decisions are present, current, and valid.

A profile-specific test may be omitted only when the variant does not claim
that profile. Unsupported behavior is declared rather than silently skipped.

Rejection reasons are typed and identify at least:

- invalid OCI graph or schema
- missing or mismatched artifact
- non-reproducible output
- prohibited filesystem content
- kernel or init policy failure
- guest-agent identity or protocol failure
- mount contract failure
- backend boot or readiness failure
- unsupported or untested compatibility claim
- missing, invalid, stale, or untrusted supply-chain evidence
- vulnerability policy failure
- promotion policy failure

Failed bundles remain addressable for investigation but cannot be promoted,
cached as production-ready, or scheduled.

### Promotion Flow

PicoCompute uses four promotion stages:

| Stage | Meaning | Required evidence |
|---|---|---|
| `built` | Immutable bundle graph exists | Build provenance, initial SBOM, secret scan, artifact digests, and builder signature |
| `validated` | Required static and backend tests pass | Validation report, reproducibility result, vulnerability result, and conformance evidence |
| `candidate` | Release owners accept the exact bundle for pre-production rollout | Signed candidate attestation referencing all required evidence and approved exceptions |
| `production` | The bundle is eligible for production policy and rollout | Signed production attestation with Runtime, Security, and Build/Release approval |

Promotion is monotonic evidence for one digest. It does not copy mutable files
between stage-specific repositories, rewrite manifests, change annotations,
or rebuild artifacts. Registries may replicate the same digest between
repositories or regions, but replication must preserve bytes and referrer
relationships.

Stage tags such as `candidate` or `production` may aid discovery. Hosts and
schedulers resolve them to a digest before policy evaluation and persist only
the digest. Moving or deleting a tag does not promote, revoke, or change an
already identified bundle.

A bundle is rejected or removed from production eligibility when:

- required evidence is missing, invalid, expired, revoked, or no longer
  trusted
- a vulnerability or incident policy revokes the bundle
- a component digest or registry payload fails integrity verification
- compatibility or conformance evidence is withdrawn
- the production attestation is revoked or superseded by a deny decision

Revocation is signed policy evidence distributed independently of mutable
tags. Cached copies remain unusable after their verification evidence becomes
revoked or stale.

### Production Verification Policy

The scheduler verifies enough trusted metadata to determine eligibility and
records the root bundle digest, selected variant digest, compatibility profile,
and evidence revision in the placement decision.

Before caching or booting a production image, the host verifies in this
order:

1. The requested root bundle digest matches the scheduled digest.
2. The root index and selected variant form a valid OCI graph.
3. The root signature chains to an approved PicoCompute image signing identity.
4. A valid, unrevoked `production` attestation targets the root digest.
5. The promotion attestation references accepted provenance, SBOM,
   vulnerability, secret-scan, validation, and conformance evidence.
6. Provenance identifies an approved source repository, revision, builder,
   workflow, build definition, and digest-pinned materials.
7. Vulnerability findings and exceptions satisfy the current host policy.
8. The selected variant and every component match their descriptor digests
   and sizes.
9. The host, backend, architecture, CPU, machine, device, protocol, mount, and
   snapshot requirements match the scheduled profile and local capabilities.
10. The materialized rootfs and guest agent match the expected identities
    before guest execution is admitted.

Verification fails closed. Network or registry failure does not permit use of
an unverified cache entry. A cache entry may be reused only while its digest,
evidence, revocation status, and policy freshness satisfy the configured
offline window. The window is bounded and disabled for evidence classes that
must be checked online by policy.

After boot, the ADR-0003 readiness exchange confirms:

- sandbox and boot identity
- root bundle, variant, and PicoCompute manifest digests
- guest-agent artifact digest
- selected protocol version and capability set

A mismatch prevents the sandbox from becoming `Running`.

### Warm Image and Snapshot Integration

Warm snapshots are not embedded in or substituted for the canonical guest
bundle. They are separate signed OCI artifacts derived from an exact root
bundle and variant digest.

A warm snapshot manifest records:

- source root bundle, variant, PicoCompute manifest, rootfs, kernel, initrd,
  firmware, and guest-agent digests
- backend family and exact runtime compatibility policy
- architecture, CPU template and required features
- machine and device model
- snapshot format version and state profile
- initialization recipe and quiesce evidence
- excluded mount and secret-absence evidence
- validation, provenance, SBOM, vulnerability, signature, and promotion
  references

Warm snapshots are backend-bound and cannot add backend compatibility to the
source bundle. Cross-backend restore is prohibited. A new source bundle
digest, runtime-incompatible backend version, CPU or device change, protocol
change, revoked source evidence, or changed exclusion contract invalidates
the warm artifact for restore.

Base warm snapshots contain no tenant state, active exec, credential, access
lease, protocol session, boot secret, or live network authority. Restore
creates fresh sandbox, boot, protocol, network, policy, and credential
identity as required by ADR-0007.

### Ownership and Enforcement Boundaries

| Concern | Authority |
|---|---|
| Manifest schema and compatibility semantics | Guest Image Pipeline maintainers with Runtime and Security review |
| Source and component build definitions | Build/Release owners |
| Backend profile requirements | Runtime owners and backend conformance |
| Protocol ranges and capabilities | ADR-0003 schema and guest-protocol owners |
| Mount classes and snapshot behavior | contract with Storage and Security review |
| Supply-chain and vulnerability policy | Security and Build/Release owners |
| Promotion decision | Release policy with required Runtime, Security, and Build/Release approval |
| Placement eligibility | Control plane using verified manifest and policy evidence |
| Final artifact and compatibility verification | Host agent before cache use and boot |
| Warm snapshot capture and restore | Snapshot pipeline under ADR-0007 |

Runtime adapters receive an already selected and verified variant. They
materialize and attach the declared artifacts but do not choose components,
broaden compatibility, waive verification, or promote images.

## Consequences

### Positive

- One digest identifies the complete released guest image across backends and
  architectures.
- OCI distribution provides standard content addressing, deduplication,
  replication, and evidence attachment.
- Firecracker, QEMU, and gVisor receive native artifact forms derived from one
  normalized filesystem source.
- Scheduler and host compatibility checks use signed, bounded, test-backed
  metadata.
- Kernel, init, rootfs, and guest-agent drift cannot occur through host-time
  composition.
- Promotion is auditable and cannot change the tested bytes.
- Production verification is fail-closed and repeated at the host boundary.
- Warm snapshots remain explicit derivative artifacts with strict source and
  backend binding.

### Negative

- The pipeline must build, validate, distribute, and retain several
  backend-specific renderings.
- Adding compatibility requires a new signed bundle even when component bytes
  do not change.
- OCI registry referrer support and replication behavior become operational
  requirements.
- Reproducible ext4, kernel, and OCI outputs require strict toolchain and
  filesystem controls.
- Production admission performs more metadata and signature verification
  before boot.
- A bundle can be blocked by stale vulnerability, conformance, promotion, or
  revocation evidence even when its bytes are locally cached.

## Rejected Alternatives

### Monolithic VM Archive

Each release would publish one archive containing a rootfs, kernel, manifest,
guest agent, signatures, and optional snapshot files.

**Rejected**: An opaque archive duplicates shared components, is awkward for
gVisor, weakens standard registry distribution and referrer support, and
requires downloading or unpacking the archive to inspect individual
artifacts. OCI provides the same release-unit integrity with content
addressing and standard graph traversal.

### OCI Rootfs Only with Backend Wrapping

The canonical artifact would be an OCI container image. Runtime-specific
pipelines or hosts would convert it to ext4, choose a kernel and init path,
and wrap it for Firecracker or QEMU.

**Rejected**: The production boot bytes would not be the promoted and tested
artifact. Kernel, init, filesystem rendering, and guest-agent compatibility
would depend on the wrapping environment, and host-time conversion would make
reproducibility and provenance harder to verify.

The selected design still uses an OCI filesystem for gVisor and derives all
rootfs forms from one normalized tree, but it promotes the resulting backend
variants together.

### Independently Promoted Components Composed at Runtime

Rootfs, kernel, initrd, firmware, and guest agent would each have independent
release channels. The scheduler or host would select a supposedly compatible
set at boot.

**Rejected**: Compatibility becomes a dynamic solver and creates combinations
that were not built or tested together. Independent promotion also permits
rollback and revocation states that are difficult to reason about. PicoCompute
promotes a complete tested bundle and forbids component substitution.

### Mutable Stage Repositories

Build, validation, candidate, and production stages would copy or rewrite
artifacts into separate repositories.

**Rejected**: Copy and rewrite flows can change manifests, lose referrers, or
produce different digests after validation. Stages are signed attestations
over one immutable digest. Replication may move identical bytes but cannot
change identity.

### Embedded Supply-Chain Evidence

The PicoCompute manifest would include its own signature, SBOM, provenance, and
promotion state.

**Rejected**: Signing or promoting would change the manifest and bundle
digest, creating a recursive identity problem and preventing independent
evidence refresh. OCI referrers bind replaceable evidence to an immutable
subject digest without modifying the subject.

## Follow-Up Implementation Issues

| Issue | Relationship to this ADR |
|---|---|
| | Build the pinned, reproducible normalized rootfs pipeline and deterministic backend renderers |
| | Define the versioned mount contract, paths, permissions, persistence, and snapshot behavior |
| | Build and package the approved kernel, init, initrd, firmware, and boot profiles |
| | Inject and verify the exact guest-agent artifact in every rootfs rendering |
| | Define the JSON schema and implement graph, artifact, boot, readiness, mount, and compatibility validation |
| | Generate SPDX, SLSA/in-toto, vulnerability, signature, revocation, and promotion evidence |
| | Generate separately signed, backend-bound warm snapshots referencing exact bundle and variant digests |

## References

- [OCI Image Layout Specification](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
- [OCI Image Manifest Specification](https://github.com/opencontainers/image-spec/blob/main/manifest.md)
- [OCI Image Index Specification](https://github.com/opencontainers/image-spec/blob/main/image-index.md)
- [OCI Distribution Specification and Referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [SLSA v1.2 provenance](https://slsa.dev/spec/v1.2/provenance)
- [in-toto Statement v1](https://in-toto.io/Statement/v1)
- [SPDX 3.0.1 specification](https://spdx.github.io/spdx-spec/v3.0.1)
- [Sigstore signature verification](https://docs.sigstore.dev/cosign/verifying/verify)
- [Firecracker guest image requirements](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
- [Firecracker snapshot support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)
- [gVisor containerd integration](https://gvisor.dev/docs/user_guide/containerd/quick_start)

## Required Review

The ADR remains `Proposed` until the artifact,
compatibility, verification, and promotion contract is approved:

- Runtime owner
- Security owner
- Build/Release owner
