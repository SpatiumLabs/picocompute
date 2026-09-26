# ADR-0010: eBPF Tooling Strategy

**Status**: Proposed
**Date**: 2026-07-10
**Milestone**: M0 - eBPF Integration
**Depends on**:
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md),
[ADR-0005](0005-per-sandbox-networking-model.md),
[ADR-0006](0006-production-security-posture-for-sandbox-isolation.md),
[ADR-0008](0008-guest-image-format-and-build-pipeline.md)

## Context

PicoCompute's `network-agent` owns per-sandbox namespaces, veth/TAP devices,
routes, and nftables policy
([ADR-0005](0005-per-sandbox-networking-model.md),
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md)). Host-side eBPF is
the next enforcement and observation surface for traffic on those interfaces:
TC classifiers, optional future LSM hooks, timers, and specialized maps.

Before shipping production programs, PicoCompute must choose:

1. **Framework**: a pure-Rust stack (**aya**) versus C programs with a Rust
   loader (**libbpf-rs**).
2. **Kernel and privilege floor**: minimum host kernel, BTF, and Linux
   capabilities for load and attach.
3. **Artifact pipeline**: how compiled `.o` objects are built, signed,
   distributed, and verified, aligned with the guest-image trust model in
   [ADR-0008](0008-guest-image-format-and-build-pipeline.md).

The evaluation compared both frameworks on a shared TC classifier shape
(IPv4 destination blocklist on a veth `clsact` qdisc): program type
`BPF_PROG_TYPE_SCHED_CLS`, hash map policy, `TC_ACT_SHOT` `TC_ACT_PIPE`.

This ADR records the decision. It does not implement production loaders,
policy compilation, or network-agent integration.

## Decision

PicoCompute adopts:

| Concern | Decision |
| --- | --- |
| eBPF framework | **aya** (`aya` userspace + `aya-ebpf` programs) |
| Kernel program language | **Rust** |
| First program class | **TC classifier** (`BPF_PROG_TYPE_SCHED_CLS`) on agent-managed veth |
| Production kernel floor | **Linux 5.15** with host BTF; feature gates raise the floor per bundle |
| Loader capabilities (TC v1) | **`CAP_BPF` + `CAP_NET_ADMIN`** only by default |
| Artifact form | **Separate, digest-pinned OCI eBPF bundle** with referrer evidence |
| Escape hatch | libbpf-rs only via explicit spike or ADR amendment, not as a parallel default |

### Framework: aya

aya is the default for PicoCompute host eBPF because:

1. **Monorepo fit**: PicoCompute is a Rust workspace. Writing both loader and
   program in Rust keeps review, lint, and ownership in one language.
2. **Shared ABI types**: Maps, policy keys, and constants can live in shared
   crates consumed by `network-agent` and the eBPF package, reducing drift.
3. **Smaller runtime surface**: aya talks to the kernel through syscalls. It
   does not require libbpf or libelf at runtime, which shrinks host SBOM and
   privileged-binary linking.
4. **Adequate TC and CO-RE support**: aya documents `SchedClassifier`,
   `clsact` attach, BTF load, and typed maps suitable for production TC
   policy paths.
5. **CI model**: Build cost is a pinned BPF/LLVM/`bpf-linker` toolchain in a
   digest-pinned Linux builder, which matches PicoCompute's existing image-build
   pattern more cleanly than a permanent C program tree.

libbpf-rs remains a **documented alternative**, not a second production stack.
Choose it only when a required helper, program type, or CO-RE pattern is
blocked in aya and a time-boxed evaluation proves libbpf is necessary. Any
permanent switch requires amending this ADR.

#### Evaluation summary (aya vs libbpf-rs)

| Dimension | aya | libbpf-rs | PicoCompute preference |
| --- | --- | --- | --- |
| Kernel program language | Rust (`aya-ebpf`, `#![no_std]`) | C via clang libbpf-cargo | aya (Rust monorepo) |
| Userspace language | Rust (`aya`) | Rust (`libbpf-rs`) | Tie |
| Runtime native deps | libc syscalls only | libbpf via libbpf-sys (+ libelf) | aya (smaller SBOM) |
| Compile-time safety | Rust types and shared crates on both sides; verifier still final | C kernel program; Rust skel for userspace | aya for shared map/ABI types |
| Verifier ergonomics | Sufficient for TC policies; capture logs in CI | Mature C examples; slight edge on novel helpers | Tie for TC v1 |
| Map API | Typed Rust maps on both sides of the load boundary | libbpf map wrappers over skeleton | aya |
| CO-RE BTF | BTF load and CO-RE; pin BTF inputs at build | Reference libbpf CO-RE | Tie (both production-capable) |
| TC classifier support | `SchedClassifier` + `clsact` | libbpf TC attach APIs | Tie |
| CI supply chain | stable Rust host + `bpf-linker` + pinned LLVM | + clang, libelf, libbpf headers | aya |
| Kernel feature lag | Rust bindings can trail slightly | libbpf tracks kernel first | libbpf-rs (not decisive) |

Neither framework replaces the kernel verifier. aya improves *source* safety
(map key/value types, section macros, shared crates). Packet header access
remains unsafe relative to kernel memory, which matches the eBPF model.
libbpf-rs generates strong userspace types from the C object, but the kernel
program stays outside `rustc`.

Both support the maps PicoCompute needs for v1 (hash, array, per-CPU, LRU, LPM
trie, ringbuf as required) and CO-RE when objects retain BTF/BTF.ext and the
host provides kernel BTF. Release builds must not compile against the CI
runner's live `/sys/kernel/btf/vmlinux`; pin a target BTF or generated
`vmlinux` input in the builder.

| CI concern | aya | libbpf-rs |
| --- | --- | --- |
| BPF compile | `bpfel-unknown-none` `bpfeb-unknown-none` + `bpf-linker` | clang + libbpf-cargo |
| Host build | stable Rust workspace | stable Rust + native link of libbpf |
| Cross-arch BPF endian | dual targets in builder | dual clang targets |
| Offline rebuild | pin crates, LLVM, bpf-linker, BTF input | pin crates, clang, libbpf, headers, BTF input |

libbpf-rs is rejected as the default because it forces a permanent C program
tree and dual-language ownership, expands runtime coupling through
libbpf-sys/libelf, and is unnecessary for the artifact contract: the OCI
bundle cares about ELF sections, BTF, maps, and attach metadata, which aya
produces without libbpf on the load path.

#### Residual risks of choosing aya

| Risk | Mitigation |
| --- | --- |
| Helper or program type not yet bound in aya | Time-boxed spike; temporary libbpf-rs only if blocked; amend ADR if permanent |
| rustc/LLVM BPF codegen surprises vs clang | Pin toolchain versions; dual-endian CI; conformance load on golden kernels |
| Verifier friction on complex packet parses | Keep programs small; prefer maps and bounded parses; capture verifier logs in validation reports |

### Kernel version floor

Declare floors **per feature**, then set a production host baseline. Precise
floors supersede issue text where they differ (LSM is 5.7; bloom is
5.16).

| Feature | Minimum kernel |
| --- | --- |
| TC classifier (`SCHED_CLS`) | 4.1 |
| `clsact` qdisc | 4.5 |
| Host BTF (CO-RE) | 4.18 (required in production) |
| Bounded loops | 5.3 |
| BPF LSM program type | 5.7 |
| `CAP_BPF` | 5.8 |
| Ring buffer map | 5.8 |
| BPF timers | 5.15 |
| Bloom filter maps | 5.16 |

**Production host floor for PicoCompute compute**: **Linux 5.15** with
`CONFIG_DEBUG_INFO_BTF=y` (or equivalent shipping BTF at
`/sys/kernel/btf/vmlinux`).

Bundle profiles declare their own minimums; admission validates the declared
feature set against the host:

| Bundle profile | Minimum kernel | Required host features |
| --- | --- | --- |
| TC classifier only (hash/array maps, no timers, no bloom, no LSM) | **5.15** | BTF, `clsact`, JIT preferred |
| TC + BPF timers | **5.15** | As above + timer helpers |
| TC + bloom filter maps | **5.16** | As above + bloom maps |
| BPF LSM programs | **5.7** program type; **5.8+** preferred with `CAP_BPF` | `CONFIG_BPF_LSM`, LSM hooks enabled |

Rationale:

- 5.15 is a long-lived LTS class and includes BPF timers.
- Default networking TC programs do not require bloom maps; bundles that use
  bloom declare **5.16**.
- BPF LSM bundles declare **5.7+** for the program type and require LSM/BTF
  host config; they still run on the 5.15+ production floor.
- Current Packer/AMI compute images (Ubuntu 24.04 26.04 class) ship **6.x**
  kernels and already satisfy the floor. The floor is the admission contract,
  not an invitation to run unvalidated older hosts. Prefer a pinned modern
  golden kernel for CI and production images; that pin may be stricter than
  the artifact floor.

Admission **must** validate each artifact's declared minimum kernel, Kconfig
features, helpers, and attach types against the running host. Do not infer a
universal floor from "this is a TC program."

### Capabilities

For the initial TC-on-veth path:

| Capability | Role |
| --- | --- |
| `CAP_BPF` | Load programs and create maps via `bpf(2)` without `CAP_SYS_ADMIN` |
| `CAP_NET_ADMIN` | Manage `clsact`/TC attach and interface-scoped network admin |

Rules:

- Do not grant `CAP_SYS_ADMIN` for eBPF load in production.
- Do not grant `CAP_PERFMON`, `CAP_SYS_RESOURCE`, or other caps unless a
  program type requires them; record extras in the bundle config and helper
  policy.
- Prefer a **narrow privileged helper** (or a tightly capability-bounded path
  inside `network-agent`) that loads only digest-pinned, verified artifacts and
  attaches only to agent-managed interfaces. It accepts a scheduled root digest
  and expected program/attach metadata, never a tenant-supplied ELF path,
  object name, map pin path, interface name, or attach command.

This extends [ADR-0002](0002-host-runtime-lifecycle-orchestration.md)'s
`CAP_NET_ADMIN` network-setup privilege with explicit `CAP_BPF` for program
load.

#### Host environment gates

Before load, the host must satisfy:

1. Kernel release >= bundle minimum.
2. `/sys/kernel/btf/vmlinux` present when CO-RE is required.
3. Required Kconfig features available (probe or documented host image profile).
4. Effective capabilities include the declared set (`CAP_BPF` +
   `CAP_NET_ADMIN` for TC v1).
5. Architecture and BPF endianness match the artifact (or the selected OCI
   index variant).

Missing any gate is a hard admission failure. Do not load an unsigned local
`.o` as a fallback.

| Environment | Kernel class | Status vs floor |
| --- | --- | --- |
| Packer compute host (Ubuntu 26.04) | 6.x | Above floor |
| AMI fallback (Ubuntu 24.04) | 6.x | Above floor |
| Developer CI Linux | Must be >= 5.15 + BTF for load tests | Use a pinned golden kernel |

macOS workstations cannot load eBPF. Local iteration uses Linux VMs, remote
hosts, or CI Linux runners.

### eBPF artifact pipeline

Treat a compiled eBPF ELF as a **separate, host-native PicoCompute OCI artifact
bundle**, not as a guest-image layer and not as an unsigned file dropped next
to the agent. Its immutable root digest is the deployment identity. This keeps
host-network policy independently releasable while applying the same OCI
referrer, SBOM, provenance, signature, validation, promotion, revocation, and
fail-closed admission model specified for guest images in
[ADR-0008](0008-guest-image-format-and-build-pipeline.md).

The host-agent or network-agent release configuration must name the exact BPF
bundle digest. It must never select an object through a mutable tag or local
path. If a guest-image profile depends on a network-policy ABI, record both
immutable digests in a signed compatibility or promotion attestation. Do not
make the BPF object a referrer of every guest image: it is a host artifact with
its own kernel and attach compatibility lifecycle.

#### Artifact graph

Publish `pico-ebpf` as an OCI image manifest (or index when multiple
endian/host-profile variants ship together):

```text
pico-ebpf@sha256:<root>
  config: application/vnd.pico.ebpf.config.v1+json
  layer: application/vnd.pico.ebpf.elf.v1+elf
  referrers (subject = sha256:<root>):
    SPDX SBOM | SLSA provenance | Sigstore signature
    validation report | vulnerability result | promotion/revocation
```

The config is canonical JSON and must declare at least:

- schema version, bundle version, and policy-interface version
- program names and ELF section names
- BPF endianness and supported host architectures
- ELF layer descriptor
- map ABI and intended program and attach types
- required BTF/CO-RE features, helpers, and Kconfig flags
- minimum kernel version
- required loader capabilities
- source revision and validation-report digest

Add a new config schema version rather than silently broadening compatibility.
The framework choice (aya today) may change the build wrapper, but not this
artifact contract.

OCI permits non-container content in an image manifest with an artifact-
specific config media type and the payload in layers. Production registries
must support the OCI 1.1 referrers API; test pagination. Implement the
tag-schema fallback only for compatibility with registries that lack
referrers.

Tags are discovery aliases only. Production identity is always the root
digest.

#### Build and validation

1. Build in an isolated, **digest-pinned Linux builder**.
2. Pin source revision, `Cargo.lock`, aya/`bpf-linker` versions, LLVM/Clang
   and `llvm-objcopy`, target BTF or generated `vmlinux` input, BPF headers,
   linker flags, and builder image digest.
3. Do **not** read the CI runner's live `/sys/kernel/btf/vmlinux` for release
   objects.
4. Compile for the declared BPF endianness; retain BTF and BTF.ext needed for
   CO-RE.
5. Produce an uncompressed `.o`, calculate its digest and size, then assemble
   the OCI manifest or index from those immutable descriptors.
6. Before signing, run static ELF checks and an isolated conformance test:
   expected program sections and map ABI, BTF and CO-RE relocation inspection,
   bounded verifier-log capture, load and attach to a disposable veth TC
   classifier, policy behavior, detach and cleanup. The report must identify
   the exact kernel/BTF profile used.
7. Prefer independent rebuild comparison under the same pins; byte mismatch
   fails release unless an approved deterministic-verification exception is
   documented.

#### Evidence and signing

Create evidence after the root digest exists, and attach every evidence
artifact to that digest as an OCI referrer:

| Evidence | BPF-specific content |
| --- | --- |
| SPDX SBOM | ELF digest, source crates and native deps, LLVM/Clang, BPF headers, generated `vmlinux` or BTF input, licenses, builder components |
| SLSA v1.2 provenance | In-toto subjects for the root manifest or index **and** ELF layer; source revision; pinned build inputs; build definition; builder identity; invocation; resolved dependencies |
| Signature | Sigstore over the OCI root digest, issued only by the approved PicoCompute release identity |
| Validation report | Static inspection, verifier result, kernel/BTF profile, veth TC conformance, map ABI, attach/detach and policy test results |
| Promotion revocation | Stage, policy revision, accepted evidence digests, approvers, time bounds, deny or supersession state |

Prefer registry-native Cosign signing of the OCI digest (`cosign sign` /
`cosign verify`) over ad-hoc blob signatures so the root signature binds the
referenced ELF layer and the referrer graph keeps evidence discoverable.
Keyless signing is acceptable only when verification pins the Fulcio trust
root, OIDC issuer, certificate identity, repository, workflow, and environment
expected by PicoCompute. A valid signature from any other identity is a rejection.

#### Host admission (fail closed)

Before a load or cache reuse:

1. Resolve the scheduled root digest; verify manifest, config, layer media
   types, descriptor sizes, and digests.
2. Discover required referrers, verify each `subject` equals the root digest,
   and reject missing, stale, revoked, or untrusted evidence.
3. Verify the Cosign signature and its exact identity and issuer constraints.
   Verify SLSA provenance against approved repository, revision, builder,
   workflow, and pinned material policy. Apply SBOM, vulnerability,
   validation, and production-promotion policies.
4. Verify local compatibility: kernel release, BTF and CO-RE requirements,
   Kconfig features, program and attach types, required helpers, architecture
   and endianness, map ABI, and effective capabilities (`CAP_BPF` +
   `CAP_NET_ADMIN` for TC v1).
5. Load only declared programs; attach only to agent-managed interfaces; pin
   maps and handles under an agent-owned directory; verify loaded program and
   map IDs match the expected object. On any error, detach newly attached
   programs, remove newly created pins, and quarantine the cached artifact.

Persist root and ELF digests, validation-report digest, kernel/BTF profile,
map ABI version, attached interface, program IDs, and policy epoch.
Revalidate on agent restart; detach or quarantine on revocation or host drift.

#### Relation to `pico-image`

Reuse descriptor and validation *concepts* from `crates/pico-image`. That
crate currently emits local CycloneDX/provenance JSON and custom Ed25519
bundles without OCI publication or referrer traversal. Production eBPF
distribution must follow the OCI/SLSA/Sigstore contract above (shared
supply-chain work tracked with guest-image hardening, e.g. class
work). Do not treat today's on-disk `pico-image` formats as the final eBPF
shipping path.

## Consequences

### Positive

- One Rust-native eBPF stack aligned with PicoCompute ownership and review.
- Explicit kernel and capability contracts for host admission.
- Independent, signed eBPF releases without coupling to guest-image digests.
- TC-first path matches ADR-0005's veth-centric host networking model.

### Negative costs

- CI must maintain a BPF-capable Linux builder (`bpf-linker`, pinned LLVM,
  dual endian when needed).
- Novel kernel BPF features may appear in libbpf/C before aya bindings; rare
  escapes need process discipline.
- OCI eBPF packaging and referrer verification are new operational surface
  beyond embedding `.o` files in agent binaries.

### Neutral

- nftables remains the primary policy compiler for deny-by-default routing
  policy (ADR-0005). eBPF complements it for high-performance classification,
  observability, and future LSM/timer features; it does not replace the
  control-plane authority model.

## Alternatives considered

### libbpf-rs as default

**Rejected as default.** Strong CO-RE and C ecosystem, but forces a permanent
C program tree, libbpf/libelf runtime coupling, and dual-language ownership in
a Rust monorepo. Acceptable only as a documented escape hatch.

### Embed unsigned `.o` files in the network-agent binary

**Rejected for production.** Convenient for prototypes; fails ADR-0006/0008
requirements for signed provenance, independent promotion, revocation, and
digest-pinned admission.

### Ship eBPF objects as guest-image layers

**Rejected.** eBPF runs on the **host**, tracks host kernel/BTF compatibility,
and must release on a host lifecycle independent of guest rootfs content.

### Kernel floor of 5.8 only (CAP_BPF era)

**Rejected as the production baseline.** 5.8 enables `CAP_BPF` but omits BPF
timers (5.15) and is older than PicoCompute's intended LTS host class. Feature
gates still document 5.8+ capability semantics.

### Kernel floor of 6.1+ (or current LTS only)

**Deferred as a hard artifact contract.** Compute images already run 6.x, and
ops may pin a modern LTS (for example 6.18) for production hosts and golden CI
profiles. Declaring that pin as the universal *artifact* floor is unnecessary
for TC v1 and would reject hosts that meet 5.15 + BTF. Profiles that need
newer helpers declare higher floors in config; fleet policy may still require
a newer host image independently.

## Implementation notes (non-normative)

1. First production crate should land under the workspace (for example
   `pico-ebpf` and `network-agent` integration), not as ad-hoc research
   trees.
2. Build release objects only on Linux builders; macOS developers use VMs or
   CI for load tests.
3. First production integration target: TC attach on `network-agent`-managed
   host veth ends, with maps driven by control-plane policy epochs - never by
   tenant-supplied ELF or attach commands.
4. Extend privileged-helper documentation when the loader binary lands
   (`docs/security/privileged-helpers.md`).

## References

- [Aya book](https://aya-rs.dev/book)
- [Aya TC classifiers](https://aya-rs.dev/book/programs/classifiers)
- [Aya GitHub](https://github.com/aya-rs/aya)
- [libbpf-rs](https://github.com/libbpf/libbpf-rs)
- [BCC BPF features by kernel version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html)
- [Bloom filter map](https://docs.kernel.org/bpf/map_bloom_filter.html)
- [CAP_BPF background](https://mdaverde.com/posts/cap-bpf)
- [eBPF capabilities overview](https://docs.ebpf.io/linux)
- [OCI image manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md)
- [OCI distribution referrers](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [SLSA v1.2 provenance](https://slsa.dev/spec/v1.2/build-provenance)
- [SLSA v1.2 build requirements](https://slsa.dev/spec/v1.2/build-requirements)
- [Sigstore signing OCI artifacts](https://docs.sigstore.dev/cosign/signing/other_types)
- [Sigstore verifying signatures](https://docs.sigstore.dev/cosign/verifying/verify)
