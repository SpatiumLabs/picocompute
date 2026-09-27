//! Composable environment layers: base plus workspace plus toolkit.
//!
//! DSec 4.2/5.1 versions base image, workspace, and toolkits independently
//! and stacks them as overlayfs lowerdirs at create (read-only EROFS,
//! writable upper local), turning monolithic rebuilds into per-layer rebuilds.
//! Pico builds one normalized tree per backend variant today
//! (ADR-0008); this module adds the independently versioned composition that
//! Pico prepare/boot consumes.
//!
//! ```text
//! base (bottom, read-only, released) ->
//!   workspace (middle, read-only, released) ->
//!     toolkits (top, read-only, released, sorted by name) ->
//!       local writable upper (per-sandbox, never promoted)
//! ```
//!
//! Rules enforced here:
//!
//! - Every layer carries its own content digest plus per-layer supply-chain
//!   evidence digests (SBOM, provenance, signature). All of them are bound by
//!   one [`EnvironmentComposition::composition_digest`], so a promotion or
//!   revocation decision keyed on that digest also pins the evidence it
//!   reviewed. Only [`EnvironmentLayer::version`], a human label, is
//!   deliberately excluded so relabelling cannot change layer identity.
//! - The manifest signature covers the manifest bytes including the
//!   composition, so host verification of the manifest plus
//!   [`verify_layers_for_host`] is a signed composition check before boot.
//! - Released layers are never mutated: overlay plans mark every lower as
//!   read-only and the upper as the only writable layer. Whiteout semantics
//!   are preserved structurally by never merging the upper down into a
//!   released lower; see [`OVERLAYFS_OPAQUE_XATTR`] for the marker overlayfs
//!   itself uses and why no code needs to interpret it.
//! - Compatibility (backend, arch, protocol, profile, snapshot exclusions) is
//!   checked against the same allowlist gates as ADR-0008 and ADR-0004, and
//!   cross-checked between the composition and the manifest so placement and
//!   boot cannot disagree. A composition that broadens compatibility requires
//!   recomposition plus revalidation, never a host-time substitution.
//! - Mount-count pressure is bounded by [`MAX_ENVIRONMENT_LAYERS`] with a
//!   collapse recommendation at [`COLLAPSE_THRESHOLD_LAYERS`]. Collapse
//!   squashes the oldest toolkits into one new toolkit layer with fresh
//!   digests and provenance; it never edits a released layer in place.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::ImageError;
use crate::render::compute_file_digest;
use crate::types::{BackendCompatibility, ProtocolVersionRange};

/// Schema version for [`EnvironmentComposition`].
pub const ENVIRONMENT_SCHEMA_VERSION: &str = "1.0";

/// Hard cap on total released layers in one composition (base + workspace +
/// toolkits). Overlayfs lowerdir chains degrade and hit kernel limits as the
/// count grows; compositions above this fail closed and must collapse first.
pub const MAX_ENVIRONMENT_LAYERS: usize = 16;

/// Toolkit count (plus base/workspace) above which [`OverlayPlan`]
/// recommends a layer collapse. Collapse is advisory below the hard cap and
/// mandatory at it.
pub const COLLAPSE_THRESHOLD_LAYERS: usize = 8;

/// `trusted.overlay.opaque` xattr overlayfs sets on a directory in the upper
/// to hide every lower directory of the same name.
///
/// This is the only deletion marker PicoCompute itself never has to interpret:
/// overlayfs creates and consumes whiteouts (`0/0` character devices in the
/// upper) and opaque directories as part of mount semantics. Pico preserves
/// them by never merging the upper down into a released lower, so it needs no
/// whiteout parser and cannot accidentally drop a deletion during collapse
/// preparation. Referenced only in operator-facing advice text.
pub const OVERLAYFS_OPAQUE_XATTR: &str = "trusted.overlay.opaque";

/// Value overlayfs writes to [`OVERLAYFS_OPAQUE_XATTR`].
pub const OVERLAYFS_OPAQUE_VALUE: &str = "y";

/// Required-manifest-feature marker a reader must understand before it may
/// boot a manifest that declares an [`EnvironmentComposition`].
///
/// ADR-0008 requires a reader to reject a field or value the manifest marks as
/// required. Readers that predate this field ignore unknown JSON keys and
/// would otherwise silently boot `artifacts.rootfs` and ignore the layer
/// stack, so a layered manifest must carry this marker. See
/// [`unknown_required_features`] for the reader-side check.
pub const ENVIRONMENT_LAYER_FEATURE: &str = "environment-layers-v1";

/// Maximum length of a layer name in bytes.
const MAX_LAYER_NAME_LEN: usize = 128;

/// Kind of one environment layer in the overlay stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentLayerKind {
    /// Immutable OS root (bottom of the stack).
    Base,
    /// Immutable workspace seed (middle of the stack).
    Workspace,
    /// Immutable toolkit extension (top of the stack, sorted by name).
    Toolkit,
}

impl EnvironmentLayerKind {
    /// Stable string form used in audit records and error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Workspace => "workspace",
            Self::Toolkit => "toolkit",
        }
    }
}

/// One independently versioned, independently promoted layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentLayer {
    /// Stable layer name (for example `debian-base`, `workspace-seed`,
    /// `toolkit-python`). Unique within a composition and restricted to a
    /// single safe path component because hosts derive mount paths from it.
    pub name: String,
    /// Position of this layer in the overlay order. Assigned by
    /// [`EnvironmentComposition::new`] from the declared precedence and
    /// validated against the stored array position, so shadowing order is
    /// explicit signed data rather than a side effect of naming.
    pub order: u32,
    /// Position class of this layer in the overlay stack.
    pub kind: EnvironmentLayerKind,
    /// Content digest of the layer bytes (`sha256:<hex>`).
    pub digest: String,
    /// Size of the layer bytes.
    pub size: u64,
    /// OCI-style media type of the layer bytes.
    pub media_type: String,
    /// Human release version of this layer (for example `2026.09.1`).
    ///
    /// Deliberately excluded from [`EnvironmentComposition::composition_digest`]:
    /// it is an operator label, not layer identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Digest of the per-layer CycloneDX/SPDX SBOM. Required in production.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_digest: Option<String>,
    /// Digest of the per-layer SLSA/in-toto provenance. Required in production.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_digest: Option<String>,
    /// Digest of the per-layer detached signature bundle. Required in production.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_digest: Option<String>,
}

impl EnvironmentLayer {
    /// Build a layer and validate its fields.
    ///
    /// `order` is assigned by [`EnvironmentComposition::new`]; pass `0` here.
    ///
    /// # Errors
    ///
    /// Returns [`ImageError::CompositionValidationFailed`] when any field is
    /// malformed.
    pub fn new(
        name: impl Into<String>,
        kind: EnvironmentLayerKind,
        digest: impl Into<String>,
        size: u64,
        media_type: impl Into<String>,
    ) -> Result<Self, ImageError> {
        let layer = Self {
            name: name.into(),
            order: 0,
            kind,
            digest: digest.into(),
            size,
            media_type: media_type.into(),
            version: None,
            sbom_digest: None,
            provenance_digest: None,
            signature_digest: None,
        };
        validate_environment_layer(&layer).map_err(ImageError::CompositionValidationFailed)?;
        Ok(layer)
    }

    /// Set the human release version label.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Attach per-layer supply-chain evidence digests.
    #[must_use]
    pub fn with_evidence(
        mut self,
        sbom_digest: Option<String>,
        provenance_digest: Option<String>,
        signature_digest: Option<String>,
    ) -> Self {
        self.sbom_digest = sbom_digest;
        self.provenance_digest = provenance_digest;
        self.signature_digest = signature_digest;
        self
    }
}

/// Compatibility allowlist bound to one composition, mirroring the ADR-0008
/// variant compatibility gates (backend, arch, protocol, snapshot).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionCompatibility {
    /// Tested compatibility profile (for example `firecracker-x86_64-v1`).
    pub profile_id: String,
    /// Tested backend family/version/arch set.
    pub backends: Vec<BackendCompatibility>,
    /// Tested platform architecture (for example `x86_64`).
    pub architecture: String,
    /// Negotiable protocol ranges (ADR-0003 bootstrap contract).
    pub protocol_supported: Vec<ProtocolVersionRange>,
    /// Snapshot-excluded mount classes (must cover secret and runtime_tmp).
    pub snapshot_excluded_classes: Vec<String>,
}

/// Signed composition record binding base, workspace, and toolkits.
///
/// The manifest signature covers the serialized manifest including this
/// record, so a host that verifies the manifest signature plus
/// [`verify_layers_for_host`] has verified a signed composition before boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentComposition {
    /// Composition schema version (`1.0`).
    pub schema_version: String,
    /// Image family this composition belongs to (for example
    /// `pico-guest-standard`).
    pub image_id: String,
    /// Bottom layer: immutable OS root.
    pub base: EnvironmentLayer,
    /// Middle layer: immutable workspace seed.
    pub workspace: EnvironmentLayer,
    /// Top layers: immutable toolkit extensions, kept sorted by name for a
    /// deterministic overlay order.
    #[serde(default)]
    pub toolkits: Vec<EnvironmentLayer>,
    /// Tested compatibility allowlist for this exact layer set.
    pub compatibility: CompositionCompatibility,
    /// Canonical digest binding the ordered layer set plus compatibility
    /// (`sha256:<hex>`). Recomputed on every rebuild or recomposition.
    pub composition_digest: String,
    /// Build epoch of the composition (seconds since Unix epoch).
    pub build_epoch: i64,
}

impl EnvironmentComposition {
    /// Build a composition, assigning overlay order from the declared
    /// precedence and computing the composition digest.
    ///
    /// `base` and `workspace` occupy orders `0` and `1`. `toolkits` are
    /// consumed in the order given, receiving orders `2..`: the first entry is
    /// the topmost toolkit, so callers state shadowing order explicitly rather
    /// than relying on name sorting. Name is retained as a human label only.
    ///
    /// # Errors
    ///
    /// Returns [`ImageError::CompositionValidationFailed`] when the layer set
    /// or compatibility is malformed.
    pub fn new(
        image_id: impl Into<String>,
        base: EnvironmentLayer,
        workspace: EnvironmentLayer,
        toolkits: Vec<EnvironmentLayer>,
        compatibility: CompositionCompatibility,
        build_epoch: i64,
    ) -> Result<Self, ImageError> {
        let image_id = image_id.into();
        let mut base = base;
        base.order = 0;
        let mut workspace = workspace;
        workspace.order = 1;
        let toolkits = toolkits
            .into_iter()
            .enumerate()
            .map(|(i, mut t)| {
                t.order = (i + 2) as u32;
                t
            })
            .collect::<Vec<_>>();
        let composition_digest =
            compute_composition_digest(&image_id, &base, &workspace, &toolkits, &compatibility);
        let composition = Self {
            schema_version: ENVIRONMENT_SCHEMA_VERSION.into(),
            image_id,
            base,
            workspace,
            toolkits,
            compatibility,
            composition_digest,
            build_epoch,
        };
        validate_environment_composition(&composition)
            .map_err(ImageError::CompositionValidationFailed)?;
        Ok(composition)
    }

    /// Ordered released layers bottom to top: base, workspace, toolkits.
    pub fn ordered_layers(&self) -> Vec<&EnvironmentLayer> {
        let mut layers = Vec::with_capacity(2 + self.toolkits.len());
        layers.push(&self.base);
        layers.push(&self.workspace);
        layers.extend(self.toolkits.iter());
        layers
    }

    /// Total released layer count (excludes the per-sandbox writable upper).
    pub fn layer_count(&self) -> usize {
        2 + self.toolkits.len()
    }

    /// Recompose with one rebuilt toolkit, preserving base and workspace.
    ///
    /// This is the independent-bump path: only the named toolkit layer plus
    /// the composition record change. Base and workspace digests are
    /// byte-identical before and after.
    ///
    /// # Errors
    ///
    /// Returns [`ImageError::CompositionValidationFailed`] when the
    /// replacement is not a toolkit with the expected name or fails
    /// validation.
    pub fn with_rebuilt_toolkit(
        &self,
        toolkit_name: &str,
        rebuilt: EnvironmentLayer,
    ) -> Result<Self, ImageError> {
        if rebuilt.kind != EnvironmentLayerKind::Toolkit {
            return Err(ImageError::CompositionValidationFailed(format!(
                "replacement layer '{}' is {:?}, expected toolkit",
                rebuilt.name, rebuilt.kind
            )));
        }
        if rebuilt.name != toolkit_name {
            return Err(ImageError::CompositionValidationFailed(format!(
                "replacement layer '{}' does not match toolkit '{toolkit_name}'",
                rebuilt.name
            )));
        }
        let mut toolkits = self.toolkits.clone();
        let pos = toolkits
            .iter()
            .position(|t| t.name == toolkit_name)
            .ok_or_else(|| {
                ImageError::CompositionValidationFailed(format!(
                    "toolkit '{toolkit_name}' not in composition"
                ))
            })?;
        toolkits[pos] = rebuilt;
        Self::new(
            self.image_id.clone(),
            self.base.clone(),
            self.workspace.clone(),
            toolkits,
            self.compatibility.clone(),
            self.build_epoch,
        )
    }
}

/// Validate one layer's fields without checking composition membership.
///
/// Returns a human-readable reason on failure; callers map it into
/// [`ImageError::CompositionValidationFailed`].
///
/// # Errors
///
/// Returns `Err` with a reason when the name, digest, size, or media type is
/// malformed.
pub fn validate_environment_layer(layer: &EnvironmentLayer) -> Result<(), String> {
    validate_layer_name(&layer.name)?;
    if !layer.digest.starts_with("sha256:") || layer.digest.len() <= "sha256:".len() {
        return Err(format!(
            "layer '{}' digest '{}' does not use sha256: prefix",
            layer.name, layer.digest
        ));
    }
    if layer.size == 0 {
        return Err(format!("layer '{}' size is zero", layer.name));
    }
    if layer.media_type.is_empty() {
        return Err(format!("layer '{}' media_type is empty", layer.name));
    }
    for (label, digest) in [
        ("sbom_digest", layer.sbom_digest.as_ref()),
        ("provenance_digest", layer.provenance_digest.as_ref()),
        ("signature_digest", layer.signature_digest.as_ref()),
    ] {
        if let Some(d) = digest
            && !d.starts_with("sha256:")
        {
            return Err(format!(
                "layer '{}' {label} '{d}' does not use sha256: prefix",
                layer.name
            ));
        }
    }
    Ok(())
}

/// Validate a layer name as a single safe path component.
///
/// Hosts derive overlay mount paths from the name and join those paths with
/// `:` into the overlayfs `lowerdir=` mount option, so a name containing a path
/// separator or the option separator would either escape the layer store or
/// silently inject an extra lower layer. Restricting the charset here means
/// the sink can trust its input; `plan_overlay_stack` still keeps an inline
/// containment guard so the check dominates the sink.
///
/// # Errors
///
/// Returns `Err` with a reason when the name is empty, too long, a relative
/// path element, or contains a character outside `[A-Za-z0-9._-]`.
pub fn validate_layer_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("environment layer name is empty".into());
    }
    if name.len() > MAX_LAYER_NAME_LEN {
        return Err(format!(
            "environment layer name '{name}' exceeds {MAX_LAYER_NAME_LEN} bytes"
        ));
    }
    if name == "." || name == ".." {
        return Err(format!(
            "environment layer name '{name}' is a relative path element"
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        return Err(format!(
            "environment layer name '{name}' contains disallowed character {bad:?}; allowed set is [A-Za-z0-9._-]"
        ));
    }
    Ok(())
}

/// Validate a full composition: layer kinds, uniqueness, counts,
/// compatibility, and digest binding.
///
/// # Errors
///
/// Returns `Err` with a reason when any composition invariant fails.
pub fn validate_environment_composition(comp: &EnvironmentComposition) -> Result<(), String> {
    if comp.schema_version != ENVIRONMENT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported environment schema version: {}",
            comp.schema_version
        ));
    }
    if comp.image_id.is_empty() {
        return Err("composition image_id is empty".into());
    }
    if comp.base.kind != EnvironmentLayerKind::Base {
        return Err(format!(
            "base layer '{}' has kind {:?}, expected base",
            comp.base.name, comp.base.kind
        ));
    }
    if comp.workspace.kind != EnvironmentLayerKind::Workspace {
        return Err(format!(
            "workspace layer '{}' has kind {:?}, expected workspace",
            comp.workspace.name, comp.workspace.kind
        ));
    }
    for tk in &comp.toolkits {
        if tk.kind != EnvironmentLayerKind::Toolkit {
            return Err(format!(
                "toolkit layer '{}' has kind {:?}, expected toolkit",
                tk.name, tk.kind
            ));
        }
    }
    if comp.layer_count() > MAX_ENVIRONMENT_LAYERS {
        return Err(format!(
            "composition has {} layers, exceeding max {MAX_ENVIRONMENT_LAYERS}; collapse toolkits first",
            comp.layer_count()
        ));
    }

    for layer in comp.ordered_layers() {
        validate_environment_layer(layer)?;
    }

    let mut names = BTreeSet::new();
    for layer in comp.ordered_layers() {
        if !names.insert(layer.name.clone()) {
            return Err(format!("duplicate layer name: '{}'", layer.name));
        }
    }
    let mut digests = BTreeSet::new();
    for layer in comp.ordered_layers() {
        if !digests.insert(layer.digest.clone()) {
            return Err(format!(
                "digest collision: layer '{}' reuses digest {}",
                layer.name, layer.digest
            ));
        }
    }

    // Overlay order is explicit signed data, not a side effect of naming:
    // each layer's recorded order must equal its position in the stack, so
    // renaming a toolkit can never change which layer shadows which.
    for (position, layer) in comp.ordered_layers().iter().enumerate() {
        if layer.order as usize != position {
            return Err(format!(
                "layer '{}' declares order {} but sits at position {position}",
                layer.name, layer.order
            ));
        }
    }

    validate_composition_compatibility_fields(comp)?;

    let expected_digest = compute_composition_digest(
        &comp.image_id,
        &comp.base,
        &comp.workspace,
        &comp.toolkits,
        &comp.compatibility,
    );
    if comp.composition_digest != expected_digest {
        return Err(format!(
            "composition digest mismatch: recorded {} but recomputed {expected_digest}",
            comp.composition_digest
        ));
    }
    Ok(())
}

fn validate_composition_compatibility_fields(comp: &EnvironmentComposition) -> Result<(), String> {
    let c = &comp.compatibility;
    if c.profile_id.is_empty() {
        return Err("composition compatibility profile_id is empty".into());
    }
    if c.backends.is_empty() {
        return Err("composition compatibility backends is empty".into());
    }
    if c.architecture.is_empty() {
        return Err("composition architecture is empty".into());
    }
    if !["aarch64", "x86_64"].contains(&c.architecture.as_str()) {
        return Err(format!(
            "unsupported composition architecture '{}'",
            c.architecture
        ));
    }
    for be in &c.backends {
        if be.architecture != c.architecture {
            return Err(format!(
                "backend '{}' architecture '{}' does not match composition architecture '{}'",
                be.family, be.architecture, c.architecture
            ));
        }
    }
    if c.protocol_supported.is_empty() {
        return Err("composition protocol_supported is empty".into());
    }
    for range in &c.protocol_supported {
        if range.major == 0 {
            return Err("composition protocol range includes major version 0".into());
        }
        if range.min_minor > range.max_minor {
            return Err(format!(
                "composition protocol range min_minor ({}) > max_minor ({})",
                range.min_minor, range.max_minor
            ));
        }
    }
    if !c.snapshot_excluded_classes.contains(&"secret".to_string()) {
        return Err("composition must exclude secret mounts from snapshots".into());
    }
    if !c
        .snapshot_excluded_classes
        .contains(&"runtime_tmp".to_string())
    {
        return Err("composition must exclude runtime_tmp mounts from snapshots".into());
    }
    Ok(())
}

/// Canonical digest binding the ordered layer set, per-layer supply-chain
/// evidence, and compatibility.
///
/// `version` is deliberately excluded: it is a human release label, so
/// relabelling a layer must not change its identity. Everything else the
/// composition records - order, name, content digest, size, media type, and
/// the SBOM/provenance/signature evidence digests - is bound, so a promotion
/// or revocation decision keyed on this digest also pins the evidence it
/// reviewed.
///
/// Toolkits are hashed in stored (declared precedence) order; the caller
/// controls that order, and [`EnvironmentComposition::new`] validates each
/// layer's recorded order against its position.
pub fn compute_composition_digest(
    image_id: &str,
    base: &EnvironmentLayer,
    workspace: &EnvironmentLayer,
    toolkits: &[EnvironmentLayer],
    compatibility: &CompositionCompatibility,
) -> String {
    let layer_json = |l: &EnvironmentLayer| {
        serde_json::json!({
            "name": l.name,
            "order": l.order,
            "digest": l.digest,
            "size": l.size,
            "media_type": l.media_type,
            "sbom_digest": l.sbom_digest,
            "provenance_digest": l.provenance_digest,
            "signature_digest": l.signature_digest,
        })
    };
    let canonical = serde_json::json!({
        "schema_version": ENVIRONMENT_SCHEMA_VERSION,
        "image_id": image_id,
        "base": layer_json(base),
        "workspace": layer_json(workspace),
        "toolkits": toolkits.iter().map(layer_json).collect::<Vec<_>>(),
        "compatibility": {
            "profile_id": compatibility.profile_id,
            "backends": compatibility.backends.iter().map(|b| serde_json::json!({"family": b.family, "runtime_version": b.runtime_version, "architecture": b.architecture})).collect::<Vec<_>>(),
            "architecture": compatibility.architecture,
            "protocol_supported": compatibility.protocol_supported.iter().map(|r| serde_json::json!({"major": r.major, "min_minor": r.min_minor, "max_minor": r.max_minor})).collect::<Vec<_>>(),
            "snapshot_excluded_classes": compatibility.snapshot_excluded_classes,
        },
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    crate::util::compute_sha256_digest(&bytes)
}

/// Which layers changed between two compositions of the same image family.
///
/// A toolkit-only bump touches exactly one toolkit digest plus the
/// composition digest; base and workspace digests are unchanged. That is the
/// O(k) fast path this module exists to protect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerRebuildPlan {
    /// Names of layers whose digests differ (or were added/removed).
    pub changed_layers: Vec<String>,
    /// True when base or workspace changed (slow path: full revalidation).
    pub base_or_workspace_changed: bool,
    /// True when only toolkits changed (fast path: toolkit rebuild plus
    /// recomposition).
    pub toolkit_only: bool,
    /// Previous composition digest.
    pub from_digest: String,
    /// New composition digest.
    pub to_digest: String,
}

/// Diff two compositions of the same image family.
///
/// Both operands are validated first: `toolkit_only` is the signal callers use
/// to skip full revalidation, so a malformed or stale `to` composition must not
/// be able to select the fast path.
///
/// # Errors
///
/// Returns [`ImageError::CompositionValidationFailed`] when either composition
/// is invalid or the two belong to different image families.
pub fn plan_rebuild(
    from: &EnvironmentComposition,
    to: &EnvironmentComposition,
) -> Result<LayerRebuildPlan, ImageError> {
    validate_environment_composition(from).map_err(ImageError::CompositionValidationFailed)?;
    validate_environment_composition(to).map_err(ImageError::CompositionValidationFailed)?;
    if from.image_id != to.image_id {
        return Err(ImageError::CompositionValidationFailed(format!(
            "cannot diff compositions across image families: '{}' vs '{}'",
            from.image_id, to.image_id
        )));
    }
    let mut changed = Vec::new();
    if from.base.digest != to.base.digest {
        changed.push(from.base.name.clone());
    }
    if from.workspace.digest != to.workspace.digest {
        changed.push(from.workspace.name.clone());
    }
    let from_map: std::collections::BTreeMap<&str, &str> = from
        .toolkits
        .iter()
        .map(|t| (t.name.as_str(), t.digest.as_str()))
        .collect();
    let to_map: std::collections::BTreeMap<&str, &str> = to
        .toolkits
        .iter()
        .map(|t| (t.name.as_str(), t.digest.as_str()))
        .collect();
    let mut names = BTreeSet::new();
    names.extend(from_map.keys().copied());
    names.extend(to_map.keys().copied());
    for name in names {
        if from_map.get(name) != to_map.get(name) {
            changed.push(name.to_string());
        }
    }
    changed.sort();
    changed.dedup();
    let base_or_workspace_changed =
        from.base.digest != to.base.digest || from.workspace.digest != to.workspace.digest;
    let toolkit_only = !changed.is_empty() && !base_or_workspace_changed;
    Ok(LayerRebuildPlan {
        changed_layers: changed,
        base_or_workspace_changed,
        toolkit_only,
        from_digest: from.composition_digest.clone(),
        to_digest: to.composition_digest.clone(),
    })
}

/// Promotion stage for one immutable composition digest.
///
/// Promotion is monotonic evidence over one digest: it never rebuilds or
/// mutates layers, it only attaches signed decisions. This mirrors the
/// ADR-0008 bundle stages at composition granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionPromotionStage {
    /// Composition graph exists with digests and builder evidence.
    Built,
    /// Static, compatibility, and supply-chain checks pass.
    Validated,
    /// Release owners accept the exact digest for pre-production.
    Candidate,
    /// Eligible for production policy and rollout.
    Production,
}

impl CompositionPromotionStage {
    /// Stable string form for audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Validated => "validated",
            Self::Candidate => "candidate",
            Self::Production => "production",
        }
    }

    /// Monotonic rank used to reject stage regressions.
    fn rank(self) -> u8 {
        match self {
            Self::Built => 0,
            Self::Validated => 1,
            Self::Candidate => 2,
            Self::Production => 3,
        }
    }
}

/// Signed promotion decision targeting one composition digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionPromotion {
    /// Composition digest this decision targets.
    pub composition_digest: String,
    /// Stage granted by this decision.
    pub stage: CompositionPromotionStage,
    /// Policy revision evaluated.
    pub policy_revision: String,
    /// Evidence digests reviewed (SBOM, provenance, validation, signatures).
    pub evidence_digests: Vec<String>,
    /// Approver identity.
    pub approver: String,
    /// Decision time (epoch seconds).
    pub decided_at: i64,
}

impl CompositionPromotion {
    /// Advance a promotion without skipping stages or regressing.
    ///
    /// # Errors
    ///
    /// Returns [`ImageError::CompositionValidationFailed`] when the target
    /// digest changes, the stage regresses, or a stage is skipped.
    pub fn advance(&self, next: &CompositionPromotion) -> Result<CompositionPromotion, ImageError> {
        if self.composition_digest != next.composition_digest {
            return Err(ImageError::CompositionValidationFailed(
                "promotion must target the same composition digest".into(),
            ));
        }
        if next.stage.rank() <= self.stage.rank() {
            return Err(ImageError::CompositionValidationFailed(format!(
                "promotion stage regression: {} -> {}",
                self.stage.as_str(),
                next.stage.as_str()
            )));
        }
        if next.stage.rank() != self.stage.rank() + 1 {
            return Err(ImageError::CompositionValidationFailed(format!(
                "promotion must advance one stage at a time: {} -> {}",
                self.stage.as_str(),
                next.stage.as_str()
            )));
        }
        Ok(next.clone())
    }
}

/// Overlay mount plan for prepare/boot: ordered read-only lowerdirs plus one
/// writable upper.
///
/// Released layers are always mounted read-only. Only the per-sandbox upper
/// is writable, and it is never promoted or merged down. Deletions are
/// expressed as whiteouts (`.wh.*`) and opaque markers that survive
/// composition; collapse must carry them into the squashed layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPlan {
    /// Released layer mount points bottom to top (base, workspace, toolkits).
    pub lowerdirs: Vec<String>,
    /// Per-sandbox writable upper directory.
    pub upperdir: String,
    /// Overlay work directory (same filesystem as the upper).
    pub workdir: String,
    /// Merged view presented to the guest rootfs.
    pub mergedir: String,
    /// Colon-joined lowerdir string for the `lowerdir=` mount option.
    pub lowerdir_option: String,
    /// True when the layer count recommends a collapse before adding more
    /// toolkits.
    pub collapse_recommended: bool,
    /// Composition digest this plan was derived from (for host audit).
    pub composition_digest: String,
}

/// Plan the overlay stack for one composition.
///
/// Lowerdirs follow base bottom, workspace middle, then toolkits in declared
/// precedence order. Callers mount them read-only with a per-sandbox writable
/// upper. Whiteout semantics are preserved structurally: this function never
/// merges, squashes, or reorders layers, so overlayfs-generated whiteouts
/// (`0/0` character devices) and [`OVERLAYFS_OPAQUE_XATTR`] markers in the
/// upper stay intact.
///
/// # Errors
///
/// Returns [`ImageError::TooManyLayers`] when the layer count exceeds
/// [`MAX_ENVIRONMENT_LAYERS`], [`ImageError::CompositionValidationFailed`]
/// when the composition is invalid, and
/// [`ImageError::LayerStorePathInvalid`] when a derived lower path would fall
/// outside `layer_mount_dir`.
pub fn plan_overlay_stack(
    composition: &EnvironmentComposition,
    layer_mount_dir: &str,
    upperdir: &str,
    workdir: &str,
    mergedir: &str,
) -> Result<OverlayPlan, ImageError> {
    // Check the count first so an over-cap composition reports the typed
    // `TooManyLayers` reason rather than the generic validation failure.
    if composition.layer_count() > MAX_ENVIRONMENT_LAYERS {
        return Err(ImageError::TooManyLayers {
            count: composition.layer_count(),
            max: MAX_ENVIRONMENT_LAYERS,
        });
    }
    validate_environment_composition(composition)
        .map_err(ImageError::CompositionValidationFailed)?;
    validate_layer_store_dir(layer_mount_dir).map_err(ImageError::CompositionValidationFailed)?;

    let prefix = format!("{layer_mount_dir}/");
    let mut lowerdirs = Vec::with_capacity(composition.layer_count());
    for layer in composition.ordered_layers() {
        let path = format!("{prefix}{}", layer.name);
        // Inline guard so the name check dominates the sink: a validated name
        // is a single safe path component, and this rejects any future layer
        // or separator change that could escape the layer store or inject an
        // extra lower layer through the `:` separator.
        if !path.starts_with(&prefix)
            || path[prefix.len()..].contains('/')
            || path[prefix.len()..].contains(':')
            || path.contains("..")
        {
            return Err(ImageError::LayerStorePathInvalid {
                layer: layer.name.clone(),
                mount_dir: layer_mount_dir.to_string(),
            });
        }
        lowerdirs.push(path);
    }
    // Overlayfs `lowerdir=` lists the topmost lower first, so reverse the
    // bottom-to-top order for the mount option while keeping `lowerdirs`
    // in stack order for audit and verification.
    let mut top_first = lowerdirs.clone();
    top_first.reverse();
    let lowerdir_option = top_first.join(":");
    Ok(OverlayPlan {
        lowerdirs,
        upperdir: upperdir.to_string(),
        workdir: workdir.to_string(),
        mergedir: mergedir.to_string(),
        lowerdir_option,
        collapse_recommended: composition.layer_count() >= COLLAPSE_THRESHOLD_LAYERS,
        composition_digest: composition.composition_digest.clone(),
    })
}

/// Validate the host directory that released layers are mounted from.
///
/// # Errors
///
/// Returns `Err` with a reason when the directory is empty, relative, or
/// contains a character that is unsafe in a `lowerdir=` list.
pub fn validate_layer_store_dir(dir: &str) -> Result<(), String> {
    if dir.is_empty() {
        return Err("layer mount dir is empty".into());
    }
    if !dir.starts_with('/') {
        return Err(format!("layer mount dir '{dir}' must be absolute"));
    }
    if dir.contains(':') {
        return Err(format!(
            "layer mount dir '{dir}' contains the ':' lowerdir separator"
        ));
    }
    if dir.contains("//") {
        return Err(format!(
            "layer mount dir '{dir}' contains an empty component"
        ));
    }
    if dir.split('/').any(|c| c == "." || c == "..") {
        return Err(format!(
            "layer mount dir '{dir}' is not lexically normalized"
        ));
    }
    Ok(())
}

/// Collapse recommendation when mount count becomes a problem.
///
/// Returns `Some(reason)` when the composition should be collapsed before
/// adding more toolkits: at or above [`COLLAPSE_THRESHOLD_LAYERS`] layers, or
/// at/above the hard [`MAX_ENVIRONMENT_LAYERS`] cap. Returns `None` when the
/// stack is healthy.
pub fn collapse_advice(composition: &EnvironmentComposition) -> Option<String> {
    if composition.layer_count() >= MAX_ENVIRONMENT_LAYERS {
        return Some(format!(
            "composition has {} layers (max {MAX_ENVIRONMENT_LAYERS}): collapse required before adding toolkits",
            composition.layer_count()
        ));
    }
    if composition.layer_count() >= COLLAPSE_THRESHOLD_LAYERS {
        return Some(format!(
            "composition has {} layers (threshold {COLLAPSE_THRESHOLD_LAYERS}): squash the least-recently-changed toolkits into one new toolkit layer with fresh SBOM/provenance/signature, preserve any overlayfs opaque-directory markers ({OVERLAYFS_OPAQUE_XATTR}={OVERLAYFS_OPAQUE_VALUE}) and whiteouts from the upper, and recompose; never edit a released layer in place",
            composition.layer_count()
        ));
    }
    None
}

/// One materialized layer file the host presents for verification.
#[derive(Debug, Clone)]
pub struct HostLayerFile<'a> {
    /// Layer name matching [`EnvironmentLayer::name`].
    pub name: &'a str,
    /// Path to the materialized layer bytes.
    pub path: &'a camino::Utf8Path,
}

/// Verify materialized layer bytes against the signed composition.
///
/// Checks every ordered layer is present exactly once, every file matches its
/// declared digest and size, and the composition digest still binds the
/// recorded set. Released-layer mutability is rejected by digest: any
/// post-release edit changes bytes and fails the digest check, so hosts must
/// mount lowers read-only and keep all writes in the upper.
///
/// The count check plus the per-name lookup already reject missing, extra, and
/// duplicated entries: with `layer_files.len() == layer_count()` and every
/// declared name located, the presented set is exactly the declared set.
///
/// # Errors
///
/// Returns [`ImageError::MissingHostArtifact`] for a missing layer,
/// [`ImageError::SizeMismatch`] for a size drift, and
/// [`ImageError::DigestMismatch`] for a content drift.
pub fn verify_layers_for_host(
    composition: &EnvironmentComposition,
    layer_files: &[HostLayerFile<'_>],
) -> Result<(), ImageError> {
    validate_environment_composition(composition)
        .map_err(ImageError::CompositionValidationFailed)?;
    if layer_files.len() != composition.layer_count() {
        return Err(ImageError::MissingHostArtifact {
            artifact: "environment_layers".into(),
            image_id: composition.image_id.clone(),
            reason: format!(
                "expected {} layer files, got {}",
                composition.layer_count(),
                layer_files.len()
            ),
        });
    }
    for expected in composition.ordered_layers() {
        let found = layer_files
            .iter()
            .find(|f| f.name == expected.name)
            .ok_or_else(|| ImageError::MissingHostArtifact {
                artifact: expected.name.clone(),
                image_id: composition.image_id.clone(),
                reason: "declared in composition but missing on host".into(),
            })?;
        let actual_size = std::fs::metadata(found.path)
            .map_err(|e| {
                ImageError::IoError(std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to stat layer {} at {}: {e}",
                        expected.name, found.path
                    ),
                ))
            })?
            .len();
        if actual_size != expected.size {
            return Err(ImageError::SizeMismatch {
                artifact: format!("layer:{}", expected.name),
                expected: expected.size,
                actual: actual_size,
            });
        }
        let actual_digest = compute_file_digest(found.path)?;
        if actual_digest != expected.digest {
            return Err(ImageError::DigestMismatch {
                artifact: format!("layer:{}", expected.name),
                expected: expected.digest.clone(),
                actual: actual_digest,
            });
        }
    }
    Ok(())
}

/// Expected host capabilities for composition compatibility checks.
#[derive(Debug, Clone)]
pub struct HostCompatibilityExpectation {
    /// Backend family the host will boot (for example `firecracker`).
    pub backend: String,
    /// Host architecture (for example `x86_64`).
    pub architecture: String,
    /// Negotiated protocol major version.
    pub protocol_major: u32,
}

/// Verify composition compatibility against host capabilities and the
/// manifest-level contract (ADR-0008 allowlist plus ADR-0004 backend gates).
///
/// Every claim is cross-checked in both directions where the composition and
/// the manifest each record it (image family, architecture, backend,
/// compatibility profile, protocol range, snapshot exclusions), so a
/// composition cannot claim compatibility the manifest does not, or vice versa.
///
/// # Errors
///
/// Returns [`ImageError::IncompatibleComposition`] when backend, arch,
/// protocol, profile, or snapshot exclusions do not match.
pub fn verify_composition_compatibility(
    composition: &EnvironmentComposition,
    manifest: &crate::types::PicoComputeGuestManifest,
    expected: &HostCompatibilityExpectation,
) -> Result<(), ImageError> {
    let incompatible = |reason: String| ImageError::IncompatibleComposition { reason };

    if composition.image_id != manifest.image_id {
        return Err(incompatible(format!(
            "composition image_id '{}' does not match manifest image_id '{}'",
            composition.image_id, manifest.image_id
        )));
    }
    if composition.compatibility.architecture != expected.architecture {
        return Err(incompatible(format!(
            "composition architecture '{}' does not match host '{}'",
            composition.compatibility.architecture, expected.architecture
        )));
    }
    if manifest.platform.architecture != expected.architecture {
        return Err(incompatible(format!(
            "manifest architecture '{}' does not match host '{}'",
            manifest.platform.architecture, expected.architecture
        )));
    }
    // The profile is the tested-compatibility claim; a composition validated
    // under a different profile was never tested as this set.
    if composition.compatibility.profile_id != manifest.compatibility.profile_id {
        return Err(incompatible(format!(
            "composition profile '{}' does not match manifest profile '{}'",
            composition.compatibility.profile_id, manifest.compatibility.profile_id
        )));
    }
    let backend_ok = composition
        .compatibility
        .backends
        .iter()
        .any(|b| b.family == expected.backend && b.architecture == expected.architecture);
    if !backend_ok {
        return Err(incompatible(format!(
            "backend '{}' on '{}' is not in the composition allowlist",
            expected.backend, expected.architecture
        )));
    }
    let manifest_backend_ok = manifest
        .compatibility
        .backends
        .iter()
        .any(|b| b.family == expected.backend && b.architecture == expected.architecture);
    if !manifest_backend_ok {
        return Err(incompatible(format!(
            "backend '{}' on '{}' is not in the manifest allowlist",
            expected.backend, expected.architecture
        )));
    }
    let protocol_ok = composition
        .compatibility
        .protocol_supported
        .iter()
        .any(|r| r.major == expected.protocol_major);
    if !protocol_ok {
        return Err(incompatible(format!(
            "protocol major {} is not in the composition allowlist",
            expected.protocol_major
        )));
    }
    // The manifest is what ADR-0003 negotiates against, so the host must be
    // allowed by the manifest too, not just by the composition.
    let manifest_protocol_ok = manifest
        .protocol
        .supported
        .iter()
        .any(|r| r.major == expected.protocol_major);
    if !manifest_protocol_ok {
        return Err(incompatible(format!(
            "protocol major {} is not in the manifest allowlist",
            expected.protocol_major
        )));
    }
    // Snapshot exclusion contracts must agree: the composition and the
    // manifest must exclude the same ephemeral classes so restore, fork, and
    // warm-snapshot paths cannot diverge by layer.
    let mut comp_excl = composition.compatibility.snapshot_excluded_classes.clone();
    comp_excl.sort();
    let mut manifest_excl = manifest.snapshot.excluded_mount_classes.clone();
    manifest_excl.sort();
    if comp_excl != manifest_excl {
        return Err(incompatible(format!(
            "composition snapshot exclusions {comp_excl:?} do not match manifest {manifest_excl:?}"
        )));
    }
    Ok(())
}

/// Required-manifest features this reader understands.
///
/// A manifest may list required features in
/// `PicoComputeGuestManifest::required_features`; a reader must refuse to boot
/// a manifest naming anything outside this set (ADR-0008 schema rules).
pub fn known_required_features() -> &'static [&'static str] {
    &[ENVIRONMENT_LAYER_FEATURE]
}

/// Report required manifest features this reader does not understand.
///
/// # Errors
///
/// Returns [`ImageError::UnknownRequiredFeature`] naming the first
/// unrecognized feature when the manifest requires behavior this reader
/// cannot provide.
pub fn unknown_required_features(
    manifest: &crate::types::PicoComputeGuestManifest,
) -> Result<(), ImageError> {
    for feature in &manifest.required_features {
        if !known_required_features().contains(&feature.as_str()) {
            return Err(ImageError::UnknownRequiredFeature {
                image_id: manifest.image_id.clone(),
                feature: feature.clone(),
            });
        }
    }
    Ok(())
}

/// Per-layer supply-chain gate: every layer must carry SBOM, provenance, and
/// signature evidence digests.
///
/// ADR-0008 requires those evidence classes for every released artifact, so
/// a composition is only eligible for promotion when this returns an empty
/// list. The evidence digests are bound into
/// [`EnvironmentComposition::composition_digest`], so a decision keyed on that
/// digest also pins the evidence it reviewed. Enforced by
/// `validation::check_environment_supply_chain` and surfaced for operator
/// tooling.
pub fn layers_missing_supply_chain_evidence(composition: &EnvironmentComposition) -> Vec<String> {
    composition
        .ordered_layers()
        .iter()
        .filter(|l| {
            l.sbom_digest.is_none() || l.provenance_digest.is_none() || l.signature_digest.is_none()
        })
        .map(|l| l.name.clone())
        .collect()
}

/// Audit record hosts and placement persist on READY.
///
/// Contains image family, composition digest, ordered layer digests, and the
/// compatibility profile so retrospective audits can prove which exact layer
/// set booted without re-reading the manifest.
pub fn format_composition_audit_record(
    composition: &EnvironmentComposition,
    manifest_digest: &str,
) -> String {
    let layers: Vec<serde_json::Value> = composition
        .ordered_layers()
        .iter()
        .map(|l| {
            serde_json::json!({
                "name": l.name,
                "order": l.order,
                "kind": l.kind.as_str(),
                "digest": l.digest,
            })
        })
        .collect();
    serde_json::json!({
        "image_id": composition.image_id,
        "composition_digest": composition.composition_digest,
        "manifest_digest": manifest_digest,
        "profile_id": composition.compatibility.profile_id,
        "architecture": composition.compatibility.architecture,
        "layer_count": composition.layer_count(),
        "layers": layers,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BackendCompatibility, ProtocolVersionRange};

    pub(crate) fn test_layer(
        name: &str,
        kind: EnvironmentLayerKind,
        digest_suffix: &str,
    ) -> EnvironmentLayer {
        EnvironmentLayer {
            name: name.into(),
            order: 0,
            kind,
            digest: format!("sha256:{digest_suffix}"),
            size: 1024,
            media_type: "application/vnd.pico.layer.erofs".into(),
            version: Some("2026.09.1".into()),
            sbom_digest: Some(
                "sha256:sbom000000000000000000000000000000000000000000000000000000000001".into(),
            ),
            provenance_digest: Some(
                "sha256:prov000000000000000000000000000000000000000000000000000000000001".into(),
            ),
            signature_digest: Some(
                "sha256:sig0000000000000000000000000000000000000000000000000000000000001".into(),
            ),
        }
    }

    pub(crate) fn test_compatibility() -> CompositionCompatibility {
        CompositionCompatibility {
            profile_id: "firecracker-x86_64-v1".into(),
            backends: vec![BackendCompatibility {
                family: "firecracker".into(),
                runtime_version: "1.0".into(),
                architecture: "x86_64".into(),
            }],
            architecture: "x86_64".into(),
            protocol_supported: vec![ProtocolVersionRange {
                major: 1,
                min_minor: 0,
                max_minor: 0,
            }],
            snapshot_excluded_classes: vec!["secret".into(), "runtime_tmp".into()],
        }
    }

    pub(crate) fn test_composition() -> EnvironmentComposition {
        EnvironmentComposition::new(
            "pico-guest-standard",
            test_layer("debian-base", EnvironmentLayerKind::Base, "base"),
            test_layer("workspace-seed", EnvironmentLayerKind::Workspace, "work"),
            vec![
                test_layer("toolkit-python", EnvironmentLayerKind::Toolkit, "py"),
                test_layer("toolkit-node", EnvironmentLayerKind::Toolkit, "nd"),
            ],
            test_compatibility(),
            1781170000,
        )
        .expect("test composition must validate")
    }

    #[test]
    fn new_preserves_declared_toolkit_precedence() {
        // Declaration order wins over name order: the first toolkit declared is
        // the topmost, so shadowing never depends on how a layer was named.
        let comp = EnvironmentComposition::new(
            "img",
            test_layer("b", EnvironmentLayerKind::Base, "b1"),
            test_layer("w", EnvironmentLayerKind::Workspace, "w1"),
            vec![
                test_layer("toolkit-z", EnvironmentLayerKind::Toolkit, "z1"),
                test_layer("toolkit-a", EnvironmentLayerKind::Toolkit, "a1"),
            ],
            test_compatibility(),
            1,
        )
        .unwrap();
        let names: Vec<&str> = comp.toolkits.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["toolkit-z", "toolkit-a"]);
        let orders: Vec<u32> = comp.toolkits.iter().map(|t| t.order).collect();
        assert_eq!(orders, vec![2, 3]);
    }

    #[test]
    fn toolkit_precedence_changes_composition_digest() {
        // Two orderings of the same layer set produce different digests, so the
        // merged view is bound by the composition digest.
        let mk = |names: (&str, &str)| {
            EnvironmentComposition::new(
                "img",
                test_layer("b", EnvironmentLayerKind::Base, "b1"),
                test_layer("w", EnvironmentLayerKind::Workspace, "w1"),
                vec![
                    test_layer(names.0, EnvironmentLayerKind::Toolkit, "t1"),
                    test_layer(names.1, EnvironmentLayerKind::Toolkit, "t2"),
                ],
                test_compatibility(),
                1,
            )
            .unwrap()
        };
        let ab = mk(("toolkit-a", "toolkit-b"));
        let ba = mk(("toolkit-b", "toolkit-a"));
        assert_ne!(ab.composition_digest, ba.composition_digest);
    }

    #[test]
    fn layer_order_must_match_position() {
        let mut comp = test_composition();
        comp.toolkits[0].order = 9;
        let err = validate_environment_composition(&comp).unwrap_err();
        assert!(err.contains("order"), "unexpected error: {err}");
    }

    #[test]
    fn composition_digest_binds_per_layer_evidence() {
        let base = test_composition();
        let mut altered = base.clone();
        altered.toolkits[0].sbom_digest = Some("sha256:different-sbom".into());
        // The digest is unchanged, so recomposition is required to record it.
        let recomputed = compute_composition_digest(
            &altered.image_id,
            &altered.base,
            &altered.workspace,
            &altered.toolkits,
            &altered.compatibility,
        );
        assert_ne!(
            recomputed, base.composition_digest,
            "evidence digests must be bound into the composition digest"
        );
    }

    #[test]
    fn composition_digest_ignores_version_label() {
        let base = test_composition();
        let mut relabelled = base.clone();
        relabelled.toolkits[0].version = Some("2099.01.0".into());
        let recomputed = compute_composition_digest(
            &relabelled.image_id,
            &relabelled.base,
            &relabelled.workspace,
            &relabelled.toolkits,
            &relabelled.compatibility,
        );
        assert_eq!(
            recomputed, base.composition_digest,
            "relabelling must not change layer identity"
        );
    }

    #[test]
    fn ordered_layers_follow_base_workspace_toolkits() {
        // `test_composition` declares python before node, so python is the
        // topmost toolkit and therefore last in bottom-to-top order.
        let comp = test_composition();
        let names: Vec<&str> = comp
            .ordered_layers()
            .iter()
            .map(|l| l.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "debian-base",
                "workspace-seed",
                "toolkit-python",
                "toolkit-node"
            ]
        );
    }

    #[test]
    fn toolkit_rebuild_preserves_base_and_workspace() {
        let comp = test_composition();
        let rebuilt = EnvironmentLayer {
            digest: "sha256:py2".into(),
            size: 2048,
            ..test_layer("toolkit-python", EnvironmentLayerKind::Toolkit, "py")
        };
        let next = comp
            .with_rebuilt_toolkit("toolkit-python", rebuilt)
            .unwrap();
        assert_eq!(next.base.digest, comp.base.digest);
        assert_eq!(next.workspace.digest, comp.workspace.digest);
        assert_ne!(next.composition_digest, comp.composition_digest);
        let plan = plan_rebuild(&comp, &next).unwrap();
        assert!(plan.toolkit_only);
        assert!(!plan.base_or_workspace_changed);
        assert_eq!(plan.changed_layers, vec!["toolkit-python"]);
    }

    #[test]
    fn overlay_plan_orders_lowerdirs_and_flags_collapse() {
        let comp = test_composition();
        let plan = plan_overlay_stack(&comp, "/mnt/layers", "/upper", "/work", "/merged").unwrap();
        assert_eq!(plan.lowerdirs.len(), 4);
        assert!(plan.lowerdirs[0].ends_with("debian-base"));
        assert!(plan.lowerdirs[1].ends_with("workspace-seed"));
        assert_eq!(plan.composition_digest, comp.composition_digest);
        assert!(!plan.collapse_recommended);
        assert!(plan.lowerdir_option.contains("/mnt/layers/debian-base"));
    }

    #[test]
    fn collapse_advice_triggers_at_threshold() {
        let mut toolkits = Vec::new();
        for i in 0..8 {
            toolkits.push(test_layer(
                &format!("toolkit-{i:02}"),
                EnvironmentLayerKind::Toolkit,
                &format!("tk{i:02}"),
            ));
        }
        let comp = EnvironmentComposition::new(
            "img",
            test_layer("b", EnvironmentLayerKind::Base, "bb"),
            test_layer("w", EnvironmentLayerKind::Workspace, "ww"),
            toolkits,
            test_compatibility(),
            1,
        )
        .unwrap();
        assert!(comp.layer_count() >= COLLAPSE_THRESHOLD_LAYERS);
        let advice = collapse_advice(&comp).expect("must recommend collapse");
        assert!(advice.contains(OVERLAYFS_OPAQUE_XATTR));
    }

    #[test]
    fn promotion_advances_one_stage_without_regression() {
        let comp = test_composition();
        let built = CompositionPromotion {
            composition_digest: comp.composition_digest.clone(),
            stage: CompositionPromotionStage::Built,
            policy_revision: "pol-1".into(),
            evidence_digests: vec![],
            approver: "builder".into(),
            decided_at: 1,
        };
        let validated = CompositionPromotion {
            stage: CompositionPromotionStage::Validated,
            ..built.clone()
        };
        let next = built.advance(&validated).unwrap();
        assert_eq!(next.stage, CompositionPromotionStage::Validated);
        assert!(validated.advance(&built).is_err());
    }

    #[test]
    fn rejects_duplicate_layer_names() {
        let res = EnvironmentComposition::new(
            "img",
            test_layer("same", EnvironmentLayerKind::Base, "b1"),
            test_layer("same", EnvironmentLayerKind::Workspace, "w1"),
            vec![],
            test_compatibility(),
            1,
        );
        assert!(res.is_err());
    }
}
