//! Image and rootfs cache model (ST-CACHE).
//!
//! Classifies S-CACHE-COLD, S-CACHE-WARM, and S-CACHE-THRASH observations
//! and emits the report the load harness and cost model
//! consume. P0 tests exercise the model with synthetic series.
//! P1+ host runs must feed the same [`analyze_image_cache`] seam.
//!
//! This module does not generate load, pull images, or set a launch proven
//! operating point. P0/P1 reports never authorize regional quotas.

use serde::{Deserialize, Serialize};

use crate::capacity::{
    CapacityFinding, CapacityScope, DensityZone, FailureClass, ResourcePressureSample,
    ValidationPhase, ZoneBounds,
};
use crate::runtime::RuntimeType;
use crate::snapshot::cache_tiering::CacheTier;

/// ADR-0012 scenarios owned by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImageCacheScenario {
    /// WP-COLD against empty host/cell cache.
    #[serde(rename = "S-CACHE-COLD")]
    Cold,
    /// Repeat boots of the candidate image.
    #[serde(rename = "S-CACHE-WARM")]
    Warm,
    /// Working set larger than cache.
    #[serde(rename = "S-CACHE-THRASH")]
    Thrash,
}

impl ImageCacheScenario {
    /// Axis used for zone bounds and the knee.
    pub fn axis(self) -> ImageCacheAxis {
        match self {
            Self::Thrash => ImageCacheAxis::WorkingSetImages,
            Self::Cold | Self::Warm => ImageCacheAxis::ConcurrentPrepares,
        }
    }

    /// Scenario identifier used in evidence artifacts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "S-CACHE-COLD",
            Self::Warm => "S-CACHE-WARM",
            Self::Thrash => "S-CACHE-THRASH",
        }
    }
}

/// Measured quantity that defines an image-cache zone boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageCacheAxis {
    /// Concurrent in-flight image prepares (cold/warm).
    ConcurrentPrepares,
    /// Distinct images in the working set (thrash).
    WorkingSetImages,
}

/// Guest image profile under prepare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageProfile {
    /// Minimal rootfs (alpine-like).
    Minimal,
    /// MIX-AGENT-V1 guest.
    Agent,
    /// WP-SESSION guest.
    Session,
}

impl ImageProfile {
    /// Identifier used in reports and metric labels.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Agent => "agent",
            Self::Session => "session",
        }
    }
}

/// Cache lookup result for one prepare window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageCacheResult {
    /// Digest already materialized on this tier.
    Hit,
    /// Digest had to be fetched or promoted.
    Miss,
    /// Lookup missed because a prior entry was evicted.
    Evicted,
}

impl ImageCacheResult {
    /// Identifier used in reports and `cache_result` labels.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Evicted => "evicted",
        }
    }
}

/// Thresholds that map an image-cache sample onto [`DensityZone`].
///
/// Availability SLOs are error ratios on terminal valid events.
/// Prepare/verify/overlay p99 values are diagnostic until latency histogram
/// buckets are budgeted.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ImageCacheThresholds {
    /// Inclusive upper bound of the safe boot-error band.
    pub boot_error_warning: f64,
    /// Inclusive lower bound of the saturation boot-error band.
    pub boot_error_saturation: f64,
    /// Diagnostic warm prepare p99 (1s). Does not saturate a zone.
    pub warm_prepare_p99_warning_secs: f64,
    /// Diagnostic verify p99. Does not saturate a zone.
    pub verify_p99_warning_secs: f64,
    /// Diagnostic overlay p99. Does not saturate a zone.
    pub overlay_p99_warning_secs: f64,
    pub utilization_warning: f64,
    pub utilization_saturation: f64,
    pub memory_pressure_warning: f64,
    pub memory_pressure_saturation: f64,
    /// Warm host-local hit-rate warning (does not saturate if boots succeed).
    pub warm_hit_rate_warning: f64,
    /// Relative error band for advertised vs recommended cache bytes.
    pub calibration_error_band: f64,
    /// Extra capacity kept above the measured working set.
    pub cache_headroom: f64,
}

impl Default for ImageCacheThresholds {
    fn default() -> Self {
        Self {
            boot_error_warning: 0.0025,
            boot_error_saturation: 0.005,
            warm_prepare_p99_warning_secs: 1.0,
            verify_p99_warning_secs: 0.05,
            overlay_p99_warning_secs: 0.5,
            utilization_warning: 0.75,
            utilization_saturation: 0.90,
            memory_pressure_warning: 15.0,
            memory_pressure_saturation: 30.0,
            warm_hit_rate_warning: 0.90,
            calibration_error_band: 0.15,
            cache_headroom: 0.25,
        }
    }
}

/// Safety invariants that fail the run even when SLOs are green.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageCacheSafetyFlags {
    /// Isolation floor held.
    pub isolation_held: bool,
    /// Destroy/cleanup completed for failed prepares.
    pub cleanup_complete: bool,
    /// Backend selection did not change under pressure.
    pub backend_unchanged: bool,
    /// Overlay, layer, or fd leak detected.
    pub leak_detected: bool,
    /// No credential or undeclared secret material in cached layers.
    pub secret_free: bool,
    /// Served digest matched the pin.
    pub digest_held: bool,
    /// Signature and attestation checks ran and passed (or denied closed).
    pub signature_verified: bool,
    /// Pulls were digest-pinned, never a floating tag.
    pub pinned: bool,
    /// Host skipped verification on a cache hit.
    pub verification_skipped: bool,
}

impl Default for ImageCacheSafetyFlags {
    fn default() -> Self {
        Self {
            isolation_held: true,
            cleanup_complete: true,
            backend_unchanged: true,
            leak_detected: false,
            secret_free: true,
            digest_held: true,
            signature_verified: true,
            pinned: true,
            verification_skipped: false,
        }
    }
}

/// One held image-prepare load step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageCacheObservation {
    /// Concurrent in-flight image prepares.
    pub concurrent_prepares: u64,
    /// Distinct images offered in this window.
    pub working_set_images: u64,
    /// Configured cache capacity for this tier.
    pub cache_capacity_bytes: u64,
    /// Occupied cache bytes after the window.
    pub cache_used_bytes: u64,
    /// Prepare attempts offered.
    pub offered: u64,
    /// Prepare attempts admitted.
    pub admitted: u64,
    /// Prepare attempts completed.
    pub completed: u64,
    /// Intended `unavailable` shed.
    pub unavailable_rejects: u64,
    /// Timeouts (must not rise with shed).
    pub timeouts: u64,
    /// SLO-BOOT error ratio on terminal valid events.
    pub boot_error_ratio: f64,
    /// Boots that failed `reason=image` (fail-closed is allowed on cold).
    pub boot_reason_image: u64,
    pub prepare_p50_seconds: Option<f64>,
    pub prepare_p95_seconds: Option<f64>,
    pub prepare_p99_seconds: Option<f64>,
    pub verify_p50_seconds: Option<f64>,
    pub verify_p95_seconds: Option<f64>,
    pub verify_p99_seconds: Option<f64>,
    pub overlay_p50_seconds: Option<f64>,
    pub overlay_p95_seconds: Option<f64>,
    pub overlay_p99_seconds: Option<f64>,
    pub image_profile: ImageProfile,
    pub cache_tier: CacheTier,
    pub cache_result: ImageCacheResult,
    pub image_size_bytes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    /// Same-digest prepares that did not share one in-flight fetch.
    pub duplicate_fetches: u64,
    pub unsigned_served: u64,
    pub unpinned_served: u64,
    pub unverified_served: u64,
    pub wrong_digest_served: u64,
    pub tenant_layer_leaks: u64,
    pub pressure: ResourcePressureSample,
    pub safety: ImageCacheSafetyFlags,
    pub scheduler_placed: bool,
    pub scheduler_should_throttle: bool,
    /// Image verification/promotion audit events in this window.
    pub audit_events: u64,
}

impl ImageCacheObservation {
    /// Warm host-local hit at `concurrent_prepares`.
    pub fn warm_at_concurrent(concurrent_prepares: u64) -> Self {
        Self {
            concurrent_prepares,
            working_set_images: 1,
            cache_capacity_bytes: lab_host_local_cache_bytes(),
            cache_used_bytes: lab_typical_image_bytes(),
            offered: concurrent_prepares,
            admitted: concurrent_prepares,
            completed: concurrent_prepares,
            unavailable_rejects: 0,
            timeouts: 0,
            boot_error_ratio: 0.0,
            boot_reason_image: 0,
            prepare_p50_seconds: Some(0.08),
            prepare_p95_seconds: Some(0.12),
            prepare_p99_seconds: Some(0.18),
            verify_p50_seconds: Some(0.002),
            verify_p95_seconds: Some(0.004),
            verify_p99_seconds: Some(0.008),
            overlay_p50_seconds: Some(0.04),
            overlay_p95_seconds: Some(0.07),
            overlay_p99_seconds: Some(0.12),
            image_profile: ImageProfile::Minimal,
            cache_tier: CacheTier::HostLocal,
            cache_result: ImageCacheResult::Hit,
            image_size_bytes: lab_typical_image_bytes(),
            cache_hits: concurrent_prepares,
            cache_misses: 0,
            cache_evictions: 0,
            duplicate_fetches: 0,
            unsigned_served: 0,
            unpinned_served: 0,
            unverified_served: 0,
            wrong_digest_served: 0,
            tenant_layer_leaks: 0,
            pressure: ResourcePressureSample::default(),
            safety: ImageCacheSafetyFlags::default(),
            scheduler_placed: true,
            scheduler_should_throttle: false,
            audit_events: concurrent_prepares,
        }
    }

    /// Cold miss at `concurrent_prepares` against an empty cache.
    pub fn cold_at_concurrent(concurrent_prepares: u64) -> Self {
        let mut obs = Self::warm_at_concurrent(concurrent_prepares);
        obs.cache_used_bytes = 0;
        obs.cache_result = ImageCacheResult::Miss;
        obs.cache_hits = 0;
        obs.cache_misses = concurrent_prepares;
        obs.prepare_p50_seconds = Some(4.0);
        obs.prepare_p95_seconds = Some(8.0);
        obs.prepare_p99_seconds = Some(12.0);
        obs.overlay_p50_seconds = Some(0.20);
        obs.overlay_p95_seconds = Some(0.35);
        obs.overlay_p99_seconds = Some(0.45);
        obs
    }

    /// Thrash step: working set larger than cache slots.
    pub fn thrash_at_working_set(working_set_images: u64, cache_slots: u64) -> Self {
        let evictions = working_set_images.saturating_sub(cache_slots);
        let mut obs = Self::warm_at_concurrent(working_set_images);
        obs.working_set_images = working_set_images;
        obs.cache_capacity_bytes = cache_slots.saturating_mul(lab_typical_image_bytes());
        obs.cache_used_bytes = cache_slots.min(working_set_images) * lab_typical_image_bytes();
        obs.cache_result = if evictions > 0 {
            ImageCacheResult::Evicted
        } else {
            ImageCacheResult::Hit
        };
        obs.cache_hits = cache_slots.min(working_set_images);
        obs.cache_misses = evictions;
        obs.cache_evictions = evictions;
        obs.prepare_p50_seconds = Some(if evictions > 0 { 3.0 } else { 0.08 });
        obs.prepare_p95_seconds = Some(if evictions > 0 { 7.0 } else { 0.12 });
        obs.prepare_p99_seconds = Some(if evictions > 0 { 11.0 } else { 0.18 });
        obs
    }

    fn axis_value(&self, axis: ImageCacheAxis) -> u64 {
        match axis {
            ImageCacheAxis::ConcurrentPrepares => self.concurrent_prepares,
            ImageCacheAxis::WorkingSetImages => self.working_set_images,
        }
    }
}

/// Why a step landed in its zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageCacheZoneReason {
    WithinEnvelope,
    MemoryPressure,
    UtilizationPressure,
    BootErrorRatio,
    PrepareLatency,
    VerifyLatency,
    OverlayLatency,
    SchedulerThrottle,
    SchedulerRejected,
    TimeoutInsteadOfShed,
    IsolationBroken,
    CleanupIncomplete,
    BackendChanged,
    ResourceLeak,
    SecretMaterial,
    CacheMiss,
    CacheEviction,
    UnsignedServed,
    UnpinnedServed,
    UnverifiedServed,
    WrongDigest,
    VerificationSkipped,
    TenantLayerLeak,
}

/// Classified cold/warm/thrash step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassifiedImageCacheStep {
    /// Axis value for this step.
    pub axis_value: u64,
    /// Operating zone.
    pub zone: DensityZone,
    /// Why the step landed in that zone.
    pub reasons: Vec<ImageCacheZoneReason>,
    /// Source sample.
    pub observation: ImageCacheObservation,
}

/// p50/p95/p99 prepare, verify, and overlay latency for one profile and tier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImagePrepareLatencySlice {
    pub image_profile: ImageProfile,
    pub cache_tier: CacheTier,
    pub cache_result: ImageCacheResult,
    pub host_sku: String,
    pub prepare_p50_seconds: Option<f64>,
    pub prepare_p95_seconds: Option<f64>,
    pub prepare_p99_seconds: Option<f64>,
    pub verify_p50_seconds: Option<f64>,
    pub verify_p95_seconds: Option<f64>,
    pub verify_p99_seconds: Option<f64>,
    pub overlay_p50_seconds: Option<f64>,
    pub overlay_p95_seconds: Option<f64>,
    pub overlay_p99_seconds: Option<f64>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    pub completed: u64,
}

/// Aggregated cache hit/miss/eviction counts for the series.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ImageCacheTelemetry {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub hit_rate: Option<f64>,
}

/// Advertised cache bytes vs recommended size from the measured working set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageCacheCalibration {
    pub advertised_bytes: u64,
    pub recommended_bytes: u64,
    pub measured_working_set_images: Option<u64>,
    pub relative_error: Option<f64>,
    pub error_band: f64,
    pub within_band: bool,
    pub class: Option<FailureClass>,
}

/// Recommended cache size for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageCacheSizeRecommendation {
    pub host_local_bytes: u64,
    pub cell_cache_bytes: u64,
    pub working_set_images: u64,
    pub typical_image_bytes: u64,
    pub headroom: f64,
}

/// Dashboards, alerts, traces, and audit kinds operators must watch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageCacheObservabilityEvidence {
    /// Grafana dashboard UIDs.
    pub dashboards: Vec<String>,
    /// Prometheus alert names.
    pub alerts: Vec<String>,
    /// Trace selectors (service/span/outcome).
    pub traces: Vec<String>,
    /// Audit event kinds.
    pub audit_kinds: Vec<String>,
}

impl ImageCacheObservabilityEvidence {
    /// P0 evidence set. Live scrape is not required; names must match
    /// dashboards, recording rules, and the image-cache runbook.
    pub fn p0_required() -> Self {
        Self {
            dashboards: vec![
                "pico-image-cache".into(),
                "pico-lifecycle-operations".into(),
                "pico-slo-error-budget".into(),
            ],
            alerts: vec![
                "PicoComputeImageCacheHitRateLow".into(),
                "PicoComputeImagePrepareSaturated".into(),
                "PicoComputeSloBurnFast".into(),
            ],
            traces: vec!["prepare_sandbox".into(), "image_prepare".into()],
            audit_kinds: vec!["image_verification".into()],
        }
    }

    fn is_complete(&self) -> bool {
        let required = Self::p0_required();
        contains_all(&self.dashboards, &required.dashboards)
            && contains_all(&self.alerts, &required.alerts)
            && contains_all(&self.traces, &required.traces)
            && contains_all(&self.audit_kinds, &required.audit_kinds)
    }
}

fn contains_all(haystack: &[String], needles: &[String]) -> bool {
    needles
        .iter()
        .all(|need| haystack.iter().any(|h| h == need))
}

/// Input to [`analyze_image_cache`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageCacheInput {
    /// Scenario under test.
    pub scenario: ImageCacheScenario,
    /// Validation phase. P0/P1 must not set an LPOP.
    pub phase: ValidationPhase,
    /// Aggregation scope.
    pub scope: CapacityScope,
    /// Runtime backend for this series.
    pub backend: RuntimeType,
    /// Host SKU identifier (for example `lab-64vcpu`).
    pub host_sku: String,
    /// Advertised host-local or cell cache bytes.
    pub advertised_cache_bytes: u64,
    /// Ordered load steps.
    pub steps: Vec<ImageCacheObservation>,
    pub thresholds: ImageCacheThresholds,
    /// Named dashboards, alerts, traces, and audit kinds.
    pub observability: ImageCacheObservabilityEvidence,
    /// True when Grafana/alertmanager were scraped in this run.
    pub live_observability: bool,
    /// True when host image fetch/verify/cache actually ran.
    pub image_path_live: bool,
    /// True when per-sandbox rootfs overlay creation actually ran.
    pub overlay_path_live: bool,
}

/// Image cache report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageCacheReport {
    pub scenario: ImageCacheScenario,
    pub phase: ValidationPhase,
    pub scope: CapacityScope,
    pub backend: RuntimeType,
    pub host_sku: String,
    pub axis: ImageCacheAxis,
    pub zones: ZoneBounds,
    pub knee: Option<u64>,
    /// Always `None` before P2.
    pub proposed_lpop: Option<u64>,
    pub calibration: ImageCacheCalibration,
    pub sizing: ImageCacheSizeRecommendation,
    pub latency_by_profile_and_tier: Vec<ImagePrepareLatencySlice>,
    pub cache: ImageCacheTelemetry,
    pub findings: Vec<CapacityFinding>,
    pub steps: Vec<ClassifiedImageCacheStep>,
    pub observability: ImageCacheObservabilityEvidence,
}

impl ImageCacheReport {
    /// Content digest of the report JSON (hex-encoded blake3).
    pub fn artifact_digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Short Markdown summary for the evidence bundle.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Image cache report\n\n");
        out.push_str(&format!(
            "- Scenario: {}\n- Phase: {:?}\n- Scope: {:?}\n- Backend: {}\n- Host SKU: {}\n",
            self.scenario.as_str(),
            self.phase,
            self.scope,
            self.backend,
            self.host_sku
        ));
        out.push_str(&format!(
            "- Safe max: {}\n- Warning max (LPOP cap): {}\n- Saturation onset/knee: {}\n- Proposed LPOP: {}\n",
            fmt_opt(self.zones.safe_max),
            fmt_opt(self.zones.warning_max),
            fmt_opt(self.knee),
            fmt_opt(self.proposed_lpop)
        ));
        out.push_str(&format!(
            "- Advertised cache bytes: {}\n- Recommended host-local bytes: {}\n- Recommended cell bytes: {}\n- Cache hit rate: {}\n",
            self.calibration.advertised_bytes,
            self.sizing.host_local_bytes,
            self.sizing.cell_cache_bytes,
            self.cache
                .hit_rate
                .map(|rate| format!("{rate:.3}"))
                .unwrap_or_else(|| "none".into())
        ));
        if self.latency_by_profile_and_tier.is_empty() {
            out.push_str("- Latency by profile/tier: none\n");
        } else {
            out.push_str("- Latency by profile/tier:\n");
            for slice in &self.latency_by_profile_and_tier {
                out.push_str(&format!(
                    "  - {}/{}/{}: prepare p50={} p99={} verify p99={} overlay p99={}\n",
                    slice.image_profile.as_str(),
                    slice.cache_tier.as_str(),
                    slice.cache_result.as_str(),
                    fmt_lat(slice.prepare_p50_seconds),
                    fmt_lat(slice.prepare_p99_seconds),
                    fmt_lat(slice.verify_p99_seconds),
                    fmt_lat(slice.overlay_p99_seconds)
                ));
            }
        }
        if self.findings.is_empty() {
            out.push_str("- Findings: none\n");
        } else {
            out.push_str("- Findings:\n");
            for finding in &self.findings {
                out.push_str(&format!(
                    "  - class {:?}: {} ({})\n",
                    finding.class, finding.code, finding.detail
                ));
            }
        }
        out
    }
}

fn fmt_opt(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn fmt_lat(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.3}s"))
        .unwrap_or_else(|| "none".into())
}

fn finding(class: FailureClass, code: &str, detail: impl Into<String>) -> CapacityFinding {
    CapacityFinding {
        class,
        code: code.into(),
        detail: detail.into(),
        follow_up_issue: None,
    }
}

fn finding_follow(
    class: FailureClass,
    code: &str,
    detail: impl Into<String>,
    issue: &str,
) -> CapacityFinding {
    CapacityFinding {
        class,
        code: code.into(),
        detail: detail.into(),
        follow_up_issue: Some(issue.into()),
    }
}

/// Lab-host typical guest image size used by P0 sizing (`512 MiB`).
pub fn lab_typical_image_bytes() -> u64 {
    512 * 1024 * 1024
}

/// Lab-host local image cache cap (`8 GiB`).
pub fn lab_host_local_cache_bytes() -> u64 {
    8 * 1024 * 1024 * 1024
}

/// Lab cell image cache cap (`32 GiB`).
pub fn lab_cell_cache_bytes() -> u64 {
    32 * 1024 * 1024 * 1024
}

/// Lab-host working set that the 8 GiB host-local cache is sized for.
pub fn lab_host_local_working_set_images() -> u64 {
    8
}

/// Cache bytes needed to hold `working_set_images` at `typical_image_bytes`
/// plus `headroom`.
pub fn recommend_cache_bytes(
    working_set_images: u64,
    typical_image_bytes: u64,
    headroom: f64,
) -> u64 {
    let raw = working_set_images as f64 * typical_image_bytes as f64 * (1.0 + headroom);
    raw.ceil() as u64
}

/// Unproven P0 sizing for the lab SKU.
pub fn lab_cache_size_recommendation() -> ImageCacheSizeRecommendation {
    let typical = lab_typical_image_bytes();
    let headroom = ImageCacheThresholds::default().cache_headroom;
    let host_ws = lab_host_local_working_set_images();
    ImageCacheSizeRecommendation {
        host_local_bytes: recommend_cache_bytes(host_ws, typical, headroom),
        cell_cache_bytes: recommend_cache_bytes(host_ws * 4, typical, headroom),
        working_set_images: host_ws,
        typical_image_bytes: typical,
        headroom,
    }
}

/// Classify one observation against the provided thresholds.
pub fn classify_image_cache(
    observation: &ImageCacheObservation,
    scenario: ImageCacheScenario,
    thresholds: &ImageCacheThresholds,
) -> ClassifiedImageCacheStep {
    let mut reasons = Vec::new();
    let safety = &observation.safety;

    if !safety.isolation_held {
        reasons.push(ImageCacheZoneReason::IsolationBroken);
    }
    if !safety.cleanup_complete {
        reasons.push(ImageCacheZoneReason::CleanupIncomplete);
    }
    if !safety.backend_unchanged {
        reasons.push(ImageCacheZoneReason::BackendChanged);
    }
    if safety.leak_detected {
        reasons.push(ImageCacheZoneReason::ResourceLeak);
    }
    if !safety.secret_free {
        reasons.push(ImageCacheZoneReason::SecretMaterial);
    }
    if observation.unsigned_served > 0 {
        reasons.push(ImageCacheZoneReason::UnsignedServed);
    }
    if observation.unpinned_served > 0 {
        reasons.push(ImageCacheZoneReason::UnpinnedServed);
    }
    if observation.unverified_served > 0 {
        reasons.push(ImageCacheZoneReason::UnverifiedServed);
    }
    if observation.wrong_digest_served > 0 {
        reasons.push(ImageCacheZoneReason::WrongDigest);
    }
    if safety.verification_skipped {
        reasons.push(ImageCacheZoneReason::VerificationSkipped);
    }
    if observation.tenant_layer_leaks > 0 {
        reasons.push(ImageCacheZoneReason::TenantLayerLeak);
    }
    if observation.timeouts > 0 && observation.unavailable_rejects > 0 {
        reasons.push(ImageCacheZoneReason::TimeoutInsteadOfShed);
    }

    let safety_fail = reasons.iter().any(|r| {
        matches!(
            r,
            ImageCacheZoneReason::IsolationBroken
                | ImageCacheZoneReason::CleanupIncomplete
                | ImageCacheZoneReason::BackendChanged
                | ImageCacheZoneReason::ResourceLeak
                | ImageCacheZoneReason::SecretMaterial
                | ImageCacheZoneReason::UnsignedServed
                | ImageCacheZoneReason::UnpinnedServed
                | ImageCacheZoneReason::UnverifiedServed
                | ImageCacheZoneReason::WrongDigest
                | ImageCacheZoneReason::VerificationSkipped
                | ImageCacheZoneReason::TenantLayerLeak
                | ImageCacheZoneReason::TimeoutInsteadOfShed
        )
    });

    if observation.boot_error_ratio >= thresholds.boot_error_saturation {
        reasons.push(ImageCacheZoneReason::BootErrorRatio);
    }
    if observation.pressure.memory_cgroup >= thresholds.memory_pressure_saturation {
        reasons.push(ImageCacheZoneReason::MemoryPressure);
    }
    if utilization_saturated(&observation.pressure, thresholds) {
        reasons.push(ImageCacheZoneReason::UtilizationPressure);
    }
    if !observation.scheduler_placed && observation.offered > observation.admitted {
        reasons.push(ImageCacheZoneReason::SchedulerRejected);
    }

    let saturating = safety_fail
        || reasons.iter().any(|r| {
            matches!(
                r,
                ImageCacheZoneReason::BootErrorRatio
                    | ImageCacheZoneReason::MemoryPressure
                    | ImageCacheZoneReason::UtilizationPressure
                    | ImageCacheZoneReason::SchedulerRejected
            )
        });

    if saturating {
        return ClassifiedImageCacheStep {
            axis_value: observation.axis_value(scenario.axis()),
            zone: DensityZone::Saturation,
            reasons,
            observation: observation.clone(),
        };
    }

    if observation.boot_error_ratio >= thresholds.boot_error_warning {
        reasons.push(ImageCacheZoneReason::BootErrorRatio);
    }
    if observation.pressure.memory_cgroup >= thresholds.memory_pressure_warning {
        reasons.push(ImageCacheZoneReason::MemoryPressure);
    }
    if utilization_warning(&observation.pressure, thresholds) {
        reasons.push(ImageCacheZoneReason::UtilizationPressure);
    }
    if matches!(scenario, ImageCacheScenario::Warm)
        && observation
            .prepare_p99_seconds
            .is_some_and(|p99| p99 >= thresholds.warm_prepare_p99_warning_secs)
    {
        reasons.push(ImageCacheZoneReason::PrepareLatency);
    }
    if observation
        .verify_p99_seconds
        .is_some_and(|p99| p99 >= thresholds.verify_p99_warning_secs)
    {
        reasons.push(ImageCacheZoneReason::VerifyLatency);
    }
    if observation
        .overlay_p99_seconds
        .is_some_and(|p99| p99 >= thresholds.overlay_p99_warning_secs)
    {
        reasons.push(ImageCacheZoneReason::OverlayLatency);
    }
    if observation.scheduler_should_throttle {
        reasons.push(ImageCacheZoneReason::SchedulerThrottle);
    }
    if observation.cache_misses > 0 && !matches!(scenario, ImageCacheScenario::Cold) {
        reasons.push(ImageCacheZoneReason::CacheMiss);
    }
    if observation.cache_evictions > 0 && matches!(scenario, ImageCacheScenario::Warm) {
        reasons.push(ImageCacheZoneReason::CacheEviction);
    }

    let zone = if reasons.is_empty() {
        reasons.push(ImageCacheZoneReason::WithinEnvelope);
        DensityZone::Safe
    } else {
        DensityZone::Warning
    };

    ClassifiedImageCacheStep {
        axis_value: observation.axis_value(scenario.axis()),
        zone,
        reasons,
        observation: observation.clone(),
    }
}

fn utilization_saturated(
    pressure: &ResourcePressureSample,
    thresholds: &ImageCacheThresholds,
) -> bool {
    pressure.cpu >= thresholds.utilization_saturation
        || pressure.disk >= thresholds.utilization_saturation
        || pressure.network >= thresholds.utilization_saturation
        || pressure.process_slots >= thresholds.utilization_saturation
}

fn utilization_warning(
    pressure: &ResourcePressureSample,
    thresholds: &ImageCacheThresholds,
) -> bool {
    pressure.cpu >= thresholds.utilization_warning
        || pressure.disk >= thresholds.utilization_warning
        || pressure.network >= thresholds.utilization_warning
        || pressure.process_slots >= thresholds.utilization_warning
}

/// Classify an image-cache series and emit zone bounds, latency slices, and sizing.
pub fn analyze_image_cache(input: ImageCacheInput) -> ImageCacheReport {
    let axis = input.scenario.axis();
    let mut steps: Vec<ClassifiedImageCacheStep> = input
        .steps
        .iter()
        .map(|obs| classify_image_cache(obs, input.scenario, &input.thresholds))
        .collect();
    steps.sort_by_key(|step| step.axis_value);

    let mut findings = Vec::new();
    if steps.is_empty() {
        findings.push(finding(
            FailureClass::A,
            "no_measurements",
            "image cache report has no steps",
        ));
    }

    let zones = image_cache_zone_bounds(&steps);
    let knee = zones
        .saturation_onset
        .or_else(|| image_cache_goodput_knee(&steps));
    let proposed_lpop = if input.phase.may_set_lpop() {
        zones.warning_max
    } else {
        None
    };

    if !input.phase.may_set_lpop() {
        findings.push(finding(
            FailureClass::C,
            "phase_cannot_set_lpop",
            format!(
                "{:?} may not set an LPOP; warning max is a candidate input only",
                input.phase
            ),
        ));
    }

    if zones.saturation_onset.is_none() && !steps.is_empty() {
        findings.push(finding(
            FailureClass::C,
            "saturation_not_reached",
            "run did not reach a saturation knee",
        ));
    }

    for step in &steps {
        push_image_cache_findings(&mut findings, step);
    }

    if matches!(input.scenario, ImageCacheScenario::Thrash)
        && steps.iter().any(|s| {
            s.reasons.iter().any(|r| {
                matches!(
                    r,
                    ImageCacheZoneReason::WrongDigest
                        | ImageCacheZoneReason::VerificationSkipped
                        | ImageCacheZoneReason::TenantLayerLeak
                        | ImageCacheZoneReason::UnsignedServed
                )
            })
        })
    {
        findings.push(finding(
            FailureClass::A,
            "thrash_broke_supply_chain",
            "S-CACHE-THRASH eviction served a wrong digest, skipped verification, or leaked layers",
        ));
    }

    let cache = cache_telemetry(&steps);
    if matches!(input.scenario, ImageCacheScenario::Warm)
        && let Some(host_local_rate) = host_local_hit_rate(&steps)
        && host_local_rate < input.thresholds.warm_hit_rate_warning
    {
        findings.push(finding(
            FailureClass::B,
            "warm_cache_hit_rate_low",
            format!(
                "host-local hit rate {host_local_rate:.3} is below {}",
                input.thresholds.warm_hit_rate_warning
            ),
        ));
    }

    let typical_image = typical_image_bytes(&steps);
    let fitting = if axis == ImageCacheAxis::WorkingSetImages {
        fitting_working_set(&steps)
    } else {
        None
    };
    let working_set = fitting.unwrap_or_else(lab_host_local_working_set_images);
    let recommended_host =
        recommend_cache_bytes(working_set, typical_image, input.thresholds.cache_headroom);
    let sizing = ImageCacheSizeRecommendation {
        host_local_bytes: recommended_host,
        cell_cache_bytes: recommend_cache_bytes(
            working_set * 4,
            typical_image,
            input.thresholds.cache_headroom,
        ),
        working_set_images: working_set,
        typical_image_bytes: typical_image,
        headroom: input.thresholds.cache_headroom,
    };
    let calibration = if axis == ImageCacheAxis::WorkingSetImages {
        calibrate_cache_bytes(
            input.advertised_cache_bytes,
            recommended_host,
            fitting,
            input.thresholds.calibration_error_band,
        )
    } else {
        ImageCacheCalibration {
            advertised_bytes: input.advertised_cache_bytes,
            recommended_bytes: recommended_host,
            measured_working_set_images: None,
            relative_error: None,
            error_band: input.thresholds.calibration_error_band,
            within_band: true,
            class: None,
        }
    };
    if let Some(class) = calibration.class {
        let code = match class {
            FailureClass::A => "cache_under_sized",
            FailureClass::B => "cache_over_sized",
            FailureClass::C => "cache_unmeasured",
        };
        findings.push(finding(
            class,
            code,
            format!(
                "advertised {} vs recommended {}",
                calibration.advertised_bytes, calibration.recommended_bytes
            ),
        ));
    }

    if !input.image_path_live {
        findings.push(finding_follow(
            FailureClass::C,
            "image_path_not_live",
            "host image fetch/verify/cache is not on the prepare path; this series is synthetic",
            "BSD-184",
        ));
    }
    if !input.overlay_path_live {
        findings.push(finding_follow(
            FailureClass::C,
            "overlay_path_not_live",
            "per-sandbox rootfs overlay creation is not implemented; overlay latency is synthetic",
            "BSD-184",
        ));
    }
    if !input.live_observability {
        findings.push(finding(
            FailureClass::C,
            "live_dashboard_not_exercised",
            "named dashboards and alerts are the operator evidence set; live scrape was not run",
        ));
    }
    if !input.observability.is_complete() {
        findings.push(finding(
            FailureClass::B,
            "observability_evidence_incomplete",
            "report is missing a required dashboard, alert, trace, or audit kind",
        ));
    }
    findings.push(finding_follow(
        FailureClass::C,
        "harness_not_driving_live",
        "live S-CACHE-COLD/S-CACHE-WARM/S-CACHE-THRASH require the 22 harness",
        "22",
    ));
    findings.push(finding_follow(
        FailureClass::C,
        "image_cache_result_labels_missing",
        "sandbox prepare histograms are not labeled cache_result; report slices use observation fields",
        "21",
    ));

    if steps.iter().any(|s| s.observation.duplicate_fetches > 0) {
        findings.push(finding(
            FailureClass::B,
            "prepare_not_single_flight",
            "concurrent prepares of the same digest issued duplicate fetches",
        ));
    }

    dedupe_findings(&mut findings);

    ImageCacheReport {
        scenario: input.scenario,
        phase: input.phase,
        scope: input.scope,
        backend: input.backend,
        host_sku: input.host_sku.clone(),
        axis,
        zones,
        knee,
        proposed_lpop,
        calibration,
        sizing,
        latency_by_profile_and_tier: latency_slices(&input.host_sku, &steps),
        cache,
        findings,
        steps,
        observability: input.observability,
    }
}

fn image_cache_zone_bounds(steps: &[ClassifiedImageCacheStep]) -> ZoneBounds {
    let collapsed = collapse_worst_zone_per_axis(steps);
    let mut safe_max = None;
    let mut warning_max = None;
    let mut saturation_onset = None;
    let mut left_safe = false;
    for (axis_value, zone) in collapsed {
        match zone {
            DensityZone::Safe => {
                if !left_safe && saturation_onset.is_none() {
                    safe_max = Some(axis_value);
                    warning_max = Some(axis_value);
                }
            }
            DensityZone::Warning => {
                left_safe = true;
                if saturation_onset.is_none() {
                    warning_max = Some(axis_value);
                }
            }
            DensityZone::Saturation => {
                left_safe = true;
                if saturation_onset.is_none() {
                    saturation_onset = Some(axis_value);
                }
            }
        }
    }
    ZoneBounds {
        safe_max,
        warning_max,
        saturation_onset,
    }
}

fn collapse_worst_zone_per_axis(steps: &[ClassifiedImageCacheStep]) -> Vec<(u64, DensityZone)> {
    let mut out = Vec::new();
    for step in steps {
        match out.last_mut() {
            Some((axis, zone)) if *axis == step.axis_value => {
                if step.zone > *zone {
                    *zone = step.zone;
                }
            }
            _ => out.push((step.axis_value, step.zone)),
        }
    }
    out
}

fn image_cache_goodput_knee(steps: &[ClassifiedImageCacheStep]) -> Option<u64> {
    let mut prev_completed: Option<u64> = None;
    for step in steps {
        if let Some(prev) = prev_completed
            && step.observation.completed <= prev
            && step.observation.offered > step.observation.completed
        {
            return Some(step.axis_value);
        }
        prev_completed = Some(step.observation.completed);
    }
    None
}

fn cache_telemetry(steps: &[ClassifiedImageCacheStep]) -> ImageCacheTelemetry {
    let hits = steps.iter().map(|s| s.observation.cache_hits).sum();
    let misses = steps.iter().map(|s| s.observation.cache_misses).sum();
    let evictions = steps.iter().map(|s| s.observation.cache_evictions).sum();
    ImageCacheTelemetry {
        hits,
        misses,
        evictions,
        hit_rate: hit_rate(hits, misses),
    }
}

fn host_local_hit_rate(steps: &[ClassifiedImageCacheStep]) -> Option<f64> {
    let hits = steps
        .iter()
        .filter(|s| s.observation.cache_tier == CacheTier::HostLocal)
        .map(|s| s.observation.cache_hits)
        .sum();
    let misses = steps
        .iter()
        .filter(|s| s.observation.cache_tier == CacheTier::HostLocal)
        .map(|s| s.observation.cache_misses)
        .sum();
    hit_rate(hits, misses)
}

fn hit_rate(hits: u64, misses: u64) -> Option<f64> {
    let lookups = hits + misses;
    if lookups == 0 {
        None
    } else {
        Some(hits as f64 / lookups as f64)
    }
}

fn fitting_working_set(steps: &[ClassifiedImageCacheStep]) -> Option<u64> {
    steps
        .iter()
        .filter(|s| {
            s.observation.cache_evictions == 0
                && s.observation.cache_capacity_bytes > 0
                && s.observation.cache_used_bytes <= s.observation.cache_capacity_bytes
        })
        .map(|s| s.observation.working_set_images)
        .max()
        .filter(|ws| *ws > 0)
}

fn typical_image_bytes(steps: &[ClassifiedImageCacheStep]) -> u64 {
    steps
        .iter()
        .map(|s| s.observation.image_size_bytes)
        .max()
        .filter(|bytes| *bytes > 0)
        .unwrap_or_else(lab_typical_image_bytes)
}

fn calibrate_cache_bytes(
    advertised_bytes: u64,
    recommended_bytes: u64,
    measured_working_set_images: Option<u64>,
    error_band: f64,
) -> ImageCacheCalibration {
    if measured_working_set_images.is_none() || recommended_bytes == 0 {
        return ImageCacheCalibration {
            advertised_bytes,
            recommended_bytes,
            measured_working_set_images,
            relative_error: None,
            error_band,
            within_band: advertised_bytes == 0 && recommended_bytes == 0,
            class: Some(FailureClass::C),
        };
    }
    let relative_error =
        (advertised_bytes as f64 - recommended_bytes as f64) / recommended_bytes as f64;
    let within_band = relative_error.abs() <= error_band;
    let class = if within_band {
        None
    } else if relative_error < -error_band {
        Some(FailureClass::A)
    } else {
        Some(FailureClass::B)
    };
    ImageCacheCalibration {
        advertised_bytes,
        recommended_bytes,
        measured_working_set_images,
        relative_error: Some(relative_error),
        error_band,
        within_band,
        class,
    }
}

fn latency_slices(
    host_sku: &str,
    steps: &[ClassifiedImageCacheStep],
) -> Vec<ImagePrepareLatencySlice> {
    let mut slices: Vec<ImagePrepareLatencySlice> = Vec::new();
    for step in steps {
        let obs = &step.observation;
        if let Some(existing) = slices.iter_mut().find(|slice| {
            slice.image_profile == obs.image_profile
                && slice.cache_tier == obs.cache_tier
                && slice.cache_result == obs.cache_result
                && slice.host_sku == host_sku
        }) {
            existing.prepare_p50_seconds =
                max_opt(existing.prepare_p50_seconds, obs.prepare_p50_seconds);
            existing.prepare_p95_seconds =
                max_opt(existing.prepare_p95_seconds, obs.prepare_p95_seconds);
            existing.prepare_p99_seconds =
                max_opt(existing.prepare_p99_seconds, obs.prepare_p99_seconds);
            existing.verify_p50_seconds =
                max_opt(existing.verify_p50_seconds, obs.verify_p50_seconds);
            existing.verify_p95_seconds =
                max_opt(existing.verify_p95_seconds, obs.verify_p95_seconds);
            existing.verify_p99_seconds =
                max_opt(existing.verify_p99_seconds, obs.verify_p99_seconds);
            existing.overlay_p50_seconds =
                max_opt(existing.overlay_p50_seconds, obs.overlay_p50_seconds);
            existing.overlay_p95_seconds =
                max_opt(existing.overlay_p95_seconds, obs.overlay_p95_seconds);
            existing.overlay_p99_seconds =
                max_opt(existing.overlay_p99_seconds, obs.overlay_p99_seconds);
            existing.cache_hits = existing.cache_hits.saturating_add(obs.cache_hits);
            existing.cache_misses = existing.cache_misses.saturating_add(obs.cache_misses);
            existing.cache_evictions = existing.cache_evictions.saturating_add(obs.cache_evictions);
            existing.completed = existing.completed.saturating_add(obs.completed);
        } else {
            slices.push(ImagePrepareLatencySlice {
                image_profile: obs.image_profile,
                cache_tier: obs.cache_tier,
                cache_result: obs.cache_result,
                host_sku: host_sku.to_string(),
                prepare_p50_seconds: obs.prepare_p50_seconds,
                prepare_p95_seconds: obs.prepare_p95_seconds,
                prepare_p99_seconds: obs.prepare_p99_seconds,
                verify_p50_seconds: obs.verify_p50_seconds,
                verify_p95_seconds: obs.verify_p95_seconds,
                verify_p99_seconds: obs.verify_p99_seconds,
                overlay_p50_seconds: obs.overlay_p50_seconds,
                overlay_p95_seconds: obs.overlay_p95_seconds,
                overlay_p99_seconds: obs.overlay_p99_seconds,
                cache_hits: obs.cache_hits,
                cache_misses: obs.cache_misses,
                cache_evictions: obs.cache_evictions,
                completed: obs.completed,
            });
        }
    }
    slices.sort_by_key(|slice| {
        (
            slice.image_profile.as_str(),
            slice.cache_tier.as_str(),
            slice.cache_result.as_str(),
        )
    });
    slices
}

fn max_opt(left: Option<f64>, right: Option<f64>) -> Option<f64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn push_image_cache_findings(findings: &mut Vec<CapacityFinding>, step: &ClassifiedImageCacheStep) {
    for reason in &step.reasons {
        let item = match reason {
            ImageCacheZoneReason::IsolationBroken => Some(finding(
                FailureClass::A,
                "isolation_broken",
                "isolation floor failed under image prepare load",
            )),
            ImageCacheZoneReason::CleanupIncomplete => Some(finding(
                FailureClass::A,
                "cleanup_incomplete",
                "image prepare left overlays, layers, or leases",
            )),
            ImageCacheZoneReason::BackendChanged => Some(finding(
                FailureClass::A,
                "silent_backend_fallback",
                "backend selection changed under image-cache pressure",
            )),
            ImageCacheZoneReason::ResourceLeak => Some(finding(
                FailureClass::A,
                "resource_leak",
                "fd, overlay, or layer count grew without offered load",
            )),
            ImageCacheZoneReason::SecretMaterial => Some(finding(
                FailureClass::A,
                "secret_material_in_cache",
                "credential or undeclared secret state appeared in a cached layer",
            )),
            ImageCacheZoneReason::UnsignedServed => Some(finding(
                FailureClass::A,
                "unsigned_image_served",
                "unsigned image was served from cache",
            )),
            ImageCacheZoneReason::UnpinnedServed => Some(finding(
                FailureClass::A,
                "unpinned_image_served",
                "unpinned tag was pulled or served from cache",
            )),
            ImageCacheZoneReason::UnverifiedServed => Some(finding(
                FailureClass::A,
                "unverified_image_served",
                "unverified image was served from cache",
            )),
            ImageCacheZoneReason::WrongDigest => Some(finding(
                FailureClass::A,
                "wrong_digest_served",
                "cache eviction served a digest other than the pin",
            )),
            ImageCacheZoneReason::VerificationSkipped => Some(finding(
                FailureClass::A,
                "verification_skipped",
                "cache hit skipped signature or digest verification",
            )),
            ImageCacheZoneReason::TenantLayerLeak => Some(finding(
                FailureClass::A,
                "tenant_layer_leak",
                "eviction leaked tenant overlay layers",
            )),
            ImageCacheZoneReason::TimeoutInsteadOfShed => Some(finding(
                FailureClass::A,
                "timeout_instead_of_shed",
                "timeouts rose with unavailable rejects; shed path is not clean",
            )),
            ImageCacheZoneReason::PrepareLatency => Some(finding(
                FailureClass::B,
                "warm_prepare_p99_diagnostic",
                "warm prepare p99 crossed the diagnostic threshold",
            )),
            ImageCacheZoneReason::VerifyLatency => Some(finding(
                FailureClass::B,
                "verify_p99_diagnostic",
                "image signature verification p99 crossed the diagnostic threshold",
            )),
            ImageCacheZoneReason::OverlayLatency => Some(finding(
                FailureClass::B,
                "overlay_p99_diagnostic",
                "rootfs overlay p99 crossed the diagnostic threshold",
            )),
            _ => None,
        };
        if let Some(item) = item {
            findings.push(item);
        }
    }
    if step.observation.audit_events == 0
        && (step.observation.admitted > 0 || step.observation.unavailable_rejects > 0)
    {
        findings.push(finding(
            FailureClass::B,
            "audit_missing_on_image_prepare",
            "image prepare window emitted no image_verification audit events",
        ));
    }
}

fn dedupe_findings(findings: &mut Vec<CapacityFinding>) {
    let mut seen = Vec::new();
    findings.retain(|finding| {
        let key = (finding.class, finding.code.clone());
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
}

/// Compare prepare latency slices across image profiles for the same host SKU.
pub fn compare_image_profiles(reports: &[ImageCacheReport]) -> Vec<ImageProfileRow> {
    reports
        .iter()
        .flat_map(|report| {
            report
                .latency_by_profile_and_tier
                .iter()
                .map(|slice| ImageProfileRow {
                    image_profile: slice.image_profile,
                    host_sku: slice.host_sku.clone(),
                    cache_tier: slice.cache_tier,
                    cache_result: slice.cache_result,
                    prepare_p50_seconds: slice.prepare_p50_seconds,
                    prepare_p99_seconds: slice.prepare_p99_seconds,
                    verify_p99_seconds: slice.verify_p99_seconds,
                    overlay_p99_seconds: slice.overlay_p99_seconds,
                })
        })
        .collect()
}

/// One row of an image-profile comparison table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageProfileRow {
    pub image_profile: ImageProfile,
    pub host_sku: String,
    pub cache_tier: CacheTier,
    pub cache_result: ImageCacheResult,
    pub prepare_p50_seconds: Option<f64>,
    pub prepare_p99_seconds: Option<f64>,
    pub verify_p99_seconds: Option<f64>,
    pub overlay_p99_seconds: Option<f64>,
}

#[cfg(test)]
mod tests;
