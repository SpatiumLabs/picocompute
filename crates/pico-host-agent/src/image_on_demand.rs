//! Verification-gated on-demand image reads (CAP-165).
//!
//! Serves only accessed bytes after the verification gate has admitted the
//! digest. Containers use an EROFS-style metadata-local plus lazy-data path;
//! VM disks use a chunked block path with a local second-level cache
//! (256 KiB chunks, readahead coalescing). Both paths share one fail-closed
//! rule: a network or registry failure never permits unverified cache use,
//! and eviction never serves the wrong digest or skips verification
//! (class-A per ADR-0012).
//!
//! ## Ordering guarantee
//!
//! 1. Verify digest plus production attestation plus revocation first
//!    ([`OnDemandImageCache::admit_verified`]).
//! 2. Fetch on demand only for an admitted digest
//!    ([`OnDemandImageCache::fetch_range`]).
//!
//! `fetch_range` checks the verified set and the revocation list before
//! touching cached bytes or calling the chunk provider. A missing admission,
//! a revoked digest, or a provider failure returns [`FetchError`] and never
//! serves bytes. Chunks are keyed by `(digest, chunk_index)`, so evicting one
//! digest cannot surface another digest's bytes.
//!
//! ## What this is not
//!
//! This is the userspace read-path policy and second-level cache. It does not
//! mount EROFS, OverlayBD, or ublk devices and does not speak the registry
//! wire protocol. The chunk provider seam (`fetch_range`'s `provider`
//! closure) is where a registry client will plug in; the gate around it is
//! what this module guarantees. Composable-layer schema changes are out of
//! scope.

use std::collections::{HashSet, VecDeque};

use hashbrown::HashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::image_verify::{ImageVerificationMode, VerifiedImageRecord};

/// Chunk size for the VM-disk block path (256 KiB, matches the ublk chunk
/// described in CAP-165).
pub const DEFAULT_CHUNK_BYTES: u64 = 256 * 1024;

/// Default second-level cache cap (5 GiB host-local, matches
/// `docs/capacity/image-cache.md`).
pub const DEFAULT_MAX_CACHED_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Default readahead depth in chunks.
pub const DEFAULT_READAHEAD_CHUNKS: u64 = 2;

/// Largest single `fetch_range` read (1 GiB). Bounds the assembled buffer and
/// the chunk loop so a huge `len` cannot OOM the host or spin forever.
pub const MAX_FETCH_BYTES: u64 = 1024 * 1024 * 1024;

/// Largest chunk count per `fetch_range` call. Bounds loop iterations when a
/// small `chunk_bytes` meets a large `len`.
pub const MAX_FETCH_CHUNKS: u64 = 16_384;

/// Lazy-read shape selected per runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LazyReadKind {
    /// Containers: metadata local, file data fetched on demand.
    ContainerMetadataLocal,
    /// VM disks: fixed-size block chunks with a local second-level cache.
    VmChunked,
}

impl LazyReadKind {
    /// Selects the read shape for a runtime.
    pub fn for_runtime(runtime: pico_core::RuntimeType) -> Self {
        match runtime {
            pico_core::RuntimeType::GVisor => Self::ContainerMetadataLocal,
            _ => Self::VmChunked,
        }
    }

    /// Stable identifier for logs and audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContainerMetadataLocal => "container_metadata_local",
            Self::VmChunked => "vm_chunked",
        }
    }
}

/// Configuration for the verification-gated lazy-read path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnDemandConfig {
    /// Master switch. When false the cache refuses every fetch with
    /// [`FetchError::Disabled`] so callers fall back to the eager path.
    #[serde(default)]
    pub enabled: bool,
    /// Chunk size in bytes for the VM-disk path.
    #[serde(default = "default_chunk_bytes")]
    pub chunk_bytes: u64,
    /// Cap for cached chunk bytes before oldest chunks are evicted.
    #[serde(default = "default_max_cached_bytes")]
    pub max_cached_bytes: u64,
    /// Readahead depth in chunks (advisory; the provider decides).
    #[serde(default = "default_readahead_chunks")]
    pub readahead_chunks: u64,
    /// Cache tier label reported on hit/miss/eviction counters.
    #[serde(default = "default_tier")]
    pub tier: String,
    /// Digests refused even when signed (exact `sha256:<hex>` match).
    #[serde(default)]
    pub revoked_digests: Vec<String>,
    /// Optional file holding one revoked digest per line (`#` comments and
    /// blank lines ignored). Loaded at construction; a missing file fails
    /// closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_file: Option<String>,
}

fn default_chunk_bytes() -> u64 {
    DEFAULT_CHUNK_BYTES
}

fn default_max_cached_bytes() -> u64 {
    DEFAULT_MAX_CACHED_BYTES
}

fn default_readahead_chunks() -> u64 {
    DEFAULT_READAHEAD_CHUNKS
}

fn default_tier() -> String {
    "host_local".to_string()
}

impl Default for OnDemandConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            chunk_bytes: default_chunk_bytes(),
            max_cached_bytes: default_max_cached_bytes(),
            readahead_chunks: default_readahead_chunks(),
            tier: default_tier(),
            revoked_digests: Vec::new(),
            revocation_file: None,
        }
    }
}

impl OnDemandConfig {
    /// Validates ranges that would otherwise corrupt chunk math.
    pub fn validated(&self) -> Result<(), String> {
        if self.chunk_bytes == 0 {
            return Err("on-demand chunk_bytes must be non-zero".to_string());
        }
        if self.chunk_bytes > 64 * 1024 * 1024 {
            return Err("on-demand chunk_bytes exceeds 64 MiB".to_string());
        }
        if self.max_cached_bytes == 0 {
            return Err("on-demand max_cached_bytes must be non-zero".to_string());
        }
        if self.tier.is_empty() || self.tier.contains('/') || self.tier.contains(' ') {
            return Err("on-demand tier must be a non-empty label-safe string".to_string());
        }
        Ok(())
    }
}

/// Digests refused by the verification gate.
#[derive(Debug, Clone, Default)]
pub struct RevocationList {
    revoked: HashSet<String>,
}

impl RevocationList {
    /// Builds the list from config plus an optional revocation file.
    ///
    /// A configured but unreadable revocation file fails closed: construction
    /// returns an error and the host must refuse on-demand serves rather than
    /// run without revocation data.
    pub fn from_config(config: &OnDemandConfig) -> Result<Self, String> {
        let mut revoked: HashSet<String> = config.revoked_digests.iter().cloned().collect();
        if let Some(path) = config.revocation_file.as_deref() {
            let contents = std::fs::read_to_string(path)
                .map_err(|e| format!("on-demand revocation file {path} unreadable: {e}"))?;
            for line in contents.lines() {
                let entry = line.trim();
                if entry.is_empty() || entry.starts_with('#') {
                    continue;
                }
                revoked.insert(entry.to_string());
            }
        }
        Ok(Self { revoked })
    }

    /// Test-only list from an explicit set.
    pub fn test_only(digests: &[&str]) -> Self {
        Self {
            revoked: digests.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// True when `digest` is revoked.
    pub fn is_revoked(&self, digest: &str) -> bool {
        self.revoked.contains(digest)
    }
}

/// Why an on-demand read was refused. Every variant fails closed with
/// `reason=image` on the boot path; none permits unverified bytes.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// No verified admission exists for this digest. The caller must verify
    /// first; the cache never fetches speculatively.
    #[error("digest {digest} has no verified admission; verify before serve")]
    NotVerified { digest: String },
    /// The digest is revoked. Signed-but-revoked images never boot.
    #[error("digest {digest} is revoked")]
    Revoked { digest: String },
    /// The chunk provider (registry or network) failed. Fail-closed: no
    /// cached or partial bytes are served.
    #[error("fetch failed for digest {digest} chunk {chunk}: {reason}")]
    NetworkFailure {
        digest: String,
        chunk: u64,
        reason: String,
    },
    /// On-demand path is disabled; the caller must use the eager path.
    #[error("on-demand reads are disabled")]
    Disabled,
    /// Requested range is empty.
    #[error("empty read range")]
    EmptyRange,
    /// The requested range is not servable: arithmetic overflow, over
    /// [`MAX_FETCH_BYTES`], over [`MAX_FETCH_CHUNKS`] chunks, or not
    /// representable for allocation.
    #[error("invalid read range offset={offset} len={len}: {reason}")]
    InvalidRange {
        offset: u64,
        len: u64,
        reason: String,
    },
    /// The record was not admitted in production mode. On-demand serves
    /// require production attestation (pinned-signer signature); development
    /// admissions never serve lazy bytes.
    #[error("digest {digest} lacks production attestation")]
    MissingAttestation { digest: String },
}

impl FetchError {
    /// Typed boot-failure classification: every on-demand refusal is an image
    /// materialization failure, never a backend or protocol fault.
    pub fn non_ready_reason(&self) -> pico_core::NonReadyReason {
        pico_core::NonReadyReason::Image
    }

    /// Stable short label for metrics and audit records.
    pub fn reason_label(&self) -> &'static str {
        match self {
            Self::NotVerified { .. } => "image_on_demand_not_verified",
            Self::Revoked { .. } => "image_on_demand_revoked",
            Self::NetworkFailure { .. } => "image_on_demand_fetch_failed",
            Self::Disabled => "image_on_demand_disabled",
            Self::EmptyRange => "image_on_demand_empty_range",
            Self::InvalidRange { .. } => "image_on_demand_invalid_range",
            Self::MissingAttestation { .. } => "image_on_demand_missing_attestation",
        }
    }
}

/// Cache lookup outcome for one `fetch_range` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnDemandCacheResult {
    Hit,
    Miss,
    Evicted,
}

impl OnDemandCacheResult {
    /// Value for the `cache_result` metric label and S-CACHE evidence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Evicted => "evicted",
        }
    }
}

/// Point-in-time cache counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnDemandStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub used_bytes: u64,
    pub verified_digests: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ChunkKey {
    digest: String,
    chunk: u64,
}

struct Inner {
    verified: HashSet<String>,
    chunks: HashMap<ChunkKey, Vec<u8>>,
    insertion_order: VecDeque<ChunkKey>,
    used_bytes: u64,
    hits: u64,
    misses: u64,
    evictions: u64,
    /// Digests that lost at least one chunk to eviction. The next fetch for
    /// such a digest reports `evicted` once, so S-CACHE-THRASH evidence can
    /// distinguish a cold miss from an eviction miss.
    evicted_digests: HashSet<String>,
}

/// Verification-gated lazy-read cache.
///
/// The verified set and the chunk store live behind one mutex so admission
/// and eviction cannot interleave into serving the wrong digest.
pub struct OnDemandImageCache {
    config: OnDemandConfig,
    revocation: RevocationList,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for OnDemandImageCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("OnDemandImageCache")
            .field("enabled", &self.config.enabled)
            .field("chunk_bytes", &self.config.chunk_bytes)
            .field("used_bytes", &inner.used_bytes)
            .field("verified_digests", &inner.verified.len())
            .field("chunks", &inner.chunks.len())
            .finish()
    }
}

impl OnDemandImageCache {
    /// Builds the cache, loading the revocation list fail-closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the config is invalid or the revocation file
    /// cannot be read. The host must refuse on-demand serves in that case.
    pub fn new(config: OnDemandConfig) -> Result<Self, String> {
        config.validated()?;
        let revocation = RevocationList::from_config(&config)?;
        Ok(Self {
            config,
            revocation,
            inner: Mutex::new(Inner {
                verified: HashSet::new(),
                chunks: HashMap::default(),
                insertion_order: VecDeque::new(),
                used_bytes: 0,
                hits: 0,
                misses: 0,
                evictions: 0,
                evicted_digests: HashSet::new(),
            }),
        })
    }

    /// Test-only cache with an explicit revocation set and small cap.
    pub fn test_only(config: OnDemandConfig, revoked: &[&str]) -> Result<Self, String> {
        config.validated()?;
        Ok(Self {
            config,
            revocation: RevocationList::test_only(revoked),
            inner: Mutex::new(Inner {
                verified: HashSet::new(),
                chunks: HashMap::default(),
                insertion_order: VecDeque::new(),
                used_bytes: 0,
                hits: 0,
                misses: 0,
                evictions: 0,
                evicted_digests: HashSet::new(),
            }),
        })
    }

    /// Whether on-demand serves are enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Tier label reported on hit/miss/eviction counters.
    pub fn tier(&self) -> &str {
        &self.config.tier
    }

    /// Chunk size in bytes.
    pub fn chunk_bytes(&self) -> u64 {
        self.config.chunk_bytes
    }

    /// Admits a digest for on-demand serving after verification.
    ///
    /// Must be called after [`crate::image_verify::ImageVerifier::verify`]
    /// succeeds and before any [`Self::fetch_range`] for the same digest.
    /// Checks revocation first so a signed-but-revoked image is refused even
    /// when verification passed. Emits the `image_verification` audit event
    /// that proves verification ran before serve.
    pub fn admit_verified(&self, record: &VerifiedImageRecord) -> Result<(), FetchError> {
        if !self.config.enabled {
            return Err(FetchError::Disabled);
        }
        // Production attestation is part of the gate: a development admission
        // (unsigned images tolerated) must never serve lazy bytes with
        // `verification_before_serve` set. Config validation also requires
        // production mode for on-demand; this check holds even for
        // programmatically constructed caches that bypass it.
        if record.mode != ImageVerificationMode::Production {
            tracing::warn!(
                event = "image_on_demand_unattested",
                manifest_digest = %record.manifest_digest,
                mode = ?record.mode,
                "on-demand admission refused: production attestation required"
            );
            return Err(FetchError::MissingAttestation {
                digest: record.manifest_digest.clone(),
            });
        }
        if self.revocation.is_revoked(&record.manifest_digest) {
            tracing::warn!(
                event = "image_on_demand_revoked",
                manifest_digest = %record.manifest_digest,
                "on-demand admission refused: digest revoked"
            );
            return Err(FetchError::Revoked {
                digest: record.manifest_digest.clone(),
            });
        }
        {
            let mut inner = self.inner.lock();
            inner.verified.insert(record.manifest_digest.clone());
        }
        // Audit proof that verification ran before any byte is served. The
        // digest is the cache key, never a metric label.
        tracing::info!(
            event = "image_verification",
            image_id = %record.image_id,
            manifest_digest = %record.manifest_digest,
            signer = record.signer_identity.as_deref().unwrap_or("unsigned"),
            mode = ?record.mode,
            on_demand = true,
            verification_before_serve = true,
            "image verified before on-demand serve"
        );
        Ok(())
    }

    /// True when `digest` has a verified admission.
    pub fn is_verified(&self, digest: &str) -> bool {
        self.inner.lock().verified.contains(digest)
    }

    /// Prepare-level lookup hint for S-CACHE evidence.
    ///
    /// Returns `Hit` when the digest is already admitted, `Evicted` when it
    /// lost bytes to eviction since admission, and `Miss` otherwise. Reports
    /// `evicted` once per eviction: peeking consumes the marker so repeated
    /// prepares converge back to `hit` instead of reporting thrash forever.
    /// Byte fetches via [`Self::fetch_range`] share the same marker, so an
    /// eviction is reported once across both paths, whichever peeks first.
    pub fn prepare_result(&self, digest: &str) -> OnDemandCacheResult {
        let mut inner = self.inner.lock();
        if !inner.verified.contains(digest) {
            return OnDemandCacheResult::Miss;
        }
        if inner.evicted_digests.remove(digest) {
            OnDemandCacheResult::Evicted
        } else {
            OnDemandCacheResult::Hit
        }
    }

    /// Fetches `[offset, offset + len)` for a verified digest.
    ///
    /// The provider supplies one chunk at a time and is called only for
    /// chunks missing from the second-level cache. `len` is capped at
    /// [`MAX_FETCH_BYTES`] and the span at [`MAX_FETCH_CHUNKS`] chunks;
    /// overflows and over-limit ranges fail with [`FetchError::InvalidRange`]
    /// before any provider call or allocation.
    ///
    /// A provider failure fails closed: nothing is served and the error maps
    /// to `reason=image` upstream. Chunks fetched before the failure stay
    /// cached (they are digest-keyed under a verified admission, so retaining
    /// them cannot serve unverified bytes); only serving is all-or-nothing.
    /// Returns the bytes plus whether every chunk was a cache hit.
    ///
    /// Reads clamp to the bytes the provider supplies: a short provider
    /// chunk (for example the final chunk of an image) yields a short read.
    /// Callers needing exact-length reads must compare the returned length
    /// to `len`.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::NotVerified`] without calling the provider when
    /// no admission exists, [`FetchError::Revoked`] when the digest is
    /// revoked, and [`FetchError::NetworkFailure`] when the provider fails.
    pub fn fetch_range(
        &self,
        digest: &str,
        offset: u64,
        len: u64,
        provider: &mut dyn FnMut(u64) -> Result<Vec<u8>, String>,
    ) -> Result<(Vec<u8>, OnDemandCacheResult), FetchError> {
        if !self.config.enabled {
            return Err(FetchError::Disabled);
        }
        if len == 0 {
            return Err(FetchError::EmptyRange);
        }
        {
            let inner = self.inner.lock();
            if !inner.verified.contains(digest) {
                return Err(FetchError::NotVerified {
                    digest: digest.to_string(),
                });
            }
        }
        if self.revocation.is_revoked(digest) {
            return Err(FetchError::Revoked {
                digest: digest.to_string(),
            });
        }

        let chunk_bytes = self.config.chunk_bytes;
        let end = offset.checked_add(len).ok_or(FetchError::InvalidRange {
            offset,
            len,
            reason: "offset + len overflows u64".to_string(),
        })?;
        if len > MAX_FETCH_BYTES {
            return Err(FetchError::InvalidRange {
                offset,
                len,
                reason: format!("len exceeds MAX_FETCH_BYTES ({MAX_FETCH_BYTES})"),
            });
        }
        let first_chunk = offset / chunk_bytes;
        let last_chunk = (end - 1) / chunk_bytes;
        // Checked `end` with `len >= 1` guarantees `last_chunk >= first_chunk`:
        // `end - 1 >= offset` and integer division is monotonic. The `len`
        // cap above also bounds `last_chunk - first_chunk + 1 <= len`, so the
        // `+ 1` cannot overflow.
        let chunk_count = last_chunk - first_chunk + 1;
        if chunk_count > MAX_FETCH_CHUNKS {
            return Err(FetchError::InvalidRange {
                offset,
                len,
                reason: format!(
                    "range spans {chunk_count} chunks, over MAX_FETCH_CHUNKS ({MAX_FETCH_CHUNKS})"
                ),
            });
        }
        let mut all_hit = true;
        let mut saw_evicted_digest = false;
        let len_usize = usize::try_from(len).map_err(|_| FetchError::InvalidRange {
            offset,
            len,
            reason: "len does not fit in usize".to_string(),
        })?;
        let mut assembled = Vec::with_capacity(len_usize);

        for chunk_idx in first_chunk..=last_chunk {
            let key = ChunkKey {
                digest: digest.to_string(),
                chunk: chunk_idx,
            };
            let cached = self.inner.lock().chunks.get(&key).cloned();
            let chunk_bytes_vec = match cached {
                Some(bytes) => {
                    self.record_hit();
                    bytes
                }
                None => {
                    all_hit = false;
                    // The digest lost bytes to eviction earlier; this miss is
                    // evidence of thrash rather than a cold start.
                    if self.inner.lock().evicted_digests.contains(digest) {
                        saw_evicted_digest = true;
                    }
                    let fetched =
                        provider(chunk_idx).map_err(|reason| FetchError::NetworkFailure {
                            digest: digest.to_string(),
                            chunk: chunk_idx,
                            reason,
                        })?;
                    self.insert_chunk(key, fetched.clone());
                    self.record_miss();
                    fetched
                }
            };
            // Slice the chunk down to the requested window. `saturating_add`
            // guards against a pathological provider returning a huge chunk
            // for a range near `u64::MAX`; the window math below then clamps.
            let chunk_start = chunk_idx * chunk_bytes;
            let chunk_end = chunk_start.saturating_add(chunk_bytes_vec.len() as u64);
            let want_start = offset.max(chunk_start);
            let want_end = (offset + len).min(chunk_end);
            if want_start < want_end {
                let from = (want_start - chunk_start) as usize;
                let to = (want_end - chunk_start) as usize;
                assembled.extend_from_slice(&chunk_bytes_vec[from..to]);
            }
        }

        if saw_evicted_digest {
            self.inner.lock().evicted_digests.remove(digest);
        }
        let result = if all_hit {
            OnDemandCacheResult::Hit
        } else if saw_evicted_digest {
            OnDemandCacheResult::Evicted
        } else {
            OnDemandCacheResult::Miss
        };
        tracing::info!(
            event = "image_on_demand_serve",
            manifest_digest = %digest,
            cache_result = %result.as_str(),
            bytes = assembled.len(),
            verification_before_serve = true,
            "on-demand bytes served after verification"
        );
        Ok((assembled, result))
    }

    /// Drops every cached chunk for `digest`.
    ///
    /// The verified admission is retained: eviction drops bytes, never trust.
    /// A later fetch for the same digest is a miss (or `evicted` once) and
    /// still requires the verified set plus a revocation re-check. Returns
    /// the bytes freed.
    pub fn evict_digest(&self, digest: &str) -> u64 {
        let tier = self.config.tier.clone();
        let mut inner = self.inner.lock();
        let before = inner.used_bytes;
        // Collect first: `retain` cannot also mutate the eviction counters
        // through the same borrow.
        let evicted_keys: Vec<ChunkKey> = inner
            .chunks
            .keys()
            .filter(|key| key.digest == digest)
            .cloned()
            .collect();
        for key in evicted_keys {
            if let Some(bytes) = inner.chunks.remove(&key) {
                inner.used_bytes = inner.used_bytes.saturating_sub(bytes.len() as u64);
                inner.evictions += 1;
                crate::metrics::record_image_cache_eviction(&tier);
            }
        }
        inner.insertion_order.retain(|key| key.digest != digest);
        if inner.used_bytes < before {
            inner.evicted_digests.insert(digest.to_string());
        }
        before - inner.used_bytes
    }

    /// Current counters.
    pub fn stats(&self) -> OnDemandStats {
        let inner = self.inner.lock();
        OnDemandStats {
            hits: inner.hits,
            misses: inner.misses,
            evictions: inner.evictions,
            used_bytes: inner.used_bytes,
            verified_digests: inner.verified.len() as u64,
        }
    }

    fn record_hit(&self) {
        self.inner.lock().hits += 1;
        crate::metrics::record_image_cache_hit(&self.config.tier);
    }

    fn record_miss(&self) {
        self.inner.lock().misses += 1;
        crate::metrics::record_image_cache_miss(&self.config.tier);
    }

    fn insert_chunk(&self, key: ChunkKey, bytes: Vec<u8>) {
        let mut inner = self.inner.lock();
        // Refresh path: replacing an existing chunk does not change order.
        if let Some(old) = inner.chunks.insert(key.clone(), bytes) {
            inner.used_bytes = inner.used_bytes.saturating_sub(old.len() as u64);
        } else {
            inner.insertion_order.push_back(key.clone());
        }
        if let Some(stored) = inner.chunks.get(&key) {
            inner.used_bytes += stored.len() as u64;
        }
        // Size-bounded eviction: drop oldest chunks first. Eviction is keyed
        // by digest, so it cannot surface another digest's bytes.
        while inner.used_bytes > self.config.max_cached_bytes {
            let Some(oldest) = inner.insertion_order.pop_front() else {
                break;
            };
            if let Some(removed) = inner.chunks.remove(&oldest) {
                inner.used_bytes = inner.used_bytes.saturating_sub(removed.len() as u64);
                inner.evictions += 1;
                inner.evicted_digests.insert(oldest.digest.clone());
                crate::metrics::record_image_cache_eviction(&self.config.tier);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_verify::ImageVerificationMode;

    fn test_record(digest: &str) -> VerifiedImageRecord {
        test_record_with_mode(digest, ImageVerificationMode::Production)
    }

    fn test_record_with_mode(digest: &str, mode: ImageVerificationMode) -> VerifiedImageRecord {
        VerifiedImageRecord {
            image_id: "pico-guest-standard".to_string(),
            manifest_digest: digest.to_string(),
            signer_identity: Some("ci-builder".to_string()),
            composition_digest: None,
            composition_audit_record: None,
            layer_count: 0,
            mode,
        }
    }

    fn enabled_config() -> OnDemandConfig {
        OnDemandConfig {
            enabled: true,
            chunk_bytes: 8,
            max_cached_bytes: 64,
            readahead_chunks: 1,
            tier: "host_local".to_string(),
            revoked_digests: Vec::new(),
            revocation_file: None,
        }
    }

    fn chunk_provider(
        data: Vec<u8>,
        chunk_bytes: u64,
    ) -> impl FnMut(u64) -> Result<Vec<u8>, String> {
        move |idx| {
            let start = idx * chunk_bytes;
            let start_usize: usize = start.try_into().expect("chunk math fits in usize");
            if start_usize >= data.len() {
                return Err("chunk beyond image".to_string());
            }
            let end = (start_usize + chunk_bytes as usize).min(data.len());
            Ok(data[start_usize..end].to_vec())
        }
    }

    #[test]
    fn config_rejects_zero_chunk_bytes() {
        let mut config = enabled_config();
        config.chunk_bytes = 0;
        assert!(config.validated().is_err());
    }

    #[test]
    fn config_rejects_oversized_chunks() {
        let mut config = enabled_config();
        config.chunk_bytes = 128 * 1024 * 1024;
        assert!(config.validated().is_err());
    }

    #[test]
    fn fetch_without_admission_fails_closed_without_calling_provider() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &[]).unwrap();
        let mut called = false;
        let mut provider = |_: u64| {
            called = true;
            Ok(vec![1, 2, 3])
        };
        let err = cache
            .fetch_range("sha256:abc", 0, 3, &mut provider)
            .expect_err("unverified fetch must fail");
        assert!(matches!(err, FetchError::NotVerified { .. }));
        assert!(!called, "provider must not run before verification");
        assert_eq!(
            err.non_ready_reason(),
            pico_core::NonReadyReason::Image,
            "on-demand refusal is an image failure"
        );
    }

    #[test]
    fn revoked_digest_never_serves_even_after_admission_attempt() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &["sha256:revoked"]).unwrap();
        let err = cache
            .admit_verified(&test_record("sha256:revoked"))
            .expect_err("revoked admission must fail");
        assert!(matches!(err, FetchError::Revoked { .. }));
        let mut provider = |_: u64| Ok(vec![9; 8]);
        let err = cache
            .fetch_range("sha256:revoked", 0, 4, &mut provider)
            .expect_err("revoked fetch must fail");
        assert!(matches!(
            err,
            FetchError::NotVerified { .. } | FetchError::Revoked { .. }
        ));
    }

    #[test]
    fn verify_then_fetch_serves_bytes_and_reports_miss_then_hit() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &[]).unwrap();
        let digest = "sha256:img1";
        cache.admit_verified(&test_record(digest)).unwrap();
        let data: Vec<u8> = (0..32).collect();
        let mut provider = chunk_provider(data.clone(), 8);
        let (first, result) = cache.fetch_range(digest, 0, 16, &mut provider).unwrap();
        assert_eq!(first, data[0..16]);
        assert_eq!(result, OnDemandCacheResult::Miss);
        // Second read of the same window is served from the second-level cache.
        let mut failing = |_: u64| Err::<Vec<u8>, String>("must not be called".to_string());
        let (second, result) = cache.fetch_range(digest, 0, 16, &mut failing).unwrap();
        assert_eq!(second, data[0..16]);
        assert_eq!(result, OnDemandCacheResult::Hit);
        let stats = cache.stats();
        assert_eq!(stats.verified_digests, 1);
        assert!(stats.hits >= 2, "hits: {}", stats.hits);
        assert!(stats.misses >= 2, "misses: {}", stats.misses);
    }

    #[test]
    fn network_failure_serves_nothing_and_caches_nothing() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &[]).unwrap();
        let digest = "sha256:flaky";
        cache.admit_verified(&test_record(digest)).unwrap();
        let mut failing = |_: u64| Err::<Vec<u8>, String>("registry unavailable".to_string());
        let err = cache
            .fetch_range(digest, 0, 8, &mut failing)
            .expect_err("provider failure must fail closed");
        assert!(matches!(err, FetchError::NetworkFailure { .. }));
        assert_eq!(err.reason_label(), "image_on_demand_fetch_failed");
        // A later fetch with a healthy provider still misses (nothing was
        // cached from the failure) and then serves.
        let mut healthy = |_: u64| Ok(vec![7; 8]);
        let (bytes, result) = cache.fetch_range(digest, 0, 8, &mut healthy).unwrap();
        assert_eq!(bytes, vec![7; 8]);
        assert_eq!(result, OnDemandCacheResult::Miss);
    }

    #[test]
    fn eviction_never_serves_wrong_digest() {
        let mut config = enabled_config();
        config.chunk_bytes = 8;
        config.max_cached_bytes = 16;
        let cache = OnDemandImageCache::test_only(config, &[]).unwrap();
        cache.admit_verified(&test_record("sha256:a")).unwrap();
        cache.admit_verified(&test_record("sha256:b")).unwrap();
        let mut provider_a = |_: u64| Ok(vec![0xAA; 8]);
        let mut provider_b = |_: u64| Ok(vec![0xBB; 8]);
        // Fill the cache with A (2 chunks = 16 bytes, at cap), then fetch B
        // which forces eviction of A's oldest chunk.
        cache
            .fetch_range("sha256:a", 0, 16, &mut provider_a)
            .unwrap();
        cache
            .fetch_range("sha256:b", 0, 8, &mut provider_b)
            .unwrap();
        // A is still verified, but its evicted chunk must be refetched, never
        // served from B's bytes.
        let (bytes, result) = cache
            .fetch_range("sha256:a", 0, 8, &mut provider_a)
            .unwrap();
        assert_eq!(bytes, vec![0xAA; 8]);
        assert!(
            matches!(
                result,
                OnDemandCacheResult::Miss | OnDemandCacheResult::Evicted
            ),
            "evicted digest refetch is not a hit: {result:?}"
        );
        assert_ne!(bytes, vec![0xBB; 8], "cross-digest serve is forbidden");
    }

    #[test]
    fn explicit_evict_reports_evicted_once() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &[]).unwrap();
        let digest = "sha256:evict-me";
        cache.admit_verified(&test_record(digest)).unwrap();
        let mut provider = |_: u64| Ok(vec![1; 8]);
        cache.fetch_range(digest, 0, 8, &mut provider).unwrap();
        assert!(cache.evict_digest(digest) > 0);
        let (bytes, result) = cache.fetch_range(digest, 0, 8, &mut provider).unwrap();
        assert_eq!(bytes, vec![1; 8]);
        assert_eq!(result, OnDemandCacheResult::Evicted);
        // The evicted marker clears after one report; the next hit is a hit.
        let mut failing = |_: u64| Err::<Vec<u8>, String>("must not be called".to_string());
        let (_, result) = cache.fetch_range(digest, 0, 8, &mut failing).unwrap();
        assert_eq!(result, OnDemandCacheResult::Hit);
    }

    #[test]
    fn lazy_read_kind_matches_runtime_family() {
        assert_eq!(
            LazyReadKind::for_runtime(pico_core::RuntimeType::GVisor),
            LazyReadKind::ContainerMetadataLocal
        );
        assert_eq!(
            LazyReadKind::for_runtime(pico_core::RuntimeType::Firecracker),
            LazyReadKind::VmChunked
        );
        assert_eq!(
            LazyReadKind::for_runtime(pico_core::RuntimeType::Qemu),
            LazyReadKind::VmChunked
        );
    }

    #[test]
    fn revocation_file_with_comments_loads() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("revoked.txt");
        std::fs::write(&path, "# revoked digests\n\nsha256:bad1\nsha256:bad2\n").unwrap();
        let config = OnDemandConfig {
            enabled: true,
            revocation_file: Some(path.to_string_lossy().to_string()),
            ..enabled_config()
        };
        let list = RevocationList::from_config(&config).unwrap();
        assert!(list.is_revoked("sha256:bad1"));
        assert!(list.is_revoked("sha256:bad2"));
        assert!(!list.is_revoked("sha256:good"));
    }

    #[test]
    fn missing_revocation_file_fails_closed() {
        let config = OnDemandConfig {
            revocation_file: Some("/nonexistent/revoked.txt".to_string()),
            ..enabled_config()
        };
        assert!(RevocationList::from_config(&config).is_err());
        assert!(OnDemandImageCache::new(config).is_err());
    }

    #[test]
    fn disabled_cache_refuses_admit_and_fetch() {
        let cache = OnDemandImageCache::test_only(OnDemandConfig::default(), &[]).unwrap();
        assert!(!cache.is_enabled());
        assert!(matches!(
            cache.admit_verified(&test_record("sha256:x")),
            Err(FetchError::Disabled)
        ));
        let mut provider = |_: u64| Ok(vec![1]);
        assert!(matches!(
            cache.fetch_range("sha256:x", 0, 1, &mut provider),
            Err(FetchError::Disabled)
        ));
    }

    #[test]
    fn admit_verified_rejects_development_records() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &[]).unwrap();
        let err = cache
            .admit_verified(&test_record_with_mode(
                "sha256:dev",
                ImageVerificationMode::Development,
            ))
            .expect_err("development admission must fail");
        assert!(matches!(err, FetchError::MissingAttestation { .. }));
        assert_eq!(err.reason_label(), "image_on_demand_missing_attestation");
        assert_eq!(
            err.non_ready_reason(),
            pico_core::NonReadyReason::Image,
            "attestation refusal is an image failure"
        );
        // The digest stays unadmitted: fetches still fail closed.
        let mut provider = |_: u64| Ok(vec![0; 8]);
        assert!(matches!(
            cache.fetch_range("sha256:dev", 0, 8, &mut provider),
            Err(FetchError::NotVerified { .. })
        ));
    }

    #[test]
    fn fetch_range_rejects_invalid_ranges_without_calling_provider() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &[]).unwrap();
        let digest = "sha256:ranges";
        cache.admit_verified(&test_record(digest)).unwrap();
        let mut called = false;
        let mut provider = |_: u64| {
            called = true;
            Ok(vec![0; 8])
        };
        // Overflow.
        let err = cache
            .fetch_range(digest, u64::MAX, 2, &mut provider)
            .expect_err("overflowing range must fail");
        assert!(matches!(err, FetchError::InvalidRange { .. }));
        // Over the byte cap.
        let err = cache
            .fetch_range(digest, 0, MAX_FETCH_BYTES + 1, &mut provider)
            .expect_err("oversized range must fail");
        assert!(matches!(err, FetchError::InvalidRange { .. }));
        assert!(!called, "provider must not run for invalid ranges");
        assert_eq!(
            err.non_ready_reason(),
            pico_core::NonReadyReason::Image,
            "invalid range is an image failure"
        );
        assert_eq!(err.reason_label(), "image_on_demand_invalid_range");
    }

    #[test]
    fn fetch_range_rejects_excessive_chunk_counts() {
        let mut config = enabled_config();
        config.chunk_bytes = 1;
        let cache = OnDemandImageCache::test_only(config, &[]).unwrap();
        let digest = "sha256:chunks";
        cache.admit_verified(&test_record(digest)).unwrap();
        let mut provider = |_: u64| Ok(vec![0; 1]);
        let err = cache
            .fetch_range(digest, 0, MAX_FETCH_CHUNKS + 1, &mut provider)
            .expect_err("excessive chunk span must fail");
        assert!(matches!(err, FetchError::InvalidRange { .. }));
    }

    #[test]
    fn prepare_result_reports_evicted_once() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &[]).unwrap();
        let digest = "sha256:peek-evicted";
        assert_eq!(
            cache.prepare_result(digest),
            OnDemandCacheResult::Miss,
            "unseen digest is a miss"
        );
        cache.admit_verified(&test_record(digest)).unwrap();
        let mut provider = |_: u64| Ok(vec![1; 8]);
        cache.fetch_range(digest, 0, 8, &mut provider).unwrap();
        assert_eq!(
            cache.prepare_result(digest),
            OnDemandCacheResult::Hit,
            "admitted digest is a hit"
        );
        assert!(cache.evict_digest(digest) > 0);
        assert_eq!(
            cache.prepare_result(digest),
            OnDemandCacheResult::Evicted,
            "evicted digest reports evicted once"
        );
        assert_eq!(
            cache.prepare_result(digest),
            OnDemandCacheResult::Hit,
            "marker is consumed: prepares converge back to hit"
        );
    }

    #[test]
    fn partial_provider_failure_serves_nothing_but_keeps_prior_chunks() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &[]).unwrap();
        let digest = "sha256:partial";
        cache.admit_verified(&test_record(digest)).unwrap();
        // Chunk 0 succeeds, chunk 1 fails: nothing is served.
        let mut flaky = |idx: u64| -> Result<Vec<u8>, String> {
            if idx == 0 {
                Ok(vec![0xCC; 8])
            } else {
                Err("chunk 1 unavailable".to_string())
            }
        };
        let err = cache
            .fetch_range(digest, 0, 16, &mut flaky)
            .expect_err("partial failure must fail closed");
        assert!(matches!(err, FetchError::NetworkFailure { chunk: 1, .. }));
        // Chunk 0 was valid under a verified admission, so it stays cached; a
        // follow-up read of that window hits without touching the provider.
        let mut failing = |_: u64| Err::<Vec<u8>, String>("must not be called".to_string());
        let (bytes, result) = cache.fetch_range(digest, 0, 8, &mut failing).unwrap();
        assert_eq!(bytes, vec![0xCC; 8]);
        assert_eq!(result, OnDemandCacheResult::Hit);
    }

    #[test]
    fn short_provider_chunk_clamps_read() {
        let cache = OnDemandImageCache::test_only(enabled_config(), &[]).unwrap();
        let digest = "sha256:short";
        cache.admit_verified(&test_record(digest)).unwrap();
        // Provider supplies fewer bytes than the chunk size (end of image):
        // the read clamps instead of failing.
        let mut provider = |_: u64| Ok(vec![0xDD; 4]);
        let (bytes, _) = cache.fetch_range(digest, 0, 8, &mut provider).unwrap();
        assert_eq!(bytes, vec![0xDD; 4]);
    }
}
