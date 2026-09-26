//! Persistent garbage-collection tracking for COW layer reference counts.
//!
//! Extends the in-memory [`super::CowCleanupTracker`](super::super::CowCleanupTracker)
//! with disk-backed persistence so that reference counts survive process
//! restarts.
//!
//! ## Design
//!
//! Reference counts are stored as a JSON file at `gc_path`. On every
//! mutation (register/deregister/sweep), the file is atomically
//! rewritten via temp-file + `rename(2)`.
//!
//! ## Crash safety
//!
//! The GC file is a cache of truth; the authoritative reference count
//! can always be rebuilt by scanning all workspace metadata files.
//! On startup, [`CowFilesystemEngine::open`](super::CowFilesystemEngine::open)
//! rebuilds the GC from workspace metadata if the GC file disagrees.

use hashbrown::HashMap;
use std::path::PathBuf;

use super::super::cleanup::{LayerRefCount, LayerRefTracker};
use super::super::{CowLayer, LayerKind};

/// Persistent GC store backed by a JSON file.
///
/// Tracks reference counts for base layers so that shared data
/// is never deleted while any live workspace references it.
#[derive(Debug)]
pub struct GcStore {
    /// Path to the persistent GC JSON file.
    path: PathBuf,
    /// In-memory reference counts, kept in sync with disk.
    ref_counts: HashMap<String, LayerRefCount>,
}

impl GcStore {
    /// Opens or creates a GC store at the given path.
    ///
    /// If the path exists and contains valid JSON, it is loaded.
    /// Otherwise, an empty store is initialized.
    pub fn new(path: PathBuf) -> Self {
        let ref_counts = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|data| serde_json::from_str::<Vec<LayerRefCount>>(&data).ok())
                .map(|entries| {
                    entries
                        .into_iter()
                        .map(|rc| (rc.blob_ref.clone(), rc))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            HashMap::new()
        };

        Self { path, ref_counts }
    }

    /// Registers a base layer, incrementing its reference count.
    ///
    /// Called when a new workspace is created that shares this base layer.
    /// Persists the updated counts to disk.
    pub fn register_base_layer(&mut self, layer: &CowLayer) {
        debug_assert_eq!(
            layer.kind,
            LayerKind::Base,
            "register_base_layer called on non-base layer"
        );
        match self.ref_counts.get_mut(&layer.blob_ref) {
            Some(rc) => rc.inc(),
            None => {
                self.ref_counts.insert(
                    layer.blob_ref.clone(),
                    LayerRefCount::new(&layer.blob_ref, layer.size_bytes),
                );
            }
        }
        let _ = self.persist();
    }

    /// Deregisters a base layer, decrementing its reference count.
    ///
    /// Called when a workspace that shared this base layer is deleted.
    /// Returns `true` if the layer has no remaining references and can
    /// be safely removed from storage.
    /// Persists the updated counts to disk.
    pub fn deregister_base_layer(&mut self, layer: &CowLayer) -> bool {
        debug_assert_eq!(
            layer.kind,
            LayerKind::Base,
            "deregister_base_layer called on non-base layer"
        );
        let released = if let Some(rc) = self.ref_counts.get_mut(&layer.blob_ref) {
            rc.dec();
            rc.is_released()
        } else {
            false
        };
        let _ = self.persist();
        released
    }

    /// Returns the current reference count for a layer blob reference.
    pub fn get_ref_count(&self, blob_ref: &str) -> Option<u32> {
        self.ref_counts.get(blob_ref).map(|rc| rc.ref_count)
    }

    /// Returns all layer reference counts.
    pub fn all_ref_counts(&self) -> Vec<&LayerRefCount> {
        self.ref_counts.values().collect()
    }

    /// Returns the total number of released layers (ref_count = 0)
    /// that are eligible for final deletion.
    pub fn released_layer_count(&self) -> usize {
        self.ref_counts
            .values()
            .filter(|rc| rc.is_released())
            .count()
    }

    /// Removes all released layers from the tracker.
    ///
    /// Returns the blob references that were fully released.
    /// Persists the updated counts to disk.
    pub fn sweep_released(&mut self) -> Vec<String> {
        let released: Vec<String> = self
            .ref_counts
            .iter()
            .filter(|(_, rc)| rc.is_released())
            .map(|(blob_ref, _)| blob_ref.clone())
            .collect();
        for blob_ref in &released {
            self.ref_counts.remove(blob_ref);
        }
        let _ = self.persist();
        released
    }

    /// Persists the reference counts to disk atomically.
    fn persist(&self) -> Result<(), std::io::Error> {
        let tmp = self.path.with_extension("tmp");
        let entries: Vec<&LayerRefCount> = self.ref_counts.values().collect();
        let data = serde_json::to_string_pretty(&entries).map_err(std::io::Error::other)?;
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

impl LayerRefTracker for GcStore {
    fn register_base_layer(&mut self, layer: &CowLayer) {
        self.register_base_layer(layer);
    }

    fn deregister_base_layer(&mut self, layer: &CowLayer) -> bool {
        self.deregister_base_layer(layer)
    }

    fn get_ref_count(&self, blob_ref: &str) -> Option<u32> {
        self.get_ref_count(blob_ref)
    }

    fn all_ref_counts(&self) -> Vec<&LayerRefCount> {
        self.all_ref_counts()
    }

    fn released_layer_count(&self) -> usize {
        self.released_layer_count()
    }

    fn sweep_released(&mut self) -> Vec<String> {
        self.sweep_released()
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::CowLayer;
    use super::*;
    use tempfile::TempDir;

    fn make_base_layer(blob_ref: &str, size: u64) -> CowLayer {
        CowLayer {
            layer_id: format!("layer_{blob_ref}"),
            kind: LayerKind::Base,
            blob_ref: blob_ref.to_string(),
            layer_index: 0,
            parent_blob_ref: None,
            size_bytes: size,
            digest: None,
            created_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn make_gc_store() -> (GcStore, TempDir) {
        let tmp = TempDir::new().expect("tempdir");
        let store = GcStore::new(tmp.path().join("gc.json"));
        (store, tmp)
    }

    #[test]
    fn register_and_deregister_layers() {
        let (mut store, _tmp) = make_gc_store();
        let layer = make_base_layer("blob_01", 1024);

        // Register twice to build up ref count
        store.register_base_layer(&layer);
        store.register_base_layer(&layer);
        assert_eq!(store.get_ref_count("blob_01"), Some(2));

        assert!(!store.deregister_base_layer(&layer)); // 2 -> 1, still active
        assert_eq!(store.get_ref_count("blob_01"), Some(1));
        assert!(store.deregister_base_layer(&layer)); // 1 -> 0, now released
        assert!(store.deregister_base_layer(&layer)); // 0 -> 0, stays released (saturating)
    }

    #[test]
    fn multiple_registrations() {
        let (mut store, _tmp) = make_gc_store();
        let layer = make_base_layer("shared", 2048);

        store.register_base_layer(&layer);
        store.register_base_layer(&layer);
        store.register_base_layer(&layer);
        assert_eq!(store.get_ref_count("shared"), Some(3));

        store.deregister_base_layer(&layer);
        assert_eq!(store.get_ref_count("shared"), Some(2));
        assert!(!store.deregister_base_layer(&layer));
        assert!(store.deregister_base_layer(&layer)); // now released
    }

    #[test]
    fn released_layer_count() {
        let (mut store, _tmp) = make_gc_store();
        let a = make_base_layer("a", 100);
        let b = make_base_layer("b", 200);

        store.register_base_layer(&a);
        store.register_base_layer(&b);
        assert_eq!(store.released_layer_count(), 0);

        store.deregister_base_layer(&a);
        assert_eq!(store.released_layer_count(), 1);

        store.deregister_base_layer(&b);
        assert_eq!(store.released_layer_count(), 2);
    }

    #[test]
    fn sweep_removes_released() {
        let (mut store, _tmp) = make_gc_store();
        let layer = make_base_layer("to_sweep", 512);

        store.register_base_layer(&layer);
        store.deregister_base_layer(&layer);
        assert_eq!(store.released_layer_count(), 1);

        let swept = store.sweep_released();
        assert_eq!(swept, vec!["to_sweep"]);
        assert_eq!(store.released_layer_count(), 0);
        assert_eq!(store.get_ref_count("to_sweep"), None);
    }

    #[test]
    fn persist_and_reload() {
        let (tmp_dir, _tmp_guard) = {
            let tmp = TempDir::new().expect("tempdir");
            let path = tmp.path().join("gc.json");
            (path.to_owned(), tmp)
        };

        // Create and populate
        {
            let mut store = GcStore::new(tmp_dir.clone());
            let layer = make_base_layer("persist_test", 4096);
            store.register_base_layer(&layer);
            store.register_base_layer(&layer); // ref count = 2
        }

        // Reload
        {
            let store = GcStore::new(tmp_dir.clone());
            assert_eq!(store.get_ref_count("persist_test"), Some(2));
        }

        // Modify and reload
        {
            let mut store = GcStore::new(tmp_dir.clone());
            let layer = make_base_layer("persist_test", 4096);
            store.deregister_base_layer(&layer); // ref count = 1
        }

        {
            let store = GcStore::new(tmp_dir.clone());
            assert_eq!(store.get_ref_count("persist_test"), Some(1));
        }
    }

    #[test]
    fn empty_store_has_no_counts() {
        let (store, _tmp) = make_gc_store();
        assert_eq!(store.get_ref_count("nothing"), None);
        assert_eq!(store.released_layer_count(), 0);
        assert!(store.all_ref_counts().is_empty());
    }

    #[test]
    fn deregister_unknown_blob_returns_false() {
        let (mut store, _tmp) = make_gc_store();
        let layer = make_base_layer("unknown", 100);
        assert!(!store.deregister_base_layer(&layer));
    }

    #[test]
    fn sweep_empty_store_returns_empty() {
        let (mut store, _tmp) = make_gc_store();
        let swept = store.sweep_released();
        assert!(swept.is_empty());
    }
}
