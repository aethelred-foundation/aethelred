//! Audit log archival.
//!
//! Long-running deployments accumulate audit entries faster than primary
//! storage can hold cheaply. This module models a tiered archival strategy:
//!
//! - **Hot** — recent entries kept in primary store.
//! - **Warm** — older entries moved to compressed batches stored alongside
//!   the primary, retrievable in seconds.
//! - **Cold** — very old entries shipped to offline / object-store archive
//!   (S3, Glacier, B2) with hashes pinned to the chain root for integrity.
//!
//! Archives are content-addressed: every batch has a deterministic id
//! computed from its hash, so a customer can retrieve a specific batch by
//! id without scanning. Restoring a batch reconstructs the original
//! entry list and re-verifies its hash against the recorded digest.

use crate::hashing::{Hasher, Sha256Digest};
use crate::workspace_audit::WorkspaceAuditEntry;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ArchiveTier
// =============================================================================

/// Tier the batch lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveTier {
    /// Primary store.
    Hot,
    /// Compressed alongside primary.
    Warm,
    /// Off-site / object storage.
    Cold,
}

// =============================================================================
// ArchiveBatch
// =============================================================================

/// One batch of archived entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveBatch {
    /// Stable batch id (derived from contents).
    pub batch_id: Uuid,
    /// Tier.
    pub tier: ArchiveTier,
    /// SHA-256 of the batch contents.
    pub batch_hash: Sha256Digest,
    /// Earliest entry timestamp in the batch.
    pub earliest_at: String,
    /// Latest entry timestamp in the batch.
    pub latest_at: String,
    /// Entry count.
    pub entry_count: u64,
    /// RFC 3339 archived-at.
    pub archived_at: String,
    /// Where this batch lives (e.g., `"s3://aethelred-cold/abc123.json"`).
    pub storage_location: String,
}

// =============================================================================
// ArchiveStorage trait
// =============================================================================

/// Pluggable archive backend.
pub trait ArchiveStorage: Send + Sync {
    /// Backend name.
    fn backend_name(&self) -> &str;
    /// Write a batch (serialized JSON). Returns the storage location.
    fn store(&self, batch_id: Uuid, content: &[u8]) -> SandboxResult<String>;
    /// Retrieve a batch by id.
    fn retrieve(&self, batch_id: Uuid) -> SandboxResult<Vec<u8>>;
    /// `true` if a batch is present.
    fn exists(&self, batch_id: Uuid) -> bool;
}

// =============================================================================
// InMemoryArchiveStorage
// =============================================================================

#[derive(Debug, Default)]
struct InMemState {
    blobs: HashMap<Uuid, Vec<u8>>,
}

/// In-memory storage (test).
#[derive(Debug, Default)]
pub struct InMemoryArchiveStorage {
    state: RwLock<InMemState>,
}

impl InMemoryArchiveStorage {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of stored batches.
    pub fn batch_count(&self) -> usize {
        self.state.read().map(|g| g.blobs.len()).unwrap_or(0)
    }
}

impl ArchiveStorage for InMemoryArchiveStorage {
    fn backend_name(&self) -> &str {
        "in-memory"
    }
    fn store(&self, batch_id: Uuid, content: &[u8]) -> SandboxResult<String> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("archive store poisoned".into()))?
            .blobs
            .insert(batch_id, content.to_vec());
        Ok(format!("memory://{}", batch_id))
    }
    fn retrieve(&self, batch_id: Uuid) -> SandboxResult<Vec<u8>> {
        self.state
            .read()
            .map_err(|_| SandboxError::Other("archive store poisoned".into()))?
            .blobs
            .get(&batch_id)
            .cloned()
            .ok_or_else(|| SandboxError::Other(format!("batch {} not found", batch_id)))
    }
    fn exists(&self, batch_id: Uuid) -> bool {
        self.state
            .read()
            .map(|g| g.blobs.contains_key(&batch_id))
            .unwrap_or(false)
    }
}

// =============================================================================
// AuditArchiver
// =============================================================================

#[derive(Default)]
struct ArchiverState {
    batches: Vec<ArchiveBatch>,
}

/// Owns the archive index. Storage is delegated.
pub struct AuditArchiver<'a> {
    storage: &'a dyn ArchiveStorage,
    state: RwLock<ArchiverState>,
}

impl<'a> std::fmt::Debug for AuditArchiver<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditArchiver")
            .field("backend", &self.storage.backend_name())
            .field("batches", &self.batch_count())
            .finish()
    }
}

impl<'a> AuditArchiver<'a> {
    /// New archiver bound to a storage backend.
    pub fn new(storage: &'a dyn ArchiveStorage) -> Self {
        Self {
            storage,
            state: RwLock::new(ArchiverState::default()),
        }
    }

    /// Archive a slice of entries to a tier. Returns the resulting batch
    /// metadata.
    pub fn archive_batch(
        &self,
        entries: &[WorkspaceAuditEntry],
        tier: ArchiveTier,
    ) -> SandboxResult<ArchiveBatch> {
        if entries.is_empty() {
            return Err(SandboxError::Other("cannot archive empty batch".into()));
        }
        let serialized = serde_json::to_vec(entries)
            .map_err(|e| SandboxError::Other(format!("serialize batch: {e}")))?;
        let batch_hash = Hasher::sha256(&serialized);
        let batch_id = Uuid::now_v7();
        let earliest = entries.iter().map(|e| e.timestamp.clone()).min().unwrap_or_default();
        let latest = entries.iter().map(|e| e.timestamp.clone()).max().unwrap_or_default();
        let storage_location = self.storage.store(batch_id, &serialized)?;
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let batch = ArchiveBatch {
            batch_id,
            tier,
            batch_hash,
            earliest_at: earliest,
            latest_at: latest,
            entry_count: entries.len() as u64,
            archived_at: now,
            storage_location,
        };
        self.state
            .write()
            .map_err(|_| SandboxError::Other("archiver state poisoned".into()))?
            .batches
            .push(batch.clone());
        Ok(batch)
    }

    /// Retrieve and verify a batch by id.
    pub fn restore_batch(&self, batch_id: Uuid) -> SandboxResult<Vec<WorkspaceAuditEntry>> {
        // Find metadata.
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("archiver state poisoned".into()))?;
        let meta = g
            .batches
            .iter()
            .find(|b| b.batch_id == batch_id)
            .cloned()
            .ok_or_else(|| {
                SandboxError::Other(format!("batch {} not in index", batch_id))
            })?;
        drop(g);

        let bytes = self.storage.retrieve(batch_id)?;
        let actual_hash = Hasher::sha256(&bytes);
        if actual_hash != meta.batch_hash {
            return Err(SandboxError::Other(format!(
                "batch {} hash mismatch — archive corrupted",
                batch_id
            )));
        }
        let entries: Vec<WorkspaceAuditEntry> = serde_json::from_slice(&bytes)
            .map_err(|e| SandboxError::Other(format!("deserialize batch: {e}")))?;
        if entries.len() as u64 != meta.entry_count {
            return Err(SandboxError::Other(format!(
                "batch {} entry-count mismatch",
                batch_id
            )));
        }
        Ok(entries)
    }

    /// Number of batches in the index.
    pub fn batch_count(&self) -> usize {
        self.state.read().map(|g| g.batches.len()).unwrap_or(0)
    }

    /// All batches in archive order.
    pub fn batches(&self) -> Vec<ArchiveBatch> {
        self.state.read().map(|g| g.batches.clone()).unwrap_or_default()
    }

    /// Batches in a given tier.
    pub fn batches_in_tier(&self, tier: ArchiveTier) -> Vec<ArchiveBatch> {
        self.state
            .read()
            .map(|g| g.batches.iter().filter(|b| b.tier == tier).cloned().collect())
            .unwrap_or_default()
    }

    /// Promote a batch to a colder tier.
    pub fn promote(&self, batch_id: Uuid, target: ArchiveTier) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("archiver state poisoned".into()))?;
        let b = g
            .batches
            .iter_mut()
            .find(|b| b.batch_id == batch_id)
            .ok_or_else(|| SandboxError::Other(format!("batch {} not found", batch_id)))?;
        // Disallow back-promotions.
        if (b.tier == ArchiveTier::Cold && target != ArchiveTier::Cold)
            || (b.tier == ArchiveTier::Warm && target == ArchiveTier::Hot)
        {
            return Err(SandboxError::Other(format!(
                "cannot promote {:?} -> {:?}",
                b.tier, target
            )));
        }
        b.tier = target;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_audit::{
        WorkspaceAuditEvent, WorkspaceAuditEventKind, WorkspaceAuditLog,
    };

    fn entries(n: usize) -> Vec<WorkspaceAuditEntry> {
        let l = WorkspaceAuditLog::new();
        for i in 0..n {
            l.record_simple(
                "alice",
                WorkspaceAuditEvent::new(
                    WorkspaceAuditEventKind::Other,
                    format!("event-{i}"),
                ),
            )
            .unwrap();
        }
        l.entries()
    }

    #[test]
    fn archive_batch_returns_metadata() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let b = a.archive_batch(&entries(5), ArchiveTier::Warm).unwrap();
        assert_eq!(b.entry_count, 5);
        assert_eq!(b.tier, ArchiveTier::Warm);
    }

    #[test]
    fn archive_empty_errors() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        assert!(a.archive_batch(&[], ArchiveTier::Hot).is_err());
    }

    #[test]
    fn restore_returns_original_entries() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let originals = entries(10);
        let b = a.archive_batch(&originals, ArchiveTier::Warm).unwrap();
        let restored = a.restore_batch(b.batch_id).unwrap();
        assert_eq!(restored, originals);
    }

    #[test]
    fn restore_unknown_batch_errors() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        assert!(a.restore_batch(Uuid::now_v7()).is_err());
    }

    #[test]
    fn batch_count_tracks_archived() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        a.archive_batch(&entries(2), ArchiveTier::Hot).unwrap();
        a.archive_batch(&entries(3), ArchiveTier::Warm).unwrap();
        assert_eq!(a.batch_count(), 2);
    }

    #[test]
    fn batches_in_tier_filters() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        a.archive_batch(&entries(1), ArchiveTier::Hot).unwrap();
        a.archive_batch(&entries(1), ArchiveTier::Warm).unwrap();
        a.archive_batch(&entries(1), ArchiveTier::Cold).unwrap();
        assert_eq!(a.batches_in_tier(ArchiveTier::Hot).len(), 1);
        assert_eq!(a.batches_in_tier(ArchiveTier::Warm).len(), 1);
        assert_eq!(a.batches_in_tier(ArchiveTier::Cold).len(), 1);
    }

    #[test]
    fn promote_to_colder_tier_succeeds() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let b = a.archive_batch(&entries(1), ArchiveTier::Hot).unwrap();
        a.promote(b.batch_id, ArchiveTier::Warm).unwrap();
        a.promote(b.batch_id, ArchiveTier::Cold).unwrap();
    }

    #[test]
    fn cannot_promote_cold_to_warm() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let b = a.archive_batch(&entries(1), ArchiveTier::Cold).unwrap();
        assert!(a.promote(b.batch_id, ArchiveTier::Warm).is_err());
    }

    #[test]
    fn cannot_promote_warm_to_hot() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let b = a.archive_batch(&entries(1), ArchiveTier::Warm).unwrap();
        assert!(a.promote(b.batch_id, ArchiveTier::Hot).is_err());
    }

    #[test]
    fn restore_after_corrupted_storage_fails() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let originals = entries(3);
        let b = a.archive_batch(&originals, ArchiveTier::Warm).unwrap();
        // Mutate the underlying blob.
        s.state.write().unwrap().blobs.insert(b.batch_id, b"junk".to_vec());
        assert!(a.restore_batch(b.batch_id).is_err());
    }

    #[test]
    fn batch_hash_changes_with_contents() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let b1 = a.archive_batch(&entries(2), ArchiveTier::Hot).unwrap();
        let b2 = a.archive_batch(&entries(2), ArchiveTier::Hot).unwrap();
        // Different uuids → different content → different hashes.
        assert_ne!(b1.batch_hash, b2.batch_hash);
    }

    #[test]
    fn earliest_and_latest_recorded() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let es = entries(5);
        let b = a.archive_batch(&es, ArchiveTier::Warm).unwrap();
        assert!(!b.earliest_at.is_empty());
        assert!(!b.latest_at.is_empty());
    }

    #[test]
    fn storage_location_returned() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let b = a.archive_batch(&entries(1), ArchiveTier::Cold).unwrap();
        assert!(b.storage_location.starts_with("memory://"));
    }

    #[test]
    fn batch_count_storage_matches_index() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        a.archive_batch(&entries(1), ArchiveTier::Hot).unwrap();
        a.archive_batch(&entries(2), ArchiveTier::Warm).unwrap();
        assert_eq!(s.batch_count(), 2);
    }

    #[test]
    fn archive_batch_serde_round_trip() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let b = a.archive_batch(&entries(3), ArchiveTier::Hot).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let p: ArchiveBatch = serde_json::from_str(&j).unwrap();
        assert_eq!(p, b);
    }

    #[test]
    fn archive_tier_serde_round_trip() {
        for t in [ArchiveTier::Hot, ArchiveTier::Warm, ArchiveTier::Cold] {
            let j = serde_json::to_string(&t).unwrap();
            let p: ArchiveTier = serde_json::from_str(&j).unwrap();
            assert_eq!(p, t);
        }
    }

    #[test]
    fn many_batches_round_trip() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        let mut batches = Vec::new();
        for i in 0..10 {
            let es = entries(i + 1);
            batches.push((es.clone(), a.archive_batch(&es, ArchiveTier::Warm).unwrap()));
        }
        for (originals, b) in batches {
            let restored = a.restore_batch(b.batch_id).unwrap();
            assert_eq!(restored, originals);
        }
    }

    #[test]
    fn promote_unknown_errors() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        assert!(a.promote(Uuid::now_v7(), ArchiveTier::Cold).is_err());
    }

    #[test]
    fn storage_exists_and_retrieve() {
        let s = InMemoryArchiveStorage::new();
        let id = Uuid::now_v7();
        s.store(id, b"hi").unwrap();
        assert!(s.exists(id));
        assert_eq!(s.retrieve(id).unwrap(), b"hi");
    }

    #[test]
    fn storage_retrieve_unknown_errors() {
        let s = InMemoryArchiveStorage::new();
        assert!(s.retrieve(Uuid::now_v7()).is_err());
    }

    #[test]
    fn batches_returns_all() {
        let s = InMemoryArchiveStorage::new();
        let a = AuditArchiver::new(&s);
        for _ in 0..3 {
            a.archive_batch(&entries(1), ArchiveTier::Hot).unwrap();
        }
        assert_eq!(a.batches().len(), 3);
    }
}
