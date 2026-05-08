//! Durable evidence-log persistence.
//!
//! Replaces the in-memory-only `EvidenceLog` with a file-backed store that
//! survives restarts. Production deployments require this — an evidence log
//! that vanishes on process restart is not evidence.
//!
//! ## Design
//!
//! - **Append-only JSON-lines** — each appended seal is one line
//!   (`{"index":N, "seal":..., "leaf_hash":...}\n`). Crash-safe under
//!   single-writer assumption.
//! - **fsync on every append by default** — durable up to the last
//!   committed entry. Configurable to batch fsync for higher throughput.
//! - **Recovery on open** — when the store is opened, all existing entries
//!   are read, leaf hashes recomputed, indices verified for monotonicity.
//! - **Tamper detection on recovery** — if a leaf hash on disk doesn't match
//!   the seal's recomputed hash, recovery fails closed (the file has been
//!   modified out of band).
//! - **Compaction stub** — `compact_to(snapshot_path)` writes the current
//!   state to a snapshot file (current + Merkle root). Production
//!   deployments use this to bound disk growth.
//!
//! ## Trade-offs vs. RocksDB / SQLite
//!
//! This is intentionally a single-writer JSON-lines log, not a full B-tree
//! database. The argument: (a) we're append-only, (b) we want trivially
//! verifiable on-disk format (an auditor can `cat` the file and read it
//! with their eyes), (c) no native deps. For high-throughput multi-tenant
//! deployments, swap [`PersistentEvidenceLog`] for a `RocksDbEvidenceLog`
//! by implementing [`EvidenceStore`].
//!
//! ## Single-writer
//!
//! `PersistentEvidenceLog` assumes a single writer (one process or
//! thread holding the file). Multi-writer is out of scope for this layer;
//! use a database for that.

use crate::evidence::{EvidenceLogEntry, MerkleProof};
use crate::hashing::{Hasher, Sha256Digest};
use crate::seal::DigitalSeal;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Generic durable evidence-store contract.
pub trait EvidenceStore: Send + Sync {
    /// Append a seal, return the assigned entry.
    fn append(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry>;
    /// Number of entries in the store.
    fn len(&self) -> usize;
    /// `true` if no entries have been appended.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Compute the current Merkle root.
    fn root(&self) -> SandboxResult<Sha256Digest>;
    /// Build a Merkle inclusion proof for the entry at `index`.
    fn proof(&self, index: u64) -> SandboxResult<MerkleProof>;
    /// Get all entries.
    fn entries(&self) -> SandboxResult<Vec<EvidenceLogEntry>>;
}

/// Persistence configuration.
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// fsync after every append. Default: `true` (durable).
    pub sync_on_append: bool,
    /// Verify leaf hashes during recovery. Default: `true`.
    pub verify_on_recovery: bool,
    /// Maximum acceptable file size before compaction is recommended.
    /// Default: 256 MiB.
    pub max_file_size_bytes: u64,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            sync_on_append: true,
            verify_on_recovery: true,
            max_file_size_bytes: 256 * 1024 * 1024,
        }
    }
}

/// File-backed persistent evidence log (JSON-lines).
pub struct PersistentEvidenceLog {
    path: PathBuf,
    config: PersistenceConfig,
    state: Mutex<PersistedState>,
}

struct PersistedState {
    entries: Vec<EvidenceLogEntry>,
    leaf_hashes: Vec<Sha256Digest>,
    file: BufWriter<File>,
}

impl PersistentEvidenceLog {
    /// Open (or create) a persistent evidence log at `path`.
    /// Recovers all existing entries from disk.
    pub fn open(path: impl AsRef<Path>) -> SandboxResult<Self> {
        Self::open_with(path, PersistenceConfig::default())
    }

    /// Open with a custom config.
    pub fn open_with(
        path: impl AsRef<Path>,
        config: PersistenceConfig,
    ) -> SandboxResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut entries: Vec<EvidenceLogEntry> = Vec::new();
        let mut leaf_hashes: Vec<Sha256Digest> = Vec::new();
        // Recover.
        if path.exists() {
            let f = File::open(&path).map_err(|e| {
                SandboxError::Evidence(format!("open {}: {}", path.display(), e))
            })?;
            let reader = BufReader::new(f);
            for (lineno, line) in reader.lines().enumerate() {
                let line = line.map_err(|e| {
                    SandboxError::Evidence(format!("read line {}: {}", lineno + 1, e))
                })?;
                if line.trim().is_empty() {
                    continue;
                }
                let entry: EvidenceLogEntry = serde_json::from_str(&line).map_err(|e| {
                    SandboxError::Evidence(format!(
                        "parse line {}: {}",
                        lineno + 1,
                        e
                    ))
                })?;
                if config.verify_on_recovery {
                    let recomputed = Hasher::hash_value(&entry.seal)?;
                    if recomputed != entry.leaf_hash {
                        return Err(SandboxError::Evidence(format!(
                            "leaf hash mismatch at line {} (index {}): file={} recomputed={} — TAMPER DETECTED",
                            lineno + 1,
                            entry.index,
                            entry.leaf_hash.to_hex(),
                            recomputed.to_hex()
                        )));
                    }
                }
                if entry.index as usize != entries.len() {
                    return Err(SandboxError::Evidence(format!(
                        "non-monotonic index at line {}: expected {}, got {}",
                        lineno + 1,
                        entries.len(),
                        entry.index
                    )));
                }
                leaf_hashes.push(entry.leaf_hash);
                entries.push(entry);
            }
        }
        // Open for appending.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                SandboxError::Evidence(format!("open append {}: {}", path.display(), e))
            })?;
        let writer = BufWriter::new(file);
        Ok(Self {
            path,
            config,
            state: Mutex::new(PersistedState {
                entries,
                leaf_hashes,
                file: writer,
            }),
        })
    }

    /// Path of the underlying file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Compact the log into a snapshot file. Writes a single JSON object
    /// containing the full entries and current Merkle root.
    pub fn compact_to(&self, snapshot_path: impl AsRef<Path>) -> SandboxResult<()> {
        let state = self.state.lock().map_err(|_| {
            SandboxError::Evidence("persistent log poisoned".into())
        })?;
        let snapshot = Snapshot {
            entries: state.entries.clone(),
            merkle_root: Hasher::merkle_root(&state.leaf_hashes),
            entry_count: state.entries.len() as u64,
            schema_version: 1,
        };
        let mut f = File::create(snapshot_path.as_ref()).map_err(|e| {
            SandboxError::Evidence(format!("create snapshot: {e}"))
        })?;
        let json = serde_json::to_vec_pretty(&snapshot).map_err(|e| {
            SandboxError::Evidence(format!("serialise snapshot: {e}"))
        })?;
        f.write_all(&json).map_err(|e| {
            SandboxError::Evidence(format!("write snapshot: {e}"))
        })?;
        f.sync_all().map_err(|e| {
            SandboxError::Evidence(format!("sync snapshot: {e}"))
        })?;
        Ok(())
    }

    /// Restore from a snapshot file. Truncates the current log and replays
    /// the snapshot entries.
    pub fn restore_from(&self, snapshot_path: impl AsRef<Path>) -> SandboxResult<()> {
        let bytes = std::fs::read(snapshot_path.as_ref()).map_err(|e| {
            SandboxError::Evidence(format!("read snapshot: {e}"))
        })?;
        let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|e| {
            SandboxError::Evidence(format!("parse snapshot: {e}"))
        })?;
        let mut state = self.state.lock().map_err(|_| {
            SandboxError::Evidence("persistent log poisoned".into())
        })?;
        // Truncate the file.
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&self.path)
            .map_err(|e| {
                SandboxError::Evidence(format!("truncate: {e}"))
            })?;
        let mut new_entries: Vec<EvidenceLogEntry> = Vec::with_capacity(snapshot.entries.len());
        let mut new_leaves: Vec<Sha256Digest> = Vec::with_capacity(snapshot.entries.len());
        for entry in &snapshot.entries {
            let line = serde_json::to_string(entry).map_err(|e| {
                SandboxError::Evidence(format!("serialise entry: {e}"))
            })?;
            file.write_all(line.as_bytes()).map_err(|e| {
                SandboxError::Evidence(format!("write entry: {e}"))
            })?;
            file.write_all(b"\n").map_err(|e| {
                SandboxError::Evidence(format!("write nl: {e}"))
            })?;
            new_entries.push(entry.clone());
            new_leaves.push(entry.leaf_hash);
        }
        file.sync_all().map_err(|e| {
            SandboxError::Evidence(format!("sync: {e}"))
        })?;
        // Re-open append handle.
        let file_append = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                SandboxError::Evidence(format!("re-open: {e}"))
            })?;
        state.file = BufWriter::new(file_append);
        state.entries = new_entries;
        state.leaf_hashes = new_leaves;
        Ok(())
    }

    /// Current on-disk byte size.
    pub fn file_size_bytes(&self) -> SandboxResult<u64> {
        let meta = std::fs::metadata(&self.path).map_err(|e| {
            SandboxError::Evidence(format!("metadata: {e}"))
        })?;
        Ok(meta.len())
    }

    /// `true` if file size has crossed the configured threshold.
    pub fn needs_compaction(&self) -> SandboxResult<bool> {
        Ok(self.file_size_bytes()? > self.config.max_file_size_bytes)
    }

    /// Force-flush the buffered writer.
    pub fn flush(&self) -> SandboxResult<()> {
        let mut state = self.state.lock().map_err(|_| {
            SandboxError::Evidence("persistent log poisoned".into())
        })?;
        state.file.flush().map_err(|e| {
            SandboxError::Evidence(format!("flush: {e}"))
        })?;
        if self.config.sync_on_append {
            state.file.get_ref().sync_all().map_err(|e| {
                SandboxError::Evidence(format!("sync: {e}"))
            })?;
        }
        Ok(())
    }
}

impl EvidenceStore for PersistentEvidenceLog {
    fn append(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> {
        let mut state = self.state.lock().map_err(|_| {
            SandboxError::Evidence("persistent log poisoned".into())
        })?;
        let index = state.entries.len() as u64;
        let leaf_hash = Hasher::hash_value(&seal)?;
        let entry = EvidenceLogEntry {
            index,
            seal,
            leaf_hash,
        };
        let line = serde_json::to_string(&entry).map_err(|e| {
            SandboxError::Evidence(format!("serialise entry: {e}"))
        })?;
        state.file.write_all(line.as_bytes()).map_err(|e| {
            SandboxError::Evidence(format!("write entry: {e}"))
        })?;
        state.file.write_all(b"\n").map_err(|e| {
            SandboxError::Evidence(format!("write nl: {e}"))
        })?;
        state.file.flush().map_err(|e| {
            SandboxError::Evidence(format!("flush: {e}"))
        })?;
        if self.config.sync_on_append {
            state.file.get_ref().sync_all().map_err(|e| {
                SandboxError::Evidence(format!("sync: {e}"))
            })?;
        }
        state.entries.push(entry.clone());
        state.leaf_hashes.push(leaf_hash);
        Ok(entry)
    }

    fn len(&self) -> usize {
        self.state.lock().map(|s| s.entries.len()).unwrap_or(0)
    }

    fn root(&self) -> SandboxResult<Sha256Digest> {
        let state = self.state.lock().map_err(|_| {
            SandboxError::Evidence("persistent log poisoned".into())
        })?;
        Ok(Hasher::merkle_root(&state.leaf_hashes))
    }

    fn proof(&self, index: u64) -> SandboxResult<MerkleProof> {
        let state = self.state.lock().map_err(|_| {
            SandboxError::Evidence("persistent log poisoned".into())
        })?;
        let n = state.leaf_hashes.len();
        let idx = index as usize;
        if idx >= n {
            return Err(SandboxError::Evidence(format!(
                "index {} out of range (len={})",
                index, n
            )));
        }
        let leaf_hash = state.leaf_hashes[idx];
        let mut siblings: Vec<Sha256Digest> = Vec::new();
        let mut current_level = state.leaf_hashes.clone();
        let mut current_idx = idx;
        while current_level.len() > 1 {
            let sibling_idx = if current_idx % 2 == 0 {
                if current_idx + 1 < current_level.len() {
                    current_idx + 1
                } else {
                    current_idx
                }
            } else {
                current_idx - 1
            };
            siblings.push(current_level[sibling_idx]);
            let mut next_level: Vec<Sha256Digest> =
                Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Hasher::merkle_combine(chunk[0], chunk[1]));
                } else {
                    next_level.push(Hasher::merkle_combine(chunk[0], chunk[0]));
                }
            }
            current_level = next_level;
            current_idx /= 2;
        }
        let root = current_level[0];
        Ok(MerkleProof {
            leaf_index: index,
            leaf_hash,
            siblings,
            root,
        })
    }

    fn entries(&self) -> SandboxResult<Vec<EvidenceLogEntry>> {
        let state = self.state.lock().map_err(|_| {
            SandboxError::Evidence("persistent log poisoned".into())
        })?;
        Ok(state.entries.clone())
    }
}

/// Snapshot file format (used by `compact_to` / `restore_from`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Schema version of the snapshot file.
    pub schema_version: u32,
    /// All entries in the log at snapshot time.
    pub entries: Vec<EvidenceLogEntry>,
    /// Number of entries (denormalized for quick checks).
    pub entry_count: u64,
    /// Merkle root over all entries.
    pub merkle_root: Sha256Digest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{ApprovalRecord, ModelReference, RetentionClass, SealVersion};
    use crate::Sector;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn dummy_seal(seed: u64) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "credit_decision".into(),
            event_hash: Hasher::sha256(format!("event-{seed}").as_bytes()),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: Hasher::sha256(format!("in-{seed}").as_bytes()),
            output_hash: Hasher::sha256(format!("out-{seed}").as_bytes()),
            approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    fn tmp_path(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aethelred-evlog-{}-{}.jsonl",
            std::process::id(),
            suffix
        ))
    }

    #[test]
    fn open_creates_empty_log() {
        let p = tmp_path("empty");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn append_persists_to_disk() {
        let p = tmp_path("append");
        let _ = std::fs::remove_file(&p);
        {
            let log = PersistentEvidenceLog::open(&p).unwrap();
            log.append(dummy_seal(1)).unwrap();
            log.append(dummy_seal(2)).unwrap();
            assert_eq!(log.len(), 2);
        }
        // Re-open — should recover both.
        let log = PersistentEvidenceLog::open(&p).unwrap();
        assert_eq!(log.len(), 2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn append_assigns_monotonic_indices() {
        let p = tmp_path("monotonic");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        let e1 = log.append(dummy_seal(1)).unwrap();
        let e2 = log.append(dummy_seal(2)).unwrap();
        assert_eq!(e1.index, 0);
        assert_eq!(e2.index, 1);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn root_changes_after_append() {
        let p = tmp_path("root");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        log.append(dummy_seal(1)).unwrap();
        let r1 = log.root().unwrap();
        log.append(dummy_seal(2)).unwrap();
        let r2 = log.root().unwrap();
        assert_ne!(r1, r2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn proof_verifies_after_recovery() {
        let p = tmp_path("recover-proof");
        let _ = std::fs::remove_file(&p);
        {
            let log = PersistentEvidenceLog::open(&p).unwrap();
            for i in 0..5 {
                log.append(dummy_seal(i)).unwrap();
            }
        }
        let log = PersistentEvidenceLog::open(&p).unwrap();
        for i in 0..5 {
            let proof = log.proof(i).unwrap();
            assert!(proof.verify());
        }
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn proof_oor_returns_error() {
        let p = tmp_path("oor");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        log.append(dummy_seal(1)).unwrap();
        assert!(log.proof(99).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn entries_returns_all_appended() {
        let p = tmp_path("entries");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        for i in 0..3 {
            log.append(dummy_seal(i)).unwrap();
        }
        let es = log.entries().unwrap();
        assert_eq!(es.len(), 3);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn tampered_file_recovery_fails_closed() {
        let p = tmp_path("tamper");
        let _ = std::fs::remove_file(&p);
        {
            let log = PersistentEvidenceLog::open(&p).unwrap();
            log.append(dummy_seal(1)).unwrap();
        }
        // Tamper with the file: replace `event_hash` with a different value
        // but keep the original `leaf_hash`.
        let content = std::fs::read_to_string(&p).unwrap();
        let tampered = content.replacen(
            "credit_decision",
            "tampered_event_type",
            1,
        );
        std::fs::write(&p, tampered).unwrap();
        let r = PersistentEvidenceLog::open(&p);
        assert!(r.is_err(), "tampered file should not open cleanly");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn compact_and_restore_round_trip() {
        let p = tmp_path("compact-src");
        let snap = tmp_path("compact-snap");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&snap);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        for i in 0..7 {
            log.append(dummy_seal(i)).unwrap();
        }
        log.compact_to(&snap).unwrap();
        let p2 = tmp_path("compact-dst");
        let _ = std::fs::remove_file(&p2);
        let log2 = PersistentEvidenceLog::open(&p2).unwrap();
        log2.restore_from(&snap).unwrap();
        assert_eq!(log2.len(), 7);
        // Roots match.
        assert_eq!(log.root().unwrap(), log2.root().unwrap());
        std::fs::remove_file(&p).ok();
        std::fs::remove_file(&snap).ok();
        std::fs::remove_file(&p2).ok();
    }

    #[test]
    fn file_size_grows_with_appends() {
        let p = tmp_path("size");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        let s0 = log.file_size_bytes().unwrap();
        log.append(dummy_seal(1)).unwrap();
        let s1 = log.file_size_bytes().unwrap();
        assert!(s1 > s0);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn needs_compaction_false_for_small_log() {
        let p = tmp_path("compact-needed");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        log.append(dummy_seal(1)).unwrap();
        assert!(!log.needs_compaction().unwrap());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn config_can_disable_sync() {
        let p = tmp_path("nosync");
        let _ = std::fs::remove_file(&p);
        let mut cfg = PersistenceConfig::default();
        cfg.sync_on_append = false;
        let log = PersistentEvidenceLog::open_with(&p, cfg).unwrap();
        log.append(dummy_seal(1)).unwrap();
        log.flush().unwrap();
        assert_eq!(log.len(), 1);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn snapshot_serde_round_trip() {
        let p = tmp_path("snap-serde");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        log.append(dummy_seal(1)).unwrap();
        let snap_path = tmp_path("snap-serde-out");
        log.compact_to(&snap_path).unwrap();
        let bytes = std::fs::read(&snap_path).unwrap();
        let s: Snapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s.entry_count, 1);
        std::fs::remove_file(&p).ok();
        std::fs::remove_file(&snap_path).ok();
    }

    #[test]
    fn many_appends_recover_correctly() {
        let p = tmp_path("many");
        let _ = std::fs::remove_file(&p);
        {
            let log = PersistentEvidenceLog::open(&p).unwrap();
            for i in 0..50 {
                log.append(dummy_seal(i)).unwrap();
            }
        }
        let log = PersistentEvidenceLog::open(&p).unwrap();
        assert_eq!(log.len(), 50);
        let proof_24 = log.proof(24).unwrap();
        assert!(proof_24.verify());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn path_is_returned() {
        let p = tmp_path("path");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        assert_eq!(log.path(), p.as_path());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn flush_works_when_empty() {
        let p = tmp_path("flush-empty");
        let _ = std::fs::remove_file(&p);
        let log = PersistentEvidenceLog::open(&p).unwrap();
        log.flush().unwrap();
        std::fs::remove_file(&p).ok();
    }
}
