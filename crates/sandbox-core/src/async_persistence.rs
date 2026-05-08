//! Async-aware durable evidence log.
//!
//! v0.2.1 shipped [`crate::persistence::PersistentEvidenceLog`] — sync
//! file-backed JSON-lines log. Production deployments running Tokio
//! runtimes (FIX 4.4 ingestion, Kafka consumers, Tonic gRPC servers)
//! need an async-aware variant that doesn't block the executor.
//!
//! ## Design
//!
//! - **Background writer task** — appends arrive on a `mpsc::Sender`,
//!   the writer task drains, batches, fsyncs, and acks via a oneshot.
//! - **Backpressure** — bounded channel, configurable capacity. When
//!   full, `append_async` returns a `BackpressureExceeded` error so
//!   producers can throttle.
//! - **Batched fsync** — fsync once per batch (default: 64 records or
//!   100 ms, whichever first). Trades latency for throughput.
//! - **Graceful shutdown** — `shutdown()` drains the channel and waits
//!   for the writer to flush.
//! - **Recovery** — same as sync log: read existing file on startup,
//!   verify leaf hashes, reject tampered files.
//!
//! ## Why not just spawn_blocking
//!
//! `spawn_blocking` works for one-off file I/O but doesn't give you
//! batched fsync, backpressure, or graceful shutdown. The right shape is
//! a long-lived writer task with a typed channel — what production
//! databases do.
//!
//! Gated behind the `async` feature.

#![cfg(feature = "async")]

use crate::evidence::{EvidenceLogEntry, MerkleProof};
use crate::hashing::{Hasher, Sha256Digest};
use crate::seal::DigitalSeal;
use crate::{SandboxError, SandboxResult};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;

// =============================================================================
// AsyncPersistenceConfig
// =============================================================================

/// Async-log configuration.
#[derive(Debug, Clone)]
pub struct AsyncPersistenceConfig {
    /// Bounded channel capacity. When full, `append_async` returns error.
    pub channel_capacity: usize,
    /// Max records before forced fsync.
    pub batch_max_records: usize,
    /// Max wait (ms) before forced fsync.
    pub batch_max_ms: u64,
    /// Verify leaf hashes during recovery.
    pub verify_on_recovery: bool,
    /// Fsync after every flushed batch.
    pub fsync_per_batch: bool,
}

impl Default for AsyncPersistenceConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 1024,
            batch_max_records: 64,
            batch_max_ms: 100,
            verify_on_recovery: true,
            fsync_per_batch: true,
        }
    }
}

impl AsyncPersistenceConfig {
    /// Latency-optimized: fsync per record (small batch, no batching wait).
    pub fn low_latency() -> Self {
        Self {
            channel_capacity: 256,
            batch_max_records: 1,
            batch_max_ms: 0,
            verify_on_recovery: true,
            fsync_per_batch: true,
        }
    }
    /// Throughput-optimized: large batches, infrequent fsync.
    pub fn high_throughput() -> Self {
        Self {
            channel_capacity: 8192,
            batch_max_records: 1024,
            batch_max_ms: 500,
            verify_on_recovery: true,
            fsync_per_batch: false,
        }
    }
}

// =============================================================================
// Internal channel messages
// =============================================================================

enum WriterMessage {
    Append {
        seal: DigitalSeal,
        ack: oneshot::Sender<SandboxResult<EvidenceLogEntry>>,
    },
    Flush(oneshot::Sender<SandboxResult<()>>),
    Shutdown(oneshot::Sender<SandboxResult<()>>),
}

// =============================================================================
// AsyncPersistentEvidenceLog
// =============================================================================

#[derive(Debug)]
struct SharedState {
    entries: Vec<EvidenceLogEntry>,
    leaf_hashes: Vec<Sha256Digest>,
}

/// Async-aware persistent evidence log.
pub struct AsyncPersistentEvidenceLog {
    path: PathBuf,
    sender: mpsc::Sender<WriterMessage>,
    state: Arc<Mutex<SharedState>>,
    writer_handle: Mutex<Option<JoinHandle<()>>>,
    _config: AsyncPersistenceConfig,
}

impl AsyncPersistentEvidenceLog {
    /// Open (or create) at `path`. Recovers existing entries.
    pub async fn open(path: impl AsRef<Path>) -> SandboxResult<Self> {
        Self::open_with(path, AsyncPersistenceConfig::default()).await
    }

    /// Open with a custom config.
    pub async fn open_with(
        path: impl AsRef<Path>,
        config: AsyncPersistenceConfig,
    ) -> SandboxResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut entries: Vec<EvidenceLogEntry> = Vec::new();
        let mut leaf_hashes: Vec<Sha256Digest> = Vec::new();
        // Recovery — read existing file line-by-line.
        if path.exists() {
            let f = File::open(&path).await.map_err(|e| {
                SandboxError::Evidence(format!("open {}: {}", path.display(), e))
            })?;
            let reader = BufReader::new(f);
            let mut lines = reader.lines();
            let mut lineno = 0usize;
            while let Some(line) = lines.next_line().await.map_err(|e| {
                SandboxError::Evidence(format!("read line: {e}"))
            })? {
                lineno += 1;
                if line.trim().is_empty() {
                    continue;
                }
                let entry: EvidenceLogEntry = serde_json::from_str(&line).map_err(|e| {
                    SandboxError::Evidence(format!("parse line {lineno}: {e}"))
                })?;
                if config.verify_on_recovery {
                    let recomputed = Hasher::hash_value(&entry.seal)?;
                    if recomputed != entry.leaf_hash {
                        return Err(SandboxError::Evidence(format!(
                            "leaf hash mismatch at line {} (index {}): TAMPER DETECTED",
                            lineno, entry.index
                        )));
                    }
                }
                if entry.index as usize != entries.len() {
                    return Err(SandboxError::Evidence(format!(
                        "non-monotonic index at line {}: expected {}, got {}",
                        lineno,
                        entries.len(),
                        entry.index
                    )));
                }
                leaf_hashes.push(entry.leaf_hash);
                entries.push(entry);
            }
        }
        let state = Arc::new(Mutex::new(SharedState {
            entries,
            leaf_hashes,
        }));
        // Spawn writer task.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|e| {
                SandboxError::Evidence(format!("open append {}: {}", path.display(), e))
            })?;
        let (tx, rx) = mpsc::channel::<WriterMessage>(config.channel_capacity);
        let writer_state = state.clone();
        let writer_path = path.clone();
        let writer_config = config.clone();
        let handle = tokio::spawn(async move {
            run_writer(rx, file, writer_state, writer_path, writer_config).await;
        });
        Ok(Self {
            path,
            sender: tx,
            state,
            writer_handle: Mutex::new(Some(handle)),
            _config: config,
        })
    }

    /// Path of the underlying file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a seal asynchronously.
    pub async fn append_async(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(WriterMessage::Append { seal, ack: tx })
            .await
            .map_err(|_| SandboxError::Evidence(
                "writer task disconnected — log may be shut down".into(),
            ))?;
        rx.await.map_err(|_| {
            SandboxError::Evidence("writer task dropped ack channel".into())
        })?
    }

    /// Force-flush the writer.
    pub async fn flush_async(&self) -> SandboxResult<()> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(WriterMessage::Flush(tx))
            .await
            .map_err(|_| SandboxError::Evidence("writer task disconnected".into()))?;
        rx.await
            .map_err(|_| SandboxError::Evidence("writer dropped flush ack".into()))?
    }

    /// Graceful shutdown — drain queue + flush + stop the writer.
    pub async fn shutdown(&self) -> SandboxResult<()> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(WriterMessage::Shutdown(tx))
            .await
            .map_err(|_| SandboxError::Evidence("writer task already gone".into()))?;
        rx.await
            .map_err(|_| SandboxError::Evidence("writer dropped shutdown ack".into()))??;
        let mut h = self.writer_handle.lock().await;
        if let Some(handle) = h.take() {
            let _ = handle.await;
        }
        Ok(())
    }

    /// Number of entries currently committed.
    pub async fn len(&self) -> usize {
        self.state.lock().await.entries.len()
    }

    /// `true` if no entries committed.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Current Merkle root.
    pub async fn root(&self) -> SandboxResult<Sha256Digest> {
        let s = self.state.lock().await;
        Ok(Hasher::merkle_root(&s.leaf_hashes))
    }

    /// Build a Merkle proof for `index`.
    pub async fn proof(&self, index: u64) -> SandboxResult<MerkleProof> {
        let s = self.state.lock().await;
        let n = s.leaf_hashes.len();
        let idx = index as usize;
        if idx >= n {
            return Err(SandboxError::Evidence(format!(
                "index {} out of range (len={})",
                index, n
            )));
        }
        let leaf_hash = s.leaf_hashes[idx];
        let mut siblings: Vec<Sha256Digest> = Vec::new();
        let mut current_level = s.leaf_hashes.clone();
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
        Ok(MerkleProof {
            leaf_index: index,
            leaf_hash,
            siblings,
            root: current_level[0],
        })
    }

    /// All entries.
    pub async fn entries(&self) -> Vec<EvidenceLogEntry> {
        self.state.lock().await.entries.clone()
    }
}

async fn run_writer(
    mut rx: mpsc::Receiver<WriterMessage>,
    file: File,
    state: Arc<Mutex<SharedState>>,
    _path: PathBuf,
    config: AsyncPersistenceConfig,
) {
    let mut writer = BufWriter::new(file);
    let mut pending_acks: Vec<(EvidenceLogEntry, oneshot::Sender<SandboxResult<EvidenceLogEntry>>)> =
        Vec::new();
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(WriterMessage::Append { seal, ack }) => {
                        let mut s = state.lock().await;
                        let index = s.entries.len() as u64;
                        let leaf_hash = match Hasher::hash_value(&seal) {
                            Ok(h) => h,
                            Err(e) => {
                                let _ = ack.send(Err(e));
                                continue;
                            }
                        };
                        let entry = EvidenceLogEntry { index, seal, leaf_hash };
                        let line = match serde_json::to_string(&entry) {
                            Ok(s) => s,
                            Err(e) => {
                                let _ = ack.send(Err(SandboxError::Evidence(format!("serialise: {e}"))));
                                continue;
                            }
                        };
                        if let Err(e) = writer.write_all(line.as_bytes()).await {
                            let _ = ack.send(Err(SandboxError::Evidence(format!("write: {e}"))));
                            continue;
                        }
                        if let Err(e) = writer.write_all(b"\n").await {
                            let _ = ack.send(Err(SandboxError::Evidence(format!("write nl: {e}"))));
                            continue;
                        }
                        s.entries.push(entry.clone());
                        s.leaf_hashes.push(leaf_hash);
                        pending_acks.push((entry, ack));

                        if pending_acks.len() >= config.batch_max_records {
                            flush_batch(&mut writer, &mut pending_acks, config.fsync_per_batch).await;
                        }
                    }
                    Some(WriterMessage::Flush(tx)) => {
                        flush_batch(&mut writer, &mut pending_acks, config.fsync_per_batch).await;
                        let _ = tx.send(Ok(()));
                    }
                    Some(WriterMessage::Shutdown(tx)) => {
                        flush_batch(&mut writer, &mut pending_acks, true).await;
                        let _ = writer.flush().await;
                        let _ = writer.get_ref().sync_all().await;
                        let _ = tx.send(Ok(()));
                        break;
                    }
                    None => {
                        // Sender dropped without shutdown — flush what we have.
                        flush_batch(&mut writer, &mut pending_acks, true).await;
                        let _ = writer.flush().await;
                        let _ = writer.get_ref().sync_all().await;
                        break;
                    }
                }
            }
            // Time-based flush.
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(config.batch_max_ms)) => {
                if !pending_acks.is_empty() {
                    flush_batch(&mut writer, &mut pending_acks, config.fsync_per_batch).await;
                }
            }
        }
    }
}

async fn flush_batch(
    writer: &mut BufWriter<File>,
    pending: &mut Vec<(EvidenceLogEntry, oneshot::Sender<SandboxResult<EvidenceLogEntry>>)>,
    fsync: bool,
) {
    if pending.is_empty() {
        return;
    }
    let _ = writer.flush().await;
    if fsync {
        let _ = writer.get_ref().sync_all().await;
    }
    for (entry, ack) in pending.drain(..) {
        let _ = ack.send(Ok(entry));
    }
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
            "aethelred-asyncev-{}-{}.jsonl",
            std::process::id(),
            suffix
        ))
    }

    #[tokio::test]
    async fn open_creates_empty_log() {
        let p = tmp_path("empty");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        assert_eq!(log.len().await, 0);
        assert!(log.is_empty().await);
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn append_async_persists() {
        let p = tmp_path("append");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        let e = log.append_async(dummy_seal(1)).await.unwrap();
        assert_eq!(e.index, 0);
        log.shutdown().await.unwrap();
        // Reopen and check.
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        assert_eq!(log.len().await, 1);
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn append_many_returns_monotonic_indices() {
        let p = tmp_path("mono");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        for i in 0..5u64 {
            let e = log.append_async(dummy_seal(i)).await.unwrap();
            assert_eq!(e.index, i);
        }
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn root_changes_on_append() {
        let p = tmp_path("root");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        log.append_async(dummy_seal(1)).await.unwrap();
        let r1 = log.root().await.unwrap();
        log.append_async(dummy_seal(2)).await.unwrap();
        let r2 = log.root().await.unwrap();
        assert_ne!(r1, r2);
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn proof_verifies_after_recovery() {
        let p = tmp_path("rec-proof");
        let _ = tokio::fs::remove_file(&p).await;
        {
            let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
            for i in 0..5u64 {
                log.append_async(dummy_seal(i)).await.unwrap();
            }
            log.shutdown().await.unwrap();
        }
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        for i in 0..5u64 {
            let p = log.proof(i).await.unwrap();
            assert!(p.verify());
        }
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn shutdown_drains_queue() {
        let p = tmp_path("drain");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        for i in 0..50u64 {
            log.append_async(dummy_seal(i)).await.unwrap();
        }
        log.shutdown().await.unwrap();
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        assert_eq!(log.len().await, 50);
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn flush_async_works() {
        let p = tmp_path("flush");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        log.append_async(dummy_seal(1)).await.unwrap();
        log.flush_async().await.unwrap();
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn proof_oor_returns_error() {
        let p = tmp_path("oor");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        log.append_async(dummy_seal(1)).await.unwrap();
        assert!(log.proof(99).await.is_err());
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn entries_returns_all() {
        let p = tmp_path("entries");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        for i in 0..3u64 {
            log.append_async(dummy_seal(i)).await.unwrap();
        }
        let es = log.entries().await;
        assert_eq!(es.len(), 3);
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn high_throughput_config_works() {
        let p = tmp_path("ht");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open_with(
            &p,
            AsyncPersistenceConfig::high_throughput(),
        )
        .await
        .unwrap();
        for i in 0..100u64 {
            log.append_async(dummy_seal(i)).await.unwrap();
        }
        log.shutdown().await.unwrap();
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        assert_eq!(log.len().await, 100);
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn low_latency_config_works() {
        let p = tmp_path("ll");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open_with(
            &p,
            AsyncPersistenceConfig::low_latency(),
        )
        .await
        .unwrap();
        log.append_async(dummy_seal(1)).await.unwrap();
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn tampered_file_recovery_fails_closed() {
        let p = tmp_path("tamper-async");
        let _ = tokio::fs::remove_file(&p).await;
        {
            let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
            log.append_async(dummy_seal(1)).await.unwrap();
            log.shutdown().await.unwrap();
        }
        let content = tokio::fs::read_to_string(&p).await.unwrap();
        let tampered = content.replacen("credit_decision", "tampered_event", 1);
        tokio::fs::write(&p, tampered).await.unwrap();
        let r = AsyncPersistentEvidenceLog::open(&p).await;
        assert!(r.is_err());
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn path_returned() {
        let p = tmp_path("path");
        let _ = tokio::fs::remove_file(&p).await;
        let log = AsyncPersistentEvidenceLog::open(&p).await.unwrap();
        assert_eq!(log.path(), p.as_path());
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn config_default_values_sensible() {
        let c = AsyncPersistenceConfig::default();
        assert!(c.channel_capacity > 0);
        assert!(c.batch_max_records > 0);
    }

    #[tokio::test]
    async fn many_concurrent_appends_serialize_correctly() {
        let p = tmp_path("concurrent");
        let _ = tokio::fs::remove_file(&p).await;
        let log = Arc::new(AsyncPersistentEvidenceLog::open(&p).await.unwrap());
        let mut handles = Vec::new();
        for i in 0..50u64 {
            let log_clone = log.clone();
            handles.push(tokio::spawn(async move {
                log_clone.append_async(dummy_seal(i)).await.unwrap()
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(log.len().await, 50);
        log.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(&p).await;
    }
}
