//! Encrypted backup & restore of evidence logs.
//!
//! v0.2.1 [`crate::persistence::PersistentEvidenceLog::compact_to`] writes
//! a plaintext snapshot. Production deployments need:
//!
//! - **Encryption at rest** for snapshots (AES-CTR/SHA-256-PRF stream).
//! - **Integrity check** — recompute Merkle root + per-entry leaf hashes
//!   on restore and reject tampered files.
//! - **Versioning** — schema_version baked in.
//! - **Per-tenant key separation** — each tenant's backup encrypted with
//!   that tenant's key (so a stolen-disk attacker can't read another
//!   tenant's data).
//! - **Manifest** — separate plaintext manifest with metadata + Merkle
//!   root, signed so an auditor can locate the backup without
//!   decrypting it.
//!
//! ## What we ship
//!
//! - [`BackupManifest`] — manifest format (schema, tenant, root, byte
//!   length, encrypted hash).
//! - [`BackupEncryption`] — pluggable encryption trait + reuses
//!   [`crate::crypto_shred::Cipher`] (StreamCipherSha256).
//! - [`Backup`] — `create_from(...)` and `restore_to(...)` operations.
//! - [`BackupKey`] — wraps a 32-byte key + a 16-byte nonce.
//!
//! ## Wire format
//!
//! `<backup-name>.manifest.json` — plaintext metadata + Merkle root.
//! `<backup-name>.snapshot.enc`   — encrypted snapshot bytes.

use crate::crypto_shred::{Cipher, StreamCipherSha256};
use crate::evidence::{EvidenceLog, EvidenceLogEntry};
use crate::hashing::{Hasher, Sha256Digest};
use crate::{Sector, SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// BackupKey
// =============================================================================

/// 32-byte key + 16-byte nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupKey {
    /// 32-byte symmetric key.
    pub key: [u8; 32],
    /// 16-byte nonce (per-backup).
    pub nonce: [u8; 16],
}

impl BackupKey {
    /// New key from raw bytes.
    pub fn new(key: [u8; 32], nonce: [u8; 16]) -> Self {
        Self { key, nonce }
    }

    /// Derive a key from a passphrase + salt (PBKDF2-style with 100k SHA-256 iterations).
    pub fn from_passphrase(passphrase: &[u8], salt: &[u8]) -> Self {
        // Iterated SHA-256 — adequate for the shredding-style use case;
        // production deployments use Argon2id.
        let mut buf = Vec::with_capacity(32 + salt.len());
        buf.extend_from_slice(passphrase);
        buf.extend_from_slice(salt);
        let mut h = Hasher::sha256(&buf).0;
        for _ in 0..100_000 {
            h = Hasher::sha256(&h).0;
        }
        // Use the first 16 bytes of the salt's hash as nonce.
        let nonce_h = Hasher::sha256(salt).0;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_h[..16]);
        Self { key: h, nonce }
    }

    /// Hex of the key (for logging — production deployments don't log keys).
    pub fn key_hex(&self) -> String {
        hex::encode(self.key)
    }
}

// =============================================================================
// BackupManifest
// =============================================================================

/// Plaintext manifest accompanying an encrypted snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupManifest {
    /// Schema version.
    pub schema_version: u32,
    /// Backup id.
    pub backup_id: Uuid,
    /// Tenant id.
    pub tenant_id: String,
    /// Sector.
    pub sector: Sector,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// Number of entries in the backup.
    pub entry_count: u64,
    /// Merkle root over entries (plaintext-derived; auditors verify
    /// without decrypting).
    pub merkle_root: Sha256Digest,
    /// Hash of the encrypted snapshot bytes (integrity).
    pub encrypted_hash: Sha256Digest,
    /// Cipher algorithm name.
    pub cipher: String,
    /// Length of encrypted snapshot in bytes.
    pub encrypted_bytes: u64,
}

// =============================================================================
// Snapshot — internal in-flight format (plaintext before encryption)
// =============================================================================

/// In-memory snapshot (plaintext form).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSnapshot {
    /// Tenant id.
    pub tenant_id: String,
    /// Sector.
    pub sector: Sector,
    /// All entries.
    pub entries: Vec<EvidenceLogEntry>,
    /// Merkle root for cross-check.
    pub merkle_root: Sha256Digest,
}

// =============================================================================
// Backup
// =============================================================================

/// Create / restore encrypted backups.
pub struct Backup {
    cipher: Box<dyn Cipher>,
}

impl Default for Backup {
    fn default() -> Self {
        Self::new(Box::new(StreamCipherSha256))
    }
}

impl Backup {
    /// New backup operator with a custom cipher.
    pub fn new(cipher: Box<dyn Cipher>) -> Self {
        Self { cipher }
    }

    /// Cipher algorithm name.
    pub fn algorithm(&self) -> String {
        self.cipher.algorithm().to_string()
    }

    /// Create an encrypted backup from a [`crate::EvidenceLog`].
    ///
    /// Writes two files: `<base>.manifest.json` + `<base>.snapshot.enc`.
    pub fn create_from(
        &self,
        log: &EvidenceLog,
        tenant_id: impl Into<String>,
        sector: Sector,
        out_dir: impl AsRef<Path>,
        base_name: &str,
        key: &BackupKey,
    ) -> SandboxResult<BackupManifest> {
        let tenant_id = tenant_id.into();
        let bundle = log.export(tenant_id.clone(), sector)?;
        let snapshot = EncryptedSnapshot {
            tenant_id: bundle.tenant_id.clone(),
            sector: bundle.sector,
            entries: bundle.entries.clone(),
            merkle_root: bundle.merkle_root,
        };
        let plaintext = serde_json::to_vec(&snapshot).map_err(|e| {
            SandboxError::Other(format!("serialise snapshot: {e}"))
        })?;
        let ciphertext = self.cipher.encrypt(&key.key, &key.nonce, &plaintext);
        let encrypted_hash = Hasher::sha256(&ciphertext);
        let out_dir = out_dir.as_ref();
        std::fs::create_dir_all(out_dir).map_err(|e| {
            SandboxError::Other(format!("create dir: {e}"))
        })?;
        let snapshot_path = out_dir.join(format!("{base_name}.snapshot.enc"));
        std::fs::write(&snapshot_path, &ciphertext).map_err(|e| {
            SandboxError::Other(format!("write snapshot: {e}"))
        })?;
        let manifest = BackupManifest {
            schema_version: 1,
            backup_id: Uuid::now_v7(),
            tenant_id,
            sector,
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            entry_count: bundle.entries.len() as u64,
            merkle_root: bundle.merkle_root,
            encrypted_hash,
            cipher: self.cipher.algorithm().to_string(),
            encrypted_bytes: ciphertext.len() as u64,
        };
        let manifest_path = out_dir.join(format!("{base_name}.manifest.json"));
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| {
            SandboxError::Other(format!("serialise manifest: {e}"))
        })?;
        std::fs::write(&manifest_path, manifest_bytes).map_err(|e| {
            SandboxError::Other(format!("write manifest: {e}"))
        })?;
        Ok(manifest)
    }

    /// Restore a backup into a fresh [`EvidenceLog`].
    pub fn restore_to(
        &self,
        in_dir: impl AsRef<Path>,
        base_name: &str,
        key: &BackupKey,
    ) -> SandboxResult<(BackupManifest, EvidenceLog)> {
        let in_dir = in_dir.as_ref();
        let manifest_path = in_dir.join(format!("{base_name}.manifest.json"));
        let snapshot_path = in_dir.join(format!("{base_name}.snapshot.enc"));
        let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| {
            SandboxError::Other(format!("read manifest: {e}"))
        })?;
        let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes).map_err(|e| {
            SandboxError::Other(format!("parse manifest: {e}"))
        })?;
        let ciphertext = std::fs::read(&snapshot_path).map_err(|e| {
            SandboxError::Other(format!("read snapshot: {e}"))
        })?;
        // Verify the manifest's encrypted_hash.
        let recomputed = Hasher::sha256(&ciphertext);
        if recomputed != manifest.encrypted_hash {
            return Err(SandboxError::Other(format!(
                "encrypted snapshot hash mismatch — expected {}, got {} (TAMPERED)",
                manifest.encrypted_hash.to_hex(),
                recomputed.to_hex()
            )));
        }
        // Verify byte length.
        if ciphertext.len() as u64 != manifest.encrypted_bytes {
            return Err(SandboxError::Other(format!(
                "encrypted snapshot length mismatch — expected {}, got {}",
                manifest.encrypted_bytes,
                ciphertext.len()
            )));
        }
        // Decrypt.
        let plaintext = self.cipher.decrypt(&key.key, &key.nonce, &ciphertext);
        if plaintext.is_empty() && !ciphertext.is_empty() {
            return Err(SandboxError::Crypto(
                "MAC failed (wrong key or tampered ciphertext)".into(),
            ));
        }
        let snapshot: EncryptedSnapshot = serde_json::from_slice(&plaintext).map_err(|e| {
            SandboxError::Other(format!("parse snapshot: {e}"))
        })?;
        // Verify Merkle root.
        let mut leaves = Vec::with_capacity(snapshot.entries.len());
        for entry in &snapshot.entries {
            let recomputed = Hasher::hash_value(&entry.seal)?;
            if recomputed != entry.leaf_hash {
                return Err(SandboxError::Other(format!(
                    "leaf hash mismatch at entry {} — TAMPERED",
                    entry.index
                )));
            }
            leaves.push(entry.leaf_hash);
        }
        let recomputed_root = Hasher::merkle_root(&leaves);
        if recomputed_root != manifest.merkle_root {
            return Err(SandboxError::Other(format!(
                "Merkle root mismatch — expected {}, got {} (TAMPERED)",
                manifest.merkle_root.to_hex(),
                recomputed_root.to_hex()
            )));
        }
        // All checks pass — replay into a fresh log.
        let log = EvidenceLog::new();
        for entry in &snapshot.entries {
            log.append(entry.seal.clone())?;
        }
        Ok((manifest, log))
    }

    /// Verify a backup *without* decrypting the snapshot.
    /// Useful for auditors: confirms the manifest's claimed encrypted_hash
    /// matches the on-disk file.
    pub fn verify_manifest_only(
        &self,
        in_dir: impl AsRef<Path>,
        base_name: &str,
    ) -> SandboxResult<BackupManifest> {
        let in_dir = in_dir.as_ref();
        let manifest_path = in_dir.join(format!("{base_name}.manifest.json"));
        let snapshot_path = in_dir.join(format!("{base_name}.snapshot.enc"));
        let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| {
            SandboxError::Other(format!("read manifest: {e}"))
        })?;
        let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes).map_err(|e| {
            SandboxError::Other(format!("parse manifest: {e}"))
        })?;
        let ciphertext = std::fs::read(&snapshot_path).map_err(|e| {
            SandboxError::Other(format!("read snapshot: {e}"))
        })?;
        let recomputed = Hasher::sha256(&ciphertext);
        if recomputed != manifest.encrypted_hash {
            return Err(SandboxError::Other(format!(
                "encrypted snapshot hash mismatch — TAMPERED"
            )));
        }
        Ok(manifest)
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Compute a backup base name with timestamp.
pub fn timestamp_base_name(prefix: &str) -> String {
    let now = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
        .replace([':', '-', 'T'], "_");
    format!("{prefix}_{now}")
}

/// List all backups in a directory (matching `<base>.manifest.json`).
pub fn list_backups(in_dir: impl AsRef<Path>) -> SandboxResult<Vec<PathBuf>> {
    let dir = in_dir.as_ref();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| {
        SandboxError::Other(format!("read_dir: {e}"))
    })? {
        let entry = entry.map_err(|e| SandboxError::Other(format!("dir entry: {e}")))?;
        let p = entry.path();
        if p.extension()
            .and_then(|s| s.to_str())
            .map(|s| s == "json")
            .unwrap_or(false)
            && p.file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.ends_with(".manifest.json"))
                .unwrap_or(false)
        {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::*;
    use std::collections::BTreeMap;

    fn dummy_seal(seed: u64) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "x".into(),
            event_hash: Hasher::sha256(format!("e-{seed}").as_bytes()),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: Hasher::sha256(b"i"),
            output_hash: Hasher::sha256(b"o"),
            approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "wf".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    fn make_log(n: u64) -> EvidenceLog {
        let log = EvidenceLog::new();
        for i in 0..n {
            log.append(dummy_seal(i)).unwrap();
        }
        log
    }

    fn tmp_dir(suffix: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "aethelred-backup-{}-{}",
            std::process::id(),
            suffix
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn key() -> BackupKey {
        BackupKey::new([0xab; 32], [0xcd; 16])
    }

    #[test]
    fn create_and_restore_round_trip() {
        let p = tmp_dir("roundtrip");
        let log = make_log(5);
        let backup = Backup::default();
        let manifest = backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        assert_eq!(manifest.entry_count, 5);
        let (restored_manifest, restored_log) =
            backup.restore_to(&p, "test", &key()).unwrap();
        assert_eq!(restored_manifest.entry_count, 5);
        assert_eq!(restored_log.len(), 5);
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn restore_with_wrong_key_fails() {
        let p = tmp_dir("wrong-key");
        let log = make_log(3);
        let backup = Backup::default();
        backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        let wrong_key = BackupKey::new([0xff; 32], [0xff; 16]);
        let r = backup.restore_to(&p, "test", &wrong_key);
        assert!(r.is_err());
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn restore_tampered_snapshot_fails() {
        let p = tmp_dir("tamper-snap");
        let log = make_log(3);
        let backup = Backup::default();
        backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        let snapshot_path = p.join("test.snapshot.enc");
        let mut bytes = std::fs::read(&snapshot_path).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&snapshot_path, bytes).unwrap();
        let r = backup.restore_to(&p, "test", &key());
        assert!(r.is_err());
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn restore_tampered_manifest_root_fails() {
        let p = tmp_dir("tamper-manifest");
        let log = make_log(3);
        let backup = Backup::default();
        backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        // Corrupt the manifest's merkle_root field.
        let manifest_path = p.join("test.manifest.json");
        let s = std::fs::read_to_string(&manifest_path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&s).unwrap();
        v["merkle_root"] = serde_json::json!("0".repeat(64));
        std::fs::write(&manifest_path, v.to_string()).unwrap();
        let r = backup.restore_to(&p, "test", &key());
        assert!(r.is_err());
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn restore_missing_manifest_fails() {
        let p = tmp_dir("missing-manifest");
        let backup = Backup::default();
        let r = backup.restore_to(&p, "nonexistent", &key());
        assert!(r.is_err());
    }

    #[test]
    fn verify_manifest_only_succeeds_for_clean_backup() {
        let p = tmp_dir("verify-only");
        let log = make_log(2);
        let backup = Backup::default();
        backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        let manifest = backup.verify_manifest_only(&p, "test").unwrap();
        assert_eq!(manifest.entry_count, 2);
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn verify_manifest_only_fails_when_snapshot_missing() {
        let p = tmp_dir("verify-missing");
        let log = make_log(2);
        let backup = Backup::default();
        backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        std::fs::remove_file(p.join("test.snapshot.enc")).ok();
        let r = backup.verify_manifest_only(&p, "test");
        assert!(r.is_err());
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn from_passphrase_is_deterministic() {
        let k1 = BackupKey::from_passphrase(b"secret", b"FAB-2026");
        let k2 = BackupKey::from_passphrase(b"secret", b"FAB-2026");
        assert_eq!(k1, k2);
    }

    #[test]
    fn from_passphrase_different_salt_different_key() {
        let k1 = BackupKey::from_passphrase(b"secret", b"a");
        let k2 = BackupKey::from_passphrase(b"secret", b"b");
        assert_ne!(k1.key, k2.key);
    }

    #[test]
    fn manifest_serde_round_trip() {
        let p = tmp_dir("manifest-serde");
        let log = make_log(2);
        let backup = Backup::default();
        let m = backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        let j = serde_json::to_string(&m).unwrap();
        let q: BackupManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(q, m);
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn timestamp_base_name_format() {
        let s = timestamp_base_name("backup");
        assert!(s.starts_with("backup_"));
    }

    #[test]
    fn list_backups_finds_manifests() {
        let p = tmp_dir("list");
        let log = make_log(1);
        let backup = Backup::default();
        backup
            .create_from(&log, "FAB", Sector::Finance, &p, "a", &key())
            .unwrap();
        backup
            .create_from(&log, "FAB", Sector::Finance, &p, "b", &key())
            .unwrap();
        let list = list_backups(&p).unwrap();
        assert_eq!(list.len(), 2);
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn list_backups_empty_dir_returns_empty() {
        let p = tmp_dir("empty");
        let list = list_backups(&p).unwrap();
        assert!(list.is_empty());
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn list_backups_nonexistent_dir_returns_empty() {
        let list = list_backups("/tmp/aethelred-no-such-dir-xyz").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn manifest_records_metadata() {
        let p = tmp_dir("meta");
        let log = make_log(7);
        let backup = Backup::default();
        let m = backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        assert_eq!(m.tenant_id, "FAB");
        assert_eq!(m.entry_count, 7);
        assert_eq!(m.cipher, "sha256-prf-stream-v1");
        assert!(m.encrypted_bytes > 0);
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn empty_log_can_be_backed_up() {
        let p = tmp_dir("empty-log");
        let log = EvidenceLog::new();
        let backup = Backup::default();
        let m = backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        assert_eq!(m.entry_count, 0);
        let (_, restored) = backup.restore_to(&p, "test", &key()).unwrap();
        assert_eq!(restored.len(), 0);
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn many_entries_round_trip() {
        let p = tmp_dir("many");
        let log = make_log(100);
        let backup = Backup::default();
        backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        let (_, restored) = backup.restore_to(&p, "test", &key()).unwrap();
        assert_eq!(restored.len(), 100);
        std::fs::remove_dir_all(&p).ok();
    }

    #[test]
    fn backup_key_hex_returned() {
        let k = key();
        assert_eq!(k.key_hex().len(), 64);
    }

    #[test]
    fn algorithm_returned() {
        let b = Backup::default();
        assert_eq!(b.algorithm(), "sha256-prf-stream-v1");
    }

    #[test]
    fn restore_after_truncated_snapshot_fails() {
        let p = tmp_dir("truncated");
        let log = make_log(5);
        let backup = Backup::default();
        backup
            .create_from(&log, "FAB", Sector::Finance, &p, "test", &key())
            .unwrap();
        let snapshot_path = p.join("test.snapshot.enc");
        let mut bytes = std::fs::read(&snapshot_path).unwrap();
        bytes.truncate(bytes.len() / 2);
        std::fs::write(&snapshot_path, bytes).unwrap();
        let r = backup.restore_to(&p, "test", &key());
        assert!(r.is_err());
        std::fs::remove_dir_all(&p).ok();
    }
}
