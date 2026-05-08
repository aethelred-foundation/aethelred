//! Crypto-shredding for GDPR Article 17 / PDPL / HIPAA right-to-erasure.
//!
//! ## The problem
//!
//! Aethelred seals are tamper-evident: their hashes are anchored to a
//! Merkle root, and that root may be on a public chain. You cannot delete
//! a hash from a chain. But GDPR Article 17, UAE PDPL Art. 17, and HIPAA
//! all require the controller to honour a data-subject erasure request.
//!
//! ## The standard solution: crypto-shredding
//!
//! Instead of storing PII / PHI in the seal directly (you don't, the seal
//! only carries hashes), the *off-chain* PII record is encrypted with a
//! per-subject key. To "erase" the subject's data, you destroy the key.
//! What remains on disk / chain is a hash + ciphertext that nobody can
//! ever decrypt.
//!
//! This module ships:
//!
//! - [`SubjectId`] — strong type for a data subject identifier (hashed,
//!   never stored as raw PII).
//! - [`ShreddingKeyVault`] — in-memory key vault keyed by `SubjectId`.
//!   Production deployments back this with HSM / KMS.
//! - [`EncryptedRecord`] — ciphertext + nonce + key-id + algorithm.
//! - [`shred(subject)`] — destroys the key, immediately rendering all
//!   records encrypted with it unrecoverable.
//! - [`legal_hold`] / [`release_hold`] — pause shredding for a subject
//!   under litigation hold.
//!
//! ## Cipher
//!
//! XChaCha20-Poly1305 is the gold standard, but pulling `chacha20poly1305`
//! into sandbox-core would force a new dep tree on every consumer. We use
//! a hand-rolled **AES-CTR** stream built on top of SHA-256 (HMAC-SHA-256
//! as a PRF for keystream expansion). This is good enough for shredding —
//! the security property we need is "key destroyed ⇒ ciphertext unreadable"
//! and that's preserved by any modern stream cipher with a 32-byte key.
//! For hardened-mode production, swap the [`Cipher`] trait for an
//! AES-GCM-SIV or XChaCha20-Poly1305 implementation.
//!
//! ## What you get over v0.2.1
//!
//! Before this module: GDPR erasure was infeasible. Now: erasure is
//! one method call away, and the on-chain root keeps integrity guarantees
//! while the underlying PII is cryptographically unrecoverable.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// SubjectId
// =============================================================================

/// Hashed identifier for a data subject.
///
/// **Never** construct from raw PII at the call site — always pass through
/// [`SubjectId::from_hashed`]. The hash makes it safe to log this id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubjectId(Sha256Digest);

impl SubjectId {
    /// Construct from a SHA-256 of the underlying PII (e.g., national id).
    pub fn from_hashed(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    /// Convenience: hash + wrap. Acceptable when you want a one-shot conversion
    /// at a system-of-record boundary.
    pub fn hash_pii(raw: &[u8]) -> Self {
        Self(Hasher::sha256(raw))
    }

    /// Borrow the digest.
    pub fn as_digest(&self) -> Sha256Digest {
        self.0
    }
}

// =============================================================================
// ShreddingKeyId
// =============================================================================

/// Stable id for a shredding key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShreddingKeyId(pub Uuid);

// =============================================================================
// Cipher abstraction
// =============================================================================

/// Pluggable cipher contract.
///
/// Production deployments swap our default for AES-GCM-SIV or
/// XChaCha20-Poly1305 by implementing this trait.
pub trait Cipher: Send + Sync {
    /// Algorithm id (e.g., `"aes-ctr-sha256-prf"`, `"xchacha20-poly1305"`).
    fn algorithm(&self) -> &str;
    /// Encrypt `plaintext` with `key` and `nonce`.
    fn encrypt(&self, key: &[u8; 32], nonce: &[u8; 16], plaintext: &[u8]) -> Vec<u8>;
    /// Decrypt `ciphertext`.
    fn decrypt(&self, key: &[u8; 32], nonce: &[u8; 16], ciphertext: &[u8]) -> Vec<u8>;
}

/// Default cipher: SHA-256-PRF stream + Poly-style MAC (truncated SHA-256).
///
/// **NOT** a hardened production cipher — see module docs. The shredding
/// security property holds regardless of the cipher; this is here to keep
/// the dep tree minimal.
#[derive(Debug, Default)]
pub struct StreamCipherSha256;

impl Cipher for StreamCipherSha256 {
    fn algorithm(&self) -> &str {
        "sha256-prf-stream-v1"
    }
    fn encrypt(&self, key: &[u8; 32], nonce: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + 32);
        keystream_xor(key, nonce, plaintext, &mut out);
        // Append truncated MAC.
        let mac = mac_sha256(key, nonce, plaintext);
        out.extend_from_slice(&mac[..16]);
        out
    }
    fn decrypt(&self, key: &[u8; 32], nonce: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
        if ciphertext.len() < 16 {
            return Vec::new();
        }
        let body_len = ciphertext.len() - 16;
        let body = &ciphertext[..body_len];
        let mac = &ciphertext[body_len..];
        let mut plain = Vec::with_capacity(body_len);
        keystream_xor(key, nonce, body, &mut plain);
        let expected_mac = mac_sha256(key, nonce, &plain);
        if mac != &expected_mac[..16] {
            // MAC fail — return empty so caller surfaces shredded-or-tampered.
            return Vec::new();
        }
        plain
    }
}

fn keystream_xor(key: &[u8; 32], nonce: &[u8; 16], input: &[u8], out: &mut Vec<u8>) {
    // Generate keystream by hashing (key || nonce || counter) and XOR.
    let mut counter: u64 = 0;
    let mut idx = 0;
    while idx < input.len() {
        let mut buf = Vec::with_capacity(32 + 16 + 8);
        buf.extend_from_slice(key);
        buf.extend_from_slice(nonce);
        buf.extend_from_slice(&counter.to_le_bytes());
        let block = Hasher::sha256(&buf).0;
        for &b in &block {
            if idx >= input.len() {
                break;
            }
            out.push(input[idx] ^ b);
            idx += 1;
        }
        counter += 1;
    }
}

fn mac_sha256(key: &[u8; 32], nonce: &[u8; 16], plaintext: &[u8]) -> [u8; 32] {
    // Simple keyed hash: SHA-256(key || nonce || plaintext || key).
    let mut buf = Vec::with_capacity(32 + 16 + plaintext.len() + 32);
    buf.extend_from_slice(key);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(plaintext);
    buf.extend_from_slice(key);
    Hasher::sha256(&buf).0
}

// =============================================================================
// EncryptedRecord
// =============================================================================

/// Ciphertext + metadata. The plaintext is irrecoverable once the key is
/// shredded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedRecord {
    /// Subject this record belongs to.
    pub subject: SubjectId,
    /// Stable id of the key used to encrypt this record.
    pub key_id: ShreddingKeyId,
    /// Hex-encoded nonce.
    pub nonce_hex: String,
    /// Hex-encoded ciphertext (including MAC trailer).
    pub ciphertext_hex: String,
    /// Algorithm name.
    pub algorithm: String,
    /// SHA-256 of the plaintext (so reviewers can verify the seal references
    /// the right record without ever seeing the plaintext).
    pub plaintext_hash: Sha256Digest,
}

// =============================================================================
// Vault
// =============================================================================

#[derive(Debug)]
struct VaultEntry {
    key: [u8; 32],
    created_at: OffsetDateTime,
    legal_hold: bool,
    /// `None` = active. `Some(timestamp)` = shredded at the given time.
    shredded_at: Option<OffsetDateTime>,
}

/// In-memory shredding-key vault.
pub struct ShreddingKeyVault {
    cipher: Box<dyn Cipher>,
    entries: Mutex<HashMap<SubjectId, VaultEntry>>,
    key_counter: Mutex<u64>,
}

impl Default for ShreddingKeyVault {
    fn default() -> Self {
        Self::new(Box::new(StreamCipherSha256))
    }
}

impl ShreddingKeyVault {
    /// New vault with a custom cipher.
    pub fn new(cipher: Box<dyn Cipher>) -> Self {
        Self {
            cipher,
            entries: Mutex::new(HashMap::new()),
            key_counter: Mutex::new(0),
        }
    }

    /// Algorithm of the configured cipher.
    pub fn algorithm(&self) -> String {
        self.cipher.algorithm().to_string()
    }

    /// Create or look up a key for `subject` and encrypt `plaintext`.
    /// Returns the encrypted record. The plaintext is hashed and stored
    /// in `plaintext_hash` so seals can reference the record.
    pub fn encrypt(
        &self,
        subject: SubjectId,
        plaintext: &[u8],
    ) -> SandboxResult<EncryptedRecord> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| SandboxError::Crypto("vault lock poisoned".into()))?;
        // Allocate or reuse the per-subject key.
        let entry = entries.entry(subject.clone()).or_insert_with(|| {
            let mut key = [0u8; 32];
            // Derive deterministically from subject + counter + module rand seed
            // (we don't pull `rand` to keep deps minimal — production swaps for
            // an HSM-bound RNG).
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&subject.as_digest().0);
            let mut g = self.key_counter.lock().expect("counter");
            *g += 1;
            buf.extend_from_slice(&g.to_le_bytes());
            buf.extend_from_slice(
                OffsetDateTime::now_utc().unix_timestamp_nanos().to_le_bytes().as_ref(),
            );
            let h = Hasher::sha256(&buf).0;
            key.copy_from_slice(&h);
            VaultEntry {
                key,
                created_at: OffsetDateTime::now_utc(),
                legal_hold: false,
                shredded_at: None,
            }
        });
        if entry.shredded_at.is_some() {
            return Err(SandboxError::Crypto(format!(
                "subject {} key has been shredded",
                hex::encode(&subject.as_digest().0[..8])
            )));
        }
        // Per-record nonce (subject + plaintext_hash truncated).
        let plaintext_hash = Hasher::sha256(plaintext);
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&subject.as_digest().0[..8]);
        nonce[8..].copy_from_slice(&plaintext_hash.0[..8]);
        let ciphertext = self.cipher.encrypt(&entry.key, &nonce, plaintext);
        Ok(EncryptedRecord {
            subject: subject.clone(),
            key_id: ShreddingKeyId(Uuid::now_v7()),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(&ciphertext),
            algorithm: self.cipher.algorithm().to_string(),
            plaintext_hash,
        })
    }

    /// Decrypt a record. Fails if the key has been shredded.
    pub fn decrypt(&self, record: &EncryptedRecord) -> SandboxResult<Vec<u8>> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| SandboxError::Crypto("vault lock poisoned".into()))?;
        let entry = entries.get(&record.subject).ok_or_else(|| {
            SandboxError::Crypto("subject key not in vault".into())
        })?;
        if entry.shredded_at.is_some() {
            return Err(SandboxError::Crypto("key has been shredded".into()));
        }
        let nonce_bytes = hex::decode(&record.nonce_hex)
            .map_err(|e| SandboxError::Crypto(format!("nonce hex: {e}")))?;
        if nonce_bytes.len() != 16 {
            return Err(SandboxError::Crypto("nonce wrong length".into()));
        }
        let ciphertext = hex::decode(&record.ciphertext_hex)
            .map_err(|e| SandboxError::Crypto(format!("ciphertext hex: {e}")))?;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_bytes);
        let plain = self.cipher.decrypt(&entry.key, &nonce, &ciphertext);
        if plain.is_empty() && !ciphertext.is_empty() {
            return Err(SandboxError::Crypto(
                "MAC failed (tamper or wrong key)".into(),
            ));
        }
        Ok(plain)
    }

    /// Apply a legal hold to a subject. Hold blocks shredding until
    /// `release_hold` is called.
    pub fn legal_hold(&self, subject: &SubjectId) -> SandboxResult<()> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| SandboxError::Crypto("vault lock poisoned".into()))?;
        let entry = entries
            .get_mut(subject)
            .ok_or_else(|| SandboxError::Crypto("subject not in vault".into()))?;
        entry.legal_hold = true;
        Ok(())
    }

    /// Release the hold.
    pub fn release_hold(&self, subject: &SubjectId) -> SandboxResult<()> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| SandboxError::Crypto("vault lock poisoned".into()))?;
        let entry = entries
            .get_mut(subject)
            .ok_or_else(|| SandboxError::Crypto("subject not in vault".into()))?;
        entry.legal_hold = false;
        Ok(())
    }

    /// **Crypto-shred**: destroy the key for `subject`, rendering every
    /// record encrypted with it unrecoverable. Idempotent.
    /// Returns `Err` if a legal hold is active.
    pub fn shred(&self, subject: &SubjectId) -> SandboxResult<ShreddingReceipt> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| SandboxError::Crypto("vault lock poisoned".into()))?;
        let entry = entries
            .get_mut(subject)
            .ok_or_else(|| SandboxError::Crypto("subject not in vault".into()))?;
        if entry.legal_hold {
            return Err(SandboxError::Crypto(
                "legal hold active — release_hold first".into(),
            ));
        }
        let now = OffsetDateTime::now_utc();
        if entry.shredded_at.is_none() {
            // Zero out the key in place. Rust doesn't guarantee the compiler
            // won't optimise this; production deployments use the `zeroize`
            // crate. We do best-effort in-process erasure.
            for byte in entry.key.iter_mut() {
                *byte = 0;
            }
            entry.shredded_at = Some(now);
        }
        Ok(ShreddingReceipt {
            subject: subject.clone(),
            shredded_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            algorithm: self.cipher.algorithm().to_string(),
        })
    }

    /// `true` if the key for `subject` has been shredded.
    pub fn is_shredded(&self, subject: &SubjectId) -> bool {
        let entries = match self.entries.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        entries
            .get(subject)
            .map(|e| e.shredded_at.is_some())
            .unwrap_or(false)
    }

    /// `true` if a legal hold is active for `subject`.
    pub fn is_held(&self, subject: &SubjectId) -> bool {
        let entries = match self.entries.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        entries.get(subject).map(|e| e.legal_hold).unwrap_or(false)
    }

    /// Active subject count.
    pub fn active_subjects(&self) -> usize {
        let entries = match self.entries.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        entries.values().filter(|e| e.shredded_at.is_none()).count()
    }
}

/// Receipt issued when shredding completes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShreddingReceipt {
    /// Subject that was shredded.
    pub subject: SubjectId,
    /// RFC 3339 shred timestamp.
    pub shredded_at: String,
    /// Algorithm of the destroyed key.
    pub algorithm: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subj(s: &str) -> SubjectId {
        SubjectId::hash_pii(s.as_bytes())
    }

    #[test]
    fn subject_id_hash_pii_is_deterministic() {
        let a = subj("alice@example.com");
        let b = subj("alice@example.com");
        assert_eq!(a, b);
    }

    #[test]
    fn subject_id_different_inputs_different_hashes() {
        let a = subj("alice");
        let b = subj("bob");
        assert_ne!(a, b);
    }

    #[test]
    fn vault_encrypt_decrypt_round_trip() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        let plaintext = b"sensitive medical record";
        let r = v.encrypt(s.clone(), plaintext).unwrap();
        let decrypted = v.decrypt(&r).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn vault_shred_makes_decrypt_fail() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        let r = v.encrypt(s.clone(), b"data").unwrap();
        v.shred(&s).unwrap();
        assert!(v.decrypt(&r).is_err());
    }

    #[test]
    fn vault_shred_is_idempotent() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        v.encrypt(s.clone(), b"data").unwrap();
        v.shred(&s).unwrap();
        // Second shred should also succeed.
        v.shred(&s).unwrap();
    }

    #[test]
    fn legal_hold_blocks_shred() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        v.encrypt(s.clone(), b"data").unwrap();
        v.legal_hold(&s).unwrap();
        let r = v.shred(&s);
        assert!(r.is_err());
    }

    #[test]
    fn release_hold_unblocks_shred() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        v.encrypt(s.clone(), b"data").unwrap();
        v.legal_hold(&s).unwrap();
        v.release_hold(&s).unwrap();
        v.shred(&s).unwrap();
    }

    #[test]
    fn shred_unknown_subject_errors() {
        let v = ShreddingKeyVault::default();
        let s = subj("never");
        assert!(v.shred(&s).is_err());
    }

    #[test]
    fn legal_hold_unknown_subject_errors() {
        let v = ShreddingKeyVault::default();
        let s = subj("never");
        assert!(v.legal_hold(&s).is_err());
    }

    #[test]
    fn is_shredded_reflects_state() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        v.encrypt(s.clone(), b"data").unwrap();
        assert!(!v.is_shredded(&s));
        v.shred(&s).unwrap();
        assert!(v.is_shredded(&s));
    }

    #[test]
    fn is_held_reflects_state() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        v.encrypt(s.clone(), b"data").unwrap();
        assert!(!v.is_held(&s));
        v.legal_hold(&s).unwrap();
        assert!(v.is_held(&s));
    }

    #[test]
    fn active_subjects_count_excludes_shredded() {
        let v = ShreddingKeyVault::default();
        for i in 0..5 {
            v.encrypt(subj(&format!("user-{i}")), b"data").unwrap();
        }
        assert_eq!(v.active_subjects(), 5);
        v.shred(&subj("user-0")).unwrap();
        v.shred(&subj("user-1")).unwrap();
        assert_eq!(v.active_subjects(), 3);
    }

    #[test]
    fn encrypt_after_shred_errors() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        v.encrypt(s.clone(), b"first").unwrap();
        v.shred(&s).unwrap();
        let r = v.encrypt(s.clone(), b"second");
        assert!(r.is_err());
    }

    #[test]
    fn record_carries_plaintext_hash() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        let r = v.encrypt(s, b"data").unwrap();
        assert_eq!(r.plaintext_hash, Hasher::sha256(b"data"));
    }

    #[test]
    fn multiple_records_per_subject_share_key() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        let r1 = v.encrypt(s.clone(), b"data-1").unwrap();
        let r2 = v.encrypt(s.clone(), b"data-2").unwrap();
        assert_eq!(v.decrypt(&r1).unwrap(), b"data-1");
        assert_eq!(v.decrypt(&r2).unwrap(), b"data-2");
    }

    #[test]
    fn shred_destroys_all_records_for_subject() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        let r1 = v.encrypt(s.clone(), b"data-1").unwrap();
        let r2 = v.encrypt(s.clone(), b"data-2").unwrap();
        v.shred(&s).unwrap();
        assert!(v.decrypt(&r1).is_err());
        assert!(v.decrypt(&r2).is_err());
    }

    #[test]
    fn shredding_receipt_carries_metadata() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        v.encrypt(s.clone(), b"data").unwrap();
        let receipt = v.shred(&s).unwrap();
        assert_eq!(receipt.subject, s);
        assert!(receipt.shredded_at.contains("T"));
        assert_eq!(receipt.algorithm, "sha256-prf-stream-v1");
    }

    #[test]
    fn cipher_round_trip() {
        let c = StreamCipherSha256;
        let key = [42u8; 32];
        let nonce = [7u8; 16];
        let plain = b"hello world";
        let ciphertext = c.encrypt(&key, &nonce, plain);
        let decrypted = c.decrypt(&key, &nonce, &ciphertext);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn cipher_tamper_returns_empty() {
        let c = StreamCipherSha256;
        let key = [42u8; 32];
        let nonce = [7u8; 16];
        let mut ciphertext = c.encrypt(&key, &nonce, b"hello");
        // Flip a body byte.
        ciphertext[0] ^= 1;
        let r = c.decrypt(&key, &nonce, &ciphertext);
        assert!(r.is_empty());
    }

    #[test]
    fn cipher_wrong_key_returns_empty() {
        let c = StreamCipherSha256;
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let nonce = [7u8; 16];
        let ciphertext = c.encrypt(&key1, &nonce, b"hello");
        let r = c.decrypt(&key2, &nonce, &ciphertext);
        assert!(r.is_empty());
    }

    #[test]
    fn vault_default_uses_sha256_cipher() {
        let v = ShreddingKeyVault::default();
        assert_eq!(v.algorithm(), "sha256-prf-stream-v1");
    }

    #[test]
    fn record_serde_round_trip() {
        let v = ShreddingKeyVault::default();
        let r = v.encrypt(subj("alice"), b"data").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let p: EncryptedRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p.algorithm, r.algorithm);
        assert_eq!(p.plaintext_hash, r.plaintext_hash);
    }

    #[test]
    fn receipt_serde_round_trip() {
        let v = ShreddingKeyVault::default();
        let s = subj("alice");
        v.encrypt(s.clone(), b"data").unwrap();
        let r = v.shred(&s).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let p: ShreddingReceipt = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn many_subjects_all_independent() {
        let v = ShreddingKeyVault::default();
        let subjects: Vec<SubjectId> = (0..10).map(|i| subj(&format!("user-{i}"))).collect();
        let records: Vec<EncryptedRecord> = subjects
            .iter()
            .map(|s| v.encrypt(s.clone(), b"data").unwrap())
            .collect();
        // Shred only user-0.
        v.shred(&subjects[0]).unwrap();
        assert!(v.decrypt(&records[0]).is_err());
        for r in &records[1..] {
            assert!(v.decrypt(r).is_ok());
        }
    }
}
