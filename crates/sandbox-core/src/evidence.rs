//! Evidence log — tamper-evident, Merkle-anchored append-only log of seals.
//!
//! Every sandbox run appends one or more [`crate::seal::DigitalSeal`]s to an
//! [`EvidenceLog`]. The log produces:
//!
//! - A Merkle root over all current entries.
//! - Per-entry inclusion proofs (`MerkleProof`) for reviewer-side
//!   independent verification.
//! - An [`EvidenceBundle`] export — the artefact reviewers / regulators /
//!   partners receive.
//!
//! ## Tamper-evident semantics
//!
//! Inserting, deleting, or reordering an entry changes the Merkle root.
//! Reviewers verify a seal by checking that the proof reconstructs the root
//! they were given (e.g., out-of-band, anchored on the mainnet, or signed by
//! the validator quorum).

use crate::hashing::{Hasher, Sha256Digest};
use crate::seal::DigitalSeal;
use crate::SandboxError;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use uuid::Uuid;

/// A single entry in the evidence log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLogEntry {
    /// Index in the log (0-based, monotonic).
    pub index: u64,
    /// The seal.
    pub seal: DigitalSeal,
    /// Hash of the seal at insertion time (the leaf hash).
    pub leaf_hash: Sha256Digest,
}

/// Merkle inclusion proof for an evidence-log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf this proof is for.
    pub leaf_index: u64,
    /// The leaf hash.
    pub leaf_hash: Sha256Digest,
    /// Sibling hashes from leaf up to root.
    pub siblings: Vec<Sha256Digest>,
    /// Root hash claimed by this proof.
    pub root: Sha256Digest,
}

impl MerkleProof {
    /// Verify this proof reconstructs `root` from `leaf_hash`.
    pub fn verify(&self) -> bool {
        let mut current = self.leaf_hash;
        let mut idx = self.leaf_index;
        for sibling in &self.siblings {
            // If idx is even, current is left; else right.
            current = if idx % 2 == 0 {
                Hasher::merkle_combine(current, *sibling)
            } else {
                Hasher::merkle_combine(*sibling, current)
            };
            idx /= 2;
        }
        current == self.root
    }
}

/// Evidence bundle — the export payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Bundle id.
    pub bundle_id: Uuid,
    /// Sandbox tenant id (e.g., `"FAB"`).
    pub tenant_id: String,
    /// Sandbox sector.
    pub sector: crate::Sector,
    /// All entries in this bundle.
    pub entries: Vec<EvidenceLogEntry>,
    /// Merkle root over all entries.
    pub merkle_root: Sha256Digest,
    /// RFC 3339 export timestamp.
    pub exported_at: String,
}

/// Tamper-evident, append-only seal log.
#[derive(Debug, Default)]
pub struct EvidenceLog {
    inner: RwLock<EvidenceLogState>,
}

#[derive(Debug, Default)]
struct EvidenceLogState {
    entries: Vec<EvidenceLogEntry>,
    leaf_hashes: Vec<Sha256Digest>,
}

impl EvidenceLog {
    /// New empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a seal. Returns the assigned index and leaf hash.
    pub fn append(&self, seal: DigitalSeal) -> crate::SandboxResult<EvidenceLogEntry> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| SandboxError::Evidence("log poisoned".into()))?;
        let index = state.entries.len() as u64;
        let leaf_hash = Hasher::hash_value(&seal)?;
        let entry = EvidenceLogEntry {
            index,
            seal,
            leaf_hash,
        };
        state.entries.push(entry.clone());
        state.leaf_hashes.push(leaf_hash);
        Ok(entry)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.inner.read().map(|s| s.entries.len()).unwrap_or(0)
    }

    /// `true` if no entries have been appended.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Compute the current Merkle root.
    pub fn root(&self) -> crate::SandboxResult<Sha256Digest> {
        let state = self
            .inner
            .read()
            .map_err(|_| SandboxError::Evidence("log poisoned".into()))?;
        Ok(Hasher::merkle_root(&state.leaf_hashes))
    }

    /// Build a Merkle inclusion proof for the entry at `index`.
    pub fn proof(&self, index: u64) -> crate::SandboxResult<MerkleProof> {
        let state = self
            .inner
            .read()
            .map_err(|_| SandboxError::Evidence("log poisoned".into()))?;
        let n = state.leaf_hashes.len();
        let idx = index as usize;
        if idx >= n {
            return Err(SandboxError::Evidence(format!(
                "index {} out of range (len={})",
                index, n
            )));
        }
        let leaf_hash = state.leaf_hashes[idx];
        // Build proof bottom-up.
        let mut siblings: Vec<Sha256Digest> = Vec::new();
        let mut current_level: Vec<Sha256Digest> = state.leaf_hashes.clone();
        let mut current_idx = idx;
        while current_level.len() > 1 {
            let sibling_idx = if current_idx % 2 == 0 {
                // Sibling is to the right; if odd-leaf, duplicate self.
                if current_idx + 1 < current_level.len() {
                    current_idx + 1
                } else {
                    current_idx
                }
            } else {
                current_idx - 1
            };
            siblings.push(current_level[sibling_idx]);
            // Promote to next level.
            let mut next_level: Vec<Sha256Digest> = Vec::with_capacity((current_level.len() + 1) / 2);
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

    /// Export an evidence bundle for review.
    pub fn export(
        &self,
        tenant_id: impl Into<String>,
        sector: crate::Sector,
    ) -> crate::SandboxResult<EvidenceBundle> {
        use time::OffsetDateTime;
        let state = self
            .inner
            .read()
            .map_err(|_| SandboxError::Evidence("log poisoned".into()))?;
        let merkle_root = Hasher::merkle_root(&state.leaf_hashes);
        let exported_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| SandboxError::Evidence(format!("rfc3339: {e}")))?;
        Ok(EvidenceBundle {
            bundle_id: Uuid::now_v7(),
            tenant_id: tenant_id.into(),
            sector,
            entries: state.entries.clone(),
            merkle_root,
            exported_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{ApprovalRecord, DigitalSeal, ModelReference, RetentionClass, SealVersion};
    use crate::Sector;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn dummy_seal(idx: u64) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "credit_decision".into(),
            event_hash: Hasher::sha256(format!("event-{idx}").as_bytes()),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: Hasher::sha256(b"in"),
            output_hash: Hasher::sha256(b"out"),
            approvals: vec![ApprovalRecord::unsigned("a", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "t".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn append_increments_length_and_index() {
        let log = EvidenceLog::new();
        assert_eq!(log.len(), 0);
        let e1 = log.append(dummy_seal(1)).unwrap();
        let e2 = log.append(dummy_seal(2)).unwrap();
        assert_eq!(e1.index, 0);
        assert_eq!(e2.index, 1);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn root_changes_when_a_seal_is_added() {
        let log = EvidenceLog::new();
        log.append(dummy_seal(1)).unwrap();
        let r1 = log.root().unwrap();
        log.append(dummy_seal(2)).unwrap();
        let r2 = log.root().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn proof_verifies_for_each_entry() {
        let log = EvidenceLog::new();
        for i in 0..5 {
            log.append(dummy_seal(i)).unwrap();
        }
        for i in 0..5 {
            let proof = log.proof(i).unwrap();
            assert!(proof.verify(), "proof for index {i} must verify");
        }
    }

    #[test]
    fn proof_for_out_of_range_index_errors() {
        let log = EvidenceLog::new();
        log.append(dummy_seal(1)).unwrap();
        assert!(log.proof(5).is_err());
    }

    #[test]
    fn export_bundle_carries_all_entries() {
        let log = EvidenceLog::new();
        for i in 0..3 {
            log.append(dummy_seal(i)).unwrap();
        }
        let bundle = log.export("FAB", Sector::Finance).unwrap();
        assert_eq!(bundle.entries.len(), 3);
        assert_eq!(bundle.tenant_id, "FAB");
    }
}
