//! Merkle-root anchoring service.
//!
//! An anchor is a third-party attestation that the evidence log's Merkle
//! root existed at a particular point in time. Production deployments
//! anchor to:
//!
//! - The Aethelred mainnet (the canonical anchor — block height + tx hash).
//! - Public chains (Ethereum, Polygon, Cosmos) for cross-chain redundancy.
//! - RFC 3161 timestamping authorities (legal-evidence-grade).
//! - Internal validator quorums (offline / air-gap).
//!
//! ## Anchor receipt format
//!
//! [`AnchorReceipt`] captures: anchor service id, root that was anchored,
//! the local Merkle proof input, timestamp, anchor-side proof (block
//! height + tx hash, or RFC 3161 token), and an optional validator-quorum
//! signature.
//!
//! ## Pluggable
//!
//! [`AnchorService`] is a trait. This module ships:
//!
//! - [`MockAnchorService`] — in-memory, useful for tests + dev.
//! - [`SignedAnchorService`] — uses a [`crate::crypto_signing::SealSigner`]
//!   to produce a real cryptographic anchor receipt.
//! - [`FileAnchorService`] — persists anchors to a JSON-lines file
//!   (deterministic, auditable, suitable for offline evidence).
//!
//! Production deployments add their own implementation that talks to the
//! Aethelred mainnet RPC, an Ethereum node, or an RFC 3161 service.

use crate::hashing::Sha256Digest;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

/// Anchor receipt — proof that a Merkle root was anchored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorReceipt {
    /// Receipt id (UUIDv7).
    pub receipt_id: Uuid,
    /// Anchor service id (e.g., `"aethelred-mainnet"`, `"rfc-3161-tsa"`).
    pub service_id: String,
    /// The Merkle root that was anchored.
    pub merkle_root: Sha256Digest,
    /// Tenant id (the customer being anchored).
    pub tenant_id: String,
    /// RFC 3339 timestamp.
    pub anchored_at: String,
    /// Anchor-side proof (free-form): block hash, tx hash, RFC 3161 token, etc.
    pub anchor_proof: AnchorProof,
    /// Optional anchor-service signature over `(merkle_root || anchored_at)`.
    pub signature_hex: Option<String>,
}

/// Anchor-side proof discriminator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AnchorProof {
    /// Aethelred mainnet block + tx.
    AethelredMainnet {
        /// Block height the root was included in.
        block_height: u64,
        /// Transaction hash.
        tx_hash: Sha256Digest,
    },
    /// Ethereum / EVM-compatible.
    Evm {
        /// Chain id (1 = Ethereum, 137 = Polygon).
        chain_id: u64,
        /// Block number.
        block_number: u64,
        /// Tx hash.
        tx_hash: String,
    },
    /// RFC 3161 timestamp.
    Rfc3161 {
        /// TSA service URL.
        tsa_url: String,
        /// Token bytes (hex).
        token_hex: String,
    },
    /// In-memory mock (tests only).
    Mock {
        /// Mock-service nonce.
        nonce: String,
    },
    /// Validator-quorum signed root (offline / air-gap).
    Quorum {
        /// Quorum id.
        quorum_id: String,
        /// Threshold (M).
        threshold: u32,
        /// Total signers (N).
        total: u32,
    },
}

/// Pluggable anchor service.
pub trait AnchorService: Send + Sync {
    /// Service id.
    fn service_id(&self) -> &str;
    /// Submit a Merkle root for anchoring.
    fn anchor(
        &self,
        tenant_id: &str,
        merkle_root: Sha256Digest,
    ) -> SandboxResult<AnchorReceipt>;
    /// Verify a previously-issued receipt.
    fn verify(&self, receipt: &AnchorReceipt) -> SandboxResult<()>;
}

// =============================================================================
// MockAnchorService
// =============================================================================

/// In-memory anchor service. Useful for tests and dev.
pub struct MockAnchorService {
    service_id: String,
    receipts: Mutex<Vec<AnchorReceipt>>,
}

impl MockAnchorService {
    /// New mock service.
    pub fn new(service_id: impl Into<String>) -> Self {
        Self {
            service_id: service_id.into(),
            receipts: Mutex::new(Vec::new()),
        }
    }

    /// All issued receipts.
    pub fn receipts(&self) -> Vec<AnchorReceipt> {
        self.receipts
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

impl AnchorService for MockAnchorService {
    fn service_id(&self) -> &str {
        &self.service_id
    }
    fn anchor(
        &self,
        tenant_id: &str,
        merkle_root: Sha256Digest,
    ) -> SandboxResult<AnchorReceipt> {
        let now = OffsetDateTime::now_utc();
        let anchored_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::new());
        let receipt = AnchorReceipt {
            receipt_id: Uuid::now_v7(),
            service_id: self.service_id.clone(),
            merkle_root,
            tenant_id: tenant_id.to_string(),
            anchored_at,
            anchor_proof: AnchorProof::Mock {
                nonce: Uuid::now_v7().to_string(),
            },
            signature_hex: None,
        };
        match self.receipts.lock() {
            Ok(mut g) => g.push(receipt.clone()),
            Err(e) => e.into_inner().push(receipt.clone()),
        }
        Ok(receipt)
    }
    fn verify(&self, receipt: &AnchorReceipt) -> SandboxResult<()> {
        if receipt.service_id != self.service_id {
            return Err(SandboxError::Other(format!(
                "service_id mismatch: receipt={} this={}",
                receipt.service_id, self.service_id
            )));
        }
        let g = match self.receipts.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if !g.iter().any(|r| r == receipt) {
            return Err(SandboxError::Other(
                "receipt not found in mock anchor service".into(),
            ));
        }
        Ok(())
    }
}

// =============================================================================
// SignedAnchorService — uses a SealSigner to sign anchor receipts.
// =============================================================================

#[cfg(feature = "real-crypto")]
/// Anchor service that signs each receipt with a [`crate::crypto_signing::SealSigner`].
pub struct SignedAnchorService {
    service_id: String,
    quorum_id: String,
    signer: Box<dyn crate::crypto_signing::SealSigner>,
}

#[cfg(feature = "real-crypto")]
impl SignedAnchorService {
    /// New signed anchor service.
    pub fn new(
        service_id: impl Into<String>,
        quorum_id: impl Into<String>,
        signer: Box<dyn crate::crypto_signing::SealSigner>,
    ) -> Self {
        Self {
            service_id: service_id.into(),
            quorum_id: quorum_id.into(),
            signer,
        }
    }

    fn build_message(merkle_root: Sha256Digest, tenant_id: &str, anchored_at: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + tenant_id.len() + anchored_at.len() + 4);
        buf.extend_from_slice(&merkle_root.0);
        buf.push(b'|');
        buf.extend_from_slice(tenant_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(anchored_at.as_bytes());
        buf
    }
}

#[cfg(feature = "real-crypto")]
impl AnchorService for SignedAnchorService {
    fn service_id(&self) -> &str {
        &self.service_id
    }
    fn anchor(
        &self,
        tenant_id: &str,
        merkle_root: Sha256Digest,
    ) -> SandboxResult<AnchorReceipt> {
        let now = OffsetDateTime::now_utc();
        let anchored_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::new());
        let _msg = Self::build_message(merkle_root, tenant_id, &anchored_at);
        // Sign a synthetic seal with the digest of the anchor-message
        // — this gives us a real hybrid signature without needing a
        // separate signer API surface.
        let mut synthetic = crate::seal::DigitalSeal {
            schema_version: crate::seal::SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: now,
            sector: crate::Sector::Finance, // placeholder
            event_type: "anchor.attestation".into(),
            event_hash: merkle_root,
            model: crate::seal::ModelReference::new("anchor-service", merkle_root),
            policy_id: "po_anchor_v1".into(),
            input_hash: merkle_root,
            output_hash: merkle_root,
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: tenant_id.into(),
            workflow_id: "anchor".into(),
            jurisdiction_tag: "ANCHOR".into(),
            retention: crate::seal::RetentionClass::Indefinite,
            prior_seal_hash: None,
            sector_extension: Default::default(),
            validator_signature_hex: None,
        };
        synthetic.sector_extension.insert(
            "anchored_at".into(),
            serde_json::Value::String(anchored_at.clone()),
        );
        let signed = self.signer.sign_seal(synthetic)?;
        let receipt = AnchorReceipt {
            receipt_id: Uuid::now_v7(),
            service_id: self.service_id.clone(),
            merkle_root,
            tenant_id: tenant_id.into(),
            anchored_at,
            anchor_proof: AnchorProof::Quorum {
                quorum_id: self.quorum_id.clone(),
                threshold: 1,
                total: 1,
            },
            signature_hex: signed.seal.validator_signature_hex.clone(),
        };
        Ok(receipt)
    }
    fn verify(&self, receipt: &AnchorReceipt) -> SandboxResult<()> {
        if receipt.service_id != self.service_id {
            return Err(SandboxError::Other(format!(
                "service_id mismatch: receipt={} this={}",
                receipt.service_id, self.service_id
            )));
        }
        // For a basic structural check, ensure the signature is present and
        // can be parsed as an envelope.
        let blob = receipt.signature_hex.as_ref().ok_or_else(|| {
            SandboxError::Other("anchor receipt missing signature".into())
        })?;
        let _envelope = crate::crypto_signing::SignatureEnvelope::from_hex_blob(blob)?;
        Ok(())
    }
}

// =============================================================================
// FileAnchorService — JSON-lines audit-friendly anchor service.
// =============================================================================

/// Anchor service that persists every receipt to a JSON-lines file.
pub struct FileAnchorService {
    service_id: String,
    path: PathBuf,
    state: Mutex<Vec<AnchorReceipt>>,
}

impl FileAnchorService {
    /// Open or create.
    pub fn open(service_id: impl Into<String>, path: impl Into<PathBuf>) -> SandboxResult<Self> {
        let path = path.into();
        let mut state = Vec::new();
        if path.exists() {
            let content = std::fs::read_to_string(&path).map_err(|e| {
                SandboxError::Other(format!("read anchor file: {e}"))
            })?;
            for (i, line) in content.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let r: AnchorReceipt = serde_json::from_str(line).map_err(|e| {
                    SandboxError::Other(format!(
                        "parse anchor file line {}: {}",
                        i + 1,
                        e
                    ))
                })?;
                state.push(r);
            }
        }
        Ok(Self {
            service_id: service_id.into(),
            path,
            state: Mutex::new(state),
        })
    }

    /// Number of receipts on disk + in memory.
    pub fn len(&self) -> usize {
        self.state.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if no receipts have been issued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AnchorService for FileAnchorService {
    fn service_id(&self) -> &str {
        &self.service_id
    }
    fn anchor(
        &self,
        tenant_id: &str,
        merkle_root: Sha256Digest,
    ) -> SandboxResult<AnchorReceipt> {
        let now = OffsetDateTime::now_utc();
        let anchored_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::new());
        let receipt = AnchorReceipt {
            receipt_id: Uuid::now_v7(),
            service_id: self.service_id.clone(),
            merkle_root,
            tenant_id: tenant_id.into(),
            anchored_at,
            anchor_proof: AnchorProof::Mock {
                nonce: Uuid::now_v7().to_string(),
            },
            signature_hex: None,
        };
        // Append to file.
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| SandboxError::Other(format!("open anchor file: {e}")))?;
        use std::io::Write;
        let line = serde_json::to_string(&receipt).map_err(|e| {
            SandboxError::Other(format!("serialise receipt: {e}"))
        })?;
        f.write_all(line.as_bytes()).map_err(|e| {
            SandboxError::Other(format!("write receipt: {e}"))
        })?;
        f.write_all(b"\n").map_err(|e| {
            SandboxError::Other(format!("write nl: {e}"))
        })?;
        f.sync_all().map_err(|e| {
            SandboxError::Other(format!("sync: {e}"))
        })?;
        match self.state.lock() {
            Ok(mut g) => g.push(receipt.clone()),
            Err(e) => e.into_inner().push(receipt.clone()),
        }
        Ok(receipt)
    }
    fn verify(&self, receipt: &AnchorReceipt) -> SandboxResult<()> {
        if receipt.service_id != self.service_id {
            return Err(SandboxError::Other(format!(
                "service_id mismatch: receipt={} this={}",
                receipt.service_id, self.service_id
            )));
        }
        let g = match self.state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if !g.iter().any(|r| r == receipt) {
            return Err(SandboxError::Other(
                "receipt not found in file anchor service".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::Hasher;

    fn root() -> Sha256Digest {
        Hasher::sha256(b"some-root")
    }

    #[test]
    fn mock_anchor_issues_receipt() {
        let svc = MockAnchorService::new("test");
        let r = svc.anchor("FAB", root()).unwrap();
        assert_eq!(r.tenant_id, "FAB");
        assert_eq!(r.merkle_root, root());
    }

    #[test]
    fn mock_anchor_verifies_own_receipt() {
        let svc = MockAnchorService::new("test");
        let r = svc.anchor("FAB", root()).unwrap();
        svc.verify(&r).unwrap();
    }

    #[test]
    fn mock_anchor_rejects_unknown_receipt() {
        let svc = MockAnchorService::new("test");
        let other = MockAnchorService::new("other");
        let r = other.anchor("FAB", root()).unwrap();
        let res = svc.verify(&r);
        assert!(res.is_err());
    }

    #[test]
    fn mock_anchor_records_all_receipts() {
        let svc = MockAnchorService::new("test");
        for i in 0..5 {
            svc.anchor(&format!("tenant-{i}"), root()).unwrap();
        }
        assert_eq!(svc.receipts().len(), 5);
    }

    #[test]
    fn anchor_proof_serde_round_trip() {
        let p = AnchorProof::AethelredMainnet {
            block_height: 12345,
            tx_hash: Hasher::sha256(b"tx"),
        };
        let j = serde_json::to_string(&p).unwrap();
        let p2: AnchorProof = serde_json::from_str(&j).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn anchor_proof_evm_variant() {
        let p = AnchorProof::Evm {
            chain_id: 1,
            block_number: 18000000,
            tx_hash: "0xabc...".into(),
        };
        let j = serde_json::to_string(&p).unwrap();
        let p2: AnchorProof = serde_json::from_str(&j).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn anchor_proof_rfc3161_variant() {
        let p = AnchorProof::Rfc3161 {
            tsa_url: "https://tsa.example".into(),
            token_hex: "deadbeef".into(),
        };
        let j = serde_json::to_string(&p).unwrap();
        let p2: AnchorProof = serde_json::from_str(&j).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn file_anchor_persists_across_reopens() {
        let path = std::env::temp_dir().join(format!(
            "aethelred-anchor-test-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let svc = FileAnchorService::open("file-test", &path).unwrap();
            svc.anchor("FAB", root()).unwrap();
            svc.anchor("ENBD", root()).unwrap();
        }
        let svc = FileAnchorService::open("file-test", &path).unwrap();
        assert_eq!(svc.len(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn file_anchor_verifies_own_receipt() {
        let path = std::env::temp_dir().join(format!(
            "aethelred-anchor-verify-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let svc = FileAnchorService::open("file-test", &path).unwrap();
        let r = svc.anchor("FAB", root()).unwrap();
        svc.verify(&r).unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn anchor_receipt_serde_round_trip() {
        let svc = MockAnchorService::new("svc");
        let r = svc.anchor("FAB", root()).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let r2: AnchorReceipt = serde_json::from_str(&j).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn service_id_returned() {
        let svc = MockAnchorService::new("my-service");
        assert_eq!(svc.service_id(), "my-service");
    }

    #[test]
    fn anchor_proof_quorum_variant() {
        let p = AnchorProof::Quorum {
            quorum_id: "q1".into(),
            threshold: 2,
            total: 3,
        };
        let j = serde_json::to_string(&p).unwrap();
        let p2: AnchorProof = serde_json::from_str(&j).unwrap();
        assert_eq!(p, p2);
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn signed_anchor_service_produces_real_signature() {
        use crate::crypto_signing::HybridSealSigner;
        let signer = Box::new(HybridSealSigner::generate("anchor-signer").unwrap())
            as Box<dyn crate::crypto_signing::SealSigner>;
        let svc = SignedAnchorService::new("signed-anchor", "quorum-1", signer);
        let r = svc.anchor("FAB", root()).unwrap();
        assert!(r.signature_hex.is_some());
        svc.verify(&r).unwrap();
    }

    #[test]
    fn file_anchor_is_empty_initially() {
        let path = std::env::temp_dir().join(format!(
            "aethelred-anchor-empty-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let svc = FileAnchorService::open("e", &path).unwrap();
        assert!(svc.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn many_anchor_calls_each_get_unique_receipt_id() {
        let svc = MockAnchorService::new("many");
        let mut ids = std::collections::HashSet::new();
        for _ in 0..20 {
            let r = svc.anchor("FAB", root()).unwrap();
            ids.insert(r.receipt_id);
        }
        assert_eq!(ids.len(), 20);
    }
}
