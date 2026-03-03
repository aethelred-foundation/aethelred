//! # Digital Seals
//!
//! Create and verify Digital Seals - the atomic unit of trust in Aethelred.

use serde::{Deserialize, Serialize};
use crate::crypto::{HybridKeypair, HybridSignature, HybridPublicKey};
use crate::attestation::{EnclaveReport, HardwareType};
use crate::compliance::Jurisdiction;

/// Digital Seal - proof of verified computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSeal {
    /// Unique seal identifier
    pub id: SealId,

    /// Model commitment (hash of model weights)
    pub model_commitment: [u8; 32],

    /// Input commitment (hash of input data)
    pub input_commitment: [u8; 32],

    /// Output commitment (hash of output)
    pub output_commitment: [u8; 32],

    /// TEE attestation
    pub attestation: SealAttestation,

    /// Optional ZK proof
    pub zk_proof: Option<Vec<u8>>,

    /// Metadata
    pub metadata: SealMetadata,

    /// Seal signature
    pub signature: HybridSignature,

    /// Signer public key
    pub signer: HybridPublicKey,
}

/// Seal identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SealId(pub [u8; 32]);

impl SealId {
    /// Generate a new seal ID
    pub fn new() -> Self {
        let mut id = [0u8; 32];
        crate::crypto::SecureRandom::fill_bytes(&mut id).unwrap();
        SealId(id)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SealId(*bytes)
    }

    /// To hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Default for SealId {
    fn default() -> Self {
        Self::new()
    }
}

/// Seal attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealAttestation {
    /// Hardware type
    pub hardware: HardwareType,
    /// Enclave report
    pub report: EnclaveReport,
    /// Raw attestation quote
    pub quote: Vec<u8>,
}

/// Seal metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealMetadata {
    /// Timestamp
    pub timestamp: std::time::SystemTime,
    /// Block height (if on-chain)
    pub block_height: Option<u64>,
    /// Jurisdiction
    pub jurisdiction: Jurisdiction,
    /// Purpose
    pub purpose: String,
    /// Validator set (who verified)
    pub validators: Vec<HybridPublicKey>,
}

/// Seal builder
pub struct SealBuilder {
    model_commitment: Option<[u8; 32]>,
    input_commitment: Option<[u8; 32]>,
    output_commitment: Option<[u8; 32]>,
    attestation: Option<SealAttestation>,
    zk_proof: Option<Vec<u8>>,
    jurisdiction: Jurisdiction,
    purpose: String,
}

impl SealBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        SealBuilder {
            model_commitment: None,
            input_commitment: None,
            output_commitment: None,
            attestation: None,
            zk_proof: None,
            jurisdiction: Jurisdiction::Global,
            purpose: String::new(),
        }
    }

    /// Set model commitment
    pub fn model(mut self, hash: [u8; 32]) -> Self {
        self.model_commitment = Some(hash);
        self
    }

    /// Set input commitment
    pub fn input(mut self, hash: [u8; 32]) -> Self {
        self.input_commitment = Some(hash);
        self
    }

    /// Set output commitment
    pub fn output(mut self, hash: [u8; 32]) -> Self {
        self.output_commitment = Some(hash);
        self
    }

    /// Set attestation
    pub fn attestation(mut self, att: SealAttestation) -> Self {
        self.attestation = Some(att);
        self
    }

    /// Set ZK proof
    pub fn zk_proof(mut self, proof: Vec<u8>) -> Self {
        self.zk_proof = Some(proof);
        self
    }

    /// Set jurisdiction
    pub fn jurisdiction(mut self, j: Jurisdiction) -> Self {
        self.jurisdiction = j;
        self
    }

    /// Set purpose
    pub fn purpose(mut self, p: &str) -> Self {
        self.purpose = p.to_string();
        self
    }

    /// Build and sign the seal
    pub fn build(self, keypair: &HybridKeypair) -> Result<DigitalSeal, SealError> {
        let model_commitment = self.model_commitment.ok_or(SealError::MissingField("model"))?;
        let input_commitment = self.input_commitment.ok_or(SealError::MissingField("input"))?;
        let output_commitment = self.output_commitment.ok_or(SealError::MissingField("output"))?;
        let attestation = self.attestation.ok_or(SealError::MissingField("attestation"))?;

        let id = SealId::new();

        let metadata = SealMetadata {
            timestamp: std::time::SystemTime::now(),
            block_height: None,
            jurisdiction: self.jurisdiction,
            purpose: self.purpose,
            validators: vec![keypair.public_key()],
        };

        // Sign the seal
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&id.0);
        to_sign.extend_from_slice(&model_commitment);
        to_sign.extend_from_slice(&input_commitment);
        to_sign.extend_from_slice(&output_commitment);

        let signature = keypair.sign(&to_sign);

        Ok(DigitalSeal {
            id,
            model_commitment,
            input_commitment,
            output_commitment,
            attestation,
            zk_proof: self.zk_proof,
            metadata,
            signature,
            signer: keypair.public_key(),
        })
    }
}

impl Default for SealBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DigitalSeal {
    /// Verify the seal signature
    pub fn verify_signature(&self) -> bool {
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&self.id.0);
        to_sign.extend_from_slice(&self.model_commitment);
        to_sign.extend_from_slice(&self.input_commitment);
        to_sign.extend_from_slice(&self.output_commitment);

        self.signer.verify(&to_sign, &self.signature)
    }

    /// Verify the attestation
    pub fn verify_attestation(&self) -> bool {
        // In production, verify the TEE attestation quote
        !self.attestation.quote.is_empty()
    }

    /// Export for on-chain submission
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Get seal hash
    pub fn hash(&self) -> [u8; 32] {
        crate::crypto::hash::sha256(&self.to_bytes())
    }
}

/// Seal errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum SealError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("Invalid attestation")]
    InvalidAttestation,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_id() {
        let id = SealId::new();
        assert_eq!(id.0.len(), 32);
        assert_eq!(id.to_hex().len(), 64);
    }
}
