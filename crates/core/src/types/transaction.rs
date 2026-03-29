//! Aethelred Transaction Types
//!
//! Enterprise-grade transactions with hybrid post-quantum signatures.
//!
//! # Transaction Types
//!
//! - `Transfer`: Token transfers between addresses
//! - `ComputeJob`: Submit AI computation verification jobs
//! - `Seal`: Create digital seals for verified computations
//! - `Stake`: Validator staking operations
//! - `Governance`: Protocol governance votes
//!
//! # Signature Verification
//!
//! All transactions require hybrid signatures (ECDSA + Dilithium3).
//! Verification behavior adapts based on the global QuantumThreatLevel.

use super::address::Address;
#[cfg(test)]
use crate::crypto::hash::sha256;
use crate::crypto::{
    hash::{transaction_hash, Hash256},
    hybrid::{HybridKeyPair, HybridPublicKey, HybridSecretKey, HybridSignature, VerifierConfig},
    CryptoError, QuantumThreatLevel,
};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Transaction errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Missing signature")]
    MissingSignature,

    #[error("Invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Transaction expired at {expiry}, current time {current}")]
    Expired { expiry: u64, current: u64 },

    #[error("Invalid transaction type")]
    InvalidType,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),
}

impl From<CryptoError> for TransactionError {
    fn from(e: CryptoError) -> Self {
        TransactionError::CryptoError(e.to_string())
    }
}

/// Transaction ID (32-byte hash)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId(pub Hash256);

impl TransactionId {
    /// Create from hash
    pub fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash256::from_bytes(bytes))
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Get hex string
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl fmt::Debug for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxId({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Transaction type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransactionType {
    /// Token transfer
    Transfer = 0x01,
    /// Submit compute job for verification
    ComputeJob = 0x02,
    /// Create digital seal
    Seal = 0x03,
    /// Validator staking
    Stake = 0x04,
    /// Unstake tokens
    Unstake = 0x05,
    /// Governance proposal
    Propose = 0x06,
    /// Governance vote
    Vote = 0x07,
    /// Oracle data feed update
    OracleUpdate = 0x08,
    /// Contract deployment
    Deploy = 0x09,
    /// Contract call
    Call = 0x0A,
}

impl TransactionType {
    /// Parse from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Transfer),
            0x02 => Some(Self::ComputeJob),
            0x03 => Some(Self::Seal),
            0x04 => Some(Self::Stake),
            0x05 => Some(Self::Unstake),
            0x06 => Some(Self::Propose),
            0x07 => Some(Self::Vote),
            0x08 => Some(Self::OracleUpdate),
            0x09 => Some(Self::Deploy),
            0x0A => Some(Self::Call),
            _ => None,
        }
    }

    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Check if transaction requires compute verification
    pub fn requires_compute(&self) -> bool {
        matches!(self, Self::ComputeJob | Self::Seal)
    }

    /// Get base gas cost
    pub fn base_gas(&self) -> u64 {
        match self {
            Self::Transfer => 21_000,
            Self::ComputeJob => 100_000,
            Self::Seal => 50_000,
            Self::Stake | Self::Unstake => 30_000,
            Self::Propose => 200_000,
            Self::Vote => 25_000,
            Self::OracleUpdate => 50_000,
            Self::Deploy => 500_000,
            Self::Call => 21_000, // Plus execution cost
        }
    }
}

/// Transfer transaction payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTx {
    /// Recipient address
    pub to: Address,
    /// Amount to transfer (in base units)
    pub amount: u128,
    /// Optional memo (max 256 bytes)
    pub memo: Option<Vec<u8>>,
}

impl TransferTx {
    /// Create new transfer
    pub fn new(to: Address, amount: u128) -> Self {
        Self {
            to,
            amount,
            memo: None,
        }
    }

    /// With memo
    pub fn with_memo(mut self, memo: Vec<u8>) -> Self {
        self.memo = Some(memo);
        self
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.to.serialize());
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        if let Some(memo) = &self.memo {
            bytes.push(1);
            bytes.extend_from_slice(&(memo.len() as u16).to_le_bytes());
            bytes.extend_from_slice(memo);
        } else {
            bytes.push(0);
        }
        bytes
    }
}

/// Compute job submission payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeJobTx {
    /// Model hash (SHA-256 of model weights)
    pub model_hash: Hash256,
    /// Input data hash (SHA-256 of input)
    pub input_hash: Hash256,
    /// Encrypted input data (optional, stored off-chain reference)
    pub encrypted_input_ref: Option<Vec<u8>>,
    /// Required verification method
    pub verification_method: VerificationMethod,
    /// Maximum fee willing to pay
    pub max_fee: u128,
    /// SLA requirements
    pub sla: ComputeSLA,
    /// Compliance requirements
    pub compliance: ComplianceRequirements,
}

impl ComputeJobTx {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.model_hash.as_bytes());
        bytes.extend_from_slice(self.input_hash.as_bytes());
        bytes.push(self.verification_method.to_byte());
        bytes.extend_from_slice(&self.max_fee.to_le_bytes());
        bytes.extend_from_slice(&self.sla.to_bytes());
        bytes.extend_from_slice(&self.compliance.to_bytes());
        if let Some(ref_data) = &self.encrypted_input_ref {
            bytes.push(1);
            bytes.extend_from_slice(&(ref_data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(ref_data);
        } else {
            bytes.push(0);
        }
        bytes
    }
}

/// Verification method for compute jobs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VerificationMethod {
    /// TEE-only verification (fastest)
    TeeOnly = 0x01,
    /// zkML-only verification (most private)
    ZkmlOnly = 0x02,
    /// Hybrid: TEE + zkML (highest assurance)
    Hybrid = 0x03,
    /// Multi-party computation
    Mpc = 0x04,
}

impl VerificationMethod {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::TeeOnly),
            0x02 => Some(Self::ZkmlOnly),
            0x03 => Some(Self::Hybrid),
            0x04 => Some(Self::Mpc),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Service Level Agreement for compute jobs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeSLA {
    /// Maximum latency in milliseconds
    pub max_latency_ms: u64,
    /// Minimum number of validator attestations
    pub min_attestations: u32,
    /// Required hardware tier
    pub hardware_tier: HardwareTier,
    /// Geographic restrictions (ISO 3166-1 alpha-2)
    pub geo_restrictions: Vec<String>,
}

impl ComputeSLA {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.max_latency_ms.to_le_bytes());
        bytes.extend_from_slice(&self.min_attestations.to_le_bytes());
        bytes.push(self.hardware_tier as u8);
        bytes.push(self.geo_restrictions.len() as u8);
        for geo in &self.geo_restrictions {
            bytes.extend_from_slice(geo.as_bytes());
        }
        bytes
    }
}

impl Default for ComputeSLA {
    fn default() -> Self {
        Self {
            max_latency_ms: 30_000, // 30 seconds
            min_attestations: 2,
            hardware_tier: HardwareTier::Standard,
            geo_restrictions: Vec::new(),
        }
    }
}

/// Hardware tier requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HardwareTier {
    /// Any hardware
    Standard = 0x00,
    /// GPU required
    Gpu = 0x01,
    /// TEE required (SGX/SEV/Nitro)
    Tee = 0x02,
    /// FPGA required
    Fpga = 0x03,
    /// TEE + GPU
    TeeGpu = 0x04,
}

/// Compliance requirements for compute jobs
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComplianceRequirements {
    /// Required compliance frameworks
    pub frameworks: Vec<ComplianceFramework>,
    /// Data residency requirements
    pub data_residency: Option<String>,
    /// Audit trail required
    pub audit_required: bool,
}

impl ComplianceRequirements {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.frameworks.len() as u8);
        for fw in &self.frameworks {
            bytes.push(*fw as u8);
        }
        if let Some(residency) = &self.data_residency {
            bytes.push(1);
            bytes.push(residency.len() as u8);
            bytes.extend_from_slice(residency.as_bytes());
        } else {
            bytes.push(0);
        }
        bytes.push(self.audit_required as u8);
        bytes
    }
}

/// Compliance frameworks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ComplianceFramework {
    Gdpr = 0x01,
    Hipaa = 0x02,
    PciDss = 0x03,
    Sox = 0x04,
    Ccpa = 0x05,
}

/// Digital seal creation payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealTx {
    /// Job ID that produced the result
    pub job_id: Hash256,
    /// Output hash
    pub output_hash: Hash256,
    /// Validator attestations
    pub attestations: Vec<ValidatorAttestation>,
    /// Optional zkML proof
    pub zkml_proof: Option<Vec<u8>>,
}

impl SealTx {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.job_id.as_bytes());
        bytes.extend_from_slice(self.output_hash.as_bytes());
        bytes.push(self.attestations.len() as u8);
        for att in &self.attestations {
            bytes.extend_from_slice(&att.to_bytes());
        }
        if let Some(proof) = &self.zkml_proof {
            bytes.push(1);
            bytes.extend_from_slice(&(proof.len() as u32).to_le_bytes());
            bytes.extend_from_slice(proof);
        } else {
            bytes.push(0);
        }
        bytes
    }
}

/// Validator attestation for compute result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorAttestation {
    /// Validator address
    pub validator: Address,
    /// TEE attestation document
    pub tee_attestation: Vec<u8>,
    /// Signature over (job_id || output_hash || timestamp)
    pub signature: HybridSignature,
    /// Timestamp
    pub timestamp: u64,
}

impl ValidatorAttestation {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.validator.serialize());
        bytes.extend_from_slice(&(self.tee_attestation.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.tee_attestation);
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }
}

/// Unsigned transaction
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction version
    pub version: u8,
    /// Transaction type
    pub tx_type: TransactionType,
    /// Sender address
    pub sender: Address,
    /// Sender's nonce
    pub nonce: u64,
    /// Gas price (in base units per gas)
    pub gas_price: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Chain ID (prevents replay across chains)
    pub chain_id: u64,
    /// Expiry timestamp (0 = no expiry)
    pub expiry: u64,
    /// Transaction payload
    pub payload: TransactionPayload,
}

/// Transaction payload variants
#[derive(Debug, Clone)]
pub enum TransactionPayload {
    Transfer(TransferTx),
    ComputeJob(ComputeJobTx),
    Seal(SealTx),
    Raw(Vec<u8>),
}

impl Transaction {
    /// Create a new transfer transaction
    pub fn transfer(sender: Address, to: Address, amount: u128, nonce: u64) -> Self {
        Self {
            version: 1,
            tx_type: TransactionType::Transfer,
            sender,
            nonce,
            gas_price: 1,
            gas_limit: TransactionType::Transfer.base_gas(),
            chain_id: 1, // Default chain ID
            expiry: 0,
            payload: TransactionPayload::Transfer(TransferTx::new(to, amount)),
        }
    }

    /// Create a compute job submission
    pub fn compute_job(
        sender: Address,
        model_hash: Hash256,
        input_hash: Hash256,
        nonce: u64,
    ) -> Self {
        Self {
            version: 1,
            tx_type: TransactionType::ComputeJob,
            sender,
            nonce,
            gas_price: 1,
            gas_limit: TransactionType::ComputeJob.base_gas(),
            chain_id: 1,
            expiry: 0,
            payload: TransactionPayload::ComputeJob(ComputeJobTx {
                model_hash,
                input_hash,
                encrypted_input_ref: None,
                verification_method: VerificationMethod::Hybrid,
                max_fee: 0,
                sla: ComputeSLA::default(),
                compliance: ComplianceRequirements::default(),
            }),
        }
    }

    /// Set gas parameters
    pub fn with_gas(mut self, price: u64, limit: u64) -> Self {
        self.gas_price = price;
        self.gas_limit = limit;
        self
    }

    /// Set chain ID
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Set expiry
    pub fn with_expiry(mut self, expiry: u64) -> Self {
        self.expiry = expiry;
        self
    }

    /// Compute transaction hash (signing hash)
    pub fn hash(&self) -> Hash256 {
        transaction_hash(&self.to_signing_bytes())
    }

    /// Get transaction ID (same as hash for unsigned tx)
    pub fn id(&self) -> TransactionId {
        TransactionId::from_hash(self.hash())
    }

    /// Serialize to signing bytes
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.push(self.tx_type.to_byte());
        bytes.extend_from_slice(&self.sender.serialize());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.gas_price.to_le_bytes());
        bytes.extend_from_slice(&self.gas_limit.to_le_bytes());
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.expiry.to_le_bytes());
        bytes.extend_from_slice(&self.payload_bytes());
        bytes
    }

    /// Get payload bytes
    fn payload_bytes(&self) -> Vec<u8> {
        match &self.payload {
            TransactionPayload::Transfer(tx) => tx.to_bytes(),
            TransactionPayload::ComputeJob(tx) => tx.to_bytes(),
            TransactionPayload::Seal(tx) => tx.to_bytes(),
            TransactionPayload::Raw(data) => data.clone(),
        }
    }

    /// Sign the transaction
    pub fn sign(self, keypair: &HybridKeyPair) -> Result<SignedTransaction, TransactionError> {
        let hash = self.hash();
        let signature = keypair.sign(hash.as_bytes())?;

        Ok(SignedTransaction {
            tx: self,
            signature,
            public_key: keypair.public_key().clone(),
        })
    }

    /// Sign with raw secret key
    pub fn sign_with_key(
        self,
        secret_key: &HybridSecretKey,
        public_key: HybridPublicKey,
    ) -> Result<SignedTransaction, TransactionError> {
        let hash = self.hash();
        let signature = secret_key.sign(hash.as_bytes())?;

        Ok(SignedTransaction {
            tx: self,
            signature,
            public_key,
        })
    }

    /// Check if transaction has expired
    pub fn is_expired(&self) -> bool {
        if self.expiry == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expiry
    }

    /// Calculate total gas cost
    pub fn total_gas_cost(&self) -> u128 {
        (self.gas_price as u128) * (self.gas_limit as u128)
    }
}

/// Signed transaction with hybrid signature
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// The unsigned transaction
    pub tx: Transaction,
    /// Hybrid signature (ECDSA + Dilithium3)
    pub signature: HybridSignature,
    /// Sender's public key
    pub public_key: HybridPublicKey,
}

impl SignedTransaction {
    /// Get transaction ID
    pub fn id(&self) -> TransactionId {
        self.tx.id()
    }

    /// Get transaction hash
    pub fn hash(&self) -> Hash256 {
        self.tx.hash()
    }

    /// Verify signature
    ///
    /// The `threat_level` parameter controls verification behavior:
    /// - Level 0-2: Both ECDSA and Dilithium must verify
    /// - Level 3-4: Classical optional, quantum mandatory
    /// - Level 5+: Only quantum signature checked
    pub fn verify_signature(
        &self,
        threat_level: QuantumThreatLevel,
    ) -> Result<bool, TransactionError> {
        // Verify public key matches sender address
        let derived_address = Address::from_public_key(&self.public_key);
        if derived_address != self.tx.sender {
            return Ok(false);
        }

        // Verify signature
        let hash = self.tx.hash();
        let config = verifier_config_for(threat_level, self.tx.chain_id);
        let valid = self
            .signature
            .verify(hash.as_bytes(), &self.public_key, &config)
            .is_ok();

        Ok(valid)
    }

    /// Verify signature with default threat level (NONE)
    pub fn verify(&self) -> Result<bool, TransactionError> {
        self.verify_signature(QuantumThreatLevel::NONE)
    }

    /// Serialize complete signed transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Transaction bytes
        let tx_bytes = self.tx.to_signing_bytes();
        bytes.extend_from_slice(&(tx_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&tx_bytes);

        // Signature bytes
        let sig_bytes = self.signature.to_bytes();
        bytes.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&sig_bytes);

        // Public key bytes
        let pk_bytes = self.public_key.to_bytes();
        bytes.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&pk_bytes);

        bytes
    }

    /// Get size in bytes
    pub fn size(&self) -> usize {
        self.to_bytes().len()
    }

    /// Check if transaction requires compute verification
    pub fn requires_compute_verification(&self) -> bool {
        self.tx.tx_type.requires_compute()
    }

    /// Extract compliance requirements if present
    pub fn compliance_requirements(&self) -> Option<&ComplianceRequirements> {
        match &self.tx.payload {
            TransactionPayload::ComputeJob(job) => Some(&job.compliance),
            _ => None,
        }
    }
}

/// Transaction batch for efficient verification
pub struct TransactionBatch<'a> {
    transactions: Vec<&'a SignedTransaction>,
}

impl<'a> TransactionBatch<'a> {
    /// Create new batch
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
        }
    }

    /// Add transaction to batch
    pub fn push(&mut self, tx: &'a SignedTransaction) {
        self.transactions.push(tx);
    }

    /// Batch verify all signatures
    pub fn verify_all(&self, threat_level: QuantumThreatLevel) -> Result<bool, TransactionError> {
        // Collect data for batch verification
        let messages: Vec<Vec<u8>> = self
            .transactions
            .iter()
            .map(|tx| tx.tx.hash().as_bytes().to_vec())
            .collect();

        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        let signatures: Vec<&HybridSignature> =
            self.transactions.iter().map(|tx| &tx.signature).collect();

        let public_keys: Vec<&HybridPublicKey> =
            self.transactions.iter().map(|tx| &tx.public_key).collect();

        let chain_id = self
            .transactions
            .first()
            .map(|tx| tx.tx.chain_id)
            .unwrap_or(1);
        let config = verifier_config_for(threat_level, chain_id);

        // Batch verify
        let valid =
            crate::crypto::hybrid::batch_verify(&msg_refs, &signatures, &public_keys, &config)?;

        Ok(valid)
    }

    /// Get transaction count
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl<'a> Default for TransactionBatch<'a> {
    fn default() -> Self {
        Self::new()
    }
}

fn verifier_config_for(threat_level: QuantumThreatLevel, chain_id: u64) -> VerifierConfig {
    let mut config = VerifierConfig {
        chain_id,
        ..Default::default()
    };
    if threat_level.quantum_only() {
        config.enter_panic_mode();
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_keypair() -> HybridKeyPair {
        HybridKeyPair::generate().unwrap()
    }

    #[test]
    fn test_transfer_transaction() {
        let keypair = create_test_keypair();
        let sender = Address::from_public_key(keypair.public_key());
        let recipient = Address::from_bytes([0x42; 20], super::super::address::AddressType::User);

        let tx = Transaction::transfer(sender, recipient, 1000, 0);
        assert_eq!(tx.tx_type, TransactionType::Transfer);
        assert_eq!(tx.nonce, 0);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = create_test_keypair();
        let sender = Address::from_public_key(keypair.public_key());
        let recipient = Address::from_bytes([0x42; 20], super::super::address::AddressType::User);

        let tx = Transaction::transfer(sender, recipient, 1000, 0);
        let signed = tx.sign(&keypair).unwrap();

        assert!(signed.verify().unwrap());
    }

    #[test]
    fn test_verify_with_threat_levels() {
        let keypair = create_test_keypair();
        let sender = Address::from_public_key(keypair.public_key());
        let recipient = Address::from_bytes([0x42; 20], super::super::address::AddressType::User);

        let tx = Transaction::transfer(sender, recipient, 1000, 0);
        let signed = tx.sign(&keypair).unwrap();

        // Should verify at all threat levels
        assert!(signed.verify_signature(QuantumThreatLevel::NONE).unwrap());
        assert!(signed.verify_signature(QuantumThreatLevel::HIGH).unwrap());
        assert!(signed.verify_signature(QuantumThreatLevel::Q_DAY).unwrap());
    }

    #[test]
    fn test_wrong_sender_fails() {
        let keypair = create_test_keypair();
        let wrong_sender =
            Address::from_bytes([0x11; 20], super::super::address::AddressType::User);
        let recipient = Address::from_bytes([0x42; 20], super::super::address::AddressType::User);

        // Create transaction with wrong sender
        let tx = Transaction::transfer(wrong_sender, recipient, 1000, 0);
        let signed = tx.sign(&keypair).unwrap();

        // Verification should fail because sender doesn't match public key
        assert!(!signed.verify().unwrap());
    }

    #[test]
    fn test_transaction_id() {
        let keypair = create_test_keypair();
        let sender = Address::from_public_key(keypair.public_key());
        let recipient = Address::from_bytes([0x42; 20], super::super::address::AddressType::User);

        let tx = Transaction::transfer(sender, recipient, 1000, 0);
        let id = tx.id();

        // Same transaction should have same ID
        let tx2 = Transaction::transfer(sender, recipient, 1000, 0);
        assert_eq!(id.to_hex(), tx2.id().to_hex());
    }

    #[test]
    fn test_batch_verification() {
        let keypair = create_test_keypair();
        let sender = Address::from_public_key(keypair.public_key());
        let recipient = Address::from_bytes([0x42; 20], super::super::address::AddressType::User);

        // Create multiple transactions
        let tx1 = Transaction::transfer(sender, recipient, 100, 0)
            .sign(&keypair)
            .unwrap();
        let tx2 = Transaction::transfer(sender, recipient, 200, 1)
            .sign(&keypair)
            .unwrap();
        let tx3 = Transaction::transfer(sender, recipient, 300, 2)
            .sign(&keypair)
            .unwrap();

        let mut batch = TransactionBatch::new();
        batch.push(&tx1);
        batch.push(&tx2);
        batch.push(&tx3);

        assert_eq!(batch.len(), 3);
        assert!(batch.verify_all(QuantumThreatLevel::NONE).unwrap());
    }

    #[test]
    fn test_transaction_expiry() {
        let keypair = create_test_keypair();
        let sender = Address::from_public_key(keypair.public_key());
        let recipient = Address::from_bytes([0x42; 20], super::super::address::AddressType::User);

        // Non-expiring transaction
        let tx1 = Transaction::transfer(sender, recipient, 1000, 0);
        assert!(!tx1.is_expired());

        // Expired transaction
        let tx2 = Transaction::transfer(sender, recipient, 1000, 0).with_expiry(1);
        assert!(tx2.is_expired());

        // Future expiry
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let tx3 = Transaction::transfer(sender, recipient, 1000, 0).with_expiry(future);
        assert!(!tx3.is_expired());
    }

    #[test]
    fn test_compute_job_transaction() {
        let keypair = create_test_keypair();
        let sender = Address::from_public_key(keypair.public_key());
        let model_hash = sha256(b"model weights");
        let input_hash = sha256(b"input data");

        let tx = Transaction::compute_job(sender, model_hash, input_hash, 0);
        assert_eq!(tx.tx_type, TransactionType::ComputeJob);
        assert!(tx.tx_type.requires_compute());

        let signed = tx.sign(&keypair).unwrap();
        assert!(signed.requires_compute_verification());
        assert!(signed.compliance_requirements().is_some());
    }
}
