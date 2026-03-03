//! Aethelred Block Types
//!
//! Block data structures for the Proof-of-Compute consensus.

use super::address::Address;
use super::transaction::{SignedTransaction, TransactionId};
use crate::crypto::hash::{block_hash, merkle_root, Hash256};
use std::fmt;

/// Block ID (32-byte hash)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BlockId(pub Hash256);

impl BlockId {
    /// Zero block ID (genesis parent)
    pub const ZERO: Self = Self(Hash256::ZERO);

    /// Create from hash
    pub fn from_hash(hash: Hash256) -> Self {
        Self(hash)
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

impl fmt::Debug for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockId({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Block header
#[derive(Debug, Clone)]
pub struct BlockHeader {
    /// Block version
    pub version: u32,
    /// Block height
    pub height: u64,
    /// Timestamp (Unix seconds)
    pub timestamp: u64,
    /// Previous block hash
    pub prev_block_id: BlockId,
    /// Transactions Merkle root
    pub tx_root: Hash256,
    /// State root hash
    pub state_root: Hash256,
    /// Compute results Merkle root
    pub compute_root: Hash256,
    /// Proposer address
    pub proposer: Address,
    /// Chain ID
    pub chain_id: u64,
    /// Extra data (max 32 bytes)
    pub extra_data: Vec<u8>,
}

impl BlockHeader {
    /// Create genesis block header
    pub fn genesis(chain_id: u64, timestamp: u64) -> Self {
        Self {
            version: 1,
            height: 0,
            timestamp,
            prev_block_id: BlockId::ZERO,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            compute_root: Hash256::ZERO,
            proposer: Address::ZERO,
            chain_id,
            extra_data: Vec::new(),
        }
    }

    /// Compute block ID (hash of header)
    pub fn id(&self) -> BlockId {
        BlockId::from_hash(block_hash(&self.to_bytes()))
    }

    /// Serialize header
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(self.prev_block_id.as_bytes());
        bytes.extend_from_slice(self.tx_root.as_bytes());
        bytes.extend_from_slice(self.state_root.as_bytes());
        bytes.extend_from_slice(self.compute_root.as_bytes());
        bytes.extend_from_slice(&self.proposer.serialize());
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.push(self.extra_data.len() as u8);
        bytes.extend_from_slice(&self.extra_data);
        bytes
    }

    /// Check if genesis block
    pub fn is_genesis(&self) -> bool {
        self.height == 0 && self.prev_block_id == BlockId::ZERO
    }
}

/// Complete block with header and transactions
#[derive(Debug, Clone)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// Transactions
    pub transactions: Vec<SignedTransaction>,
    /// Compute verification results
    pub compute_results: Vec<ComputeVerificationResult>,
    /// Validator votes (for BFT consensus)
    pub votes: Vec<ValidatorVote>,
}

impl Block {
    /// Create genesis block
    pub fn genesis(chain_id: u64, timestamp: u64) -> Self {
        Self {
            header: BlockHeader::genesis(chain_id, timestamp),
            transactions: Vec::new(),
            compute_results: Vec::new(),
            votes: Vec::new(),
        }
    }

    /// Get block ID
    pub fn id(&self) -> BlockId {
        self.header.id()
    }

    /// Get block height
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Compute transaction root
    pub fn compute_tx_root(&self) -> Hash256 {
        if self.transactions.is_empty() {
            return Hash256::ZERO;
        }

        let tx_hashes: Vec<Hash256> = self.transactions.iter().map(|tx| tx.hash()).collect();

        merkle_root(&tx_hashes)
    }

    /// Verify transaction root matches header
    pub fn verify_tx_root(&self) -> bool {
        self.compute_tx_root() == self.header.tx_root
    }

    /// Get transaction count
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    /// Get transaction IDs
    pub fn tx_ids(&self) -> Vec<TransactionId> {
        self.transactions.iter().map(|tx| tx.id()).collect()
    }

    /// Calculate total gas used
    pub fn total_gas_used(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.tx.gas_limit).sum()
    }

    /// Get size in bytes (approximate)
    pub fn size(&self) -> usize {
        self.header.to_bytes().len()
            + self.transactions.iter().map(|tx| tx.size()).sum::<usize>()
            + self.compute_results.len() * 256 // Approximate
            + self.votes.len() * 128 // Approximate
    }
}

/// Compute verification result included in block
#[derive(Debug, Clone)]
pub struct ComputeVerificationResult {
    /// Job ID
    pub job_id: Hash256,
    /// Output hash
    pub output_hash: Hash256,
    /// Verifying validators
    pub validators: Vec<Address>,
    /// Verification method used
    pub method: VerificationMethodUsed,
    /// zkML proof (if applicable)
    pub zkml_proof: Option<Vec<u8>>,
}

/// Verification method actually used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMethodUsed {
    TeeOnly { attestation_count: u32 },
    ZkmlOnly,
    Hybrid { attestation_count: u32 },
}

/// Validator vote in BFT consensus
#[derive(Debug, Clone)]
pub struct ValidatorVote {
    /// Validator address
    pub validator: Address,
    /// Block ID being voted on
    pub block_id: BlockId,
    /// Vote type
    pub vote_type: VoteType,
    /// Signature (hybrid)
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Vote type in BFT consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteType {
    PreVote,
    PreCommit,
    Commit,
}

/// Block builder for creating new blocks
pub struct BlockBuilder {
    header: BlockHeader,
    transactions: Vec<SignedTransaction>,
    compute_results: Vec<ComputeVerificationResult>,
    max_size: usize,
    max_gas: u64,
    current_gas: u64,
}

impl BlockBuilder {
    /// Create new block builder
    pub fn new(
        height: u64,
        prev_block_id: BlockId,
        proposer: Address,
        chain_id: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            header: BlockHeader {
                version: 1,
                height,
                timestamp,
                prev_block_id,
                tx_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
                compute_root: Hash256::ZERO,
                proposer,
                chain_id,
                extra_data: Vec::new(),
            },
            transactions: Vec::new(),
            compute_results: Vec::new(),
            max_size: 1_048_576, // 1 MB default
            max_gas: 10_000_000, // 10M gas default
            current_gas: 0,
        }
    }

    /// Set maximum block size
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Set maximum gas
    pub fn with_max_gas(mut self, max_gas: u64) -> Self {
        self.max_gas = max_gas;
        self
    }

    /// Try to add a transaction
    pub fn add_transaction(&mut self, tx: SignedTransaction) -> bool {
        let tx_gas = tx.tx.gas_limit;

        // Check gas limit
        if self.current_gas + tx_gas > self.max_gas {
            return false;
        }

        // Check size (approximate)
        let current_size: usize = self.transactions.iter().map(|t| t.size()).sum();
        if current_size + tx.size() > self.max_size {
            return false;
        }

        self.current_gas += tx_gas;
        self.transactions.push(tx);
        true
    }

    /// Add compute verification result
    pub fn add_compute_result(&mut self, result: ComputeVerificationResult) {
        self.compute_results.push(result);
    }

    /// Set state root
    pub fn with_state_root(mut self, state_root: Hash256) -> Self {
        self.header.state_root = state_root;
        self
    }

    /// Set extra data
    pub fn with_extra_data(mut self, extra_data: Vec<u8>) -> Self {
        self.header.extra_data = extra_data.into_iter().take(32).collect();
        self
    }

    /// Build the block
    pub fn build(mut self) -> Block {
        // Compute Merkle roots
        let tx_hashes: Vec<Hash256> = self.transactions.iter().map(|tx| tx.hash()).collect();
        self.header.tx_root = merkle_root(&tx_hashes);

        let compute_hashes: Vec<Hash256> = self
            .compute_results
            .iter()
            .map(|r| {
                let mut data = Vec::new();
                data.extend_from_slice(r.job_id.as_bytes());
                data.extend_from_slice(r.output_hash.as_bytes());
                crate::crypto::hash::sha256(&data)
            })
            .collect();
        self.header.compute_root = merkle_root(&compute_hashes);

        Block {
            header: self.header,
            transactions: self.transactions,
            compute_results: self.compute_results,
            votes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(1, 1234567890);
        assert_eq!(genesis.height(), 0);
        assert!(genesis.header.is_genesis());
        assert_eq!(genesis.tx_count(), 0);
    }

    #[test]
    fn test_block_id() {
        let genesis = Block::genesis(1, 1234567890);
        let id = genesis.id();
        assert!(!id.to_hex().is_empty());
    }

    #[test]
    fn test_block_builder() {
        let builder = BlockBuilder::new(1, BlockId::ZERO, Address::ZERO, 1, 1234567890);

        let block = builder.build();
        assert_eq!(block.height(), 1);
    }

    #[test]
    fn test_empty_tx_root() {
        let block = Block::genesis(1, 0);
        assert_eq!(block.compute_tx_root(), Hash256::ZERO);
        assert!(block.verify_tx_root());
    }
}
