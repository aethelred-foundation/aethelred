//! Bridge Types
//!
//! Common type definitions for the bridge relayer.

use serde::{Deserialize, Serialize};

// ============================================================================
// Address Types
// ============================================================================

/// 20-byte Ethereum address
pub type EthAddress = [u8; 20];

/// 32-byte Aethelred address
pub type AethelredAddress = [u8; 32];

/// 32-byte hash
pub type Hash = [u8; 32];

/// Token amount (256-bit for Ethereum compatibility)
pub type TokenAmount = u128;

// ============================================================================
// Deposit Types
// ============================================================================

/// Ethereum deposit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumDeposit {
    /// Unique deposit ID
    pub deposit_id: Hash,

    /// Depositor address on Ethereum
    pub depositor: EthAddress,

    /// Recipient address on Aethelred
    pub aethelred_recipient: AethelredAddress,

    /// Token address (zero address for ETH)
    pub token: EthAddress,

    /// Amount deposited
    pub amount: TokenAmount,

    /// Deposit nonce
    pub nonce: u64,

    /// Block number on Ethereum
    pub block_number: u64,

    /// Block hash
    pub block_hash: Hash,

    /// Transaction hash
    pub tx_hash: Hash,

    /// Log index in the block
    pub log_index: u32,

    /// Timestamp
    pub timestamp: u64,
}

impl EthereumDeposit {
    /// Generate a deterministic ID for this deposit
    pub fn generate_id(&self) -> Hash {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"eth-deposit-v1:");
        hasher.update(self.depositor);
        hasher.update(self.aethelred_recipient);
        hasher.update(self.token);
        hasher.update(self.amount.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.tx_hash);
        hasher.update(self.log_index.to_le_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Deposit status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositStatus {
    /// Detected on Ethereum, awaiting confirmations
    Pending,
    /// Confirmed on Ethereum, awaiting consensus
    Confirmed,
    /// Mint proposal submitted to Aethelred
    MintProposed,
    /// Minted on Aethelred
    Completed,
    /// Deposit was cancelled/refunded
    Cancelled,
    /// Failed due to error
    Failed,
}

// ============================================================================
// Withdrawal Types
// ============================================================================

/// Aethelred burn event (initiates withdrawal)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AethelredBurn {
    /// Unique burn ID
    pub burn_id: Hash,

    /// Burner address on Aethelred
    pub burner: AethelredAddress,

    /// Recipient address on Ethereum
    pub eth_recipient: EthAddress,

    /// Token type
    pub token_type: TokenType,

    /// Amount burned
    pub amount: TokenAmount,

    /// Burn nonce - Audit fix [L-07]: Sequential nonce for Aethelred→ETH direction,
    /// mirroring EthereumDeposit.nonce for the ETH→Aethelred direction.
    /// Enables off-chain monitoring to detect gaps (missed or censored burns).
    pub nonce: u64,

    /// Block height on Aethelred
    pub block_height: u64,

    /// Block hash
    pub block_hash: Hash,

    /// Transaction hash
    pub tx_hash: Hash,

    /// Timestamp
    pub timestamp: u64,
}

/// Token type on Aethelred
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// Wrapped ETH
    WrappedETH,
    /// Wrapped ERC20 (with token address)
    WrappedERC20([u8; 20]),
    /// Native AETHEL token
    NativeAETHEL,
}

/// Withdrawal status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Detected on Aethelred, awaiting confirmations
    Pending,
    /// Confirmed on Aethelred, awaiting consensus
    Confirmed,
    /// Withdrawal proposal submitted to Ethereum
    WithdrawalProposed,
    /// Consensus reached, awaiting challenge period
    ConsensusReached,
    /// Challenge period ended, can be processed
    ReadyToProcess,
    /// Unlocked on Ethereum
    Completed,
    /// Challenged/cancelled
    Challenged,
    /// Failed due to error
    Failed,
}

// ============================================================================
// Consensus Types
// ============================================================================

/// Mint proposal for Aethelred consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintProposal {
    /// Proposal ID
    pub proposal_id: Hash,

    /// Original deposit
    pub deposit: EthereumDeposit,

    /// Proposer (relayer address)
    pub proposer: AethelredAddress,

    /// Votes received
    pub votes: Vec<RelayerVote>,

    /// Status
    pub status: MintProposalStatus,

    /// Created timestamp
    pub created_at: u64,

    /// Last updated timestamp
    pub updated_at: u64,
}

/// Withdrawal proposal for Ethereum consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalProposal {
    /// Proposal ID
    pub proposal_id: Hash,

    /// Original burn event
    pub burn: AethelredBurn,

    /// Proposer (relayer address)
    pub proposer: AethelredAddress,

    /// Votes received
    pub votes: Vec<RelayerVote>,

    /// Status
    pub status: WithdrawalProposalStatus,

    /// Created timestamp
    pub created_at: u64,

    /// Challenge end time (Ethereum)
    pub challenge_end_time: u64,

    /// Last updated timestamp
    pub updated_at: u64,
}

/// Relayer vote on a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerVote {
    /// Relayer address
    pub relayer: AethelredAddress,

    /// Vote (approve = true, reject = false)
    pub approve: bool,

    /// Signature over the proposal
    pub signature: Vec<u8>,

    /// Timestamp
    pub timestamp: u64,
}

/// Mint proposal status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintProposalStatus {
    /// Awaiting votes
    Voting,
    /// Consensus reached, mint submitted
    ConsensusReached,
    /// Mint confirmed on Aethelred
    Completed,
    /// Not enough votes, expired
    Expired,
    /// Explicitly rejected
    Rejected,
}

/// Withdrawal proposal status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalProposalStatus {
    /// Awaiting votes
    Voting,
    /// Consensus reached, submitted to Ethereum
    SubmittedToEthereum,
    /// In challenge period
    InChallengePeriod,
    /// Challenge period ended, can process
    ReadyToProcess,
    /// Withdrawal processed
    Completed,
    /// Challenged
    Challenged,
    /// Expired
    Expired,
}

// ============================================================================
// Event Types
// ============================================================================

/// Events from Ethereum
#[derive(Debug, Clone)]
pub enum EthereumEvent {
    /// New deposit detected
    Deposit(EthereumDeposit),

    /// Deposit finalized (enough confirmations)
    DepositFinalized { deposit_id: Hash, block_number: u64 },

    /// Withdrawal processed on Ethereum
    WithdrawalProcessed {
        proposal_id: Hash,
        recipient: EthAddress,
        amount: TokenAmount,
        tx_hash: Hash,
    },

    /// Chain reorganization detected
    Reorg {
        from_block: u64,
        to_block: u64,
        affected_deposits: Vec<Hash>,
    },

    /// New block
    NewBlock {
        number: u64,
        hash: Hash,
        timestamp: u64,
    },
}

/// Events from Aethelred
#[derive(Debug, Clone)]
pub enum AethelredEvent {
    /// New burn detected
    Burn(AethelredBurn),

    /// Burn finalized
    BurnFinalized { burn_id: Hash, block_height: u64 },

    /// Mint completed
    MintCompleted {
        proposal_id: Hash,
        recipient: AethelredAddress,
        amount: TokenAmount,
        tx_hash: Hash,
    },

    /// New block
    NewBlock {
        height: u64,
        hash: Hash,
        timestamp: u64,
    },
}

// ============================================================================
// Configuration Types
// ============================================================================

/// Relayer identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerIdentity {
    /// Relayer's Aethelred address
    pub address: AethelredAddress,

    /// Relayer's Ethereum address
    pub eth_address: EthAddress,

    /// Public key for signing
    pub public_key: Vec<u8>,

    /// Stake amount
    pub stake: TokenAmount,

    /// Active status
    pub active: bool,
}

/// Relayer set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerSet {
    /// Active relayers
    pub relayers: Vec<RelayerIdentity>,

    /// Consensus threshold (basis points)
    pub threshold_bps: u16,

    /// Set version/epoch
    pub version: u64,

    /// Total stake
    pub total_stake: TokenAmount,
}

impl RelayerSet {
    /// Get minimum votes required for consensus
    pub fn min_votes_required(&self) -> usize {
        let active_count = self.relayers.iter().filter(|r| r.active).count();
        let threshold = (active_count * self.threshold_bps as usize) / 10000;
        if threshold == 0 {
            1
        } else {
            threshold
        }
    }

    /// Check if consensus is reached
    pub fn has_consensus(&self, vote_count: usize) -> bool {
        vote_count >= self.min_votes_required()
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert Ethereum address to hex string
pub fn eth_address_to_hex(addr: &EthAddress) -> String {
    format!("0x{}", hex::encode(addr))
}

/// Convert Aethelred address to hex string
pub fn aethelred_address_to_hex(addr: &AethelredAddress) -> String {
    format!("0x{}", hex::encode(addr))
}

/// Parse Ethereum address from hex string
pub fn parse_eth_address(s: &str) -> Option<EthAddress> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Some(addr)
}

/// Parse Aethelred address from hex string
pub fn parse_aethelred_address(s: &str) -> Option<AethelredAddress> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Some(addr)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_id_generation() {
        let deposit = EthereumDeposit {
            deposit_id: [0u8; 32],
            depositor: [1u8; 20],
            aethelred_recipient: [2u8; 32],
            token: [0u8; 20],
            amount: 1_000_000_000_000_000_000,
            nonce: 1,
            block_number: 12345,
            block_hash: [3u8; 32],
            tx_hash: [4u8; 32],
            log_index: 0,
            timestamp: 1700000000,
        };

        let id1 = deposit.generate_id();
        let id2 = deposit.generate_id();

        // Same deposit should generate same ID
        assert_eq!(id1, id2);

        // Different deposit should generate different ID
        let mut deposit2 = deposit.clone();
        deposit2.nonce = 2;
        let id3 = deposit2.generate_id();
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_relayer_set_consensus() {
        let relayers = vec![
            RelayerIdentity {
                address: [1u8; 32],
                eth_address: [1u8; 20],
                public_key: vec![],
                stake: 1000,
                active: true,
            },
            RelayerIdentity {
                address: [2u8; 32],
                eth_address: [2u8; 20],
                public_key: vec![],
                stake: 1000,
                active: true,
            },
            RelayerIdentity {
                address: [3u8; 32],
                eth_address: [3u8; 20],
                public_key: vec![],
                stake: 1000,
                active: true,
            },
        ];

        let set = RelayerSet {
            relayers,
            threshold_bps: 6700, // 67%
            version: 1,
            total_stake: 3000,
        };

        assert_eq!(set.min_votes_required(), 2); // 67% of 3 = 2.01 -> 2
        assert!(!set.has_consensus(1));
        assert!(set.has_consensus(2));
        assert!(set.has_consensus(3));
    }

    #[test]
    fn test_address_parsing() {
        let eth_hex = "0x1234567890123456789012345678901234567890";
        let eth_addr = parse_eth_address(eth_hex).unwrap();
        assert_eq!(eth_address_to_hex(&eth_addr), eth_hex);

        let aethel_hex = "0x1234567890123456789012345678901234567890123456789012345678901234";
        let aethel_addr = parse_aethelred_address(aethel_hex).unwrap();
        assert_eq!(aethelred_address_to_hex(&aethel_addr), aethel_hex);
    }
}
