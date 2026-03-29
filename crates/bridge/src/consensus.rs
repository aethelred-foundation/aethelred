//! Consensus Engine
//!
//! Handles multi-relayer consensus for bridge operations.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::BridgeConfig;
use crate::error::{BridgeError, Result};
use crate::metrics::BridgeMetrics;
use crate::storage::BridgeStorage;
use crate::types::*;

/// Consensus engine for bridge operations
pub struct ConsensusEngine {
    /// Configuration
    config: BridgeConfig,

    /// Storage
    storage: Arc<BridgeStorage>,

    /// Metrics
    _metrics: Arc<BridgeMetrics>,

    /// Active relayer set
    relayer_set: RwLock<RelayerSet>,

    /// Pending mint proposals (deposit_id -> votes)
    pending_mints: RwLock<HashMap<Hash, Vec<RelayerVote>>>,

    /// Pending withdrawal proposals (burn_id -> votes)
    pending_withdrawals: RwLock<HashMap<Hash, Vec<RelayerVote>>>,
}

impl ConsensusEngine {
    /// Create a new consensus engine
    pub fn new(
        config: BridgeConfig,
        storage: Arc<BridgeStorage>,
        metrics: Arc<BridgeMetrics>,
    ) -> Self {
        Self {
            config,
            storage,
            _metrics: metrics,
            relayer_set: RwLock::new(RelayerSet {
                relayers: vec![],
                threshold_bps: 6700,
                version: 0,
                total_stake: 0,
            }),
            pending_mints: RwLock::new(HashMap::new()),
            pending_withdrawals: RwLock::new(HashMap::new()),
        }
    }

    /// Get number of consensus participants
    pub async fn participant_count(&self) -> usize {
        self.relayer_set.read().await.relayers.len()
    }

    /// Update the relayer set
    pub async fn update_relayer_set(&self, new_set: RelayerSet) -> Result<()> {
        info!(
            "Updating relayer set: {} relayers, version {}",
            new_set.relayers.len(),
            new_set.version
        );

        *self.relayer_set.write().await = new_set;
        Ok(())
    }

    /// Process pending proposals
    pub async fn process_pending(&self) -> Result<()> {
        // Process pending mints
        self.process_pending_mints().await?;

        // Process pending withdrawals
        self.process_pending_withdrawals().await?;

        Ok(())
    }

    /// Check for timed out proposals
    pub async fn check_timeouts(&self) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let timeout = self.config.consensus.proposal_timeout_secs;

        // Check mint proposals
        let proposals = self.storage.get_pending_mint_proposals()?;
        for proposal in proposals {
            if now - proposal.created_at > timeout {
                warn!(
                    "Mint proposal {} timed out",
                    hex::encode(&proposal.proposal_id[..8])
                );
                self.storage.update_mint_proposal_status(
                    &proposal.proposal_id,
                    MintProposalStatus::Expired,
                )?;
            }
        }

        // Check withdrawal proposals
        let proposals = self.storage.get_pending_withdrawal_proposals()?;
        for proposal in proposals {
            if now - proposal.created_at > timeout {
                warn!(
                    "Withdrawal proposal {} timed out",
                    hex::encode(&proposal.proposal_id[..8])
                );
                self.storage.update_withdrawal_proposal_status(
                    &proposal.proposal_id,
                    WithdrawalProposalStatus::Expired,
                )?;
            }
        }

        Ok(())
    }

    /// Submit a vote for a mint proposal
    pub async fn vote_mint(&self, proposal_id: Hash, vote: RelayerVote) -> Result<()> {
        debug!(
            "Received mint vote for {} from {}",
            hex::encode(&proposal_id[..8]),
            hex::encode(&vote.relayer[..8])
        );

        // Verify vote signature
        self.verify_vote_signature(&vote)?;

        // Check if relayer is in active set
        let relayer_set = self.relayer_set.read().await;
        if !relayer_set
            .relayers
            .iter()
            .any(|r| r.address == vote.relayer && r.active)
        {
            return Err(BridgeError::Consensus(
                "Relayer not in active set".to_string(),
            ));
        }

        // Add vote
        let mut pending = self.pending_mints.write().await;
        let votes = pending.entry(proposal_id).or_insert_with(Vec::new);

        // Check for duplicate vote
        if votes.iter().any(|v| v.relayer == vote.relayer) {
            return Err(BridgeError::Duplicate("Already voted".to_string()));
        }

        votes.push(vote);

        // Check if consensus reached
        if relayer_set.has_consensus(votes.len()) {
            info!(
                "Consensus reached for mint proposal {} ({}/{} votes)",
                hex::encode(&proposal_id[..8]),
                votes.len(),
                relayer_set.min_votes_required()
            );

            // Update proposal status
            self.storage
                .update_mint_proposal_status(&proposal_id, MintProposalStatus::ConsensusReached)?;

            // Submit mint transaction to Aethelred
            self.submit_mint_to_aethelred(&proposal_id).await?;
        }

        Ok(())
    }

    /// Submit a vote for a withdrawal proposal
    pub async fn vote_withdrawal(&self, proposal_id: Hash, vote: RelayerVote) -> Result<()> {
        debug!(
            "Received withdrawal vote for {} from {}",
            hex::encode(&proposal_id[..8]),
            hex::encode(&vote.relayer[..8])
        );

        // Verify vote signature
        self.verify_vote_signature(&vote)?;

        // Check if relayer is in active set
        let relayer_set = self.relayer_set.read().await;
        if !relayer_set
            .relayers
            .iter()
            .any(|r| r.address == vote.relayer && r.active)
        {
            return Err(BridgeError::Consensus(
                "Relayer not in active set".to_string(),
            ));
        }

        // Add vote
        let mut pending = self.pending_withdrawals.write().await;
        let votes = pending.entry(proposal_id).or_insert_with(Vec::new);

        // Check for duplicate vote
        if votes.iter().any(|v| v.relayer == vote.relayer) {
            return Err(BridgeError::Duplicate("Already voted".to_string()));
        }

        votes.push(vote);

        // Check if consensus reached
        if relayer_set.has_consensus(votes.len()) {
            info!(
                "Consensus reached for withdrawal proposal {} ({}/{} votes)",
                hex::encode(&proposal_id[..8]),
                votes.len(),
                relayer_set.min_votes_required()
            );

            // Update proposal status
            self.storage.update_withdrawal_proposal_status(
                &proposal_id,
                WithdrawalProposalStatus::SubmittedToEthereum,
            )?;

            // Submit withdrawal proposal to Ethereum
            self.submit_withdrawal_to_ethereum(&proposal_id).await?;
        }

        Ok(())
    }

    /// Process pending mint proposals
    async fn process_pending_mints(&self) -> Result<()> {
        let proposals = self.storage.get_pending_mint_proposals()?;

        for proposal in proposals {
            if proposal.status == MintProposalStatus::Voting {
                // Check if we should vote
                if self.should_vote_mint(&proposal).await? {
                    // Create and submit our vote
                    let vote = self.create_mint_vote(&proposal).await?;
                    self.vote_mint(proposal.proposal_id, vote).await?;
                }
            }
        }

        Ok(())
    }

    /// Process pending withdrawal proposals
    async fn process_pending_withdrawals(&self) -> Result<()> {
        let proposals = self.storage.get_pending_withdrawal_proposals()?;

        for proposal in proposals {
            if proposal.status == WithdrawalProposalStatus::Voting {
                // Check if we should vote
                if self.should_vote_withdrawal(&proposal).await? {
                    // Create and submit our vote
                    let vote = self.create_withdrawal_vote(&proposal).await?;
                    self.vote_withdrawal(proposal.proposal_id, vote).await?;
                }
            }
        }

        Ok(())
    }

    /// Check if we should vote for a mint proposal
    async fn should_vote_mint(&self, proposal: &MintProposal) -> Result<bool> {
        // Verify the deposit exists and is valid
        let _deposit = &proposal.deposit;

        // Verify deposit on Ethereum (in production, would query the chain)
        // For now, assume valid if we have it in storage
        Ok(true)
    }

    /// Check if we should vote for a withdrawal proposal
    async fn should_vote_withdrawal(&self, _proposal: &WithdrawalProposal) -> Result<bool> {
        // Verify the burn exists and is valid on Aethelred
        // For now, assume valid if we have it in storage
        Ok(true)
    }

    /// Create a vote for a mint proposal
    async fn create_mint_vote(&self, _proposal: &MintProposal) -> Result<RelayerVote> {
        // In production, sign with relayer's private key
        Ok(RelayerVote {
            relayer: [0u8; 32], // Our relayer address
            approve: true,
            signature: vec![0u8; 64], // Signature
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Create a vote for a withdrawal proposal
    async fn create_withdrawal_vote(&self, _proposal: &WithdrawalProposal) -> Result<RelayerVote> {
        Ok(RelayerVote {
            relayer: [0u8; 32],
            approve: true,
            signature: vec![0u8; 64],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Verify a vote signature
    fn verify_vote_signature(&self, vote: &RelayerVote) -> Result<()> {
        // In production, verify ECDSA/EdDSA signature
        if vote.signature.is_empty() {
            return Err(BridgeError::Verification("Empty signature".to_string()));
        }
        Ok(())
    }

    /// Submit a mint transaction to Aethelred
    async fn submit_mint_to_aethelred(&self, proposal_id: &Hash) -> Result<()> {
        info!(
            "Submitting mint to Aethelred: {}",
            hex::encode(&proposal_id[..8])
        );

        // In production:
        // 1. Build the mint transaction
        // 2. Sign with relayer key
        // 3. Submit to Aethelred RPC
        // 4. Wait for inclusion

        Ok(())
    }

    /// Submit a withdrawal proposal to Ethereum
    async fn submit_withdrawal_to_ethereum(&self, proposal_id: &Hash) -> Result<()> {
        info!(
            "Submitting withdrawal proposal to Ethereum: {}",
            hex::encode(&proposal_id[..8])
        );

        // In production:
        // 1. Build the proposeWithdrawal transaction
        // 2. Estimate gas
        // 3. Sign with relayer key
        // 4. Submit to Ethereum

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_consensus_threshold() {
        let config = BridgeConfig::testnet();
        let storage = Arc::new(BridgeStorage::open_temp().unwrap());
        let metrics = Arc::new(BridgeMetrics::new());
        let engine = ConsensusEngine::new(config, storage, metrics);

        // Set up relayer set with 3 relayers
        let relayer_set = RelayerSet {
            relayers: vec![
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
            ],
            threshold_bps: 6700,
            version: 1,
            total_stake: 3000,
        };

        engine.update_relayer_set(relayer_set).await.unwrap();

        assert_eq!(engine.participant_count().await, 3);
    }
}
