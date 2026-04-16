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

            // Submit withdrawal proposal to Ethereum
            self.submit_withdrawal_to_ethereum(&proposal_id).await?;

            // Only mark the proposal as submitted once the transaction backend
            // reports success.
            self.storage.update_withdrawal_proposal_status(
                &proposal_id,
                WithdrawalProposalStatus::SubmittedToEthereum,
            )?;
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
        let stored_deposit = self
            .storage
            .get_deposit(&proposal.deposit.deposit_id)?
            .ok_or_else(|| {
                BridgeError::Consensus("Mint proposal deposit is missing".to_string())
            })?;

        if stored_deposit.tx_hash != proposal.deposit.tx_hash
            || stored_deposit.amount != proposal.deposit.amount
            || stored_deposit.aethelred_recipient != proposal.deposit.aethelred_recipient
        {
            return Err(BridgeError::Consensus(
                "Mint proposal deposit does not match stored deposit".to_string(),
            ));
        }

        match self
            .storage
            .get_deposit_status(&proposal.deposit.deposit_id)?
        {
            Some(DepositStatus::Confirmed | DepositStatus::MintProposed) => Ok(true),
            Some(status) => Err(BridgeError::Consensus(format!(
                "Mint proposal deposit is not ready for voting: {status:?}"
            ))),
            None => Err(BridgeError::Consensus(
                "Mint proposal deposit status is missing".to_string(),
            )),
        }
    }

    /// Check if we should vote for a withdrawal proposal
    async fn should_vote_withdrawal(&self, proposal: &WithdrawalProposal) -> Result<bool> {
        let stored_burn = self
            .storage
            .get_burn(&proposal.burn.burn_id)?
            .ok_or_else(|| BridgeError::Consensus("Withdrawal burn is missing".to_string()))?;

        if stored_burn.tx_hash != proposal.burn.tx_hash
            || stored_burn.amount != proposal.burn.amount
            || stored_burn.eth_recipient != proposal.burn.eth_recipient
        {
            return Err(BridgeError::Consensus(
                "Withdrawal proposal burn does not match stored burn".to_string(),
            ));
        }

        match self.storage.get_burn_status(&proposal.burn.burn_id)? {
            Some(WithdrawalStatus::Confirmed | WithdrawalStatus::WithdrawalProposed) => Ok(true),
            Some(status) => Err(BridgeError::Consensus(format!(
                "Withdrawal burn is not ready for voting: {status:?}"
            ))),
            None => Err(BridgeError::Consensus(
                "Withdrawal burn status is missing".to_string(),
            )),
        }
    }

    /// Create a vote for a mint proposal
    async fn create_mint_vote(&self, _proposal: &MintProposal) -> Result<RelayerVote> {
        let relayer = self.require_local_identity()?;

        Err(BridgeError::Signing(format!(
            "Cryptographic mint-vote signing backend is not implemented for relayer {}",
            hex::encode(&relayer[..8])
        )))
    }

    /// Create a vote for a withdrawal proposal
    async fn create_withdrawal_vote(&self, _proposal: &WithdrawalProposal) -> Result<RelayerVote> {
        let relayer = self.require_local_identity()?;

        Err(BridgeError::Signing(format!(
            "Cryptographic withdrawal-vote signing backend is not implemented for relayer {}",
            hex::encode(&relayer[..8])
        )))
    }

    /// Verify a vote signature
    fn verify_vote_signature(&self, vote: &RelayerVote) -> Result<()> {
        if vote.relayer == [0u8; 32] {
            return Err(BridgeError::Verification(
                "Vote relayer address is zero".to_string(),
            ));
        }

        if vote.signature.is_empty() {
            return Err(BridgeError::Verification("Empty signature".to_string()));
        }

        Err(BridgeError::Verification(
            "Cryptographic vote signature verification backend is not implemented".to_string(),
        ))
    }

    /// Submit a mint transaction to Aethelred
    async fn submit_mint_to_aethelred(&self, proposal_id: &Hash) -> Result<()> {
        info!(
            "Submitting mint to Aethelred: {}",
            hex::encode(&proposal_id[..8])
        );

        Err(BridgeError::Aethelred(format!(
            "Mint submission backend is not implemented for proposal {}",
            hex::encode(&proposal_id[..8])
        )))
    }

    /// Submit a withdrawal proposal to Ethereum
    async fn submit_withdrawal_to_ethereum(&self, proposal_id: &Hash) -> Result<()> {
        info!(
            "Submitting withdrawal proposal to Ethereum: {}",
            hex::encode(&proposal_id[..8])
        );

        Err(BridgeError::Ethereum(format!(
            "Withdrawal submission backend is not implemented for proposal {}",
            hex::encode(&proposal_id[..8])
        )))
    }

    fn require_local_identity(&self) -> Result<AethelredAddress> {
        self.config.identity.require_private_key()?;
        self.config.identity.aethelred_address_bytes()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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

    #[tokio::test]
    async fn test_process_pending_mints_fails_closed_without_signing_backend() {
        let tempdir = tempdir().unwrap();
        let key_path = tempdir.path().join("relayer.key");
        std::fs::write(&key_path, b"placeholder").unwrap();

        let mut config = BridgeConfig::testnet();
        config.identity.private_key_path = key_path;
        config.identity.aethelred_address = Some(format!("0x{}", hex::encode([7u8; 32])));

        let storage = Arc::new(BridgeStorage::open_temp().unwrap());
        let metrics = Arc::new(BridgeMetrics::new());
        let engine = ConsensusEngine::new(config, storage.clone(), metrics);

        let deposit = EthereumDeposit {
            deposit_id: [1u8; 32],
            depositor: [2u8; 20],
            aethelred_recipient: [3u8; 32],
            token: [0u8; 20],
            amount: 100,
            nonce: 1,
            block_number: 10,
            block_hash: [4u8; 32],
            tx_hash: [5u8; 32],
            log_index: 0,
            timestamp: 1,
        };
        storage.store_deposit(&deposit).unwrap();
        storage
            .update_deposit_status(&deposit.deposit_id, DepositStatus::Confirmed)
            .unwrap();

        let proposal = MintProposal {
            proposal_id: deposit.generate_id(),
            deposit,
            proposer: [7u8; 32],
            votes: vec![],
            status: MintProposalStatus::Voting,
            created_at: 1,
            updated_at: 1,
        };
        storage.store_mint_proposal(&proposal).unwrap();

        let error = engine
            .process_pending()
            .await
            .expect_err("automatic voting should fail closed until the signing backend exists");
        assert!(matches!(error, BridgeError::Signing(_)));
    }

    #[test]
    fn test_verify_vote_signature_fails_closed_without_crypto_backend() {
        let config = BridgeConfig::testnet();
        let storage = Arc::new(BridgeStorage::open_temp().unwrap());
        let metrics = Arc::new(BridgeMetrics::new());
        let engine = ConsensusEngine::new(config, storage, metrics);

        let vote = RelayerVote {
            relayer: [9u8; 32],
            approve: true,
            signature: vec![1; 64],
            timestamp: 1,
        };

        let error = engine
            .verify_vote_signature(&vote)
            .expect_err("vote verification should fail closed without crypto backend");
        assert!(matches!(error, BridgeError::Verification(_)));
    }
}
