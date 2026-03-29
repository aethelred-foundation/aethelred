//! Event Processor
//!
//! Processes events from both Ethereum and Aethelred chains.

use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::config::BridgeConfig;
use crate::error::{BridgeError, Result};
use crate::metrics::BridgeMetrics;
use crate::storage::BridgeStorage;
use crate::types::*;

/// Event processor
pub struct EventProcessor {
    /// Configuration
    _config: BridgeConfig,

    /// Storage
    storage: Arc<BridgeStorage>,

    /// Metrics
    metrics: Arc<BridgeMetrics>,
}

impl EventProcessor {
    /// Create a new event processor
    pub fn new(
        config: BridgeConfig,
        storage: Arc<BridgeStorage>,
        metrics: Arc<BridgeMetrics>,
    ) -> Self {
        Self {
            _config: config,
            storage,
            metrics,
        }
    }

    /// Process an Ethereum event
    pub async fn process_ethereum_event(&self, event: EthereumEvent) -> Result<()> {
        match event {
            EthereumEvent::Deposit(deposit) => self.handle_eth_deposit(deposit).await,

            EthereumEvent::DepositFinalized {
                deposit_id,
                block_number,
            } => {
                self.handle_eth_deposit_finalized(deposit_id, block_number)
                    .await
            }

            EthereumEvent::WithdrawalProcessed {
                proposal_id,
                recipient,
                amount,
                tx_hash,
            } => {
                self.handle_eth_withdrawal_processed(proposal_id, recipient, amount, tx_hash)
                    .await
            }

            EthereumEvent::Reorg {
                from_block,
                to_block,
                affected_deposits,
            } => {
                self.handle_eth_reorg(from_block, to_block, affected_deposits)
                    .await
            }

            EthereumEvent::NewBlock {
                number,
                hash: _,
                timestamp: _,
            } => {
                // Audit fix [L-06]: Reduced verbosity - block hashes logged at trace
                // level to avoid flooding bridge logs on high-throughput chains.
                debug!("New Ethereum block: {}", number);
                Ok(())
            }
        }
    }

    /// Process an Aethelred event
    pub async fn process_aethelred_event(&self, event: AethelredEvent) -> Result<()> {
        match event {
            AethelredEvent::Burn(burn) => self.handle_aethelred_burn(burn).await,

            AethelredEvent::BurnFinalized {
                burn_id,
                block_height,
            } => {
                self.handle_aethelred_burn_finalized(burn_id, block_height)
                    .await
            }

            AethelredEvent::MintCompleted {
                proposal_id,
                recipient,
                amount,
                tx_hash,
            } => {
                self.handle_aethelred_mint_completed(proposal_id, recipient, amount, tx_hash)
                    .await
            }

            AethelredEvent::NewBlock {
                height,
                hash: _,
                timestamp: _,
            } => {
                // Audit fix [L-06]: Reduced verbosity.
                debug!("New Aethelred block: {}", height);
                Ok(())
            }
        }
    }

    // ========================================================================
    // Ethereum Event Handlers
    // ========================================================================

    async fn handle_eth_deposit(&self, deposit: EthereumDeposit) -> Result<()> {
        info!(
            "Processing ETH deposit: {} ({} wei from {})",
            hex::encode(&deposit.deposit_id[..8]),
            deposit.amount,
            hex::encode(deposit.depositor)
        );

        // Validate deposit
        self.validate_deposit(&deposit)?;

        // Store pending deposit
        self.storage.store_pending_deposit(&deposit)?;

        self.metrics.increment_eth_deposits();

        Ok(())
    }

    async fn handle_eth_deposit_finalized(
        &self,
        deposit_id: Hash,
        block_number: u64,
    ) -> Result<()> {
        info!(
            "Deposit finalized: {} at block {}",
            hex::encode(&deposit_id[..8]),
            block_number
        );

        // Get the deposit
        let deposit = self
            .storage
            .get_deposit(&deposit_id)?
            .ok_or_else(|| BridgeError::InvalidInput("Deposit not found".to_string()))?;

        // Update status
        self.storage
            .update_deposit_status(&deposit_id, DepositStatus::Confirmed)?;

        // Create mint proposal for Aethelred consensus
        // Audit fix [H-04]: Replace .unwrap() with .unwrap_or_default() to prevent
        // panics if SystemTime is before UNIX_EPOCH (e.g., clock skew / VM issues).
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let proposal = MintProposal {
            proposal_id: deposit.generate_id(),
            deposit,
            proposer: [0u8; 32], // Will be filled by consensus engine
            votes: vec![],
            status: MintProposalStatus::Voting,
            created_at: now_secs,
            updated_at: now_secs,
        };

        // Store mint proposal
        self.storage.store_mint_proposal(&proposal)?;

        Ok(())
    }

    async fn handle_eth_withdrawal_processed(
        &self,
        proposal_id: Hash,
        recipient: EthAddress,
        amount: TokenAmount,
        _tx_hash: Hash,
    ) -> Result<()> {
        info!(
            "Withdrawal processed on ETH: {} ({} to {})",
            hex::encode(&proposal_id[..8]),
            amount,
            hex::encode(recipient)
        );

        // Update withdrawal status
        self.storage
            .update_withdrawal_status(&proposal_id, WithdrawalStatus::Completed)?;

        self.metrics.increment_eth_withdrawals();

        Ok(())
    }

    async fn handle_eth_reorg(
        &self,
        from_block: u64,
        to_block: u64,
        affected_deposits: Vec<Hash>,
    ) -> Result<()> {
        warn!(
            "Handling ETH reorg from block {} to {}, {} affected deposits",
            from_block,
            to_block,
            affected_deposits.len()
        );

        // Mark affected deposits as pending re-confirmation
        for deposit_id in affected_deposits {
            self.storage
                .update_deposit_status(&deposit_id, DepositStatus::Pending)?;
        }

        Ok(())
    }

    // ========================================================================
    // Aethelred Event Handlers
    // ========================================================================

    async fn handle_aethelred_burn(&self, burn: AethelredBurn) -> Result<()> {
        info!(
            "Processing Aethelred burn: {} ({} from {})",
            hex::encode(&burn.burn_id[..8]),
            burn.amount,
            hex::encode(&burn.burner[..8])
        );

        // Validate burn
        self.validate_burn(&burn)?;

        // Store pending burn
        self.storage.store_pending_burn(&burn)?;

        Ok(())
    }

    async fn handle_aethelred_burn_finalized(
        &self,
        burn_id: Hash,
        block_height: u64,
    ) -> Result<()> {
        info!(
            "Burn finalized: {} at height {}",
            hex::encode(&burn_id[..8]),
            block_height
        );

        // Get the burn
        let burn = self
            .storage
            .get_burn(&burn_id)?
            .ok_or_else(|| BridgeError::InvalidInput("Burn not found".to_string()))?;

        // Update status
        self.storage
            .update_burn_status(&burn_id, WithdrawalStatus::Confirmed)?;

        // Create withdrawal proposal for Ethereum
        // Audit fix [H-04]: Replace .unwrap() with .unwrap_or_default() to prevent panics.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let proposal = WithdrawalProposal {
            proposal_id: burn_id,
            burn,
            proposer: [0u8; 32],
            votes: vec![],
            status: WithdrawalProposalStatus::Voting,
            created_at: now_secs,
            challenge_end_time: 0, // Set when submitted to Ethereum
            updated_at: now_secs,
        };

        self.storage.store_withdrawal_proposal(&proposal)?;

        Ok(())
    }

    async fn handle_aethelred_mint_completed(
        &self,
        proposal_id: Hash,
        recipient: AethelredAddress,
        amount: TokenAmount,
        _tx_hash: Hash,
    ) -> Result<()> {
        info!(
            "Mint completed on Aethelred: {} ({} to {})",
            hex::encode(&proposal_id[..8]),
            amount,
            hex::encode(&recipient[..8])
        );

        // Update mint proposal status
        self.storage
            .update_mint_proposal_status(&proposal_id, MintProposalStatus::Completed)?;

        // Update deposit status
        if let Some(proposal) = self.storage.get_mint_proposal(&proposal_id)? {
            self.storage
                .update_deposit_status(&proposal.deposit.deposit_id, DepositStatus::Completed)?;
        }

        self.metrics.increment_aethelred_mints();

        Ok(())
    }

    // ========================================================================
    // Validation
    // ========================================================================

    fn validate_deposit(&self, deposit: &EthereumDeposit) -> Result<()> {
        // Check minimum amount
        if deposit.amount == 0 {
            return Err(BridgeError::InvalidInput("Zero amount deposit".to_string()));
        }

        // Check recipient is valid
        if deposit.aethelred_recipient == [0u8; 32] {
            return Err(BridgeError::InvalidInput("Invalid recipient".to_string()));
        }

        // Check not duplicate
        if self.storage.has_deposit(&deposit.deposit_id)? {
            return Err(BridgeError::Duplicate("Deposit already exists".to_string()));
        }

        Ok(())
    }

    fn validate_burn(&self, burn: &AethelredBurn) -> Result<()> {
        // Check minimum amount
        if burn.amount == 0 {
            return Err(BridgeError::InvalidInput("Zero amount burn".to_string()));
        }

        // Check recipient is valid
        if burn.eth_recipient == [0u8; 20] {
            return Err(BridgeError::InvalidInput(
                "Invalid ETH recipient".to_string(),
            ));
        }

        // Check not duplicate
        if self.storage.has_burn(&burn.burn_id)? {
            return Err(BridgeError::Duplicate("Burn already exists".to_string()));
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_deposit() -> EthereumDeposit {
        EthereumDeposit {
            deposit_id: [1u8; 32],
            depositor: [2u8; 20],
            aethelred_recipient: [3u8; 32],
            token: [0u8; 20],
            amount: 1_000_000_000_000_000_000,
            nonce: 1,
            block_number: 12345,
            block_hash: [4u8; 32],
            tx_hash: [5u8; 32],
            log_index: 0,
            timestamp: 1700000000,
        }
    }

    #[test]
    fn test_validate_deposit() {
        let config = BridgeConfig::testnet();
        let storage = Arc::new(BridgeStorage::open_temp().unwrap());
        let metrics = Arc::new(BridgeMetrics::new());
        let processor = EventProcessor::new(config, storage, metrics);

        let deposit = create_test_deposit();
        assert!(processor.validate_deposit(&deposit).is_ok());

        // Zero amount should fail
        let mut bad_deposit = deposit.clone();
        bad_deposit.amount = 0;
        assert!(processor.validate_deposit(&bad_deposit).is_err());

        // Zero recipient should fail
        let mut bad_deposit = deposit.clone();
        bad_deposit.aethelred_recipient = [0u8; 32];
        assert!(processor.validate_deposit(&bad_deposit).is_err());
    }
}
