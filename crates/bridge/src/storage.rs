//! Bridge Storage
//!
//! Persistent storage for bridge state using a file-backed snapshot.

use crate::error::{BridgeError, Result};
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

const STATE_FILE_NAME: &str = "bridge-state.bin";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedBridgeState {
    last_eth_block: Option<u64>,
    eth_block_hashes: HashMap<u64, Hash>,
    last_aethelred_block: Option<u64>,
    deposits: HashMap<Hash, EthereumDeposit>,
    deposit_statuses: HashMap<Hash, DepositStatus>,
    pending_deposits: HashMap<Hash, EthereumDeposit>,
    burns: HashMap<Hash, AethelredBurn>,
    burn_statuses: HashMap<Hash, WithdrawalStatus>,
    pending_burns: HashMap<Hash, AethelredBurn>,
    mint_proposals: HashMap<Hash, MintProposal>,
    withdrawal_proposals: HashMap<Hash, WithdrawalProposal>,
}

/// Bridge storage backed by a persisted snapshot file.
pub struct BridgeStorage {
    state_path: PathBuf,
    state: RwLock<PersistedBridgeState>,
}

impl BridgeStorage {
    /// Open storage at the given path
    pub fn open(path: &Path) -> Result<Self> {
        fs::create_dir_all(path)?;
        let state_path = path.join(STATE_FILE_NAME);
        let state = Self::load_state(&state_path)?;

        Ok(Self {
            state_path,
            state: RwLock::new(state),
        })
    }

    /// Open a temporary storage (for testing)
    pub fn open_temp() -> Result<Self> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BridgeError::Storage(e.to_string()))?
            .as_nanos();
        let temp_path = std::env::temp_dir().join(format!("aethelred-bridge-{unique}"));
        Self::open(&temp_path)
    }

    fn load_state(path: &Path) -> Result<PersistedBridgeState> {
        if !path.exists() {
            return Ok(PersistedBridgeState::default());
        }

        let bytes = fs::read(path)?;
        if bytes.is_empty() {
            return Ok(PersistedBridgeState::default());
        }

        bincode::deserialize(&bytes).map_err(|e| BridgeError::Storage(e.to_string()))
    }

    fn persist_state(&self, state: &PersistedBridgeState) -> Result<()> {
        let encoded = bincode::serialize(state).map_err(|e| BridgeError::Storage(e.to_string()))?;
        let temp_path = self.state_path.with_extension("tmp");
        fs::write(&temp_path, encoded)?;
        fs::rename(temp_path, &self.state_path)?;
        Ok(())
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, PersistedBridgeState>> {
        self.state
            .read()
            .map_err(|e| BridgeError::Storage(format!("bridge storage lock poisoned: {e}")))
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, PersistedBridgeState>> {
        self.state
            .write()
            .map_err(|e| BridgeError::Storage(format!("bridge storage lock poisoned: {e}")))
    }

    fn mutate_state<T>(&self, update: impl FnOnce(&mut PersistedBridgeState) -> T) -> Result<T> {
        let mut state = self.write_state()?;
        let result = update(&mut state);
        self.persist_state(&state)?;
        Ok(result)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    // ========================================================================
    // Ethereum Block Tracking
    // ========================================================================

    pub fn get_last_eth_block(&self) -> Result<Option<u64>> {
        Ok(self.read_state()?.last_eth_block)
    }

    pub fn set_last_eth_block(&self, block: u64) -> Result<()> {
        self.mutate_state(|state| {
            state.last_eth_block = Some(block);
        })?;
        Ok(())
    }

    pub fn get_eth_block_hash(&self, block: u64) -> Result<Option<Hash>> {
        Ok(self.read_state()?.eth_block_hashes.get(&block).copied())
    }

    // ========================================================================
    // Aethelred Block Tracking
    // ========================================================================

    pub fn get_last_aethelred_block(&self) -> Result<Option<u64>> {
        Ok(self.read_state()?.last_aethelred_block)
    }

    pub fn set_last_aethelred_block(&self, block: u64) -> Result<()> {
        self.mutate_state(|state| {
            state.last_aethelred_block = Some(block);
        })?;
        Ok(())
    }

    // ========================================================================
    // Deposit Storage
    // ========================================================================

    pub fn has_deposit(&self, deposit_id: &Hash) -> Result<bool> {
        let state = self.read_state()?;
        Ok(state.deposits.contains_key(deposit_id)
            || state.pending_deposits.contains_key(deposit_id))
    }

    pub fn store_deposit(&self, deposit: &EthereumDeposit) -> Result<()> {
        self.mutate_state(|state| {
            state.pending_deposits.remove(&deposit.deposit_id);
            state.deposits.insert(deposit.deposit_id, deposit.clone());
            state
                .eth_block_hashes
                .insert(deposit.block_number, deposit.block_hash);
            state
                .deposit_statuses
                .entry(deposit.deposit_id)
                .or_insert(DepositStatus::Confirmed);
        })?;
        Ok(())
    }

    pub fn get_deposit(&self, deposit_id: &Hash) -> Result<Option<EthereumDeposit>> {
        let state = self.read_state()?;
        Ok(state
            .deposits
            .get(deposit_id)
            .cloned()
            .or_else(|| state.pending_deposits.get(deposit_id).cloned()))
    }

    pub fn get_deposit_status(&self, deposit_id: &Hash) -> Result<Option<DepositStatus>> {
        Ok(self.read_state()?.deposit_statuses.get(deposit_id).copied())
    }

    pub fn store_pending_deposit(&self, deposit: &EthereumDeposit) -> Result<()> {
        self.mutate_state(|state| {
            state
                .pending_deposits
                .insert(deposit.deposit_id, deposit.clone());
            state
                .deposit_statuses
                .insert(deposit.deposit_id, DepositStatus::Pending);
            state
                .eth_block_hashes
                .insert(deposit.block_number, deposit.block_hash);
        })?;
        Ok(())
    }

    pub fn update_deposit_status(&self, deposit_id: &Hash, status: DepositStatus) -> Result<()> {
        self.mutate_state(|state| {
            state.deposit_statuses.insert(*deposit_id, status);
            if matches!(
                status,
                DepositStatus::Completed | DepositStatus::Cancelled | DepositStatus::Failed
            ) {
                if let Some(deposit) = state.pending_deposits.remove(deposit_id) {
                    state.deposits.insert(*deposit_id, deposit);
                }
            }
        })?;
        Ok(())
    }

    pub fn pending_deposit_count(&self) -> Result<usize> {
        Ok(self.read_state()?.pending_deposits.len())
    }

    // ========================================================================
    // Burn Storage
    // ========================================================================

    pub fn has_burn(&self, burn_id: &Hash) -> Result<bool> {
        let state = self.read_state()?;
        Ok(state.burns.contains_key(burn_id) || state.pending_burns.contains_key(burn_id))
    }

    pub fn store_burn(&self, burn: &AethelredBurn) -> Result<()> {
        self.mutate_state(|state| {
            state.pending_burns.remove(&burn.burn_id);
            state.burns.insert(burn.burn_id, burn.clone());
            state
                .burn_statuses
                .entry(burn.burn_id)
                .or_insert(WithdrawalStatus::Confirmed);
        })?;
        Ok(())
    }

    pub fn get_burn(&self, burn_id: &Hash) -> Result<Option<AethelredBurn>> {
        let state = self.read_state()?;
        Ok(state
            .burns
            .get(burn_id)
            .cloned()
            .or_else(|| state.pending_burns.get(burn_id).cloned()))
    }

    pub fn get_burn_status(&self, burn_id: &Hash) -> Result<Option<WithdrawalStatus>> {
        Ok(self.read_state()?.burn_statuses.get(burn_id).copied())
    }

    pub fn store_pending_burn(&self, burn: &AethelredBurn) -> Result<()> {
        self.mutate_state(|state| {
            state.pending_burns.insert(burn.burn_id, burn.clone());
            state
                .burn_statuses
                .insert(burn.burn_id, WithdrawalStatus::Pending);
        })?;
        Ok(())
    }

    pub fn update_burn_status(&self, burn_id: &Hash, status: WithdrawalStatus) -> Result<()> {
        self.mutate_state(|state| {
            state.burn_statuses.insert(*burn_id, status);
            if matches!(
                status,
                WithdrawalStatus::Completed
                    | WithdrawalStatus::Challenged
                    | WithdrawalStatus::Failed
            ) {
                if let Some(burn) = state.pending_burns.remove(burn_id) {
                    state.burns.insert(*burn_id, burn);
                }
            }
        })?;
        Ok(())
    }

    // ========================================================================
    // Mint Proposal Storage
    // ========================================================================

    pub fn store_mint_proposal(&self, proposal: &MintProposal) -> Result<()> {
        self.mutate_state(|state| {
            state
                .mint_proposals
                .insert(proposal.proposal_id, proposal.clone());
        })?;
        Ok(())
    }

    pub fn get_mint_proposal(&self, proposal_id: &Hash) -> Result<Option<MintProposal>> {
        Ok(self.read_state()?.mint_proposals.get(proposal_id).cloned())
    }

    pub fn get_pending_mint_proposals(&self) -> Result<Vec<MintProposal>> {
        Ok(self
            .read_state()?
            .mint_proposals
            .values()
            .cloned()
            .collect())
    }

    pub fn update_mint_proposal_status(
        &self,
        proposal_id: &Hash,
        status: MintProposalStatus,
    ) -> Result<()> {
        self.mutate_state(|state| {
            if let Some(proposal) = state.mint_proposals.get_mut(proposal_id) {
                proposal.status = status;
                proposal.updated_at = Self::now_secs();
            }
        })?;
        Ok(())
    }

    // ========================================================================
    // Withdrawal Proposal Storage
    // ========================================================================

    pub fn store_withdrawal_proposal(&self, proposal: &WithdrawalProposal) -> Result<()> {
        self.mutate_state(|state| {
            state
                .withdrawal_proposals
                .insert(proposal.proposal_id, proposal.clone());
        })?;
        Ok(())
    }

    pub fn get_withdrawal_proposal(
        &self,
        proposal_id: &Hash,
    ) -> Result<Option<WithdrawalProposal>> {
        Ok(self
            .read_state()?
            .withdrawal_proposals
            .get(proposal_id)
            .cloned())
    }

    pub fn get_pending_withdrawal_proposals(&self) -> Result<Vec<WithdrawalProposal>> {
        Ok(self
            .read_state()?
            .withdrawal_proposals
            .values()
            .cloned()
            .collect())
    }

    pub fn update_withdrawal_proposal_status(
        &self,
        proposal_id: &Hash,
        status: WithdrawalProposalStatus,
    ) -> Result<()> {
        self.mutate_state(|state| {
            if let Some(proposal) = state.withdrawal_proposals.get_mut(proposal_id) {
                proposal.status = status;
                proposal.updated_at = Self::now_secs();
            }
        })?;
        Ok(())
    }

    pub fn update_withdrawal_status(
        &self,
        proposal_id: &Hash,
        status: WithdrawalStatus,
    ) -> Result<()> {
        self.mutate_state(|state| {
            state.burn_statuses.insert(*proposal_id, status);
        })?;
        Ok(())
    }

    pub fn pending_withdrawal_count(&self) -> Result<usize> {
        Ok(self.read_state()?.pending_burns.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{unique}"))
    }

    fn sample_deposit() -> EthereumDeposit {
        EthereumDeposit {
            deposit_id: [1u8; 32],
            depositor: [2u8; 20],
            aethelred_recipient: [3u8; 32],
            token: [4u8; 20],
            amount: 42,
            nonce: 7,
            block_number: 100,
            block_hash: [5u8; 32],
            tx_hash: [6u8; 32],
            log_index: 0,
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn test_storage_persists_blocks_and_deposits() {
        let dir = unique_temp_path("bridge-storage-test");
        let storage = BridgeStorage::open(&dir).unwrap();
        let deposit = sample_deposit();

        storage.set_last_eth_block(123).unwrap();
        storage.store_pending_deposit(&deposit).unwrap();
        storage
            .update_deposit_status(&deposit.deposit_id, DepositStatus::Confirmed)
            .unwrap();

        let reopened = BridgeStorage::open(&dir).unwrap();
        assert_eq!(reopened.get_last_eth_block().unwrap(), Some(123));
        assert!(reopened.has_deposit(&deposit.deposit_id).unwrap());
        assert_eq!(
            reopened
                .get_deposit(&deposit.deposit_id)
                .unwrap()
                .unwrap()
                .tx_hash,
            deposit.tx_hash
        );
    }

    #[test]
    fn test_storage_persists_proposals() {
        let dir = unique_temp_path("bridge-storage-proposal-test");
        let storage = BridgeStorage::open(&dir).unwrap();
        let deposit = sample_deposit();
        let proposal = MintProposal {
            proposal_id: [9u8; 32],
            deposit,
            proposer: [8u8; 32],
            votes: vec![],
            status: MintProposalStatus::Voting,
            created_at: 10,
            updated_at: 10,
        };

        storage.store_mint_proposal(&proposal).unwrap();
        storage
            .update_mint_proposal_status(
                &proposal.proposal_id,
                MintProposalStatus::ConsensusReached,
            )
            .unwrap();

        let reopened = BridgeStorage::open(&dir).unwrap();
        let stored = reopened
            .get_mint_proposal(&proposal.proposal_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, MintProposalStatus::ConsensusReached);
    }
}
