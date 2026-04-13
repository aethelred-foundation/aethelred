//! Bridge Storage
//!
//! Persistent storage for bridge state backed by a JSON state file.

use crate::error::Result;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredDeposit {
    deposit: EthereumDeposit,
    status: DepositStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredBurn {
    burn: AethelredBurn,
    status: WithdrawalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedState {
    last_eth_block: Option<u64>,
    eth_block_hashes: HashMap<u64, Hash>,
    last_aethelred_block: Option<u64>,
    deposits: HashMap<String, StoredDeposit>,
    burns: HashMap<String, StoredBurn>,
    mint_proposals: HashMap<String, MintProposal>,
    withdrawal_proposals: HashMap<String, WithdrawalProposal>,
}

/// Bridge storage backed by a persisted JSON state file.
pub struct BridgeStorage {
    state_path: PathBuf,
    state: RwLock<PersistedState>,
}

impl BridgeStorage {
    /// Open storage at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        fs::create_dir_all(path)?;
        let state_path = path.join("bridge-state.json");
        let state = if state_path.exists() {
            let raw = fs::read_to_string(&state_path)?;
            serde_json::from_str(&raw)?
        } else {
            PersistedState::default()
        };

        Ok(Self {
            state_path,
            state: RwLock::new(state),
        })
    }

    /// Open a temporary storage (for testing).
    pub fn open_temp() -> Result<Self> {
        let temp_path = std::env::temp_dir().join(format!(
            "bridge-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Self::open(&temp_path)
    }

    fn persist_state(&self, state: &PersistedState) -> Result<()> {
        let payload = serde_json::to_vec_pretty(state)?;
        fs::write(&self.state_path, payload)?;
        Ok(())
    }

    fn hash_key(hash: &Hash) -> String {
        hex::encode(hash)
    }

    // ========================================================================
    // Ethereum Block Tracking
    // ========================================================================

    pub fn get_last_eth_block(&self) -> Result<Option<u64>> {
        Ok(self.state.read().expect("bridge storage lock poisoned").last_eth_block)
    }

    pub fn set_last_eth_block(&self, block: u64) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        state.last_eth_block = Some(block);
        self.persist_state(&state)
    }

    pub fn get_eth_block_hash(&self, block: u64) -> Result<Option<Hash>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .eth_block_hashes
            .get(&block)
            .copied())
    }

    pub fn set_eth_block_hash(&self, block: u64, hash: Hash) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        state.eth_block_hashes.insert(block, hash);
        self.persist_state(&state)
    }

    // ========================================================================
    // Aethelred Block Tracking
    // ========================================================================

    pub fn get_last_aethelred_block(&self) -> Result<Option<u64>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .last_aethelred_block)
    }

    pub fn set_last_aethelred_block(&self, block: u64) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        state.last_aethelred_block = Some(block);
        self.persist_state(&state)
    }

    // ========================================================================
    // Deposit Storage
    // ========================================================================

    pub fn has_deposit(&self, deposit_id: &Hash) -> Result<bool> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .deposits
            .contains_key(&Self::hash_key(deposit_id)))
    }

    pub fn get_deposit_status(&self, deposit_id: &Hash) -> Result<Option<DepositStatus>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .deposits
            .get(&Self::hash_key(deposit_id))
            .map(|entry| entry.status))
    }

    pub fn store_deposit(&self, deposit: &EthereumDeposit) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        let key = Self::hash_key(&deposit.deposit_id);
        let status = state
            .deposits
            .get(&key)
            .map(|entry| match entry.status {
                DepositStatus::Completed => DepositStatus::Completed,
                DepositStatus::MintProposed => DepositStatus::MintProposed,
                _ => DepositStatus::Confirmed,
            })
            .unwrap_or(DepositStatus::Confirmed);
        state.deposits.insert(
            key,
            StoredDeposit {
                deposit: deposit.clone(),
                status,
            },
        );
        self.persist_state(&state)
    }

    pub fn get_deposit(&self, deposit_id: &Hash) -> Result<Option<EthereumDeposit>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .deposits
            .get(&Self::hash_key(deposit_id))
            .map(|entry| entry.deposit.clone()))
    }

    pub fn store_pending_deposit(&self, deposit: &EthereumDeposit) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        let key = Self::hash_key(&deposit.deposit_id);
        state.deposits.entry(key).or_insert_with(|| StoredDeposit {
            deposit: deposit.clone(),
            status: DepositStatus::Pending,
        });
        self.persist_state(&state)
    }

    pub fn update_deposit_status(&self, deposit_id: &Hash, status: DepositStatus) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        let key = Self::hash_key(deposit_id);
        if let Some(entry) = state.deposits.get_mut(&key) {
            entry.status = status;
        }
        self.persist_state(&state)
    }

    pub fn pending_deposit_count(&self) -> Result<usize> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .deposits
            .values()
            .filter(|entry| matches!(entry.status, DepositStatus::Pending))
            .count())
    }

    // ========================================================================
    // Burn Storage
    // ========================================================================

    pub fn has_burn(&self, burn_id: &Hash) -> Result<bool> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .burns
            .contains_key(&Self::hash_key(burn_id)))
    }

    pub fn get_burn_status(&self, burn_id: &Hash) -> Result<Option<WithdrawalStatus>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .burns
            .get(&Self::hash_key(burn_id))
            .map(|entry| entry.status))
    }

    pub fn store_burn(&self, burn: &AethelredBurn) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        let key = Self::hash_key(&burn.burn_id);
        let status = state
            .burns
            .get(&key)
            .map(|entry| match entry.status {
                WithdrawalStatus::Completed => WithdrawalStatus::Completed,
                WithdrawalStatus::WithdrawalProposed => WithdrawalStatus::WithdrawalProposed,
                WithdrawalStatus::ConsensusReached => WithdrawalStatus::ConsensusReached,
                WithdrawalStatus::ReadyToProcess => WithdrawalStatus::ReadyToProcess,
                _ => WithdrawalStatus::Confirmed,
            })
            .unwrap_or(WithdrawalStatus::Confirmed);
        state.burns.insert(
            key,
            StoredBurn {
                burn: burn.clone(),
                status,
            },
        );
        self.persist_state(&state)
    }

    pub fn get_burn(&self, burn_id: &Hash) -> Result<Option<AethelredBurn>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .burns
            .get(&Self::hash_key(burn_id))
            .map(|entry| entry.burn.clone()))
    }

    pub fn store_pending_burn(&self, burn: &AethelredBurn) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        let key = Self::hash_key(&burn.burn_id);
        state.burns.entry(key).or_insert_with(|| StoredBurn {
            burn: burn.clone(),
            status: WithdrawalStatus::Pending,
        });
        self.persist_state(&state)
    }

    pub fn update_burn_status(&self, burn_id: &Hash, status: WithdrawalStatus) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        let key = Self::hash_key(burn_id);
        if let Some(entry) = state.burns.get_mut(&key) {
            entry.status = status;
        }
        self.persist_state(&state)
    }

    // ========================================================================
    // Mint Proposal Storage
    // ========================================================================

    pub fn store_mint_proposal(&self, proposal: &MintProposal) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        state
            .mint_proposals
            .insert(Self::hash_key(&proposal.proposal_id), proposal.clone());
        self.persist_state(&state)
    }

    pub fn get_mint_proposal(&self, proposal_id: &Hash) -> Result<Option<MintProposal>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .mint_proposals
            .get(&Self::hash_key(proposal_id))
            .cloned())
    }

    pub fn get_pending_mint_proposals(&self) -> Result<Vec<MintProposal>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .mint_proposals
            .values()
            .filter(|proposal| matches!(proposal.status, MintProposalStatus::Voting))
            .cloned()
            .collect())
    }

    pub fn update_mint_proposal_status(
        &self,
        proposal_id: &Hash,
        status: MintProposalStatus,
    ) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        let key = Self::hash_key(proposal_id);
        if let Some(entry) = state.mint_proposals.get_mut(&key) {
            entry.status = status;
            entry.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        self.persist_state(&state)
    }

    // ========================================================================
    // Withdrawal Proposal Storage
    // ========================================================================

    pub fn store_withdrawal_proposal(&self, proposal: &WithdrawalProposal) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        state
            .withdrawal_proposals
            .insert(Self::hash_key(&proposal.proposal_id), proposal.clone());
        self.persist_state(&state)
    }

    pub fn get_withdrawal_proposal(
        &self,
        proposal_id: &Hash,
    ) -> Result<Option<WithdrawalProposal>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .withdrawal_proposals
            .get(&Self::hash_key(proposal_id))
            .cloned())
    }

    pub fn get_pending_withdrawal_proposals(&self) -> Result<Vec<WithdrawalProposal>> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .withdrawal_proposals
            .values()
            .filter(|proposal| matches!(proposal.status, WithdrawalProposalStatus::Voting))
            .cloned()
            .collect())
    }

    pub fn update_withdrawal_proposal_status(
        &self,
        proposal_id: &Hash,
        status: WithdrawalProposalStatus,
    ) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        let key = Self::hash_key(proposal_id);
        if let Some(entry) = state.withdrawal_proposals.get_mut(&key) {
            entry.status = status;
            entry.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        self.persist_state(&state)
    }

    pub fn update_withdrawal_status(
        &self,
        proposal_id: &Hash,
        status: WithdrawalStatus,
    ) -> Result<()> {
        let mut state = self.state.write().expect("bridge storage lock poisoned");
        let key = Self::hash_key(proposal_id);
        if let Some(burn) = state.burns.get_mut(&key) {
            burn.status = status;
        }
        self.persist_state(&state)
    }

    pub fn pending_withdrawal_count(&self) -> Result<usize> {
        Ok(self
            .state
            .read()
            .expect("bridge storage lock poisoned")
            .withdrawal_proposals
            .values()
            .filter(|proposal| matches!(proposal.status, WithdrawalProposalStatus::Voting))
            .count())
    }
}
