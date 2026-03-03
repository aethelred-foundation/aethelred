//! Testnet Core Infrastructure
//!
//! Core blockchain functionality for the Aethelred testnet including
//! block production, transaction processing, and state management.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Block Types
// ============================================================================

/// A block in the testnet chain
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub receipts: Vec<TransactionReceipt>,
    pub uncles: Vec<BlockHeader>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
    pub validator: String,
    pub state_root: String,
    pub transactions_root: String,
    pub receipts_root: String,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub base_fee_per_gas: u64,
    pub extra_data: Vec<u8>,
    pub logs_bloom: String,
    pub difficulty: u64,
    pub nonce: u64,
    pub size: u64,
}

impl Block {
    pub fn genesis() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Block {
            header: BlockHeader {
                number: 0,
                hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                timestamp,
                validator: "0x0000000000000000000000000000000000000000".to_string(),
                state_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".to_string(),
                transactions_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".to_string(),
                receipts_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".to_string(),
                gas_used: 0,
                gas_limit: 30_000_000,
                base_fee_per_gas: 1_000_000_000, // 1 Gwei
                extra_data: b"Aethelred Testnet Genesis".to_vec(),
                logs_bloom: "0x".to_string() + &"0".repeat(512),
                difficulty: 1,
                nonce: 0,
                size: 540,
            },
            transactions: Vec::new(),
            receipts: Vec::new(),
            uncles: Vec::new(),
        }
    }
}

// ============================================================================
// Transaction Types
// ============================================================================

/// Transaction in the testnet
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub hash: String,
    pub nonce: u64,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub max_fee_per_gas: Option<u64>,
    pub max_priority_fee_per_gas: Option<u64>,
    pub input: Vec<u8>,
    pub v: u64,
    pub r: String,
    pub s: String,
    pub tx_type: TransactionType,
    pub access_list: Option<Vec<AccessListEntry>>,
    pub chain_id: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TransactionType {
    Legacy,
    EIP2930,
    EIP1559,
    AethelredSeal,  // Custom type for AI model sealing
    AethelredJob,   // Custom type for AI job submission
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessListEntry {
    pub address: String,
    pub storage_keys: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionReceipt {
    pub transaction_hash: String,
    pub transaction_index: u64,
    pub block_hash: String,
    pub block_number: u64,
    pub from: String,
    pub to: Option<String>,
    pub contract_address: Option<String>,
    pub cumulative_gas_used: u64,
    pub gas_used: u64,
    pub effective_gas_price: u64,
    pub status: TransactionStatus,
    pub logs: Vec<Log>,
    pub logs_bloom: String,
    pub tx_type: TransactionType,
    /// Debug information (only in debug mode)
    pub debug_info: Option<DebugInfo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TransactionStatus {
    Success,
    Failed,
    Pending,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub transaction_hash: String,
    pub transaction_index: u64,
    pub block_hash: String,
    pub log_index: u64,
    pub removed: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DebugInfo {
    pub execution_trace: Vec<ExecutionStep>,
    pub state_diff: StateDiff,
    pub gas_breakdown: GasBreakdown,
    pub memory_access: Vec<MemoryAccess>,
    pub storage_access: Vec<StorageAccess>,
    pub call_stack: Vec<CallFrame>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutionStep {
    pub pc: u64,
    pub op: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub depth: u32,
    pub stack: Vec<String>,
    pub memory: Option<String>,
    pub storage: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateDiff {
    pub accounts: HashMap<String, AccountDiff>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountDiff {
    pub balance: Option<(String, String)>,  // (before, after)
    pub nonce: Option<(u64, u64)>,
    pub code: Option<(Vec<u8>, Vec<u8>)>,
    pub storage: HashMap<String, (String, String)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GasBreakdown {
    pub intrinsic_gas: u64,
    pub execution_gas: u64,
    pub refund: u64,
    pub storage_gas: u64,
    pub memory_gas: u64,
    pub external_calls_gas: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryAccess {
    pub offset: u64,
    pub size: u64,
    pub access_type: AccessType,
    pub step: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageAccess {
    pub address: String,
    pub slot: String,
    pub value: String,
    pub access_type: AccessType,
    pub step: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AccessType {
    Read,
    Write,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallFrame {
    pub call_type: CallType,
    pub from: String,
    pub to: String,
    pub value: String,
    pub gas: u64,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub error: Option<String>,
    pub depth: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CallType {
    Call,
    DelegateCall,
    StaticCall,
    Create,
    Create2,
}

// ============================================================================
// Account Types
// ============================================================================

/// Account state
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: String,
    pub nonce: u64,
    pub code: Option<Vec<u8>>,
    pub code_hash: String,
    pub storage_root: String,
    pub is_contract: bool,
}

/// Account with additional testnet metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestnetAccount {
    pub account: Account,
    pub faucet_claims: u64,
    pub last_faucet_claim: Option<u64>,
    pub created_at: u64,
    pub labels: Vec<String>,
    pub notes: Option<String>,
}

// ============================================================================
// State Management
// ============================================================================

/// Testnet state at a specific block
pub struct ChainState {
    pub block_number: u64,
    accounts: HashMap<String, Account>,
    storage: HashMap<String, HashMap<String, String>>,
    code: HashMap<String, Vec<u8>>,
}

impl ChainState {
    pub fn new() -> Self {
        ChainState {
            block_number: 0,
            accounts: HashMap::new(),
            storage: HashMap::new(),
            code: HashMap::new(),
        }
    }

    pub fn get_account(&self, address: &str) -> Option<&Account> {
        self.accounts.get(address)
    }

    pub fn get_balance(&self, address: &str) -> String {
        self.accounts
            .get(address)
            .map(|a| a.balance.clone())
            .unwrap_or_else(|| "0".to_string())
    }

    pub fn get_nonce(&self, address: &str) -> u64 {
        self.accounts
            .get(address)
            .map(|a| a.nonce)
            .unwrap_or(0)
    }

    pub fn get_code(&self, address: &str) -> Option<&Vec<u8>> {
        self.code.get(address)
    }

    pub fn get_storage(&self, address: &str, slot: &str) -> Option<&String> {
        self.storage.get(address).and_then(|s| s.get(slot))
    }

    pub fn set_balance(&mut self, address: &str, balance: &str) {
        if let Some(account) = self.accounts.get_mut(address) {
            account.balance = balance.to_string();
        } else {
            self.accounts.insert(address.to_string(), Account {
                address: address.to_string(),
                balance: balance.to_string(),
                nonce: 0,
                code: None,
                code_hash: "0x".to_string(),
                storage_root: "0x".to_string(),
                is_contract: false,
            });
        }
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Block Producer
// ============================================================================

/// Produces blocks for the testnet
pub struct BlockProducer {
    config: BlockProducerConfig,
    pending_transactions: Vec<Transaction>,
    current_block_number: u64,
}

#[derive(Debug, Clone)]
pub struct BlockProducerConfig {
    pub block_time_ms: u64,
    pub max_transactions_per_block: usize,
    pub gas_limit: u64,
    pub base_fee_per_gas: u64,
    pub coinbase: String,
}

impl Default for BlockProducerConfig {
    fn default() -> Self {
        BlockProducerConfig {
            block_time_ms: 2000,
            max_transactions_per_block: 1000,
            gas_limit: 30_000_000,
            base_fee_per_gas: 1_000_000_000,
            coinbase: "0x0000000000000000000000000000000000000000".to_string(),
        }
    }
}

impl BlockProducer {
    pub fn new(config: BlockProducerConfig) -> Self {
        BlockProducer {
            config,
            pending_transactions: Vec::new(),
            current_block_number: 0,
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> Result<String, String> {
        // Validate transaction
        if tx.gas_limit > self.config.gas_limit {
            return Err("Gas limit exceeds block gas limit".to_string());
        }

        let hash = tx.hash.clone();
        self.pending_transactions.push(tx);
        Ok(hash)
    }

    pub fn produce_block(&mut self, parent: &Block) -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.current_block_number = parent.header.number + 1;

        // Select transactions that fit in the block
        let mut selected_transactions = Vec::new();
        let mut total_gas = 0u64;

        for tx in self.pending_transactions.drain(..) {
            if total_gas + tx.gas_limit <= self.config.gas_limit {
                total_gas += tx.gas_limit;
                selected_transactions.push(tx);

                if selected_transactions.len() >= self.config.max_transactions_per_block {
                    break;
                }
            }
        }

        // Create receipts (simplified)
        let receipts: Vec<TransactionReceipt> = selected_transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| TransactionReceipt {
                transaction_hash: tx.hash.clone(),
                transaction_index: i as u64,
                block_hash: "pending".to_string(),
                block_number: self.current_block_number,
                from: tx.from.clone(),
                to: tx.to.clone(),
                contract_address: None,
                cumulative_gas_used: tx.gas_limit,
                gas_used: tx.gas_limit,
                effective_gas_price: tx.gas_price,
                status: TransactionStatus::Success,
                logs: Vec::new(),
                logs_bloom: "0x".to_string() + &"0".repeat(512),
                tx_type: tx.tx_type.clone(),
                debug_info: None,
            })
            .collect();

        let block_hash = self.calculate_block_hash();

        Block {
            header: BlockHeader {
                number: self.current_block_number,
                hash: block_hash.clone(),
                parent_hash: parent.header.hash.clone(),
                timestamp,
                validator: self.config.coinbase.clone(),
                state_root: "0x".to_string(),
                transactions_root: "0x".to_string(),
                receipts_root: "0x".to_string(),
                gas_used: total_gas,
                gas_limit: self.config.gas_limit,
                base_fee_per_gas: self.config.base_fee_per_gas,
                extra_data: Vec::new(),
                logs_bloom: "0x".to_string() + &"0".repeat(512),
                difficulty: 1,
                nonce: 0,
                size: 1000 + selected_transactions.len() as u64 * 200,
            },
            transactions: selected_transactions,
            receipts,
            uncles: Vec::new(),
        }
    }

    fn calculate_block_hash(&self) -> String {
        // Simplified hash calculation
        format!("0x{:064x}", self.current_block_number * 12345678)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_transactions.len()
    }
}

// ============================================================================
// Transaction Pool (Mempool)
// ============================================================================

/// Transaction pool for pending transactions
pub struct TransactionPool {
    pending: HashMap<String, Transaction>,
    queued: HashMap<String, Vec<Transaction>>,
    max_pending: usize,
    max_queued_per_account: usize,
}

impl TransactionPool {
    pub fn new() -> Self {
        TransactionPool {
            pending: HashMap::new(),
            queued: HashMap::new(),
            max_pending: 10000,
            max_queued_per_account: 100,
        }
    }

    pub fn add(&mut self, tx: Transaction) -> Result<(), String> {
        if self.pending.len() >= self.max_pending {
            return Err("Transaction pool is full".to_string());
        }

        let hash = tx.hash.clone();
        self.pending.insert(hash, tx);
        Ok(())
    }

    pub fn get(&self, hash: &str) -> Option<&Transaction> {
        self.pending.get(hash)
    }

    pub fn remove(&mut self, hash: &str) -> Option<Transaction> {
        self.pending.remove(hash)
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn queued_count(&self) -> usize {
        self.queued.values().map(|v| v.len()).sum()
    }

    pub fn get_pending_transactions(&self, limit: usize) -> Vec<&Transaction> {
        self.pending.values().take(limit).collect()
    }
}

impl Default for TransactionPool {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Time Travel (Historical State Access)
// ============================================================================

/// Provides access to historical state
pub struct TimeTraveler {
    snapshots: HashMap<u64, ChainState>,
    max_snapshots: usize,
}

impl TimeTraveler {
    pub fn new(max_snapshots: usize) -> Self {
        TimeTraveler {
            snapshots: HashMap::new(),
            max_snapshots,
        }
    }

    pub fn save_snapshot(&mut self, block_number: u64, state: ChainState) {
        if self.snapshots.len() >= self.max_snapshots {
            // Remove oldest snapshot
            if let Some(&oldest) = self.snapshots.keys().min() {
                self.snapshots.remove(&oldest);
            }
        }
        self.snapshots.insert(block_number, state);
    }

    pub fn get_state_at(&self, block_number: u64) -> Option<&ChainState> {
        self.snapshots.get(&block_number)
    }

    pub fn available_blocks(&self) -> Vec<u64> {
        let mut blocks: Vec<_> = self.snapshots.keys().cloned().collect();
        blocks.sort();
        blocks
    }
}

impl Default for TimeTraveler {
    fn default() -> Self {
        Self::new(1000)
    }
}

// ============================================================================
// Transaction Simulator
// ============================================================================

/// Simulates transaction execution without committing to state
pub struct TransactionSimulator {
    state: ChainState,
    debug_mode: bool,
}

impl TransactionSimulator {
    pub fn new(state: ChainState) -> Self {
        TransactionSimulator {
            state,
            debug_mode: true,
        }
    }

    /// Simulate a transaction
    pub fn simulate(&self, tx: &Transaction) -> SimulationResult {
        let start = Instant::now();

        // Validate basic fields
        let from_balance = self.state.get_balance(&tx.from);
        let from_nonce = self.state.get_nonce(&tx.from);

        // Check nonce
        if tx.nonce < from_nonce {
            return SimulationResult {
                success: false,
                gas_used: 21000,
                return_value: Vec::new(),
                logs: Vec::new(),
                error: Some("Nonce too low".to_string()),
                state_changes: Vec::new(),
                execution_time_us: start.elapsed().as_micros() as u64,
                trace: None,
            };
        }

        // Simulate execution (simplified)
        let gas_used = if tx.to.is_some() {
            21000 + tx.input.len() as u64 * 16 // Base + calldata
        } else {
            32000 + tx.input.len() as u64 * 200 // Contract creation
        };

        SimulationResult {
            success: true,
            gas_used,
            return_value: Vec::new(),
            logs: Vec::new(),
            error: None,
            state_changes: vec![
                StateChange {
                    address: tx.from.clone(),
                    change_type: StateChangeType::BalanceDecrease,
                    value: format!("{}", gas_used * tx.gas_price),
                },
            ],
            execution_time_us: start.elapsed().as_micros() as u64,
            trace: if self.debug_mode {
                Some(vec![
                    ExecutionStep {
                        pc: 0,
                        op: "PUSH1".to_string(),
                        gas: tx.gas_limit,
                        gas_cost: 3,
                        depth: 1,
                        stack: Vec::new(),
                        memory: None,
                        storage: None,
                    },
                ])
            } else {
                None
            },
        }
    }

    /// Simulate multiple transactions in sequence
    pub fn simulate_batch(&self, txs: &[Transaction]) -> Vec<SimulationResult> {
        txs.iter().map(|tx| self.simulate(tx)).collect()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SimulationResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_value: Vec<u8>,
    pub logs: Vec<Log>,
    pub error: Option<String>,
    pub state_changes: Vec<StateChange>,
    pub execution_time_us: u64,
    pub trace: Option<Vec<ExecutionStep>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StateChange {
    pub address: String,
    pub change_type: StateChangeType,
    pub value: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum StateChangeType {
    BalanceIncrease,
    BalanceDecrease,
    NonceChange,
    StorageWrite,
    CodeDeploy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis();
        assert_eq!(genesis.header.number, 0);
        assert!(genesis.transactions.is_empty());
    }

    #[test]
    fn test_block_producer() {
        let config = BlockProducerConfig::default();
        let mut producer = BlockProducer::new(config);

        let genesis = Block::genesis();
        let block = producer.produce_block(&genesis);

        assert_eq!(block.header.number, 1);
        assert_eq!(block.header.parent_hash, genesis.header.hash);
    }

    #[test]
    fn test_transaction_pool() {
        let mut pool = TransactionPool::new();

        let tx = Transaction {
            hash: "0x123".to_string(),
            nonce: 0,
            from: "0xabc".to_string(),
            to: Some("0xdef".to_string()),
            value: "1000".to_string(),
            gas_limit: 21000,
            gas_price: 1000000000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            input: Vec::new(),
            v: 27,
            r: "0x".to_string(),
            s: "0x".to_string(),
            tx_type: TransactionType::Legacy,
            access_list: None,
            chain_id: 7331,
        };

        pool.add(tx).unwrap();
        assert_eq!(pool.pending_count(), 1);
    }
}
