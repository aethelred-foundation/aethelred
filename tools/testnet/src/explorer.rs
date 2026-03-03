//! Public Explorer
//!
//! Real-time blockchain explorer with advanced search, analytics,
//! and developer-friendly APIs for the Aethelred testnet.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::core::*;

// ============================================================================
// Explorer Configuration
// ============================================================================

/// Configuration for the explorer
#[derive(Debug, Clone)]
pub struct ExplorerConfig {
    /// Maximum blocks to keep in memory
    pub max_cached_blocks: usize,
    /// Maximum transactions to keep in memory
    pub max_cached_transactions: usize,
    /// Enable real-time WebSocket updates
    pub realtime_enabled: bool,
    /// Enable analytics computation
    pub analytics_enabled: bool,
    /// Enable full-text search
    pub search_enabled: bool,
    /// Search index update interval (seconds)
    pub search_index_interval: u64,
}

impl Default for ExplorerConfig {
    fn default() -> Self {
        ExplorerConfig {
            max_cached_blocks: 10000,
            max_cached_transactions: 100000,
            realtime_enabled: true,
            analytics_enabled: true,
            search_enabled: true,
            search_index_interval: 60,
        }
    }
}

// ============================================================================
// Explorer Service
// ============================================================================

/// Main explorer service
pub struct Explorer {
    config: ExplorerConfig,
    /// Cached blocks
    blocks: HashMap<u64, Block>,
    /// Block by hash index
    block_hash_index: HashMap<String, u64>,
    /// Cached transactions
    transactions: HashMap<String, TransactionWithBlock>,
    /// Address activity index
    address_index: HashMap<String, AddressActivity>,
    /// Contract registry
    contracts: HashMap<String, ContractInfo>,
    /// Model seals registry
    seals: HashMap<String, SealInfo>,
    /// Analytics data
    analytics: Analytics,
    /// Search index
    search_index: SearchIndex,
    /// Real-time subscriptions
    subscriptions: Vec<Subscription>,
    /// Latest block number
    latest_block: u64,
}

#[derive(Debug, Clone)]
pub struct TransactionWithBlock {
    pub transaction: Transaction,
    pub receipt: TransactionReceipt,
    pub block_number: u64,
    pub block_hash: String,
    pub block_timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct AddressActivity {
    pub address: String,
    pub transaction_count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub is_contract: bool,
    pub balance: String,
    pub transactions: Vec<String>,
    pub internal_transactions: Vec<String>,
    pub token_transfers: Vec<TokenTransfer>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub address: String,
    pub creator: String,
    pub creation_tx: String,
    pub creation_block: u64,
    pub bytecode: Vec<u8>,
    pub verified: bool,
    pub source_code: Option<SourceCode>,
    pub abi: Option<serde_json::Value>,
    pub name: Option<String>,
    pub is_proxy: bool,
    pub proxy_implementation: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SourceCode {
    pub language: String,
    pub version: String,
    pub files: HashMap<String, String>,
    pub settings: serde_json::Value,
    pub verified_at: u64,
}

#[derive(Debug, Clone)]
pub struct SealInfo {
    pub seal_id: String,
    pub model_id: String,
    pub model_hash: String,
    pub owner: String,
    pub sealed_at: u64,
    pub sealed_by: String,
    pub seal_hash: String,
    pub tee_attestation: Option<String>,
    pub block_number: u64,
    pub transaction_hash: String,
}

#[derive(Debug, Clone)]
pub struct TokenTransfer {
    pub token_address: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub token_type: TokenType,
    pub transaction_hash: String,
    pub log_index: u64,
}

#[derive(Debug, Clone)]
pub enum TokenType {
    ERC20,
    ERC721,
    ERC1155,
    Native,
}

impl Explorer {
    pub fn new() -> Self {
        Explorer {
            config: ExplorerConfig::default(),
            blocks: HashMap::new(),
            block_hash_index: HashMap::new(),
            transactions: HashMap::new(),
            address_index: HashMap::new(),
            contracts: HashMap::new(),
            seals: HashMap::new(),
            analytics: Analytics::default(),
            search_index: SearchIndex::new(),
            subscriptions: Vec::new(),
            latest_block: 0,
        }
    }

    /// Index a new block
    pub fn index_block(&mut self, block: Block) {
        let block_number = block.header.number;
        let block_hash = block.header.hash.clone();
        let block_timestamp = block.header.timestamp;

        // Index transactions
        for (i, tx) in block.transactions.iter().enumerate() {
            let receipt = block.receipts.get(i).cloned().unwrap_or_else(|| {
                TransactionReceipt {
                    transaction_hash: tx.hash.clone(),
                    transaction_index: i as u64,
                    block_hash: block_hash.clone(),
                    block_number,
                    from: tx.from.clone(),
                    to: tx.to.clone(),
                    contract_address: None,
                    cumulative_gas_used: tx.gas_limit,
                    gas_used: tx.gas_limit / 2,
                    effective_gas_price: tx.gas_price,
                    status: TransactionStatus::Success,
                    logs: Vec::new(),
                    logs_bloom: String::new(),
                    tx_type: tx.tx_type.clone(),
                    debug_info: None,
                }
            });

            let tx_with_block = TransactionWithBlock {
                transaction: tx.clone(),
                receipt: receipt.clone(),
                block_number,
                block_hash: block_hash.clone(),
                block_timestamp,
            };

            self.transactions.insert(tx.hash.clone(), tx_with_block);

            // Update address index
            self.update_address_index(&tx.from, &tx.hash, block_timestamp, false);
            if let Some(ref to) = tx.to {
                self.update_address_index(to, &tx.hash, block_timestamp, false);
            }

            // Check for contract creation
            if tx.to.is_none() && receipt.contract_address.is_some() {
                if let Some(ref addr) = receipt.contract_address {
                    self.contracts.insert(addr.clone(), ContractInfo {
                        address: addr.clone(),
                        creator: tx.from.clone(),
                        creation_tx: tx.hash.clone(),
                        creation_block: block_number,
                        bytecode: tx.input.clone(),
                        verified: false,
                        source_code: None,
                        abi: None,
                        name: None,
                        is_proxy: false,
                        proxy_implementation: None,
                    });
                    self.update_address_index(addr, &tx.hash, block_timestamp, true);
                }
            }

            // Process logs for token transfers
            self.process_logs(&receipt.logs, &tx.hash);
        }

        // Store block
        self.blocks.insert(block_number, block.clone());
        self.block_hash_index.insert(block_hash, block_number);
        self.latest_block = block_number;

        // Update analytics
        self.update_analytics(&block);

        // Update search index
        if self.config.search_enabled {
            self.update_search_index(&block);
        }

        // Cleanup old data if necessary
        self.cleanup_old_data();

        // Notify subscribers
        self.notify_subscribers(ExplorerEvent::NewBlock(block_number));
    }

    /// Get block by number
    pub fn get_block(&self, number: u64) -> Option<&Block> {
        self.blocks.get(&number)
    }

    /// Get block by hash
    pub fn get_block_by_hash(&self, hash: &str) -> Option<&Block> {
        self.block_hash_index.get(hash)
            .and_then(|n| self.blocks.get(n))
    }

    /// Get latest blocks
    pub fn get_latest_blocks(&self, count: usize) -> Vec<BlockSummary> {
        let mut blocks: Vec<_> = self.blocks.values()
            .map(|b| BlockSummary {
                number: b.header.number,
                hash: b.header.hash.clone(),
                timestamp: b.header.timestamp,
                validator: b.header.validator.clone(),
                transaction_count: b.transactions.len(),
                gas_used: b.header.gas_used,
                gas_limit: b.header.gas_limit,
            })
            .collect();

        blocks.sort_by(|a, b| b.number.cmp(&a.number));
        blocks.truncate(count);
        blocks
    }

    /// Get transaction by hash
    pub fn get_transaction(&self, hash: &str) -> Option<&TransactionWithBlock> {
        self.transactions.get(hash)
    }

    /// Get latest transactions
    pub fn get_latest_transactions(&self, count: usize) -> Vec<TransactionSummary> {
        let mut txs: Vec<_> = self.transactions.values()
            .map(|t| TransactionSummary {
                hash: t.transaction.hash.clone(),
                from: t.transaction.from.clone(),
                to: t.transaction.to.clone(),
                value: t.transaction.value.clone(),
                gas_used: t.receipt.gas_used,
                status: matches!(t.receipt.status, TransactionStatus::Success),
                block_number: t.block_number,
                timestamp: t.block_timestamp,
                tx_type: format!("{:?}", t.transaction.tx_type),
            })
            .collect();

        txs.sort_by(|a, b| b.block_number.cmp(&a.block_number));
        txs.truncate(count);
        txs
    }

    /// Get address information
    pub fn get_address(&self, address: &str) -> Option<AddressInfo> {
        let activity = self.address_index.get(address)?;
        let contract = self.contracts.get(address);

        Some(AddressInfo {
            address: address.to_string(),
            balance: activity.balance.clone(),
            transaction_count: activity.transaction_count,
            first_seen: activity.first_seen,
            last_seen: activity.last_seen,
            is_contract: activity.is_contract,
            contract_info: contract.cloned(),
            labels: activity.labels.clone(),
        })
    }

    /// Get address transactions
    pub fn get_address_transactions(
        &self,
        address: &str,
        page: usize,
        page_size: usize,
    ) -> Vec<TransactionSummary> {
        let activity = match self.address_index.get(address) {
            Some(a) => a,
            None => return Vec::new(),
        };

        let start = page * page_size;
        let end = start + page_size;

        activity.transactions.iter()
            .skip(start)
            .take(page_size)
            .filter_map(|hash| self.transactions.get(hash))
            .map(|t| TransactionSummary {
                hash: t.transaction.hash.clone(),
                from: t.transaction.from.clone(),
                to: t.transaction.to.clone(),
                value: t.transaction.value.clone(),
                gas_used: t.receipt.gas_used,
                status: matches!(t.receipt.status, TransactionStatus::Success),
                block_number: t.block_number,
                timestamp: t.block_timestamp,
                tx_type: format!("{:?}", t.transaction.tx_type),
            })
            .collect()
    }

    /// Get contract information
    pub fn get_contract(&self, address: &str) -> Option<&ContractInfo> {
        self.contracts.get(address)
    }

    /// Verify contract source code
    pub fn verify_contract(
        &mut self,
        address: &str,
        source: SourceCode,
        abi: serde_json::Value,
    ) -> Result<(), ExplorerError> {
        let contract = self.contracts.get_mut(address)
            .ok_or(ExplorerError::ContractNotFound)?;

        // In production, verify bytecode matches compiled source
        contract.verified = true;
        contract.source_code = Some(source);
        contract.abi = Some(abi);

        Ok(())
    }

    /// Search the blockchain
    pub fn search(&self, query: &str) -> SearchResults {
        self.search_index.search(query)
    }

    /// Get network analytics
    pub fn get_analytics(&self) -> &Analytics {
        &self.analytics
    }

    /// Get gas price statistics
    pub fn get_gas_stats(&self) -> GasStats {
        let recent_blocks: Vec<_> = self.blocks.values()
            .filter(|b| b.header.number > self.latest_block.saturating_sub(100))
            .collect();

        let gas_prices: Vec<u64> = recent_blocks.iter()
            .flat_map(|b| b.transactions.iter().map(|t| t.gas_price))
            .collect();

        if gas_prices.is_empty() {
            return GasStats::default();
        }

        let mut sorted = gas_prices.clone();
        sorted.sort();

        GasStats {
            current_block: self.latest_block,
            base_fee: recent_blocks.last().map(|b| b.header.base_fee_per_gas).unwrap_or(1_000_000_000),
            average: gas_prices.iter().sum::<u64>() / gas_prices.len() as u64,
            median: sorted[sorted.len() / 2],
            low: sorted[sorted.len() / 10],
            high: sorted[sorted.len() * 9 / 10],
            suggested_priority_fee: 1_000_000_000,
        }
    }

    /// Get model seal information
    pub fn get_seal(&self, seal_id: &str) -> Option<&SealInfo> {
        self.seals.get(seal_id)
    }

    /// List recent model seals
    pub fn list_seals(&self, count: usize) -> Vec<&SealInfo> {
        let mut seals: Vec<_> = self.seals.values().collect();
        seals.sort_by(|a, b| b.sealed_at.cmp(&a.sealed_at));
        seals.truncate(count);
        seals
    }

    /// Subscribe to real-time updates
    pub fn subscribe(&mut self, subscription: Subscription) -> String {
        let id = format!("sub-{}", uuid::Uuid::new_v4());
        self.subscriptions.push(Subscription {
            id: id.clone(),
            ..subscription
        });
        id
    }

    /// Unsubscribe from updates
    pub fn unsubscribe(&mut self, subscription_id: &str) -> bool {
        let initial_len = self.subscriptions.len();
        self.subscriptions.retain(|s| s.id != subscription_id);
        self.subscriptions.len() < initial_len
    }

    // Private helper methods

    fn update_address_index(&mut self, address: &str, tx_hash: &str, timestamp: u64, is_contract: bool) {
        let activity = self.address_index.entry(address.to_string())
            .or_insert_with(|| AddressActivity {
                address: address.to_string(),
                transaction_count: 0,
                first_seen: timestamp,
                last_seen: timestamp,
                is_contract,
                balance: "0".to_string(),
                transactions: Vec::new(),
                internal_transactions: Vec::new(),
                token_transfers: Vec::new(),
                labels: Vec::new(),
            });

        activity.transaction_count += 1;
        activity.last_seen = timestamp;
        activity.transactions.push(tx_hash.to_string());

        // Keep only last 1000 transactions per address
        if activity.transactions.len() > 1000 {
            activity.transactions.remove(0);
        }
    }

    fn process_logs(&mut self, logs: &[Log], tx_hash: &str) {
        for log in logs {
            // Check for ERC20 Transfer event
            if log.topics.len() >= 3 && log.topics[0] == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" {
                let from = &log.topics[1];
                let to = &log.topics[2];
                let value = if log.data.len() >= 32 {
                    hex::encode(&log.data[0..32])
                } else {
                    "0".to_string()
                };

                let transfer = TokenTransfer {
                    token_address: log.address.clone(),
                    from: from.clone(),
                    to: to.clone(),
                    value,
                    token_type: TokenType::ERC20,
                    transaction_hash: tx_hash.to_string(),
                    log_index: log.log_index,
                };

                if let Some(activity) = self.address_index.get_mut(from) {
                    activity.token_transfers.push(transfer.clone());
                }
                if let Some(activity) = self.address_index.get_mut(to) {
                    activity.token_transfers.push(transfer);
                }
            }
        }
    }

    fn update_analytics(&mut self, block: &Block) {
        self.analytics.total_blocks += 1;
        self.analytics.total_transactions += block.transactions.len() as u64;
        self.analytics.total_gas_used += block.header.gas_used;

        // Update 24h metrics
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let day_ago = now - 86400;

        self.analytics.transactions_24h = self.transactions.values()
            .filter(|t| t.block_timestamp >= day_ago)
            .count() as u64;
    }

    fn update_search_index(&mut self, block: &Block) {
        // Index block
        self.search_index.index_block(block);

        // Index transactions
        for tx in &block.transactions {
            self.search_index.index_transaction(tx);
        }
    }

    fn cleanup_old_data(&mut self) {
        // Remove old blocks if over limit
        while self.blocks.len() > self.config.max_cached_blocks {
            if let Some(&oldest) = self.blocks.keys().min() {
                if let Some(block) = self.blocks.remove(&oldest) {
                    self.block_hash_index.remove(&block.header.hash);
                }
            }
        }

        // Remove old transactions if over limit
        while self.transactions.len() > self.config.max_cached_transactions {
            if let Some(oldest_hash) = self.transactions.keys()
                .min_by_key(|k| self.transactions.get(*k).map(|t| t.block_number).unwrap_or(0))
                .cloned()
            {
                self.transactions.remove(&oldest_hash);
            }
        }
    }

    fn notify_subscribers(&self, event: ExplorerEvent) {
        // In production, this would push to WebSocket connections
        for subscription in &self.subscriptions {
            match (&subscription.event_type, &event) {
                (SubscriptionType::NewBlocks, ExplorerEvent::NewBlock(_)) => {
                    // Notify subscriber
                }
                (SubscriptionType::NewTransactions, ExplorerEvent::NewTransaction(_)) => {
                    // Notify subscriber
                }
                (SubscriptionType::Address(addr), ExplorerEvent::AddressActivity(a)) if addr == a => {
                    // Notify subscriber
                }
                _ => {}
            }
        }
    }
}

impl Default for Explorer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Explorer Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct BlockSummary {
    pub number: u64,
    pub hash: String,
    pub timestamp: u64,
    pub validator: String,
    pub transaction_count: usize,
    pub gas_used: u64,
    pub gas_limit: u64,
}

#[derive(Debug, Clone)]
pub struct TransactionSummary {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub gas_used: u64,
    pub status: bool,
    pub block_number: u64,
    pub timestamp: u64,
    pub tx_type: String,
}

#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub address: String,
    pub balance: String,
    pub transaction_count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub is_contract: bool,
    pub contract_info: Option<ContractInfo>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GasStats {
    pub current_block: u64,
    pub base_fee: u64,
    pub average: u64,
    pub median: u64,
    pub low: u64,
    pub high: u64,
    pub suggested_priority_fee: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Analytics {
    pub total_blocks: u64,
    pub total_transactions: u64,
    pub total_gas_used: u64,
    pub transactions_24h: u64,
    pub active_addresses_24h: u64,
    pub average_block_time: f64,
    pub tps_current: f64,
    pub tps_peak: f64,
    pub total_seals: u64,
    pub total_jobs: u64,
}

#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub event_type: SubscriptionType,
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SubscriptionType {
    NewBlocks,
    NewTransactions,
    Address(String),
    Contract(String),
    Logs(LogFilter),
}

#[derive(Debug, Clone)]
pub struct LogFilter {
    pub addresses: Vec<String>,
    pub topics: Vec<Option<String>>,
}

#[derive(Debug, Clone)]
pub enum ExplorerEvent {
    NewBlock(u64),
    NewTransaction(String),
    AddressActivity(String),
    ContractEvent(String, String),
}

// ============================================================================
// Search Index
// ============================================================================

pub struct SearchIndex {
    blocks: HashMap<u64, String>,
    transactions: HashMap<String, String>,
    addresses: HashMap<String, String>,
}

impl SearchIndex {
    pub fn new() -> Self {
        SearchIndex {
            blocks: HashMap::new(),
            transactions: HashMap::new(),
            addresses: HashMap::new(),
        }
    }

    pub fn index_block(&mut self, block: &Block) {
        let text = format!(
            "{} {} {} {}",
            block.header.number,
            block.header.hash,
            block.header.validator,
            block.header.timestamp
        );
        self.blocks.insert(block.header.number, text);
    }

    pub fn index_transaction(&mut self, tx: &Transaction) {
        let text = format!(
            "{} {} {} {}",
            tx.hash,
            tx.from,
            tx.to.as_deref().unwrap_or(""),
            tx.value
        );
        self.transactions.insert(tx.hash.clone(), text);
    }

    pub fn search(&self, query: &str) -> SearchResults {
        let query_lower = query.to_lowercase();
        let mut results = SearchResults::default();

        // Check if query is a transaction hash
        if query.starts_with("0x") && query.len() == 66 {
            if self.transactions.contains_key(query) {
                results.transactions.push(query.to_string());
            }
        }

        // Check if query is an address
        if query.starts_with("0x") && query.len() == 42 {
            if self.addresses.contains_key(query) {
                results.addresses.push(query.to_string());
            }
        }

        // Check if query is a block number
        if let Ok(block_num) = query.parse::<u64>() {
            if self.blocks.contains_key(&block_num) {
                results.blocks.push(block_num);
            }
        }

        results
    }
}

impl Default for SearchIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct SearchResults {
    pub blocks: Vec<u64>,
    pub transactions: Vec<String>,
    pub addresses: Vec<String>,
    pub contracts: Vec<String>,
    pub seals: Vec<String>,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone)]
pub enum ExplorerError {
    BlockNotFound,
    TransactionNotFound,
    AddressNotFound,
    ContractNotFound,
    InvalidQuery,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_block() {
        let mut explorer = Explorer::new();
        let block = Block::genesis();

        explorer.index_block(block);

        assert_eq!(explorer.latest_block, 0);
        assert!(explorer.get_block(0).is_some());
    }

    #[test]
    fn test_get_latest_blocks() {
        let mut explorer = Explorer::new();

        for i in 0..5 {
            let mut block = Block::genesis();
            block.header.number = i;
            block.header.hash = format!("0x{:064x}", i);
            explorer.index_block(block);
        }

        let latest = explorer.get_latest_blocks(3);
        assert_eq!(latest.len(), 3);
        assert_eq!(latest[0].number, 4);
    }

    #[test]
    fn test_search() {
        let mut explorer = Explorer::new();
        let block = Block::genesis();
        explorer.index_block(block);

        let results = explorer.search("0");
        assert!(!results.blocks.is_empty());
    }
}
