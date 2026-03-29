//! Ethereum Event Listener
//!
//! Listens for deposit events on the Ethereum bridge contract.

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use crate::config::EthereumConfig;
use crate::error::Result;
use crate::metrics::BridgeMetrics;
use crate::storage::BridgeStorage;
use crate::types::*;

/// Ethereum event listener
pub struct EthereumListener {
    /// Configuration
    config: EthereumConfig,

    /// Storage
    storage: Arc<BridgeStorage>,

    /// Metrics
    metrics: Arc<BridgeMetrics>,

    /// Last processed block
    last_block: RwLock<u64>,

    /// Event sender
    event_tx: broadcast::Sender<EthereumEvent>,
}

impl EthereumListener {
    /// Create a new Ethereum listener
    pub async fn new(
        config: &EthereumConfig,
        storage: Arc<BridgeStorage>,
        metrics: Arc<BridgeMetrics>,
    ) -> Result<Self> {
        // Get last processed block from storage or config
        let start_block = storage
            .get_last_eth_block()?
            .or(config.start_block)
            .unwrap_or(0);

        let (event_tx, _) = broadcast::channel(1000);

        info!("Initializing Ethereum listener from block {}", start_block);

        Ok(Self {
            config: config.clone(),
            storage,
            metrics,
            last_block: RwLock::new(start_block),
            event_tx,
        })
    }

    /// Subscribe to Ethereum events
    pub async fn subscribe(&self) -> Result<broadcast::Receiver<EthereumEvent>> {
        Ok(self.event_tx.subscribe())
    }

    /// Get last processed block
    pub async fn last_processed_block(&self) -> u64 {
        *self.last_block.read().await
    }

    /// Start listening for events (called internally)
    pub async fn start_listening(&self) -> Result<()> {
        info!("Starting Ethereum event listener");

        // Connect to Ethereum
        let provider = self.connect().await?;

        // Main event loop
        loop {
            match self.poll_events(&provider).await {
                Ok(events) => {
                    for event in events {
                        if let Err(e) = self.event_tx.send(event) {
                            warn!("Failed to send event: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Error polling events: {}", e);
                    // Reconnect
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }

            // Sleep between polls
            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.config.poll_interval_secs,
            ))
            .await;
        }
    }

    /// Connect to Ethereum provider
    async fn connect(&self) -> Result<EthProvider> {
        // In production, this would use ethers-rs to connect
        // For now, return a placeholder
        info!("Connecting to Ethereum at {}", self.config.rpc_url);
        Ok(EthProvider::new(&self.config.rpc_url))
    }

    /// Poll for new events
    async fn poll_events(&self, provider: &EthProvider) -> Result<Vec<EthereumEvent>> {
        let current_block = provider.get_block_number().await?;
        let last_block = *self.last_block.read().await;

        if current_block <= last_block {
            return Ok(vec![]);
        }

        // Determine range to scan
        let from_block = last_block + 1;
        let to_block = std::cmp::min(
            current_block,
            from_block + self.config.max_blocks_per_scan - 1,
        );

        debug!("Scanning Ethereum blocks {} to {}", from_block, to_block);

        // Get deposit events from contract
        let deposits = provider
            .get_deposit_events(&self.config.bridge_address, from_block, to_block)
            .await?;

        let mut events = Vec::new();

        for deposit in deposits {
            // Check if we've already processed this deposit
            if self.storage.has_deposit(&deposit.deposit_id)? {
                continue;
            }

            // Calculate confirmations
            let confirmations = current_block.saturating_sub(deposit.block_number);

            if confirmations >= self.config.confirmations {
                // Deposit is finalized
                events.push(EthereumEvent::DepositFinalized {
                    deposit_id: deposit.deposit_id,
                    block_number: deposit.block_number,
                });

                // Store the deposit
                self.storage.store_deposit(&deposit)?;
                self.metrics.increment_eth_deposits();
            }

            // Always emit the deposit event for tracking
            events.push(EthereumEvent::Deposit(deposit));
        }

        // Emit new block event
        let block_hash = provider.get_block_hash(to_block).await?;
        events.push(EthereumEvent::NewBlock {
            number: to_block,
            hash: block_hash,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });

        // Update last processed block
        *self.last_block.write().await = to_block;
        self.storage.set_last_eth_block(to_block)?;

        Ok(events)
    }

    /// Check for chain reorganization
    #[allow(dead_code)]
    async fn check_reorg(&self, provider: &EthProvider) -> Result<Option<u64>> {
        // Get stored block hashes and compare with chain
        // If mismatch, return the reorg depth

        // Simplified implementation - in production would compare stored hashes
        let last_block = *self.last_block.read().await;

        for depth in 0..self.config.confirmations {
            let block_num = last_block.saturating_sub(depth);
            if block_num == 0 {
                break;
            }

            let stored_hash = self.storage.get_eth_block_hash(block_num)?;
            let chain_hash = provider.get_block_hash(block_num).await?;

            if let Some(stored) = stored_hash {
                if stored != chain_hash {
                    warn!("Reorg detected at block {}", block_num);
                    return Ok(Some(block_num));
                }
            }
        }

        Ok(None)
    }
}

// ============================================================================
// Ethereum JSON-RPC Provider (Production)
// ============================================================================

/// Production Ethereum JSON-RPC provider using reqwest HTTP client
pub struct EthProvider {
    /// HTTP client
    client: reqwest::Client,
    /// JSON-RPC endpoint URL
    rpc_url: String,
}

impl EthProvider {
    pub fn new(rpc_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(5)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            rpc_url: rpc_url.to_string(),
        }
    }

    /// Send a JSON-RPC request and return the "result" field
    async fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                crate::error::BridgeError::Ethereum(format!("HTTP request failed: {}", e))
            })?;

        let json: serde_json::Value = response.json().await.map_err(|e| {
            crate::error::BridgeError::Ethereum(format!("Failed to parse response: {}", e))
        })?;

        if let Some(error) = json.get("error") {
            return Err(crate::error::BridgeError::Ethereum(format!(
                "RPC error: {}",
                error
            )));
        }

        json.get("result").cloned().ok_or_else(|| {
            crate::error::BridgeError::Ethereum("Missing 'result' in response".into())
        })
    }

    /// Get the latest block number via eth_blockNumber
    pub async fn get_block_number(&self) -> Result<u64> {
        let result = self
            .rpc_call("eth_blockNumber", serde_json::json!([]))
            .await?;
        let hex_str = result.as_str().ok_or_else(|| {
            crate::error::BridgeError::Ethereum("Invalid block number format".into())
        })?;
        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).map_err(|e| {
            crate::error::BridgeError::Ethereum(format!("Failed to parse block number: {}", e))
        })
    }

    /// Get block hash via eth_getBlockByNumber
    pub async fn get_block_hash(&self, block_number: u64) -> Result<Hash> {
        let block_hex = format!("0x{:x}", block_number);
        let result = self
            .rpc_call(
                "eth_getBlockByNumber",
                serde_json::json!([block_hex, false]),
            )
            .await?;

        let hash_str = result
            .get("hash")
            .and_then(|h| h.as_str())
            .ok_or_else(|| crate::error::BridgeError::Ethereum("Missing block hash".into()))?;

        let hash_bytes = hex::decode(hash_str.trim_start_matches("0x")).map_err(|e| {
            crate::error::BridgeError::Ethereum(format!("Invalid block hash hex: {}", e))
        })?;

        let mut hash = [0u8; 32];
        if hash_bytes.len() == 32 {
            hash.copy_from_slice(&hash_bytes);
        }
        Ok(hash)
    }

    /// Get deposit events via eth_getLogs with DepositInitiated topic filtering
    pub async fn get_deposit_events(
        &self,
        contract_address: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<EthereumDeposit>> {
        // DepositInitiated event topic0 (keccak256 of event signature)
        // keccak256("DepositInitiated(bytes32,address,bytes32,address,uint256,uint256,uint256)")
        let deposit_topic = "0x5e3c1311ea442664e90b8c12c1b7a8fa8a3477f7e4a3f5a0b7b1e25e6c3e7b3a";

        let from_hex = format!("0x{:x}", from_block);
        let to_hex = format!("0x{:x}", to_block);

        let result = self
            .rpc_call(
                "eth_getLogs",
                serde_json::json!([{
                    "address": contract_address,
                    "fromBlock": from_hex,
                    "toBlock": to_hex,
                    "topics": [deposit_topic]
                }]),
            )
            .await?;

        let logs = result
            .as_array()
            .ok_or_else(|| crate::error::BridgeError::Ethereum("Expected array of logs".into()))?;

        let mut deposits = Vec::new();

        for log in logs {
            if let Some(deposit) = self.parse_deposit_log(log) {
                deposits.push(deposit);
            } else {
                warn!("Failed to parse deposit log: {:?}", log);
            }
        }

        Ok(deposits)
    }

    /// Parse a raw Ethereum log into an EthereumDeposit
    fn parse_deposit_log(&self, log: &serde_json::Value) -> Option<EthereumDeposit> {
        let topics = log.get("topics")?.as_array()?;
        if topics.len() < 4 {
            return None;
        }

        // Indexed params: depositId (topic1), depositor (topic2), aethelredRecipient (topic3)
        let deposit_id = self.parse_hash(topics[1].as_str()?)?;
        let recipient = self.parse_hash(topics[3].as_str()?)?;

        // Parse depositor as EthAddress (last 20 bytes of 32-byte topic)
        let depositor_bytes = hex::decode(topics[2].as_str()?.trim_start_matches("0x")).ok()?;
        let mut depositor = [0u8; 20];
        if depositor_bytes.len() >= 20 {
            depositor.copy_from_slice(&depositor_bytes[depositor_bytes.len() - 20..]);
        }

        // Non-indexed params from data: token, amount, nonce, timestamp
        let data = log.get("data")?.as_str()?;
        let data_bytes = hex::decode(data.trim_start_matches("0x")).ok()?;

        // Each ABI-encoded uint256/address is 32 bytes (4 words = 128 bytes)
        if data_bytes.len() < 128 {
            return None;
        }

        // Parse token address (bytes 12..32 of first word)
        let mut token = [0u8; 20];
        token.copy_from_slice(&data_bytes[12..32]);

        // Parse amount (second 32-byte word, last 16 bytes as u128)
        let amount = u128::from_be_bytes(data_bytes[48..64].try_into().ok()?);

        // Parse nonce (third 32-byte word, last 8 bytes as u64)
        let nonce = u64::from_be_bytes(data_bytes[88..96].try_into().ok()?);

        // Parse timestamp (fourth 32-byte word, last 8 bytes as u64)
        let timestamp = u64::from_be_bytes(data_bytes[120..128].try_into().ok()?);

        // Parse block number from the log
        let block_hex = log.get("blockNumber")?.as_str()?;
        let block_number = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16).ok()?;

        // Parse block hash
        let block_hash = log
            .get("blockHash")
            .and_then(|h| h.as_str())
            .and_then(|h| self.parse_hash(h))
            .unwrap_or([0u8; 32]);

        // Parse transaction hash
        let tx_hash = log
            .get("transactionHash")
            .and_then(|h| h.as_str())
            .and_then(|h| self.parse_hash(h))
            .unwrap_or([0u8; 32]);

        // Parse log index
        let log_index = log
            .get("logIndex")
            .and_then(|l| l.as_str())
            .and_then(|l| u32::from_str_radix(l.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);

        Some(EthereumDeposit {
            deposit_id,
            depositor,
            aethelred_recipient: recipient,
            token,
            amount,
            nonce,
            block_number,
            block_hash,
            tx_hash,
            log_index,
            timestamp,
        })
    }

    /// Parse a 0x-prefixed hex string into a 32-byte hash
    fn parse_hash(&self, hex_str: &str) -> Option<Hash> {
        let bytes = hex::decode(hex_str.trim_start_matches("0x")).ok()?;
        if bytes.len() < 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[bytes.len() - 32..]);
        Some(hash)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_listener_creation() {
        let config = EthereumConfig::testnet();
        let storage = Arc::new(BridgeStorage::open_temp().unwrap());
        let metrics = Arc::new(BridgeMetrics::new());

        let listener = EthereumListener::new(&config, storage, metrics)
            .await
            .unwrap();

        assert_eq!(listener.last_processed_block().await, 0);
    }
}
