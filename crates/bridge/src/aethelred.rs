//! Aethelred Event Listener
//!
//! Listens for burn events on the Aethelred bridge module.

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn, error};

use crate::config::AethelredConfig;
use crate::error::{BridgeError, Result};
use crate::storage::BridgeStorage;
use crate::metrics::BridgeMetrics;
use crate::types::*;

/// Aethelred event listener
pub struct AethelredListener {
    /// Configuration
    config: AethelredConfig,

    /// Storage
    storage: Arc<BridgeStorage>,

    /// Metrics
    metrics: Arc<BridgeMetrics>,

    /// Last processed block
    last_block: RwLock<u64>,

    /// Event sender
    event_tx: broadcast::Sender<AethelredEvent>,
}

impl AethelredListener {
    /// Create a new Aethelred listener
    pub async fn new(
        config: &AethelredConfig,
        storage: Arc<BridgeStorage>,
        metrics: Arc<BridgeMetrics>,
    ) -> Result<Self> {
        // Get last processed block from storage or config
        let start_block = storage
            .get_last_aethelred_block()?
            .or(config.start_block)
            .unwrap_or(0);

        let (event_tx, _) = broadcast::channel(1000);

        info!(
            "Initializing Aethelred listener from block {}",
            start_block
        );

        Ok(Self {
            config: config.clone(),
            storage,
            metrics,
            last_block: RwLock::new(start_block),
            event_tx,
        })
    }

    /// Subscribe to Aethelred events
    pub async fn subscribe(&self) -> Result<broadcast::Receiver<AethelredEvent>> {
        Ok(self.event_tx.subscribe())
    }

    /// Get last processed block
    pub async fn last_processed_block(&self) -> u64 {
        *self.last_block.read().await
    }

    /// Start listening for events
    pub async fn start_listening(&self) -> Result<()> {
        info!("Starting Aethelred event listener");

        // Connect to Aethelred
        let client = self.connect().await?;

        // Main event loop
        loop {
            match self.poll_events(&client).await {
                Ok(events) => {
                    for event in events {
                        if let Err(e) = self.event_tx.send(event) {
                            warn!("Failed to send event: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Error polling events: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.config.poll_interval_secs,
            ))
            .await;
        }
    }

    /// Connect to Aethelred RPC
    async fn connect(&self) -> Result<AethelredClient> {
        info!("Connecting to Aethelred at {}", self.config.rpc_url);
        Ok(AethelredClient::new(&self.config.rpc_url))
    }

    /// Poll for new events
    async fn poll_events(&self, client: &AethelredClient) -> Result<Vec<AethelredEvent>> {
        let current_block = client.get_block_height().await?;
        let last_block = *self.last_block.read().await;

        if current_block <= last_block {
            return Ok(vec![]);
        }

        // Scan blocks
        let from_block = last_block + 1;
        let to_block = current_block;

        debug!("Scanning Aethelred blocks {} to {}", from_block, to_block);

        // Get burn events from bridge module
        let burns = client
            .get_burn_events(&self.config.bridge_module_address, from_block, to_block)
            .await?;

        let mut events = Vec::new();

        for burn in burns {
            // Check if already processed
            if self.storage.has_burn(&burn.burn_id)? {
                continue;
            }

            // Calculate confirmations
            let confirmations = current_block.saturating_sub(burn.block_height);

            if confirmations >= self.config.confirmations {
                events.push(AethelredEvent::BurnFinalized {
                    burn_id: burn.burn_id,
                    block_height: burn.block_height,
                });

                self.storage.store_burn(&burn)?;
                self.metrics.increment_aethelred_burns();
            }

            events.push(AethelredEvent::Burn(burn));
        }

        // Get mint completion events
        let mints = client
            .get_mint_events(&self.config.bridge_module_address, from_block, to_block)
            .await?;

        for mint in mints {
            events.push(AethelredEvent::MintCompleted {
                proposal_id: mint.proposal_id,
                recipient: mint.recipient,
                amount: mint.amount,
                tx_hash: mint.tx_hash,
            });

            self.metrics.increment_aethelred_mints();
        }

        // Emit new block event
        let block_hash = client.get_block_hash(to_block).await?;
        events.push(AethelredEvent::NewBlock {
            height: to_block,
            hash: block_hash,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });

        // Update last processed block
        *self.last_block.write().await = to_block;
        self.storage.set_last_aethelred_block(to_block)?;

        Ok(events)
    }
}

// ============================================================================
// Aethelred Cosmos REST Client (Production)
// ============================================================================

/// Production Aethelred client using Cosmos REST API via reqwest
pub struct AethelredClient {
    /// HTTP client
    client: reqwest::Client,
    /// Cosmos REST API endpoint URL
    rpc_url: String,
}

impl AethelredClient {
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

    /// Get the latest block height via /cosmos/base/tendermint/v1beta1/blocks/latest
    pub async fn get_block_height(&self) -> Result<u64> {
        let url = format!(
            "{}/cosmos/base/tendermint/v1beta1/blocks/latest",
            self.rpc_url
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("HTTP request failed: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("Failed to parse response: {}", e)))?;

        let height_str = json
            .pointer("/block/header/height")
            .and_then(|h| h.as_str())
            .ok_or_else(|| BridgeError::Aethelred("Missing block height".into()))?;

        height_str
            .parse::<u64>()
            .map_err(|e| BridgeError::Aethelred(format!("Invalid block height: {}", e)))
    }

    /// Get block hash via /cosmos/base/tendermint/v1beta1/blocks/{height}
    pub async fn get_block_hash(&self, height: u64) -> Result<Hash> {
        let url = format!(
            "{}/cosmos/base/tendermint/v1beta1/blocks/{}",
            self.rpc_url, height
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("HTTP request failed: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("Failed to parse response: {}", e)))?;

        let hash_str = json
            .pointer("/block_id/hash")
            .and_then(|h| h.as_str())
            .ok_or_else(|| BridgeError::Aethelred("Missing block hash".into()))?;

        // Tendermint block hashes are hex-encoded
        let hash_bytes = hex::decode(hash_str).map_err(|e| {
            BridgeError::Aethelred(format!("Invalid block hash hex: {}", e))
        })?;

        let mut hash = [0u8; 32];
        if hash_bytes.len() == 32 {
            hash.copy_from_slice(&hash_bytes);
        }
        Ok(hash)
    }

    /// Get burn events from bridge module via tx_search
    pub async fn get_burn_events(
        &self,
        module_address: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<AethelredBurn>> {
        // Query transactions with burn events via Cosmos tx search
        let url = format!(
            "{}/cosmos/tx/v1beta1/txs?events=message.module='bridge'&events=message.action='burn'&pagination.limit=100&order_by=ORDER_BY_ASC",
            self.rpc_url
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("HTTP request failed: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("Failed to parse response: {}", e)))?;

        let empty_txs = vec![];
        let txs = json
            .get("tx_responses")
            .and_then(|t| t.as_array())
            .unwrap_or(&empty_txs);

        let mut burns = Vec::new();

        for tx in txs {
            let tx_height = tx
                .get("height")
                .and_then(|h| h.as_str())
                .and_then(|h| h.parse::<u64>().ok())
                .unwrap_or(0);

            // Filter by block range
            if tx_height < from_block || tx_height > to_block {
                continue;
            }

            // Extract burn event attributes from logs
            if let Some(burn) = self.parse_burn_tx(tx, module_address) {
                burns.push(burn);
            }
        }

        Ok(burns)
    }

    /// Parse a transaction response into an AethelredBurn
    fn parse_burn_tx(
        &self,
        tx: &serde_json::Value,
        _module_address: &str,
    ) -> Option<AethelredBurn> {
        let tx_hash_str = tx.get("txhash")?.as_str()?;
        let tx_hash_bytes = hex::decode(tx_hash_str).ok()?;
        let mut tx_hash = [0u8; 32];
        if tx_hash_bytes.len() == 32 {
            tx_hash.copy_from_slice(&tx_hash_bytes);
        }

        let height = tx
            .get("height")?
            .as_str()?
            .parse::<u64>()
            .ok()?;

        let timestamp = tx
            .get("timestamp")
            .and_then(|t| t.as_str())
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|dt| dt.timestamp() as u64)
            .unwrap_or(0);

        // Extract event attributes from logs
        let logs = tx.get("logs")?.as_array()?;
        for log in logs {
            let events = log.get("events")?.as_array()?;
            for event in events {
                let event_type = event.get("type")?.as_str()?;
                if event_type == "burn" || event_type == "bridge_burn" {
                    let attrs = event.get("attributes")?.as_array()?;

                    let mut burn_id = [0u8; 32];
                    let mut burner = [0u8; 32];
                    let mut eth_recipient = [0u8; 20];
                    let mut amount: u128 = 0;

                    for attr in attrs {
                        let key = attr.get("key")?.as_str()?;
                        let value = attr.get("value")?.as_str().unwrap_or("");
                        match key {
                            "burn_id" => {
                                if let Ok(bytes) = hex::decode(value) {
                                    if bytes.len() == 32 {
                                        burn_id.copy_from_slice(&bytes);
                                    }
                                }
                            }
                            "sender" | "burner" => {
                                if let Ok(bytes) = hex::decode(
                                    value.strip_prefix("0x").unwrap_or(value),
                                ) {
                                    if bytes.len() == 32 {
                                        burner.copy_from_slice(&bytes);
                                    }
                                }
                            }
                            "eth_recipient" => {
                                if let Ok(bytes) = hex::decode(
                                    value.strip_prefix("0x").unwrap_or(value),
                                ) {
                                    if bytes.len() >= 20 {
                                        eth_recipient
                                            .copy_from_slice(&bytes[bytes.len() - 20..]);
                                    }
                                }
                            }
                            "amount" => amount = value.parse().unwrap_or(0),
                            _ => {}
                        }
                    }

                    return Some(AethelredBurn {
                        burn_id,
                        burner,
                        eth_recipient,
                        token_type: TokenType::NativeAETHEL,
                        amount,
                        nonce: 0, // Placeholder: actual nonce fetched from on-chain state
                        block_height: height,
                        block_hash: [0u8; 32], // Block hash fetched separately
                        tx_hash,
                        timestamp,
                    });
                }
            }
        }

        None
    }

    /// Get mint completion events from bridge module
    pub async fn get_mint_events(
        &self,
        _module_address: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<MintEvent>> {
        let url = format!(
            "{}/cosmos/tx/v1beta1/txs?events=message.module='bridge'&events=message.action='mint'&pagination.limit=100&order_by=ORDER_BY_ASC",
            self.rpc_url
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("HTTP request failed: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("Failed to parse response: {}", e)))?;

        let empty_txs = vec![];
        let txs = json
            .get("tx_responses")
            .and_then(|t| t.as_array())
            .unwrap_or(&empty_txs);

        let mut mints = Vec::new();

        for tx in txs {
            let tx_height = tx
                .get("height")
                .and_then(|h| h.as_str())
                .and_then(|h| h.parse::<u64>().ok())
                .unwrap_or(0);

            if tx_height < from_block || tx_height > to_block {
                continue;
            }

            let tx_hash_str = tx.get("txhash").and_then(|h| h.as_str()).unwrap_or("");
            let tx_hash_bytes = hex::decode(tx_hash_str).unwrap_or_default();
            let mut tx_hash = [0u8; 32];
            if tx_hash_bytes.len() == 32 {
                tx_hash.copy_from_slice(&tx_hash_bytes);
            }

            // Parse mint attributes from event logs
            if let Some(logs) = tx.get("logs").and_then(|l| l.as_array()) {
                for log in logs {
                    if let Some(events) = log.get("events").and_then(|e| e.as_array()) {
                        for event in events {
                            let event_type =
                                event.get("type").and_then(|t| t.as_str()).unwrap_or("");
                            if event_type == "mint" || event_type == "bridge_mint" {
                                let mut proposal_id = [0u8; 32];
                                let mut recipient = [0u8; 32];
                                let mut amount: u128 = 0;

                                if let Some(attrs) =
                                    event.get("attributes").and_then(|a| a.as_array())
                                {
                                    for attr in attrs {
                                        let key = attr
                                            .get("key")
                                            .and_then(|k| k.as_str())
                                            .unwrap_or("");
                                        let value = attr
                                            .get("value")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        match key {
                                            "proposal_id" => {
                                                if let Ok(bytes) = hex::decode(value) {
                                                    if bytes.len() == 32 {
                                                        proposal_id.copy_from_slice(&bytes);
                                                    }
                                                }
                                            }
                                            "recipient" => {
                                                if let Ok(bytes) = hex::decode(
                                                    value.strip_prefix("0x").unwrap_or(value),
                                                ) {
                                                    if bytes.len() == 32 {
                                                        recipient.copy_from_slice(&bytes);
                                                    }
                                                }
                                            }
                                            "amount" => amount = value.parse().unwrap_or(0),
                                            _ => {}
                                        }
                                    }
                                }

                                mints.push(MintEvent {
                                    proposal_id,
                                    recipient,
                                    amount,
                                    tx_hash,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(mints)
    }

    /// Submit a mint proposal transaction to the bridge module
    pub async fn submit_mint_proposal(&self, proposal: &MintProposal) -> Result<Hash> {
        // Submit via Cosmos REST broadcast endpoint
        let url = format!("{}/cosmos/tx/v1beta1/txs", self.rpc_url);

        let tx_body = serde_json::json!({
            "body": {
                "messages": [{
                    "@type": "/aethelred.bridge.MsgMintProposal",
                    "proposal_id": hex::encode(proposal.proposal_id),
                    "recipient": hex::encode(proposal.deposit.aethelred_recipient),
                    "amount": proposal.deposit.amount.to_string(),
                    "deposit_tx_hash": hex::encode(proposal.deposit.tx_hash),
                }],
            },
            "mode": "BROADCAST_MODE_SYNC"
        });

        let response = self
            .client
            .post(&url)
            .json(&tx_body)
            .send()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("Failed to broadcast: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::Aethelred(format!("Failed to parse response: {}", e)))?;

        let tx_hash_str = json
            .pointer("/tx_response/txhash")
            .and_then(|h| h.as_str())
            .ok_or_else(|| BridgeError::Aethelred("Missing tx hash in broadcast response".into()))?;

        let tx_hash_bytes = hex::decode(tx_hash_str).map_err(|e| {
            BridgeError::Aethelred(format!("Invalid tx hash hex: {}", e))
        })?;

        let mut tx_hash = [0u8; 32];
        if tx_hash_bytes.len() == 32 {
            tx_hash.copy_from_slice(&tx_hash_bytes);
        }
        Ok(tx_hash)
    }
}

/// Mint event (for tracking completions)
pub struct MintEvent {
    pub proposal_id: Hash,
    pub recipient: AethelredAddress,
    pub amount: TokenAmount,
    pub tx_hash: Hash,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_listener_creation() {
        let config = AethelredConfig::testnet();
        let storage = Arc::new(BridgeStorage::open_temp().unwrap());
        let metrics = Arc::new(BridgeMetrics::new());

        let listener = AethelredListener::new(&config, storage, metrics)
            .await
            .unwrap();

        assert_eq!(listener.last_processed_block().await, 0);
    }
}
