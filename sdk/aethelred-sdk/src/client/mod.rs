//! # Aethelred Client
//!
//! Network client for interacting with Aethelred nodes.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Aethelred network client
pub struct AethelredClient {
    /// Configuration
    config: ClientConfig,
    /// Connection state
    connected: bool,
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Node RPC endpoint
    pub rpc_url: String,
    /// Chain ID
    pub chain_id: String,
    /// Connection timeout
    pub timeout: Duration,
    /// Maximum retries
    pub max_retries: u32,
}

impl AethelredClient {
    /// Create a new client
    pub fn new(config: ClientConfig) -> Self {
        AethelredClient {
            config,
            connected: false,
        }
    }

    /// Connect to the node
    pub async fn connect(&mut self) -> Result<(), ClientError> {
        // In production, establish gRPC/WebSocket connection
        self.connected = true;
        Ok(())
    }

    /// Disconnect
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get chain info
    pub async fn chain_info(&self) -> Result<ChainInfo, ClientError> {
        Ok(ChainInfo {
            chain_id: self.config.chain_id.clone(),
            block_height: 0,
            latest_block_hash: [0u8; 32],
        })
    }

    /// Submit a transaction
    pub async fn submit_tx(&self, _tx: &[u8]) -> Result<TxResponse, ClientError> {
        Ok(TxResponse {
            hash: [0u8; 32],
            height: 0,
            code: 0,
        })
    }

    /// Query a transaction
    pub async fn query_tx(&self, _hash: &[u8; 32]) -> Result<TxStatus, ClientError> {
        Ok(TxStatus::Pending)
    }

    /// Get account balance
    pub async fn balance(&self, _address: &str) -> Result<u64, ClientError> {
        Ok(0)
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            rpc_url: "https://rpc.aethelred.network".to_string(),
            chain_id: "aethelred-mainnet-1".to_string(),
            timeout: Duration::from_secs(30),
            max_retries: 3,
        }
    }
}

/// Chain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub chain_id: String,
    pub block_height: u64,
    pub latest_block_hash: [u8; 32],
}

/// Transaction response
#[derive(Debug, Clone)]
pub struct TxResponse {
    pub hash: [u8; 32],
    pub height: u64,
    pub code: u32,
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    Pending,
    Confirmed,
    Failed,
}

/// Client errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ClientError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Timeout")]
    Timeout,
    #[error("Transaction failed: {0}")]
    TxFailed(String),
    #[error("Query error: {0}")]
    Query(String),
}
