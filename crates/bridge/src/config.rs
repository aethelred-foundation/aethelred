//! Bridge Configuration
//!
//! Configuration types and loading for the bridge relayer.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Relayer identity
    pub identity: RelayerIdentityConfig,

    /// Ethereum configuration
    pub ethereum: EthereumConfig,

    /// Aethelred configuration
    pub aethelred: AethelredConfig,

    /// Consensus configuration
    pub consensus: ConsensusConfig,

    /// Storage path
    pub storage_path: PathBuf,

    /// Enable metrics
    pub metrics_enabled: bool,

    /// Metrics port
    pub metrics_port: u16,

    /// Log level
    pub log_level: String,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            identity: RelayerIdentityConfig::default(),
            ethereum: EthereumConfig::default(),
            aethelred: AethelredConfig::default(),
            consensus: ConsensusConfig::default(),
            storage_path: PathBuf::from("./data/bridge"),
            metrics_enabled: true,
            metrics_port: 9100,
            log_level: "info".to_string(),
        }
    }
}

impl BridgeConfig {
    /// Load configuration from file
    pub fn load(path: &str) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::BridgeError::Config(format!("Failed to read config: {}", e)))?;

        let config: Self = serde_json::from_str(&content)
            .map_err(|e| crate::BridgeError::Config(format!("Failed to parse config: {}", e)))?;

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration
    pub fn validate(&self) -> crate::Result<()> {
        // Validate Ethereum config
        if self.ethereum.rpc_url.is_empty() {
            return Err(crate::BridgeError::Config(
                "Ethereum RPC URL is required".to_string(),
            ));
        }

        if self.ethereum.bridge_address.is_empty() {
            return Err(crate::BridgeError::Config(
                "Bridge contract address is required".to_string(),
            ));
        }

        // Validate Aethelred config
        if self.aethelred.rpc_url.is_empty() {
            return Err(crate::BridgeError::Config(
                "Aethelred RPC URL is required".to_string(),
            ));
        }

        // Validate consensus config
        if self.consensus.threshold_bps == 0 || self.consensus.threshold_bps > 10000 {
            return Err(crate::BridgeError::Config(
                "Consensus threshold must be between 1 and 10000 basis points".to_string(),
            ));
        }

        Ok(())
    }

    /// Create a testnet configuration
    pub fn testnet() -> Self {
        Self {
            identity: RelayerIdentityConfig::default(),
            ethereum: EthereumConfig::testnet(),
            aethelred: AethelredConfig::testnet(),
            consensus: ConsensusConfig::default(),
            storage_path: PathBuf::from("./data/bridge-testnet"),
            metrics_enabled: true,
            metrics_port: 9100,
            log_level: "debug".to_string(),
        }
    }

    /// Create a mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            identity: RelayerIdentityConfig::default(),
            ethereum: EthereumConfig::mainnet(),
            aethelred: AethelredConfig::mainnet(),
            consensus: ConsensusConfig {
                threshold_bps: 6700,         // 67%
                proposal_timeout_secs: 3600, // 1 hour
                vote_timeout_secs: 300,      // 5 minutes
                max_pending_proposals: 1000,
            },
            storage_path: PathBuf::from("./data/bridge-mainnet"),
            metrics_enabled: true,
            metrics_port: 9100,
            log_level: "info".to_string(),
        }
    }
}

/// Relayer identity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerIdentityConfig {
    /// Path to private key file
    pub private_key_path: PathBuf,

    /// Aethelred address (derived from key)
    pub aethelred_address: Option<String>,

    /// Ethereum address (derived from key)
    pub eth_address: Option<String>,
}

impl Default for RelayerIdentityConfig {
    fn default() -> Self {
        Self {
            private_key_path: PathBuf::from("./keys/relayer.key"),
            aethelred_address: None,
            eth_address: None,
        }
    }
}

/// Ethereum configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumConfig {
    /// RPC URL (HTTP or WebSocket)
    pub rpc_url: String,

    /// WebSocket URL for subscriptions
    pub ws_url: Option<String>,

    /// Chain ID
    pub chain_id: u64,

    /// Bridge contract address
    pub bridge_address: String,

    /// Required confirmations for finality
    pub confirmations: u64,

    /// Block polling interval (if not using WebSocket)
    pub poll_interval_secs: u64,

    /// Maximum blocks to scan per batch
    pub max_blocks_per_scan: u64,

    /// Starting block for initial sync
    pub start_block: Option<u64>,

    /// Gas price strategy
    pub gas_strategy: GasStrategy,

    /// Maximum gas price (in gwei)
    pub max_gas_price_gwei: u64,
}

impl Default for EthereumConfig {
    fn default() -> Self {
        Self::testnet()
    }
}

impl EthereumConfig {
    pub fn testnet() -> Self {
        Self {
            rpc_url: "https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY".to_string(),
            ws_url: Some("wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY".to_string()),
            chain_id: 11155111, // Sepolia
            bridge_address: "".to_string(),
            confirmations: 6,
            poll_interval_secs: 12,
            max_blocks_per_scan: 1000,
            start_block: None,
            gas_strategy: GasStrategy::Medium,
            max_gas_price_gwei: 100,
        }
    }

    pub fn mainnet() -> Self {
        Self {
            rpc_url: "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY".to_string(),
            ws_url: Some("wss://eth-mainnet.g.alchemy.com/v2/YOUR_KEY".to_string()),
            chain_id: 1, // Mainnet
            bridge_address: "".to_string(),
            confirmations: 12, // Higher for mainnet
            poll_interval_secs: 12,
            max_blocks_per_scan: 1000,
            start_block: None,
            gas_strategy: GasStrategy::Medium,
            max_gas_price_gwei: 200,
        }
    }
}

/// Gas price strategy
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum GasStrategy {
    /// Use slow/low gas price
    Slow,
    /// Use medium gas price (default)
    Medium,
    /// Use fast/high gas price
    Fast,
    /// Fixed gas price
    Fixed(u64),
}

/// Aethelred configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AethelredConfig {
    /// RPC URL
    pub rpc_url: String,

    /// WebSocket URL for subscriptions
    pub ws_url: Option<String>,

    /// Chain ID
    pub chain_id: String,

    /// Bridge module address
    pub bridge_module_address: String,

    /// Required confirmations
    pub confirmations: u64,

    /// Block polling interval
    pub poll_interval_secs: u64,

    /// Starting block for initial sync
    pub start_block: Option<u64>,
}

impl Default for AethelredConfig {
    fn default() -> Self {
        Self::testnet()
    }
}

impl AethelredConfig {
    pub fn testnet() -> Self {
        Self {
            rpc_url: "https://rpc.testnet.aethelred.org".to_string(),
            ws_url: Some("wss://ws.testnet.aethelred.org".to_string()),
            chain_id: "aethelred-testnet-1".to_string(),
            bridge_module_address: "0x0000000000000000000000000000000000000006".to_string(),
            confirmations: 1,
            poll_interval_secs: 6,
            start_block: None,
        }
    }

    pub fn mainnet() -> Self {
        Self {
            rpc_url: "https://rpc.aethelred.org".to_string(),
            ws_url: Some("wss://ws.aethelred.org".to_string()),
            chain_id: "aethelred-mainnet-1".to_string(),
            bridge_module_address: "0x0000000000000000000000000000000000000006".to_string(),
            confirmations: 3,
            poll_interval_secs: 6,
            start_block: None,
        }
    }
}

/// Consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Consensus threshold in basis points (e.g., 6700 = 67%)
    pub threshold_bps: u16,

    /// Proposal timeout in seconds
    pub proposal_timeout_secs: u64,

    /// Vote timeout in seconds
    pub vote_timeout_secs: u64,

    /// Maximum pending proposals
    pub max_pending_proposals: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            threshold_bps: 6700,         // 67%
            proposal_timeout_secs: 1800, // 30 minutes
            vote_timeout_secs: 180,      // 3 minutes
            max_pending_proposals: 500,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let mut config = BridgeConfig::default();
        // Default has empty bridge address, should fail
        assert!(config.validate().is_err());

        // Fix the config
        config.ethereum.bridge_address = "0x1234567890123456789012345678901234567890".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_testnet_config() {
        let config = BridgeConfig::testnet();
        assert_eq!(config.ethereum.chain_id, 11155111);
        assert_eq!(config.ethereum.confirmations, 6);
    }

    #[test]
    fn test_mainnet_config() {
        let config = BridgeConfig::mainnet();
        assert_eq!(config.ethereum.chain_id, 1);
        assert_eq!(config.ethereum.confirmations, 12);
        assert_eq!(config.consensus.threshold_bps, 6700);
    }
}
