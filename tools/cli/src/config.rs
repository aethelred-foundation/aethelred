//! Configuration management for the Aethelred CLI

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// CLI Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network to connect to
    pub network: String,

    /// RPC endpoint
    pub rpc_endpoint: String,

    /// API endpoint
    pub api_endpoint: String,

    /// Chain ID
    pub chain_id: String,

    /// Default output format
    pub output_format: String,

    /// Keyring backend
    pub keyring_backend: String,

    /// Default account
    pub default_account: Option<String>,

    /// Gas settings
    pub gas: GasConfig,

    /// Custom settings
    pub custom: HashMap<String, String>,
}

/// Gas configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConfig {
    /// Gas limit
    pub limit: u64,

    /// Gas price
    pub price: String,

    /// Gas adjustment
    pub adjustment: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: "testnet".to_string(),
            rpc_endpoint: "https://rpc.testnet.aethelred.io".to_string(),
            api_endpoint: "https://api.testnet.aethelred.io".to_string(),
            chain_id: "aethelred-testnet-1".to_string(),
            output_format: "text".to_string(),
            keyring_backend: "os".to_string(),
            default_account: None,
            gas: GasConfig::default(),
            custom: HashMap::new(),
        }
    }
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            limit: 200000,
            price: "0.025uaethel".to_string(),
            adjustment: 1.3,
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load(path: Option<&PathBuf>) -> anyhow::Result<Self> {
        let config_path = path
            .cloned()
            .or_else(|| Self::default_config_path())
            .unwrap_or_else(|| PathBuf::from("aethelred.toml"));

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    /// Save configuration to file
    pub fn save(&self, path: Option<&PathBuf>) -> anyhow::Result<()> {
        let config_path = path
            .cloned()
            .or_else(|| Self::default_config_path())
            .unwrap_or_else(|| PathBuf::from("aethelred.toml"));

        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(&config_path, content)?;
        Ok(())
    }

    /// Get default config path
    fn default_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("aethelred").join("config.toml"))
    }

    /// Get value by key
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "network" => Some(self.network.clone()),
            "rpc_endpoint" => Some(self.rpc_endpoint.clone()),
            "api_endpoint" => Some(self.api_endpoint.clone()),
            "chain_id" => Some(self.chain_id.clone()),
            "output_format" => Some(self.output_format.clone()),
            "keyring_backend" => Some(self.keyring_backend.clone()),
            "default_account" => self.default_account.clone(),
            "gas.limit" => Some(self.gas.limit.to_string()),
            "gas.price" => Some(self.gas.price.clone()),
            "gas.adjustment" => Some(self.gas.adjustment.to_string()),
            _ => self.custom.get(key).cloned(),
        }
    }

    /// Set value by key
    pub fn set(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        match key {
            "network" => self.network = value.to_string(),
            "rpc_endpoint" => self.rpc_endpoint = value.to_string(),
            "api_endpoint" => self.api_endpoint = value.to_string(),
            "chain_id" => self.chain_id = value.to_string(),
            "output_format" => self.output_format = value.to_string(),
            "keyring_backend" => self.keyring_backend = value.to_string(),
            "default_account" => self.default_account = Some(value.to_string()),
            "gas.limit" => self.gas.limit = value.parse()?,
            "gas.price" => self.gas.price = value.to_string(),
            "gas.adjustment" => self.gas.adjustment = value.parse()?,
            _ => {
                self.custom.insert(key.to_string(), value.to_string());
            }
        }
        Ok(())
    }

    /// Update network settings
    pub fn set_network(&mut self, network: &str) {
        self.network = network.to_string();

        match network {
            "mainnet" => {
                self.rpc_endpoint = "https://rpc.mainnet.aethelred.io".to_string();
                self.api_endpoint = "https://api.mainnet.aethelred.io".to_string();
                self.chain_id = "aethelred-mainnet-1".to_string();
            }
            "testnet" => {
                self.rpc_endpoint = "https://rpc.testnet.aethelred.io".to_string();
                self.api_endpoint = "https://api.testnet.aethelred.io".to_string();
                self.chain_id = "aethelred-testnet-1".to_string();
            }
            "devnet" => {
                self.rpc_endpoint = "https://rpc.devnet.aethelred.io".to_string();
                self.api_endpoint = "https://api.devnet.aethelred.io".to_string();
                self.chain_id = "aethelred-devnet-1".to_string();
            }
            "local" => {
                self.rpc_endpoint = "http://localhost:26657".to_string();
                self.api_endpoint = "http://localhost:1317".to_string();
                self.chain_id = "aethelred-local-1".to_string();
            }
            _ => {}
        }
    }
}

/// Network presets
pub struct NetworkPreset {
    pub name: String,
    pub rpc: String,
    pub api: String,
    pub chain_id: String,
    pub explorer: String,
    pub faucet: Option<String>,
}

impl NetworkPreset {
    pub fn mainnet() -> Self {
        Self {
            name: "mainnet".to_string(),
            rpc: "https://rpc.mainnet.aethelred.io".to_string(),
            api: "https://api.mainnet.aethelred.io".to_string(),
            chain_id: "aethelred-mainnet-1".to_string(),
            explorer: "https://explorer.aethelred.io".to_string(),
            faucet: None,
        }
    }

    pub fn testnet() -> Self {
        Self {
            name: "testnet".to_string(),
            rpc: "https://rpc.testnet.aethelred.io".to_string(),
            api: "https://api.testnet.aethelred.io".to_string(),
            chain_id: "aethelred-testnet-1".to_string(),
            explorer: "https://explorer.testnet.aethelred.io".to_string(),
            faucet: Some("https://faucet.aethelred.io".to_string()),
        }
    }

    pub fn devnet() -> Self {
        Self {
            name: "devnet".to_string(),
            rpc: "https://rpc.devnet.aethelred.io".to_string(),
            api: "https://api.devnet.aethelred.io".to_string(),
            chain_id: "aethelred-devnet-1".to_string(),
            explorer: "https://explorer.devnet.aethelred.io".to_string(),
            faucet: Some("https://devnet-faucet.aethelred.io".to_string()),
        }
    }

    pub fn local() -> Self {
        Self {
            name: "local".to_string(),
            rpc: "http://localhost:26657".to_string(),
            api: "http://localhost:1317".to_string(),
            chain_id: "aethelred-local-1".to_string(),
            explorer: "http://localhost:8080".to_string(),
            faucet: None,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::mainnet(),
            Self::testnet(),
            Self::devnet(),
            Self::local(),
        ]
    }
}
