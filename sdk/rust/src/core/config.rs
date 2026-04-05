//! Configuration for Aethelred SDK.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Local,
}

impl Network {
    pub fn rpc_url(&self) -> &'static str {
        match self {
            Network::Mainnet => "https://rpc.mainnet.aethelred.io",
            Network::Testnet => "https://rpc.testnet.aethelred.io",
            Network::Devnet => "https://rpc.devnet.aethelred.io",
            Network::Local => "http://127.0.0.1:26657",
        }
    }

    pub fn chain_id(&self) -> &'static str {
        match self {
            Network::Mainnet => "aethelred-mainnet-1",
            Network::Testnet => "aethelred-testnet-1",
            Network::Devnet => "aethelred-devnet-1",
            Network::Local => "aethelred-local",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub network: Network,
    pub rpc_url: Option<String>,
    pub chain_id: Option<String>,
    pub api_key: Option<String>,
    pub timeout: Duration,
    pub max_retries: u32,
    pub log_requests: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            rpc_url: None,
            chain_id: None,
            api_key: None,
            timeout: Duration::from_secs(30),
            max_retries: 3,
            log_requests: false,
        }
    }
}

impl Config {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            ..Default::default()
        }
    }

    pub fn mainnet() -> Self {
        Self::new(Network::Mainnet)
    }
    pub fn testnet() -> Self {
        Self::new(Network::Testnet)
    }
    pub fn devnet() -> Self {
        Self::new(Network::Devnet)
    }
    pub fn local() -> Self {
        Self::new(Network::Local)
    }

    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn get_rpc_url(&self) -> &str {
        self.rpc_url
            .as_deref()
            .unwrap_or_else(|| self.network.rpc_url())
    }

    pub fn get_chain_id(&self) -> &str {
        self.chain_id
            .as_deref()
            .unwrap_or_else(|| self.network.chain_id())
    }
}
