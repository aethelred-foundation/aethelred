//! Aethelred Testnet Infrastructure
//!
//! A **TREMENDOUS VALUE** testnet that showcases Aethelred's unique moats:
//! Proof-of-Useful-Work (PoUW), Compliance, and TEE Verification.
//!
//! This is NOT a "Table Stakes" testnet. Every feature is designed to
//! teach developers about Aethelred's differentiators while providing
//! practical testing capabilities.
//!
//! ## Tremendous Value Features
//!
//! ### 🔨 Proof-of-Work Faucet
//! Unlike boring faucets that just dispense tokens, ours requires developers
//! to run AI inference jobs - teaching them PoUW while earning tokens.
//! "Want tokens? Run this credit scoring model in your browser."
//!
//! ### ⚖️ Compliance Gauntlet
//! Simulates hostile regulatory environments (HIPAA, GDPR, DIFC) so banks
//! like FAB and DBS can test worst-case scenarios before production.
//! "What happens if UAE data accidentally leaks to Singapore?"
//!
//! ### 🌪️ Chaos Event (Purge Night)
//! Weekly resets transformed into competitive events with NFT badges.
//! Zero fees, maximum difficulty, community stress testing.
//! "Survive the Purge. Earn the badge."
//!
//! ### 📊 Verifiable Truth Dashboard
//! Inference-centric explorer that shows AI operations, not boring hashes.
//! "Block #1002: Cancer Screening (Med42 Model) | Verified by Intel SGX"
//!
//! ### 🔍 TEE Remote Attestation Debugger
//! Demystifies the "Black Box" of Trusted Execution Environments.
//! "See exactly where data enters the enclave, gets decrypted, and exits."
//!
//! ## Standard Features (Enhanced)
//!
//! - **Webhook Testing**: Full inspection, replay, and mock server
//! - **Performance Profiling**: Gas, memory, and opcode analysis
//! - **Multi-Environment**: Isolated environments per developer/team
//! - **Time Travel**: Query historical state at any block height

// ============================================================================
// TREMENDOUS VALUE Modules (Showcase Aethelred's Moats)
// ============================================================================

/// Proof-of-Work Faucet - Earn tokens by running AI inference
pub mod pow_faucet;

/// Compliance Gauntlet - Hostile regulatory environment simulation
pub mod compliance_validators;

/// Chaos Event (Purge Night) - Gamified weekly stress testing
pub mod chaos_event;

/// Verifiable Truth Dashboard - Inference-centric explorer
pub mod truth_dashboard;

/// TEE Remote Attestation Debugger - Demystify the TEE black box
pub mod tee_debugger;

// ============================================================================
// Standard Modules (Enhanced)
// ============================================================================

pub mod core;
pub mod faucet;
pub mod validators;
pub mod debug;
pub mod explorer;
pub mod webhooks;
pub mod reset;
pub mod api;
pub mod chaos;
pub mod profiling;
pub mod environments;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Re-exports - Tremendous Value Modules
pub use pow_faucet::*;
pub use compliance_validators::*;
pub use chaos_event::*;
pub use truth_dashboard::*;
pub use tee_debugger::*;

// Re-exports - Standard Modules
pub use core::*;
pub use faucet::*;
pub use validators::*;
pub use debug::*;
pub use explorer::*;
pub use webhooks::*;
pub use reset::*;
pub use api::*;

// ============================================================================
// Testnet Configuration
// ============================================================================

/// Testnet configuration
#[derive(Debug, Clone)]
pub struct TestnetConfig {
    /// Network identifier
    pub network_id: String,
    /// Chain ID
    pub chain_id: u64,
    /// Network name
    pub name: String,
    /// RPC endpoints
    pub rpc_endpoints: Vec<String>,
    /// WebSocket endpoints
    pub ws_endpoints: Vec<String>,
    /// Explorer URL
    pub explorer_url: String,
    /// Faucet URL
    pub faucet_url: String,
    /// API base URL
    pub api_base_url: String,
    /// Block time in milliseconds
    pub block_time_ms: u64,
    /// Gas limit per block
    pub block_gas_limit: u64,
    /// Native token symbol
    pub native_token_symbol: String,
    /// Native token decimals
    pub native_token_decimals: u8,
    /// Weekly reset enabled
    pub weekly_reset_enabled: bool,
    /// Reset day (0 = Sunday)
    pub reset_day: u8,
    /// Reset hour (UTC)
    pub reset_hour: u8,
    /// Debug mode enabled by default
    pub debug_mode_default: bool,
    /// Maximum environments per account
    pub max_environments_per_account: usize,
    /// Features enabled
    pub features: TestnetFeatures,
}

#[derive(Debug, Clone)]
pub struct TestnetFeatures {
    pub faucet: bool,
    pub sandbox_validators: bool,
    pub debug_mode: bool,
    pub time_travel: bool,
    pub chaos_engineering: bool,
    pub webhook_testing: bool,
    pub performance_profiling: bool,
    pub multi_environment: bool,
    pub state_snapshots: bool,
    pub transaction_simulation: bool,
}

impl Default for TestnetFeatures {
    fn default() -> Self {
        TestnetFeatures {
            faucet: true,
            sandbox_validators: true,
            debug_mode: true,
            time_travel: true,
            chaos_engineering: true,
            webhook_testing: true,
            performance_profiling: true,
            multi_environment: true,
            state_snapshots: true,
            transaction_simulation: true,
        }
    }
}

impl Default for TestnetConfig {
    fn default() -> Self {
        TestnetConfig {
            network_id: "aethelred-testnet-1".to_string(),
            chain_id: 7331,
            name: "Aethelred Testnet".to_string(),
            rpc_endpoints: vec![
                "https://rpc.testnet.aethelred.ai".to_string(),
                "https://rpc-2.testnet.aethelred.ai".to_string(),
                "https://rpc-3.testnet.aethelred.ai".to_string(),
            ],
            ws_endpoints: vec![
                "wss://ws.testnet.aethelred.ai".to_string(),
                "wss://ws-2.testnet.aethelred.ai".to_string(),
            ],
            explorer_url: "https://explorer.testnet.aethelred.ai".to_string(),
            faucet_url: "https://faucet.testnet.aethelred.ai".to_string(),
            api_base_url: "https://api.testnet.aethelred.ai".to_string(),
            block_time_ms: 2000,
            block_gas_limit: 30_000_000,
            native_token_symbol: "tAETH".to_string(),
            native_token_decimals: 18,
            weekly_reset_enabled: true,
            reset_day: 0, // Sunday
            reset_hour: 0, // 00:00 UTC
            debug_mode_default: true,
            max_environments_per_account: 10,
            features: TestnetFeatures::default(),
        }
    }
}

// ============================================================================
// Testnet Instance
// ============================================================================

/// Main testnet instance
pub struct Testnet {
    pub config: TestnetConfig,
    pub faucet: Arc<RwLock<Faucet>>,
    pub validators: Arc<RwLock<SandboxValidators>>,
    pub debugger: Arc<RwLock<Debugger>>,
    pub explorer: Arc<RwLock<Explorer>>,
    pub webhooks: Arc<RwLock<WebhookManager>>,
    pub reset_manager: Arc<RwLock<ResetManager>>,
    pub environments: Arc<RwLock<EnvironmentManager>>,
    pub chaos: Arc<RwLock<ChaosEngine>>,
    pub profiler: Arc<RwLock<Profiler>>,
    state: Arc<RwLock<TestnetState>>,
}

#[derive(Debug, Clone)]
pub struct TestnetState {
    pub current_block: u64,
    pub current_epoch: u64,
    pub genesis_time: u64,
    pub last_reset_time: u64,
    pub next_reset_time: u64,
    pub total_transactions: u64,
    pub total_accounts: u64,
    pub total_contracts: u64,
    pub total_models_sealed: u64,
    pub is_healthy: bool,
    pub sync_status: SyncStatus,
}

#[derive(Debug, Clone)]
pub enum SyncStatus {
    Synced,
    Syncing { current: u64, target: u64 },
    NotSyncing,
}

impl Testnet {
    /// Create a new testnet instance
    pub fn new(config: TestnetConfig) -> Self {
        let genesis_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let state = TestnetState {
            current_block: 0,
            current_epoch: 0,
            genesis_time,
            last_reset_time: genesis_time,
            next_reset_time: genesis_time + 7 * 24 * 60 * 60,
            total_transactions: 0,
            total_accounts: 0,
            total_contracts: 0,
            total_models_sealed: 0,
            is_healthy: true,
            sync_status: SyncStatus::Synced,
        };

        Testnet {
            faucet: Arc::new(RwLock::new(Faucet::new(FaucetConfig::default()))),
            validators: Arc::new(RwLock::new(SandboxValidators::new())),
            debugger: Arc::new(RwLock::new(Debugger::new())),
            explorer: Arc::new(RwLock::new(Explorer::new())),
            webhooks: Arc::new(RwLock::new(WebhookManager::new())),
            reset_manager: Arc::new(RwLock::new(ResetManager::new(config.clone()))),
            environments: Arc::new(RwLock::new(EnvironmentManager::new())),
            chaos: Arc::new(RwLock::new(ChaosEngine::new())),
            profiler: Arc::new(RwLock::new(Profiler::new())),
            state: Arc::new(RwLock::new(state)),
            config,
        }
    }

    /// Get testnet status
    pub fn status(&self) -> TestnetStatus {
        let state = self.state.read().unwrap();
        TestnetStatus {
            network_id: self.config.network_id.clone(),
            chain_id: self.config.chain_id,
            current_block: state.current_block,
            current_epoch: state.current_epoch,
            is_healthy: state.is_healthy,
            sync_status: state.sync_status.clone(),
            next_reset: state.next_reset_time,
            features: self.config.features.clone(),
        }
    }

    /// Get connection info for developers
    pub fn connection_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            network_id: self.config.network_id.clone(),
            chain_id: self.config.chain_id,
            rpc_endpoints: self.config.rpc_endpoints.clone(),
            ws_endpoints: self.config.ws_endpoints.clone(),
            explorer_url: self.config.explorer_url.clone(),
            faucet_url: self.config.faucet_url.clone(),
            api_base_url: self.config.api_base_url.clone(),
            native_token: TokenInfo {
                symbol: self.config.native_token_symbol.clone(),
                decimals: self.config.native_token_decimals,
                name: "Aethelred Testnet Token".to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TestnetStatus {
    pub network_id: String,
    pub chain_id: u64,
    pub current_block: u64,
    pub current_epoch: u64,
    pub is_healthy: bool,
    pub sync_status: SyncStatus,
    pub next_reset: u64,
    pub features: TestnetFeatures,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionInfo {
    pub network_id: String,
    pub chain_id: u64,
    pub rpc_endpoints: Vec<String>,
    pub ws_endpoints: Vec<String>,
    pub explorer_url: String,
    pub faucet_url: String,
    pub api_base_url: String,
    pub native_token: TokenInfo,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenInfo {
    pub symbol: String,
    pub decimals: u8,
    pub name: String,
}

// ============================================================================
// Chaos Engine (Placeholder)
// ============================================================================

pub struct ChaosEngine {
    enabled: bool,
    scenarios: Vec<ChaosScenario>,
}

#[derive(Debug, Clone)]
pub struct ChaosScenario {
    pub name: String,
    pub scenario_type: ChaosType,
    pub probability: f64,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub enum ChaosType {
    NetworkLatency { min_ms: u64, max_ms: u64 },
    PacketLoss { percentage: f64 },
    ValidatorDowntime { validator_count: usize },
    BlockReorg { depth: u64 },
    HighGasPrice { multiplier: f64 },
    MempoolCongestion { tx_count: usize },
}

impl ChaosEngine {
    pub fn new() -> Self {
        ChaosEngine {
            enabled: false,
            scenarios: Vec::new(),
        }
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn add_scenario(&mut self, scenario: ChaosScenario) {
        self.scenarios.push(scenario);
    }
}

impl Default for ChaosEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Profiler (Placeholder)
// ============================================================================

pub struct Profiler {
    enabled: bool,
    profiles: HashMap<String, ExecutionProfile>,
}

#[derive(Debug, Clone)]
pub struct ExecutionProfile {
    pub tx_hash: String,
    pub gas_used: u64,
    pub execution_time_us: u64,
    pub memory_used_bytes: u64,
    pub storage_reads: u64,
    pub storage_writes: u64,
    pub call_depth: u32,
    pub opcodes_executed: u64,
}

impl Profiler {
    pub fn new() -> Self {
        Profiler {
            enabled: false,
            profiles: HashMap::new(),
        }
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn profile_transaction(&mut self, tx_hash: &str) -> Option<ExecutionProfile> {
        self.profiles.get(tx_hash).cloned()
    }
}

impl Default for Profiler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Environment Manager (Placeholder)
// ============================================================================

pub struct EnvironmentManager {
    environments: HashMap<String, TestEnvironment>,
}

#[derive(Debug, Clone)]
pub struct TestEnvironment {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub created_at: u64,
    pub chain_id: u64,
    pub rpc_endpoint: String,
    pub state_snapshot: Option<String>,
    pub is_active: bool,
}

impl EnvironmentManager {
    pub fn new() -> Self {
        EnvironmentManager {
            environments: HashMap::new(),
        }
    }

    pub fn create_environment(&mut self, owner: &str, name: &str) -> TestEnvironment {
        let id = format!("env-{}", uuid::Uuid::new_v4());
        let env = TestEnvironment {
            id: id.clone(),
            name: name.to_string(),
            owner: owner.to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            chain_id: 7331 + self.environments.len() as u64,
            rpc_endpoint: format!("https://{}.env.testnet.aethelred.ai", id),
            state_snapshot: None,
            is_active: true,
        };
        self.environments.insert(id.clone(), env.clone());
        env
    }

    pub fn get_environment(&self, id: &str) -> Option<&TestEnvironment> {
        self.environments.get(id)
    }

    pub fn list_environments(&self, owner: &str) -> Vec<&TestEnvironment> {
        self.environments
            .values()
            .filter(|e| e.owner == owner)
            .collect()
    }
}

impl Default for EnvironmentManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Serialization implementations
// ============================================================================

impl serde::Serialize for SyncStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SyncStatus::Synced => serializer.serialize_str("synced"),
            SyncStatus::Syncing { current, target } => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("status", "syncing")?;
                map.serialize_entry("current", current)?;
                map.serialize_entry("target", target)?;
                map.end()
            }
            SyncStatus::NotSyncing => serializer.serialize_str("not_syncing"),
        }
    }
}

impl serde::Serialize for TestnetFeatures {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(10))?;
        map.serialize_entry("faucet", &self.faucet)?;
        map.serialize_entry("sandbox_validators", &self.sandbox_validators)?;
        map.serialize_entry("debug_mode", &self.debug_mode)?;
        map.serialize_entry("time_travel", &self.time_travel)?;
        map.serialize_entry("chaos_engineering", &self.chaos_engineering)?;
        map.serialize_entry("webhook_testing", &self.webhook_testing)?;
        map.serialize_entry("performance_profiling", &self.performance_profiling)?;
        map.serialize_entry("multi_environment", &self.multi_environment)?;
        map.serialize_entry("state_snapshots", &self.state_snapshots)?;
        map.serialize_entry("transaction_simulation", &self.transaction_simulation)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_testnet_creation() {
        let testnet = Testnet::new(TestnetConfig::default());
        let status = testnet.status();

        assert_eq!(status.chain_id, 7331);
        assert!(status.is_healthy);
    }

    #[test]
    fn test_connection_info() {
        let testnet = Testnet::new(TestnetConfig::default());
        let info = testnet.connection_info();

        assert!(!info.rpc_endpoints.is_empty());
        assert_eq!(info.native_token.symbol, "tAETH");
    }
}
