//! Chaos Engineering for Aethelred Testnet
//!
//! Simulate real-world failure scenarios to test application resilience:
//! - Network latency injection
//! - Packet loss simulation
//! - Validator downtime
//! - Block reorganizations
//! - Gas price spikes
//! - Mempool congestion

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use rand::Rng;
use serde::{Deserialize, Serialize};

// ============ Chaos Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosConfig {
    /// Enable chaos engineering
    pub enabled: bool,

    /// Random seed for reproducibility
    pub seed: Option<u64>,

    /// Global probability multiplier
    pub probability_multiplier: f64,

    /// Maximum concurrent failures
    pub max_concurrent_failures: usize,

    /// Auto-heal after duration
    pub auto_heal_enabled: bool,
    pub auto_heal_delay_seconds: u64,

    /// Safe mode - prevent critical failures
    pub safe_mode: bool,

    /// Excluded addresses (protected from chaos)
    pub excluded_addresses: Vec<String>,

    /// Excluded validators
    pub excluded_validators: Vec<String>,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            seed: None,
            probability_multiplier: 1.0,
            max_concurrent_failures: 3,
            auto_heal_enabled: true,
            auto_heal_delay_seconds: 300, // 5 minutes
            safe_mode: true,
            excluded_addresses: Vec::new(),
            excluded_validators: Vec::new(),
        }
    }
}

// ============ Chaos Scenarios ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosScenario {
    pub id: String,
    pub name: String,
    pub description: String,
    pub chaos_type: ChaosType,
    pub trigger: ChaosTrigger,
    pub duration: Duration,
    pub probability: f64,
    pub severity: ChaosSeverity,
    pub target: ChaosTarget,
    pub created_at: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaosType {
    /// Add latency to network requests
    NetworkLatency {
        min_ms: u64,
        max_ms: u64,
        jitter_ms: u64,
    },

    /// Drop packets
    PacketLoss {
        loss_percentage: f64,
        burst_size: Option<u32>,
    },

    /// Simulate validator failures
    ValidatorDowntime {
        validator_count: usize,
        selection: ValidatorSelection,
    },

    /// Trigger block reorganization
    BlockReorg {
        depth: u64,
        probability: f64,
    },

    /// Spike gas prices
    GasPriceSpike {
        multiplier: f64,
        duration_blocks: u64,
    },

    /// Congest the mempool
    MempoolCongestion {
        tx_count: usize,
        priority_fee: u64,
    },

    /// Slow down block production
    SlowBlocks {
        delay_multiplier: f64,
    },

    /// Simulate disk I/O failures
    StorageFailure {
        failure_type: StorageFailureType,
        probability: f64,
    },

    /// CPU throttling
    CpuThrottle {
        throttle_percentage: f64,
    },

    /// Memory pressure
    MemoryPressure {
        usage_percentage: f64,
    },

    /// RPC endpoint failures
    RpcFailure {
        failure_type: RpcFailureType,
        endpoints: Vec<String>,
    },

    /// Custom chaos script
    Custom {
        script: String,
        parameters: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidatorSelection {
    Random,
    ByAddress(Vec<String>),
    ByStakeWeight,
    Leader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageFailureType {
    ReadFailure,
    WriteFailure,
    Corruption,
    FullDisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcFailureType {
    Timeout,
    Error500,
    Error503,
    Disconnect,
    SlowResponse { delay_ms: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaosTrigger {
    /// Run immediately
    Immediate,

    /// Run on schedule
    Scheduled { start_time: u64 },

    /// Run periodically
    Periodic { interval_seconds: u64 },

    /// Trigger on condition
    Conditional { condition: ChaosCondition },

    /// Manual trigger only
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaosCondition {
    BlockHeightReached(u64),
    TransactionCount(u64),
    TimeOfDay { hour: u8, minute: u8 },
    GasPriceAbove(u64),
    MempoolSizeAbove(usize),
    ValidatorCountBelow(usize),
    Custom(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ChaosSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaosTarget {
    All,
    Validators,
    RpcEndpoints,
    Transactions,
    Blocks,
    Storage,
    Network,
    SpecificAddresses(Vec<String>),
}

// ============ Chaos Engine ============

pub struct AdvancedChaosEngine {
    config: ChaosConfig,
    scenarios: HashMap<String, ChaosScenario>,
    active_failures: Vec<ActiveFailure>,
    history: VecDeque<ChaosEvent>,
    metrics: ChaosMetrics,
    rng: rand::rngs::StdRng,
}

#[derive(Debug, Clone)]
pub struct ActiveFailure {
    pub scenario_id: String,
    pub started_at: Instant,
    pub expires_at: Option<Instant>,
    pub affected_targets: Vec<String>,
    pub chaos_type: ChaosType,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChaosEvent {
    pub id: String,
    pub scenario_id: String,
    pub event_type: ChaosEventType,
    pub timestamp: u64,
    pub details: String,
    pub affected_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub enum ChaosEventType {
    Started,
    Stopped,
    Triggered,
    Healed,
    Escalated,
    Error,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ChaosMetrics {
    pub scenarios_executed: u64,
    pub active_failures: usize,
    pub total_failure_duration_seconds: u64,
    pub transactions_affected: u64,
    pub validators_affected: u64,
    pub auto_heals_triggered: u64,
    pub failures_by_type: HashMap<String, u64>,
}

impl AdvancedChaosEngine {
    pub fn new(config: ChaosConfig) -> Self {
        use rand::SeedableRng;
        let rng = match config.seed {
            Some(seed) => rand::rngs::StdRng::seed_from_u64(seed),
            None => rand::rngs::StdRng::from_entropy(),
        };

        Self {
            config,
            scenarios: HashMap::new(),
            active_failures: Vec::new(),
            history: VecDeque::with_capacity(1000),
            metrics: ChaosMetrics::default(),
            rng,
        }
    }

    /// Enable chaos engineering
    pub fn enable(&mut self) {
        self.config.enabled = true;
    }

    /// Disable chaos engineering
    pub fn disable(&mut self) {
        self.config.enabled = false;
        self.heal_all();
    }

    /// Add a chaos scenario
    pub fn add_scenario(&mut self, scenario: ChaosScenario) -> String {
        let id = scenario.id.clone();
        self.scenarios.insert(id.clone(), scenario);
        id
    }

    /// Remove a scenario
    pub fn remove_scenario(&mut self, id: &str) -> Option<ChaosScenario> {
        self.scenarios.remove(id)
    }

    /// Enable a scenario
    pub fn enable_scenario(&mut self, id: &str) -> Result<(), String> {
        if let Some(scenario) = self.scenarios.get_mut(id) {
            scenario.enabled = true;
            Ok(())
        } else {
            Err(format!("Scenario {} not found", id))
        }
    }

    /// Disable a scenario
    pub fn disable_scenario(&mut self, id: &str) -> Result<(), String> {
        if let Some(scenario) = self.scenarios.get_mut(id) {
            scenario.enabled = false;
            Ok(())
        } else {
            Err(format!("Scenario {} not found", id))
        }
    }

    /// Trigger a specific scenario
    pub fn trigger_scenario(&mut self, id: &str) -> Result<ActiveFailure, String> {
        if !self.config.enabled {
            return Err("Chaos engineering is disabled".to_string());
        }

        let scenario = self.scenarios.get(id)
            .ok_or_else(|| format!("Scenario {} not found", id))?
            .clone();

        if !scenario.enabled {
            return Err(format!("Scenario {} is disabled", id));
        }

        // Check max concurrent failures
        if self.active_failures.len() >= self.config.max_concurrent_failures {
            return Err("Maximum concurrent failures reached".to_string());
        }

        // Check safe mode
        if self.config.safe_mode && matches!(scenario.severity, ChaosSeverity::Critical) {
            return Err("Critical failures blocked in safe mode".to_string());
        }

        let failure = ActiveFailure {
            scenario_id: id.to_string(),
            started_at: Instant::now(),
            expires_at: Some(Instant::now() + scenario.duration),
            affected_targets: self.select_targets(&scenario),
            chaos_type: scenario.chaos_type.clone(),
        };

        self.active_failures.push(failure.clone());
        self.metrics.scenarios_executed += 1;

        self.record_event(ChaosEvent {
            id: format!("evt_{}", generate_id()),
            scenario_id: id.to_string(),
            event_type: ChaosEventType::Started,
            timestamp: current_timestamp(),
            details: format!("Chaos scenario '{}' triggered", scenario.name),
            affected_count: failure.affected_targets.len(),
        });

        Ok(failure)
    }

    /// Process chaos - called periodically
    pub fn tick(&mut self) {
        if !self.config.enabled {
            return;
        }

        let now = Instant::now();

        // Check for expired failures
        let mut healed = Vec::new();
        self.active_failures.retain(|f| {
            if let Some(expires_at) = f.expires_at {
                if now >= expires_at {
                    healed.push(f.scenario_id.clone());
                    return false;
                }
            }
            true
        });

        // Record healing events
        for scenario_id in healed {
            self.metrics.auto_heals_triggered += 1;
            self.record_event(ChaosEvent {
                id: format!("evt_{}", generate_id()),
                scenario_id,
                event_type: ChaosEventType::Healed,
                timestamp: current_timestamp(),
                details: "Failure auto-healed".to_string(),
                affected_count: 0,
            });
        }

        // Check for scheduled scenarios
        let timestamp = current_timestamp();
        for (id, scenario) in &self.scenarios {
            if !scenario.enabled {
                continue;
            }

            let should_trigger = match &scenario.trigger {
                ChaosTrigger::Scheduled { start_time } if *start_time <= timestamp => true,
                ChaosTrigger::Periodic { interval_seconds } => {
                    (timestamp % *interval_seconds) == 0
                }
                _ => false,
            };

            if should_trigger && self.should_apply_probability(scenario.probability) {
                let _ = self.trigger_scenario(id);
            }
        }
    }

    /// Apply chaos to a request
    pub fn apply_chaos(&mut self, context: &ChaosContext) -> ChaosEffect {
        if !self.config.enabled || self.active_failures.is_empty() {
            return ChaosEffect::None;
        }

        // Check exclusions
        if let Some(ref address) = context.address {
            if self.config.excluded_addresses.contains(address) {
                return ChaosEffect::None;
            }
        }

        let mut effects = Vec::new();

        for failure in &self.active_failures {
            if self.affects_context(&failure, context) {
                if let Some(effect) = self.compute_effect(&failure.chaos_type) {
                    effects.push(effect);
                }
            }
        }

        if effects.is_empty() {
            ChaosEffect::None
        } else if effects.len() == 1 {
            effects.into_iter().next().unwrap()
        } else {
            ChaosEffect::Multiple(effects)
        }
    }

    fn affects_context(&self, failure: &ActiveFailure, context: &ChaosContext) -> bool {
        // Check if the failure's targets affect this context
        if failure.affected_targets.is_empty() {
            return true; // Affects all
        }

        if let Some(ref address) = context.address {
            if failure.affected_targets.contains(address) {
                return true;
            }
        }

        if let Some(ref validator) = context.validator {
            if failure.affected_targets.contains(validator) {
                return true;
            }
        }

        false
    }

    fn compute_effect(&mut self, chaos_type: &ChaosType) -> Option<ChaosEffect> {
        match chaos_type {
            ChaosType::NetworkLatency { min_ms, max_ms, jitter_ms } => {
                let base_delay = self.rng.gen_range(*min_ms..=*max_ms);
                let jitter = self.rng.gen_range(0..=*jitter_ms);
                Some(ChaosEffect::Delay(Duration::from_millis(base_delay + jitter)))
            }

            ChaosType::PacketLoss { loss_percentage, .. } => {
                if self.rng.gen::<f64>() < *loss_percentage / 100.0 {
                    Some(ChaosEffect::Drop)
                } else {
                    None
                }
            }

            ChaosType::ValidatorDowntime { .. } => {
                Some(ChaosEffect::Unavailable)
            }

            ChaosType::GasPriceSpike { multiplier, .. } => {
                Some(ChaosEffect::ModifyGasPrice(*multiplier))
            }

            ChaosType::RpcFailure { failure_type, .. } => {
                match failure_type {
                    RpcFailureType::Timeout => Some(ChaosEffect::Timeout),
                    RpcFailureType::Error500 => Some(ChaosEffect::Error("Internal Server Error".to_string())),
                    RpcFailureType::Error503 => Some(ChaosEffect::Error("Service Unavailable".to_string())),
                    RpcFailureType::Disconnect => Some(ChaosEffect::Disconnect),
                    RpcFailureType::SlowResponse { delay_ms } => {
                        Some(ChaosEffect::Delay(Duration::from_millis(*delay_ms)))
                    }
                }
            }

            ChaosType::SlowBlocks { delay_multiplier } => {
                Some(ChaosEffect::SlowDown(*delay_multiplier))
            }

            _ => None,
        }
    }

    fn select_targets(&mut self, scenario: &ChaosScenario) -> Vec<String> {
        match &scenario.target {
            ChaosTarget::All => Vec::new(),
            ChaosTarget::SpecificAddresses(addrs) => addrs.clone(),
            ChaosTarget::Validators => {
                // Would select from actual validators
                vec!["validator1".to_string(), "validator2".to_string()]
            }
            _ => Vec::new(),
        }
    }

    fn should_apply_probability(&mut self, probability: f64) -> bool {
        let adjusted = probability * self.config.probability_multiplier;
        self.rng.gen::<f64>() < adjusted
    }

    /// Heal all active failures
    pub fn heal_all(&mut self) {
        for failure in self.active_failures.drain(..) {
            self.record_event(ChaosEvent {
                id: format!("evt_{}", generate_id()),
                scenario_id: failure.scenario_id,
                event_type: ChaosEventType::Healed,
                timestamp: current_timestamp(),
                details: "Manual heal all".to_string(),
                affected_count: 0,
            });
        }
    }

    /// Heal a specific failure
    pub fn heal(&mut self, scenario_id: &str) -> Result<(), String> {
        let pos = self.active_failures.iter()
            .position(|f| f.scenario_id == scenario_id);

        if let Some(pos) = pos {
            let failure = self.active_failures.remove(pos);
            self.record_event(ChaosEvent {
                id: format!("evt_{}", generate_id()),
                scenario_id: failure.scenario_id,
                event_type: ChaosEventType::Healed,
                timestamp: current_timestamp(),
                details: "Manual heal".to_string(),
                affected_count: 0,
            });
            Ok(())
        } else {
            Err(format!("No active failure for scenario {}", scenario_id))
        }
    }

    fn record_event(&mut self, event: ChaosEvent) {
        self.history.push_front(event);
        if self.history.len() > 1000 {
            self.history.pop_back();
        }
    }

    /// Get active failures
    pub fn active_failures(&self) -> &[ActiveFailure] {
        &self.active_failures
    }

    /// Get history
    pub fn history(&self, limit: usize) -> Vec<&ChaosEvent> {
        self.history.iter().take(limit).collect()
    }

    /// Get metrics
    pub fn metrics(&self) -> &ChaosMetrics {
        &self.metrics
    }

    /// Get all scenarios
    pub fn scenarios(&self) -> &HashMap<String, ChaosScenario> {
        &self.scenarios
    }

    /// Is chaos enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[derive(Debug, Clone)]
pub struct ChaosContext {
    pub request_type: String,
    pub address: Option<String>,
    pub validator: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ChaosEffect {
    None,
    Delay(Duration),
    Drop,
    Unavailable,
    Timeout,
    Disconnect,
    Error(String),
    ModifyGasPrice(f64),
    SlowDown(f64),
    Multiple(Vec<ChaosEffect>),
}

// ============ Preset Scenarios ============

pub struct ChaosPresets;

impl ChaosPresets {
    /// High network latency scenario
    pub fn high_latency() -> ChaosScenario {
        ChaosScenario {
            id: "preset_high_latency".to_string(),
            name: "High Network Latency".to_string(),
            description: "Simulate slow network conditions".to_string(),
            chaos_type: ChaosType::NetworkLatency {
                min_ms: 500,
                max_ms: 2000,
                jitter_ms: 200,
            },
            trigger: ChaosTrigger::Manual,
            duration: Duration::from_secs(300),
            probability: 1.0,
            severity: ChaosSeverity::Medium,
            target: ChaosTarget::All,
            created_at: current_timestamp(),
            enabled: true,
        }
    }

    /// Packet loss scenario
    pub fn packet_loss() -> ChaosScenario {
        ChaosScenario {
            id: "preset_packet_loss".to_string(),
            name: "Packet Loss".to_string(),
            description: "Simulate unreliable network".to_string(),
            chaos_type: ChaosType::PacketLoss {
                loss_percentage: 10.0,
                burst_size: Some(3),
            },
            trigger: ChaosTrigger::Manual,
            duration: Duration::from_secs(180),
            probability: 1.0,
            severity: ChaosSeverity::Medium,
            target: ChaosTarget::Network,
            created_at: current_timestamp(),
            enabled: true,
        }
    }

    /// Validator downtime scenario
    pub fn validator_downtime() -> ChaosScenario {
        ChaosScenario {
            id: "preset_validator_down".to_string(),
            name: "Validator Downtime".to_string(),
            description: "Simulate validator failures".to_string(),
            chaos_type: ChaosType::ValidatorDowntime {
                validator_count: 1,
                selection: ValidatorSelection::Random,
            },
            trigger: ChaosTrigger::Manual,
            duration: Duration::from_secs(120),
            probability: 1.0,
            severity: ChaosSeverity::High,
            target: ChaosTarget::Validators,
            created_at: current_timestamp(),
            enabled: true,
        }
    }

    /// Gas price spike scenario
    pub fn gas_spike() -> ChaosScenario {
        ChaosScenario {
            id: "preset_gas_spike".to_string(),
            name: "Gas Price Spike".to_string(),
            description: "Simulate high gas prices".to_string(),
            chaos_type: ChaosType::GasPriceSpike {
                multiplier: 10.0,
                duration_blocks: 50,
            },
            trigger: ChaosTrigger::Manual,
            duration: Duration::from_secs(600),
            probability: 1.0,
            severity: ChaosSeverity::Medium,
            target: ChaosTarget::Transactions,
            created_at: current_timestamp(),
            enabled: true,
        }
    }

    /// RPC failure scenario
    pub fn rpc_outage() -> ChaosScenario {
        ChaosScenario {
            id: "preset_rpc_outage".to_string(),
            name: "RPC Outage".to_string(),
            description: "Simulate RPC endpoint failures".to_string(),
            chaos_type: ChaosType::RpcFailure {
                failure_type: RpcFailureType::Error503,
                endpoints: vec!["rpc-1".to_string()],
            },
            trigger: ChaosTrigger::Manual,
            duration: Duration::from_secs(60),
            probability: 1.0,
            severity: ChaosSeverity::High,
            target: ChaosTarget::RpcEndpoints,
            created_at: current_timestamp(),
            enabled: true,
        }
    }

    /// Block reorg scenario
    pub fn block_reorg() -> ChaosScenario {
        ChaosScenario {
            id: "preset_reorg".to_string(),
            name: "Block Reorganization".to_string(),
            description: "Simulate chain reorganization".to_string(),
            chaos_type: ChaosType::BlockReorg {
                depth: 3,
                probability: 0.1,
            },
            trigger: ChaosTrigger::Manual,
            duration: Duration::from_secs(30),
            probability: 1.0,
            severity: ChaosSeverity::Critical,
            target: ChaosTarget::Blocks,
            created_at: current_timestamp(),
            enabled: false, // Disabled by default
        }
    }

    /// All presets
    pub fn all() -> Vec<ChaosScenario> {
        vec![
            Self::high_latency(),
            Self::packet_loss(),
            Self::validator_downtime(),
            Self::gas_spike(),
            Self::rpc_outage(),
            Self::block_reorg(),
        ]
    }
}

// ============ Helper Functions ============

fn generate_id() -> String {
    use rand::Rng;
    let random: u64 = rand::thread_rng().gen();
    format!("{:x}", random)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chaos_engine_creation() {
        let config = ChaosConfig::default();
        let engine = AdvancedChaosEngine::new(config);

        assert!(!engine.is_enabled());
        assert!(engine.active_failures().is_empty());
    }

    #[test]
    fn test_add_scenario() {
        let config = ChaosConfig::default();
        let mut engine = AdvancedChaosEngine::new(config);

        let scenario = ChaosPresets::high_latency();
        let id = engine.add_scenario(scenario);

        assert!(engine.scenarios().contains_key(&id));
    }

    #[test]
    fn test_trigger_scenario() {
        let mut config = ChaosConfig::default();
        config.enabled = true;

        let mut engine = AdvancedChaosEngine::new(config);
        engine.add_scenario(ChaosPresets::high_latency());

        let result = engine.trigger_scenario("preset_high_latency");
        assert!(result.is_ok());
        assert_eq!(engine.active_failures().len(), 1);
    }

    #[test]
    fn test_chaos_disabled() {
        let config = ChaosConfig::default();
        let mut engine = AdvancedChaosEngine::new(config);

        engine.add_scenario(ChaosPresets::high_latency());

        let result = engine.trigger_scenario("preset_high_latency");
        assert!(result.is_err());
    }

    #[test]
    fn test_heal_all() {
        let mut config = ChaosConfig::default();
        config.enabled = true;

        let mut engine = AdvancedChaosEngine::new(config);
        engine.add_scenario(ChaosPresets::high_latency());
        engine.add_scenario(ChaosPresets::packet_loss());

        engine.trigger_scenario("preset_high_latency").unwrap();
        engine.trigger_scenario("preset_packet_loss").unwrap();

        assert_eq!(engine.active_failures().len(), 2);

        engine.heal_all();
        assert!(engine.active_failures().is_empty());
    }

    #[test]
    fn test_presets() {
        let presets = ChaosPresets::all();
        assert!(!presets.is_empty());
        assert!(presets.iter().any(|s| s.id == "preset_high_latency"));
    }
}
