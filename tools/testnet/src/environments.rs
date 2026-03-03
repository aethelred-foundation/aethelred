//! Multi-Environment Management for Aethelred Testnet
//!
//! Isolated development environments for teams and developers:
//! - Per-developer sandbox environments
//! - Team shared environments
//! - Environment forking and cloning
//! - State snapshots and restoration
//! - Environment templates
//! - Resource quotas and limits

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============ Environment Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    /// Maximum environments per account
    pub max_per_account: usize,

    /// Maximum team environments
    pub max_per_team: usize,

    /// Default environment lifetime (hours)
    pub default_lifetime_hours: u64,

    /// Maximum lifetime (hours)
    pub max_lifetime_hours: u64,

    /// Allow forking
    pub allow_forking: bool,

    /// Allow state snapshots
    pub allow_snapshots: bool,

    /// Maximum snapshots per environment
    pub max_snapshots: usize,

    /// Resource quotas
    pub default_quota: ResourceQuota,

    /// Templates enabled
    pub templates_enabled: bool,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            max_per_account: 5,
            max_per_team: 20,
            default_lifetime_hours: 168, // 1 week
            max_lifetime_hours: 720,     // 30 days
            allow_forking: true,
            allow_snapshots: true,
            max_snapshots: 10,
            default_quota: ResourceQuota::default(),
            templates_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    /// Maximum gas per block
    pub block_gas_limit: u64,

    /// Maximum storage (MB)
    pub storage_limit_mb: u64,

    /// Maximum transactions per second
    pub tps_limit: u64,

    /// Maximum contracts
    pub max_contracts: u64,

    /// Maximum accounts
    pub max_accounts: u64,

    /// Faucet drip amount
    pub faucet_drip: u128,

    /// Faucet cooldown (seconds)
    pub faucet_cooldown_seconds: u64,
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self {
            block_gas_limit: 30_000_000,
            storage_limit_mb: 1024,
            tps_limit: 100,
            max_contracts: 1000,
            max_accounts: 10000,
            faucet_drip: 100_000_000_000_000_000_000, // 100 tokens
            faucet_cooldown_seconds: 3600,
        }
    }
}

// ============ Environment Types ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    /// Unique environment ID
    pub id: String,

    /// Environment name
    pub name: String,

    /// Owner account
    pub owner: String,

    /// Environment type
    pub env_type: EnvironmentType,

    /// Status
    pub status: EnvironmentStatus,

    /// Chain ID (unique per environment)
    pub chain_id: u64,

    /// RPC endpoint
    pub rpc_endpoint: String,

    /// WebSocket endpoint
    pub ws_endpoint: String,

    /// Block height
    pub block_height: u64,

    /// Genesis timestamp
    pub genesis_time: u64,

    /// Creation timestamp
    pub created_at: u64,

    /// Expiration timestamp
    pub expires_at: u64,

    /// Last activity timestamp
    pub last_activity: u64,

    /// Template used (if any)
    pub template_id: Option<String>,

    /// Forked from (if any)
    pub forked_from: Option<ForkInfo>,

    /// Current state hash
    pub state_hash: String,

    /// Resource quota
    pub quota: ResourceQuota,

    /// Resource usage
    pub usage: ResourceUsage,

    /// Team members (if team environment)
    pub team_members: Vec<String>,

    /// Settings
    pub settings: EnvironmentSettings,

    /// Tags
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnvironmentType {
    /// Personal development environment
    Personal,

    /// Shared team environment
    Team { team_id: String },

    /// CI/CD pipeline environment
    Pipeline { pipeline_id: String },

    /// Load testing environment
    LoadTest,

    /// Demo environment
    Demo,

    /// Temporary (auto-deleted)
    Ephemeral { ttl_seconds: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvironmentStatus {
    Creating,
    Active,
    Paused,
    Stopping,
    Stopped,
    Deleting,
    Deleted,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkInfo {
    pub source_env_id: String,
    pub source_block: u64,
    pub source_state_hash: String,
    pub forked_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentSettings {
    /// Block time (ms)
    pub block_time_ms: u64,

    /// Auto-mine transactions
    pub auto_mine: bool,

    /// Enable debug mode
    pub debug_mode: bool,

    /// Enable time travel
    pub time_travel: bool,

    /// Enable chaos engineering
    pub chaos_enabled: bool,

    /// Gas price (wei)
    pub base_gas_price: u64,

    /// Enable EIP-1559
    pub eip1559_enabled: bool,

    /// Network latency simulation (ms)
    pub network_latency_ms: u64,

    /// Validators count
    pub validator_count: u32,
}

impl Default for EnvironmentSettings {
    fn default() -> Self {
        Self {
            block_time_ms: 1000,
            auto_mine: true,
            debug_mode: true,
            time_travel: true,
            chaos_enabled: false,
            base_gas_price: 1_000_000_000, // 1 gwei
            eip1559_enabled: true,
            network_latency_ms: 0,
            validator_count: 3,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub storage_used_mb: u64,
    pub contracts_deployed: u64,
    pub accounts_created: u64,
    pub transactions_processed: u64,
    pub faucet_requests: u64,
    pub snapshots_created: u64,
}

// ============ Environment Manager ============

pub struct AdvancedEnvironmentManager {
    config: EnvironmentConfig,
    environments: HashMap<String, Environment>,
    snapshots: HashMap<String, Vec<StateSnapshot>>,
    templates: HashMap<String, EnvironmentTemplate>,
    usage_by_owner: HashMap<String, OwnerUsage>,
    metrics: EnvironmentMetrics,
}

#[derive(Debug, Clone, Default)]
pub struct OwnerUsage {
    pub environment_count: usize,
    pub total_storage_mb: u64,
    pub total_transactions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub id: String,
    pub environment_id: String,
    pub name: String,
    pub description: Option<String>,
    pub block_height: u64,
    pub state_hash: String,
    pub size_bytes: u64,
    pub created_at: u64,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: TemplateCategory,
    pub settings: EnvironmentSettings,
    pub pre_deployed_contracts: Vec<PreDeployedContract>,
    pub initial_accounts: Vec<InitialAccount>,
    pub quota: ResourceQuota,
    pub created_by: String,
    pub created_at: u64,
    pub usage_count: u64,
    pub is_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateCategory {
    DeFi,
    NFT,
    Gaming,
    AICompute,
    General,
    Testing,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreDeployedContract {
    pub name: String,
    pub address: String,
    pub bytecode_hash: String,
    pub constructor_args: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialAccount {
    pub address: String,
    pub balance: u128,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EnvironmentMetrics {
    pub total_environments: u64,
    pub active_environments: u64,
    pub total_snapshots: u64,
    pub total_forks: u64,
    pub environments_by_type: HashMap<String, u64>,
    pub templates_used: HashMap<String, u64>,
}

impl AdvancedEnvironmentManager {
    pub fn new(config: EnvironmentConfig) -> Self {
        let mut manager = Self {
            config,
            environments: HashMap::new(),
            snapshots: HashMap::new(),
            templates: HashMap::new(),
            usage_by_owner: HashMap::new(),
            metrics: EnvironmentMetrics::default(),
        };

        // Add default templates
        manager.add_default_templates();

        manager
    }

    fn add_default_templates(&mut self) {
        // DeFi template
        self.templates.insert("defi_basic".to_string(), EnvironmentTemplate {
            id: "defi_basic".to_string(),
            name: "DeFi Development".to_string(),
            description: "Basic DeFi development environment with common contracts".to_string(),
            category: TemplateCategory::DeFi,
            settings: EnvironmentSettings::default(),
            pre_deployed_contracts: vec![
                PreDeployedContract {
                    name: "WETH".to_string(),
                    address: "0x0000000000000000000000000000000000001000".to_string(),
                    bytecode_hash: "0xweth...".to_string(),
                    constructor_args: None,
                },
                PreDeployedContract {
                    name: "USDC".to_string(),
                    address: "0x0000000000000000000000000000000000001001".to_string(),
                    bytecode_hash: "0xusdc...".to_string(),
                    constructor_args: None,
                },
            ],
            initial_accounts: vec![
                InitialAccount {
                    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                    balance: 10_000_000_000_000_000_000_000, // 10000 tokens
                    label: Some("Developer".to_string()),
                },
            ],
            quota: ResourceQuota::default(),
            created_by: "system".to_string(),
            created_at: current_timestamp(),
            usage_count: 0,
            is_public: true,
        });

        // AI Compute template
        self.templates.insert("ai_compute".to_string(), EnvironmentTemplate {
            id: "ai_compute".to_string(),
            name: "AI Compute Testing".to_string(),
            description: "Environment for testing AI model sealing and compute jobs".to_string(),
            category: TemplateCategory::AICompute,
            settings: EnvironmentSettings {
                debug_mode: true,
                ..Default::default()
            },
            pre_deployed_contracts: vec![
                PreDeployedContract {
                    name: "ModelRegistry".to_string(),
                    address: "0x0000000000000000000000000000000000002000".to_string(),
                    bytecode_hash: "0xregistry...".to_string(),
                    constructor_args: None,
                },
                PreDeployedContract {
                    name: "JobQueue".to_string(),
                    address: "0x0000000000000000000000000000000000002001".to_string(),
                    bytecode_hash: "0xjobqueue...".to_string(),
                    constructor_args: None,
                },
            ],
            initial_accounts: vec![],
            quota: ResourceQuota {
                block_gas_limit: 50_000_000, // Higher for AI ops
                ..Default::default()
            },
            created_by: "system".to_string(),
            created_at: current_timestamp(),
            usage_count: 0,
            is_public: true,
        });

        // Load testing template
        self.templates.insert("load_test".to_string(), EnvironmentTemplate {
            id: "load_test".to_string(),
            name: "Load Testing".to_string(),
            description: "High-capacity environment for load testing".to_string(),
            category: TemplateCategory::Testing,
            settings: EnvironmentSettings {
                block_time_ms: 100,
                auto_mine: true,
                debug_mode: false,
                ..Default::default()
            },
            pre_deployed_contracts: vec![],
            initial_accounts: vec![],
            quota: ResourceQuota {
                block_gas_limit: 100_000_000,
                tps_limit: 1000,
                max_contracts: 10000,
                ..Default::default()
            },
            created_by: "system".to_string(),
            created_at: current_timestamp(),
            usage_count: 0,
            is_public: true,
        });
    }

    /// Create a new environment
    pub fn create_environment(&mut self, request: CreateEnvironmentRequest) -> Result<Environment, String> {
        // Check quotas
        let owner_usage = self.usage_by_owner.entry(request.owner.clone())
            .or_default();

        if owner_usage.environment_count >= self.config.max_per_account {
            return Err(format!(
                "Maximum environments ({}) reached for account",
                self.config.max_per_account
            ));
        }

        let env_id = format!("env_{}", generate_id());
        let chain_id = 7331 + self.environments.len() as u64;

        let (settings, quota) = if let Some(template_id) = &request.template_id {
            if let Some(template) = self.templates.get_mut(template_id) {
                template.usage_count += 1;
                (template.settings.clone(), template.quota.clone())
            } else {
                return Err(format!("Template {} not found", template_id));
            }
        } else {
            (
                request.settings.unwrap_or_default(),
                self.config.default_quota.clone(),
            )
        };

        let now = current_timestamp();
        let lifetime = request.lifetime_hours
            .unwrap_or(self.config.default_lifetime_hours)
            .min(self.config.max_lifetime_hours);

        let environment = Environment {
            id: env_id.clone(),
            name: request.name,
            owner: request.owner.clone(),
            env_type: request.env_type,
            status: EnvironmentStatus::Active,
            chain_id,
            rpc_endpoint: format!("https://{}.env.testnet.aethelred.ai", env_id),
            ws_endpoint: format!("wss://{}.env.testnet.aethelred.ai", env_id),
            block_height: 0,
            genesis_time: now,
            created_at: now,
            expires_at: now + lifetime * 3600,
            last_activity: now,
            template_id: request.template_id,
            forked_from: None,
            state_hash: generate_hash(),
            quota,
            usage: ResourceUsage::default(),
            team_members: request.team_members.unwrap_or_default(),
            settings,
            tags: request.tags.unwrap_or_default(),
        };

        self.environments.insert(env_id.clone(), environment.clone());
        owner_usage.environment_count += 1;

        self.metrics.total_environments += 1;
        self.metrics.active_environments += 1;

        let type_key = match &environment.env_type {
            EnvironmentType::Personal => "personal",
            EnvironmentType::Team { .. } => "team",
            EnvironmentType::Pipeline { .. } => "pipeline",
            EnvironmentType::LoadTest => "loadtest",
            EnvironmentType::Demo => "demo",
            EnvironmentType::Ephemeral { .. } => "ephemeral",
        };
        *self.metrics.environments_by_type.entry(type_key.to_string()).or_insert(0) += 1;

        Ok(environment)
    }

    /// Fork an existing environment
    pub fn fork_environment(&mut self, env_id: &str, owner: &str, name: &str) -> Result<Environment, String> {
        if !self.config.allow_forking {
            return Err("Forking is disabled".to_string());
        }

        let source = self.environments.get(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?
            .clone();

        let fork_info = ForkInfo {
            source_env_id: env_id.to_string(),
            source_block: source.block_height,
            source_state_hash: source.state_hash.clone(),
            forked_at: current_timestamp(),
        };

        let mut forked = self.create_environment(CreateEnvironmentRequest {
            name: name.to_string(),
            owner: owner.to_string(),
            env_type: EnvironmentType::Personal,
            template_id: None,
            settings: Some(source.settings.clone()),
            lifetime_hours: None,
            team_members: None,
            tags: Some(HashMap::from([
                ("forked_from".to_string(), env_id.to_string()),
            ])),
        })?;

        forked.forked_from = Some(fork_info);
        forked.state_hash = source.state_hash.clone();

        self.environments.insert(forked.id.clone(), forked.clone());
        self.metrics.total_forks += 1;

        Ok(forked)
    }

    /// Create a state snapshot
    pub fn create_snapshot(&mut self, env_id: &str, name: &str, description: Option<String>) -> Result<StateSnapshot, String> {
        if !self.config.allow_snapshots {
            return Err("Snapshots are disabled".to_string());
        }

        let env = self.environments.get_mut(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?;

        let env_snapshots = self.snapshots.entry(env_id.to_string()).or_insert_with(Vec::new);

        if env_snapshots.len() >= self.config.max_snapshots {
            return Err(format!(
                "Maximum snapshots ({}) reached for environment",
                self.config.max_snapshots
            ));
        }

        let snapshot = StateSnapshot {
            id: format!("snap_{}", generate_id()),
            environment_id: env_id.to_string(),
            name: name.to_string(),
            description,
            block_height: env.block_height,
            state_hash: env.state_hash.clone(),
            size_bytes: env.usage.storage_used_mb * 1024 * 1024,
            created_at: current_timestamp(),
            tags: HashMap::new(),
        };

        env.usage.snapshots_created += 1;
        env_snapshots.push(snapshot.clone());
        self.metrics.total_snapshots += 1;

        Ok(snapshot)
    }

    /// Restore from snapshot
    pub fn restore_snapshot(&mut self, env_id: &str, snapshot_id: &str) -> Result<(), String> {
        let env_snapshots = self.snapshots.get(env_id)
            .ok_or_else(|| format!("No snapshots for environment {}", env_id))?;

        let snapshot = env_snapshots.iter()
            .find(|s| s.id == snapshot_id)
            .ok_or_else(|| format!("Snapshot {} not found", snapshot_id))?
            .clone();

        let env = self.environments.get_mut(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?;

        env.state_hash = snapshot.state_hash;
        env.block_height = snapshot.block_height;
        env.last_activity = current_timestamp();

        Ok(())
    }

    /// List snapshots for an environment
    pub fn list_snapshots(&self, env_id: &str) -> Vec<&StateSnapshot> {
        self.snapshots.get(env_id)
            .map(|s| s.iter().collect())
            .unwrap_or_default()
    }

    /// Delete a snapshot
    pub fn delete_snapshot(&mut self, env_id: &str, snapshot_id: &str) -> Result<(), String> {
        let snapshots = self.snapshots.get_mut(env_id)
            .ok_or_else(|| format!("No snapshots for environment {}", env_id))?;

        let pos = snapshots.iter().position(|s| s.id == snapshot_id)
            .ok_or_else(|| format!("Snapshot {} not found", snapshot_id))?;

        snapshots.remove(pos);

        if snapshots.is_empty() {
            self.snapshots.remove(env_id);
        }

        Ok(())
    }

    /// Get environment by ID
    pub fn get_environment(&self, id: &str) -> Option<&Environment> {
        self.environments.get(id)
    }

    /// List environments for an owner
    pub fn list_environments(&self, owner: &str) -> Vec<&Environment> {
        self.environments.values()
            .filter(|e| e.owner == owner || e.team_members.contains(&owner.to_string()))
            .collect()
    }

    /// Update environment settings
    pub fn update_settings(&mut self, env_id: &str, settings: EnvironmentSettings) -> Result<(), String> {
        let env = self.environments.get_mut(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?;

        env.settings = settings;
        env.last_activity = current_timestamp();

        Ok(())
    }

    /// Pause environment
    pub fn pause_environment(&mut self, env_id: &str) -> Result<(), String> {
        let env = self.environments.get_mut(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?;

        if env.status != EnvironmentStatus::Active {
            return Err("Environment is not active".to_string());
        }

        env.status = EnvironmentStatus::Paused;
        self.metrics.active_environments = self.metrics.active_environments.saturating_sub(1);

        Ok(())
    }

    /// Resume environment
    pub fn resume_environment(&mut self, env_id: &str) -> Result<(), String> {
        let env = self.environments.get_mut(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?;

        if env.status != EnvironmentStatus::Paused {
            return Err("Environment is not paused".to_string());
        }

        env.status = EnvironmentStatus::Active;
        env.last_activity = current_timestamp();
        self.metrics.active_environments += 1;

        Ok(())
    }

    /// Delete environment
    pub fn delete_environment(&mut self, env_id: &str) -> Result<(), String> {
        let env = self.environments.get(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?
            .clone();

        // Update owner usage
        if let Some(usage) = self.usage_by_owner.get_mut(&env.owner) {
            usage.environment_count = usage.environment_count.saturating_sub(1);
        }

        // Remove snapshots
        self.snapshots.remove(env_id);

        // Remove environment
        self.environments.remove(env_id);

        if matches!(env.status, EnvironmentStatus::Active) {
            self.metrics.active_environments = self.metrics.active_environments.saturating_sub(1);
        }

        Ok(())
    }

    /// Extend environment lifetime
    pub fn extend_lifetime(&mut self, env_id: &str, additional_hours: u64) -> Result<u64, String> {
        let env = self.environments.get_mut(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?;

        let max_expiry = env.created_at + self.config.max_lifetime_hours * 3600;
        let new_expiry = (env.expires_at + additional_hours * 3600).min(max_expiry);

        env.expires_at = new_expiry;

        Ok(new_expiry)
    }

    /// Add team member
    pub fn add_team_member(&mut self, env_id: &str, member: &str) -> Result<(), String> {
        let env = self.environments.get_mut(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?;

        if !env.team_members.contains(&member.to_string()) {
            env.team_members.push(member.to_string());
        }

        Ok(())
    }

    /// Remove team member
    pub fn remove_team_member(&mut self, env_id: &str, member: &str) -> Result<(), String> {
        let env = self.environments.get_mut(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?;

        env.team_members.retain(|m| m != member);

        Ok(())
    }

    /// List templates
    pub fn list_templates(&self, category: Option<TemplateCategory>) -> Vec<&EnvironmentTemplate> {
        self.templates.values()
            .filter(|t| {
                category.as_ref().map_or(true, |c| {
                    std::mem::discriminant(&t.category) == std::mem::discriminant(c)
                })
            })
            .collect()
    }

    /// Create custom template from environment
    pub fn create_template_from_env(&mut self, env_id: &str, template_name: &str, description: &str) -> Result<String, String> {
        let env = self.environments.get(env_id)
            .ok_or_else(|| format!("Environment {} not found", env_id))?;

        let template_id = format!("tpl_{}", generate_id());

        let template = EnvironmentTemplate {
            id: template_id.clone(),
            name: template_name.to_string(),
            description: description.to_string(),
            category: TemplateCategory::Custom,
            settings: env.settings.clone(),
            pre_deployed_contracts: Vec::new(), // Would extract from env
            initial_accounts: Vec::new(),
            quota: env.quota.clone(),
            created_by: env.owner.clone(),
            created_at: current_timestamp(),
            usage_count: 0,
            is_public: false,
        };

        self.templates.insert(template_id.clone(), template);

        Ok(template_id)
    }

    /// Cleanup expired environments
    pub fn cleanup_expired(&mut self) -> Vec<String> {
        let now = current_timestamp();
        let expired: Vec<String> = self.environments.iter()
            .filter(|(_, e)| e.expires_at <= now && e.status != EnvironmentStatus::Deleted)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired {
            let _ = self.delete_environment(id);
        }

        expired
    }

    /// Get metrics
    pub fn metrics(&self) -> &EnvironmentMetrics {
        &self.metrics
    }

    /// Get all environments (admin)
    pub fn all_environments(&self) -> &HashMap<String, Environment> {
        &self.environments
    }
}

impl Default for AdvancedEnvironmentManager {
    fn default() -> Self {
        Self::new(EnvironmentConfig::default())
    }
}

// ============ Request Types ============

#[derive(Debug, Clone)]
pub struct CreateEnvironmentRequest {
    pub name: String,
    pub owner: String,
    pub env_type: EnvironmentType,
    pub template_id: Option<String>,
    pub settings: Option<EnvironmentSettings>,
    pub lifetime_hours: Option<u64>,
    pub team_members: Option<Vec<String>>,
    pub tags: Option<HashMap<String, String>>,
}

// ============ Helper Functions ============

fn generate_id() -> String {
    use rand::Rng;
    let timestamp = current_timestamp();
    let random: u64 = rand::thread_rng().gen();
    format!("{:x}{:x}", timestamp, random)
}

fn generate_hash() -> String {
    use rand::Rng;
    let random: [u8; 32] = rand::thread_rng().gen();
    format!("0x{}", hex::encode(random))
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
    fn test_environment_creation() {
        let config = EnvironmentConfig::default();
        let mut manager = AdvancedEnvironmentManager::new(config);

        let request = CreateEnvironmentRequest {
            name: "Test Environment".to_string(),
            owner: "test_owner".to_string(),
            env_type: EnvironmentType::Personal,
            template_id: None,
            settings: None,
            lifetime_hours: None,
            team_members: None,
            tags: None,
        };

        let env = manager.create_environment(request);
        assert!(env.is_ok());

        let env = env.unwrap();
        assert_eq!(env.name, "Test Environment");
        assert_eq!(env.status, EnvironmentStatus::Active);
    }

    #[test]
    fn test_environment_forking() {
        let config = EnvironmentConfig::default();
        let mut manager = AdvancedEnvironmentManager::new(config);

        // Create source environment
        let request = CreateEnvironmentRequest {
            name: "Source".to_string(),
            owner: "owner1".to_string(),
            env_type: EnvironmentType::Personal,
            template_id: None,
            settings: None,
            lifetime_hours: None,
            team_members: None,
            tags: None,
        };

        let source = manager.create_environment(request).unwrap();

        // Fork it
        let forked = manager.fork_environment(&source.id, "owner2", "Forked");
        assert!(forked.is_ok());

        let forked = forked.unwrap();
        assert!(forked.forked_from.is_some());
    }

    #[test]
    fn test_snapshots() {
        let config = EnvironmentConfig::default();
        let mut manager = AdvancedEnvironmentManager::new(config);

        let request = CreateEnvironmentRequest {
            name: "Test".to_string(),
            owner: "owner".to_string(),
            env_type: EnvironmentType::Personal,
            template_id: None,
            settings: None,
            lifetime_hours: None,
            team_members: None,
            tags: None,
        };

        let env = manager.create_environment(request).unwrap();

        // Create snapshot
        let snapshot = manager.create_snapshot(&env.id, "Snapshot 1", None);
        assert!(snapshot.is_ok());

        let snapshots = manager.list_snapshots(&env.id);
        assert_eq!(snapshots.len(), 1);
    }

    #[test]
    fn test_templates() {
        let config = EnvironmentConfig::default();
        let manager = AdvancedEnvironmentManager::new(config);

        let templates = manager.list_templates(None);
        assert!(!templates.is_empty());

        // Check DeFi template exists
        assert!(templates.iter().any(|t| t.id == "defi_basic"));
    }
}
