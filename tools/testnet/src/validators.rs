//! Sandbox Validators
//!
//! Dedicated validators for testing AI model sealing, job execution,
//! and other Aethelred-specific features in a controlled environment.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Validator Types
// ============================================================================

/// A sandbox validator for testing
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxValidator {
    pub id: String,
    pub address: String,
    pub name: String,
    pub validator_type: ValidatorType,
    pub status: ValidatorStatus,
    pub stake: String,
    pub commission_rate: f64,
    pub created_at: u64,
    pub uptime_percentage: f64,
    pub total_blocks_produced: u64,
    pub total_seals_verified: u64,
    pub total_jobs_executed: u64,
    pub hardware_specs: HardwareSpecs,
    pub tee_attestation: Option<TeeAttestation>,
    pub performance_metrics: PerformanceMetrics,
    pub owner: String,
    pub is_public: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ValidatorType {
    /// Standard block producer
    BlockProducer,
    /// AI model sealing specialist
    SealValidator,
    /// AI job execution specialist
    JobExecutor,
    /// Full-featured validator (all capabilities)
    FullNode,
    /// Custom configuration
    Custom(Vec<ValidatorCapability>),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ValidatorCapability {
    BlockProduction,
    ModelSealing,
    JobExecution,
    StateSync,
    LightClient,
    Archive,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Jailed,
    Unbonding,
    Maintenance,
    Crashed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HardwareSpecs {
    pub cpu_cores: u32,
    pub cpu_model: String,
    pub ram_gb: u32,
    pub storage_gb: u32,
    pub storage_type: String,
    pub gpu: Option<GpuSpec>,
    pub tee_type: Option<TeeType>,
    pub network_bandwidth_mbps: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GpuSpec {
    pub model: String,
    pub memory_gb: u32,
    pub compute_capability: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TeeType {
    IntelSGX,
    AMDSEV,
    ArmTrustZone,
    NvidiaCVM,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TeeAttestation {
    pub tee_type: TeeType,
    pub quote: Vec<u8>,
    pub report: Vec<u8>,
    pub enclave_hash: String,
    pub verified_at: u64,
    pub valid_until: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerformanceMetrics {
    pub avg_block_time_ms: f64,
    pub avg_seal_time_ms: f64,
    pub avg_job_time_ms: f64,
    pub blocks_per_epoch: u64,
    pub seals_per_hour: f64,
    pub jobs_per_hour: f64,
    pub missed_blocks: u64,
    pub double_signs: u64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        PerformanceMetrics {
            avg_block_time_ms: 2000.0,
            avg_seal_time_ms: 5000.0,
            avg_job_time_ms: 10000.0,
            blocks_per_epoch: 100,
            seals_per_hour: 720.0,
            jobs_per_hour: 360.0,
            missed_blocks: 0,
            double_signs: 0,
        }
    }
}

// ============================================================================
// Sandbox Validators Manager
// ============================================================================

/// Manager for sandbox validators
pub struct SandboxValidators {
    validators: HashMap<String, SandboxValidator>,
    validator_sets: HashMap<String, ValidatorSet>,
    seal_queue: Vec<PendingSeal>,
    job_queue: Vec<PendingJob>,
    config: ValidatorsConfig,
    stats: ValidatorStats,
}

#[derive(Debug, Clone)]
pub struct ValidatorsConfig {
    pub max_validators: usize,
    pub max_validators_per_user: usize,
    pub min_stake: String,
    pub max_stake: String,
    pub default_commission: f64,
    pub epoch_length_blocks: u64,
    pub unbonding_period_seconds: u64,
    pub slash_fraction: f64,
    pub downtime_jail_duration_seconds: u64,
}

impl Default for ValidatorsConfig {
    fn default() -> Self {
        ValidatorsConfig {
            max_validators: 100,
            max_validators_per_user: 5,
            min_stake: "1000000000000000000000".to_string(), // 1000 tAETH
            max_stake: "10000000000000000000000000".to_string(), // 10M tAETH
            default_commission: 0.05,
            epoch_length_blocks: 100,
            unbonding_period_seconds: 86400, // 1 day
            slash_fraction: 0.05,
            downtime_jail_duration_seconds: 3600, // 1 hour
        }
    }
}

/// A set of validators for a specific purpose
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub id: String,
    pub name: String,
    pub description: String,
    pub validator_ids: Vec<String>,
    pub created_by: String,
    pub created_at: u64,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct PendingSeal {
    pub id: String,
    pub model_id: String,
    pub model_hash: String,
    pub requester: String,
    pub assigned_validator: Option<String>,
    pub submitted_at: u64,
    pub status: SealStatus,
    pub priority: u32,
}

#[derive(Debug, Clone)]
pub enum SealStatus {
    Pending,
    Assigned,
    Processing,
    Completed(SealResult),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct SealResult {
    pub seal_id: String,
    pub seal_hash: String,
    pub validator_signature: String,
    pub tee_attestation: Option<Vec<u8>>,
    pub completed_at: u64,
}

#[derive(Debug, Clone)]
pub struct PendingJob {
    pub id: String,
    pub job_type: JobType,
    pub model_id: String,
    pub input_hash: String,
    pub requester: String,
    pub assigned_validator: Option<String>,
    pub submitted_at: u64,
    pub status: JobStatus,
    pub max_gas: u64,
    pub priority: u32,
}

#[derive(Debug, Clone)]
pub enum JobType {
    Inference,
    Training,
    FineTuning,
    Evaluation,
    Custom(String),
}

#[derive(Debug, Clone)]
pub enum JobStatus {
    Pending,
    Assigned,
    Processing,
    Completed(JobResult),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct JobResult {
    pub output_hash: String,
    pub gas_used: u64,
    pub execution_time_ms: u64,
    pub validator_signature: String,
    pub completed_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ValidatorStats {
    pub total_validators: usize,
    pub active_validators: usize,
    pub total_stake: String,
    pub total_blocks_produced: u64,
    pub total_seals_verified: u64,
    pub total_jobs_executed: u64,
    pub avg_uptime: f64,
}

impl SandboxValidators {
    pub fn new() -> Self {
        let mut validators = SandboxValidators {
            validators: HashMap::new(),
            validator_sets: HashMap::new(),
            seal_queue: Vec::new(),
            job_queue: Vec::new(),
            config: ValidatorsConfig::default(),
            stats: ValidatorStats::default(),
        };

        // Create default public validators
        validators.create_default_validators();
        validators
    }

    fn create_default_validators(&mut self) {
        let default_validators = vec![
            ("validator-1", "Public Validator Alpha", ValidatorType::FullNode),
            ("validator-2", "Public Validator Beta", ValidatorType::FullNode),
            ("validator-3", "Seal Specialist Gamma", ValidatorType::SealValidator),
            ("validator-4", "Job Executor Delta", ValidatorType::JobExecutor),
            ("validator-5", "Public Validator Epsilon", ValidatorType::FullNode),
        ];

        for (id, name, vtype) in default_validators {
            let validator = SandboxValidator {
                id: id.to_string(),
                address: format!("0x{:040x}", rand::random::<u64>()),
                name: name.to_string(),
                validator_type: vtype,
                status: ValidatorStatus::Active,
                stake: "10000000000000000000000".to_string(), // 10000 tAETH
                commission_rate: 0.05,
                created_at: Self::current_timestamp(),
                uptime_percentage: 99.9,
                total_blocks_produced: rand::random::<u64>() % 10000,
                total_seals_verified: rand::random::<u64>() % 5000,
                total_jobs_executed: rand::random::<u64>() % 2000,
                hardware_specs: HardwareSpecs {
                    cpu_cores: 32,
                    cpu_model: "AMD EPYC 7763".to_string(),
                    ram_gb: 256,
                    storage_gb: 4000,
                    storage_type: "NVMe SSD".to_string(),
                    gpu: Some(GpuSpec {
                        model: "NVIDIA H100".to_string(),
                        memory_gb: 80,
                        compute_capability: "9.0".to_string(),
                    }),
                    tee_type: Some(TeeType::IntelSGX),
                    network_bandwidth_mbps: 10000,
                },
                tee_attestation: Some(TeeAttestation {
                    tee_type: TeeType::IntelSGX,
                    quote: vec![0u8; 64],
                    report: vec![0u8; 128],
                    enclave_hash: format!("0x{:064x}", rand::random::<u64>()),
                    verified_at: Self::current_timestamp(),
                    valid_until: Self::current_timestamp() + 86400 * 30,
                }),
                performance_metrics: PerformanceMetrics::default(),
                owner: "system".to_string(),
                is_public: true,
            };

            self.validators.insert(id.to_string(), validator);
        }
    }

    /// Create a new sandbox validator
    pub fn create_validator(
        &mut self,
        owner: &str,
        name: &str,
        validator_type: ValidatorType,
        stake: &str,
        hardware: HardwareSpecs,
    ) -> Result<SandboxValidator, ValidatorError> {
        // Check user limits
        let user_validators = self.validators.values()
            .filter(|v| v.owner == owner)
            .count();

        if user_validators >= self.config.max_validators_per_user {
            return Err(ValidatorError::UserLimitExceeded {
                max: self.config.max_validators_per_user,
            });
        }

        // Check global limits
        if self.validators.len() >= self.config.max_validators {
            return Err(ValidatorError::GlobalLimitExceeded {
                max: self.config.max_validators,
            });
        }

        // Validate stake
        let stake_amount: u128 = stake.parse().map_err(|_| ValidatorError::InvalidStake)?;
        let min_stake: u128 = self.config.min_stake.parse().unwrap_or(0);
        let max_stake: u128 = self.config.max_stake.parse().unwrap_or(u128::MAX);

        if stake_amount < min_stake || stake_amount > max_stake {
            return Err(ValidatorError::InvalidStake);
        }

        let id = format!("validator-{}", uuid::Uuid::new_v4());
        let address = format!("0x{:040x}", rand::random::<u64>());

        let validator = SandboxValidator {
            id: id.clone(),
            address,
            name: name.to_string(),
            validator_type,
            status: ValidatorStatus::Active,
            stake: stake.to_string(),
            commission_rate: self.config.default_commission,
            created_at: Self::current_timestamp(),
            uptime_percentage: 100.0,
            total_blocks_produced: 0,
            total_seals_verified: 0,
            total_jobs_executed: 0,
            hardware_specs: hardware,
            tee_attestation: None,
            performance_metrics: PerformanceMetrics::default(),
            owner: owner.to_string(),
            is_public: false,
        };

        self.validators.insert(id.clone(), validator.clone());
        self.update_stats();

        Ok(validator)
    }

    /// Get validator by ID
    pub fn get_validator(&self, id: &str) -> Option<&SandboxValidator> {
        self.validators.get(id)
    }

    /// List all validators
    pub fn list_validators(&self) -> Vec<&SandboxValidator> {
        self.validators.values().collect()
    }

    /// List public validators
    pub fn list_public_validators(&self) -> Vec<&SandboxValidator> {
        self.validators.values().filter(|v| v.is_public).collect()
    }

    /// List validators for a specific owner
    pub fn list_user_validators(&self, owner: &str) -> Vec<&SandboxValidator> {
        self.validators.values().filter(|v| v.owner == owner).collect()
    }

    /// Submit a seal request
    pub fn submit_seal(&mut self, seal: PendingSeal) -> Result<String, ValidatorError> {
        let id = seal.id.clone();
        self.seal_queue.push(seal);
        self.assign_seal(&id)?;
        Ok(id)
    }

    /// Submit a job request
    pub fn submit_job(&mut self, job: PendingJob) -> Result<String, ValidatorError> {
        let id = job.id.clone();
        self.job_queue.push(job);
        self.assign_job(&id)?;
        Ok(id)
    }

    /// Get seal status
    pub fn get_seal_status(&self, seal_id: &str) -> Option<&SealStatus> {
        self.seal_queue.iter()
            .find(|s| s.id == seal_id)
            .map(|s| &s.status)
    }

    /// Get job status
    pub fn get_job_status(&self, job_id: &str) -> Option<&JobStatus> {
        self.job_queue.iter()
            .find(|j| j.id == job_id)
            .map(|j| &j.status)
    }

    /// Simulate validator behavior (for testing)
    pub fn simulate_block_production(&mut self) {
        for validator in self.validators.values_mut() {
            if matches!(validator.status, ValidatorStatus::Active) {
                validator.total_blocks_produced += 1;
            }
        }
        self.update_stats();
    }

    /// Simulate seal completion
    pub fn simulate_seal_completion(&mut self, seal_id: &str) -> Option<SealResult> {
        if let Some(seal) = self.seal_queue.iter_mut().find(|s| s.id == seal_id) {
            let result = SealResult {
                seal_id: seal_id.to_string(),
                seal_hash: format!("0x{:064x}", rand::random::<u64>()),
                validator_signature: format!("0x{:0128x}", rand::random::<u128>()),
                tee_attestation: Some(vec![0u8; 64]),
                completed_at: Self::current_timestamp(),
            };

            seal.status = SealStatus::Completed(result.clone());

            // Update validator stats
            if let Some(validator_id) = &seal.assigned_validator {
                if let Some(validator) = self.validators.get_mut(validator_id) {
                    validator.total_seals_verified += 1;
                }
            }

            self.update_stats();
            return Some(result);
        }
        None
    }

    /// Simulate job completion
    pub fn simulate_job_completion(&mut self, job_id: &str) -> Option<JobResult> {
        if let Some(job) = self.job_queue.iter_mut().find(|j| j.id == job_id) {
            let result = JobResult {
                output_hash: format!("0x{:064x}", rand::random::<u64>()),
                gas_used: rand::random::<u64>() % job.max_gas,
                execution_time_ms: 1000 + rand::random::<u64>() % 9000,
                validator_signature: format!("0x{:0128x}", rand::random::<u128>()),
                completed_at: Self::current_timestamp(),
            };

            job.status = JobStatus::Completed(result.clone());

            // Update validator stats
            if let Some(validator_id) = &job.assigned_validator {
                if let Some(validator) = self.validators.get_mut(validator_id) {
                    validator.total_jobs_executed += 1;
                }
            }

            self.update_stats();
            return Some(result);
        }
        None
    }

    /// Create a custom validator set
    pub fn create_validator_set(
        &mut self,
        name: &str,
        description: &str,
        validator_ids: Vec<String>,
        created_by: &str,
    ) -> Result<ValidatorSet, ValidatorError> {
        // Verify all validators exist
        for id in &validator_ids {
            if !self.validators.contains_key(id) {
                return Err(ValidatorError::ValidatorNotFound(id.clone()));
            }
        }

        let id = format!("set-{}", uuid::Uuid::new_v4());
        let set = ValidatorSet {
            id: id.clone(),
            name: name.to_string(),
            description: description.to_string(),
            validator_ids,
            created_by: created_by.to_string(),
            created_at: Self::current_timestamp(),
            is_active: true,
        };

        self.validator_sets.insert(id.clone(), set.clone());
        Ok(set)
    }

    /// Get validator statistics
    pub fn get_stats(&self) -> ValidatorStats {
        self.stats.clone()
    }

    // Private helper methods

    fn assign_seal(&mut self, seal_id: &str) -> Result<(), ValidatorError> {
        // Find available seal validator
        let available_validator = self.validators.values()
            .find(|v| {
                matches!(v.status, ValidatorStatus::Active) &&
                matches!(v.validator_type, ValidatorType::SealValidator | ValidatorType::FullNode | ValidatorType::Custom(_))
            })
            .map(|v| v.id.clone());

        if let Some(validator_id) = available_validator {
            if let Some(seal) = self.seal_queue.iter_mut().find(|s| s.id == seal_id) {
                seal.assigned_validator = Some(validator_id);
                seal.status = SealStatus::Assigned;
            }
            Ok(())
        } else {
            Err(ValidatorError::NoAvailableValidator)
        }
    }

    fn assign_job(&mut self, job_id: &str) -> Result<(), ValidatorError> {
        // Find available job executor
        let available_validator = self.validators.values()
            .find(|v| {
                matches!(v.status, ValidatorStatus::Active) &&
                matches!(v.validator_type, ValidatorType::JobExecutor | ValidatorType::FullNode | ValidatorType::Custom(_))
            })
            .map(|v| v.id.clone());

        if let Some(validator_id) = available_validator {
            if let Some(job) = self.job_queue.iter_mut().find(|j| j.id == job_id) {
                job.assigned_validator = Some(validator_id);
                job.status = JobStatus::Assigned;
            }
            Ok(())
        } else {
            Err(ValidatorError::NoAvailableValidator)
        }
    }

    fn update_stats(&mut self) {
        self.stats.total_validators = self.validators.len();
        self.stats.active_validators = self.validators.values()
            .filter(|v| matches!(v.status, ValidatorStatus::Active))
            .count();

        let total_stake: u128 = self.validators.values()
            .map(|v| v.stake.parse::<u128>().unwrap_or(0))
            .sum();
        self.stats.total_stake = total_stake.to_string();

        self.stats.total_blocks_produced = self.validators.values()
            .map(|v| v.total_blocks_produced)
            .sum();

        self.stats.total_seals_verified = self.validators.values()
            .map(|v| v.total_seals_verified)
            .sum();

        self.stats.total_jobs_executed = self.validators.values()
            .map(|v| v.total_jobs_executed)
            .sum();

        let uptimes: Vec<f64> = self.validators.values()
            .map(|v| v.uptime_percentage)
            .collect();
        self.stats.avg_uptime = if uptimes.is_empty() {
            0.0
        } else {
            uptimes.iter().sum::<f64>() / uptimes.len() as f64
        };
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl Default for SandboxValidators {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone)]
pub enum ValidatorError {
    UserLimitExceeded { max: usize },
    GlobalLimitExceeded { max: usize },
    InvalidStake,
    ValidatorNotFound(String),
    NoAvailableValidator,
    AlreadyJailed,
    NotJailed,
    InvalidConfiguration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_validators() {
        let validators = SandboxValidators::new();
        assert!(!validators.validators.is_empty());
        assert!(validators.list_public_validators().len() >= 5);
    }

    #[test]
    fn test_create_validator() {
        let mut validators = SandboxValidators::new();

        let result = validators.create_validator(
            "user-1",
            "Test Validator",
            ValidatorType::FullNode,
            "5000000000000000000000",
            HardwareSpecs {
                cpu_cores: 8,
                cpu_model: "Test CPU".to_string(),
                ram_gb: 32,
                storage_gb: 500,
                storage_type: "SSD".to_string(),
                gpu: None,
                tee_type: None,
                network_bandwidth_mbps: 1000,
            },
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_seal_submission() {
        let mut validators = SandboxValidators::new();

        let seal = PendingSeal {
            id: "seal-1".to_string(),
            model_id: "model-1".to_string(),
            model_hash: "0x123".to_string(),
            requester: "user-1".to_string(),
            assigned_validator: None,
            submitted_at: SandboxValidators::current_timestamp(),
            status: SealStatus::Pending,
            priority: 1,
        };

        let result = validators.submit_seal(seal);
        assert!(result.is_ok());

        let status = validators.get_seal_status("seal-1");
        assert!(matches!(status, Some(SealStatus::Assigned)));
    }
}
