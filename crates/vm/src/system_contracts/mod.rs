//! Aethelred System Contracts
//!
//! Native system contracts baked into the genesis block that control the
//! network's economy, compliance, and AI job lifecycle.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        AETHELRED SYSTEM KERNEL                               │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                              │
//! │  ┌────────────────────────────────────────────────────────────────────────┐ │
//! │  │                         JOB REGISTRY                                    │ │
//! │  │                                                                         │ │
//! │  │   SUBMITTED ──► ASSIGNED ──► PROVING ──► VERIFIED ──► SETTLED          │ │
//! │  │       │             │            │           │            │             │ │
//! │  │       ▼             ▼            ▼           ▼            ▼             │ │
//! │  │   Escrow        SLA Timer    TEE/ZK      Payout      Completion        │ │
//! │  │   Locked        Started      Verify      Queue       Emit Event        │ │
//! │  │                                                                         │ │
//! │  └────────────────────────────────────────────────────────────────────────┘ │
//! │                                    │                                         │
//! │                                    ▼                                         │
//! │  ┌────────────────────────────────────────────────────────────────────────┐ │
//! │  │                       STAKING MANAGER                                   │ │
//! │  │                                                                         │ │
//! │  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │ │
//! │  │   │   Stake     │    │  Adaptive   │    │   Reward    │               │ │
//! │  │   │  Registry   │───►│   Burn      │───►│   Distrib   │               │ │
//! │  │   │             │    │   Engine    │    │             │               │ │
//! │  │   └─────────────┘    └─────────────┘    └─────────────┘               │ │
//! │  │                                                                         │ │
//! │  │   Fee Split: Prover (70%) + Validator (15-25%) + Burn (5-15%)         │ │
//! │  │                                                                         │ │
//! │  └────────────────────────────────────────────────────────────────────────┘ │
//! │                                    │                                         │
//! │                                    ▼                                         │
//! │  ┌────────────────────────────────────────────────────────────────────────┐ │
//! │  │                      COMPLIANCE MODULE                                  │ │
//! │  │                                                                         │ │
//! │  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │ │
//! │  │   │    OFAC     │    │   HIPAA     │    │    GDPR     │               │ │
//! │  │   │  Sanctions  │    │  Medical    │    │   Privacy   │               │ │
//! │  │   └─────────────┘    └─────────────┘    └─────────────┘               │ │
//! │  │                                                                         │ │
//! │  │   Pre-Transaction Enforcement + Audit Trail                            │ │
//! │  │                                                                         │ │
//! │  └────────────────────────────────────────────────────────────────────────┘ │
//! │                                                                              │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # System Contract Addresses
//!
//! System contracts are deployed at well-known addresses in the genesis block:
//! - `0x0000...0001`: JobRegistry
//! - `0x0000...0002`: StakingManager
//! - `0x0000...0003`: ComplianceModule
//! - `0x0000...0004`: GovernanceModule (future)
//! - `0x0000...0005`: TreasuryModule (future)

pub mod bank;
pub mod compliance;
pub mod error;
pub mod events;
pub mod job_registry;
pub mod pouw_engine;
pub mod slashing;
pub mod staking;
pub mod tokenomics;
pub mod types;

// Re-exports
pub use bank::{Bank, BankConfig};
pub use compliance::{
    Certification, ComplianceCheckResult, ComplianceConfig, ComplianceModule, ComplianceStandard,
    ComplianceStatistics, ConsentRecord, Did as ComplianceDid, JurisdictionConfig, ViolationType,
};
pub use error::{Result as SystemContractResult, SystemContractError};
pub use events::{
    ComplianceEvent, EventLog, JobEvent, PoUWEvent, SlashingEvent, StakingEvent, SystemEvent,
    TokenomicsEvent,
};
pub use job_registry::{JobConfig, JobRegistry, JobState, SlaPolicy};
pub use slashing::{
    AttestationChallenge, BanRecord, Challenge, ChallengeState, OffenseSeverity, OffenseType,
    ReliabilityMetrics, SlashingCondition, SlashingConfig, SlashingEvidence, SlashingManager,
    SlashingResult, SlashingStatistics,
};
pub use staking::{FeeSplit, SlashingParams, StakeInfo, StakingConfig, StakingManager};
pub use tokenomics::{
    AdaptiveBurnEngine, AllocationCategory, BurnConfig, BurnStats, CategoryStats,
    EmissionCalculator, EmissionScheduleInfo, FeeDistribution, GenesisAllocation, SupplyInfo,
    TokenomicsConfig, TokenomicsManager, VestingPosition,
    VestingSchedule as TokenomicsVestingSchedule, COMPUTE_POUW_POOL, CORE_CONTRIBUTORS_POOL,
    DECIMALS, ECOSYSTEM_GRANTS_POOL, FOUNDATION_RESERVE_POOL, HALVING_INTERVAL_SECS,
    INSURANCE_STABILITY_POOL, LABS_TREASURY_POOL, ONE_AETHEL, PUBLIC_SALE_POOL,
    STRATEGIC_INVESTORS_POOL, TOTAL_GENESIS_SUPPLY,
};
pub use types::{
    generate_job_id, is_zero_address, Address, ComplianceRequirement, ComplianceTag, Did, Hash,
    JobAssignResult, JobCancelResult, JobId, JobPriority, JobStatus, JobSubmitResult, Proof,
    ProofMetadata, ProofSubmitResult, SanctionsUpdate, Signature, StakeRole, SubmitJobParams,
    SubmitProofParams, TeeAttestation, TeeType, TokenAmount, Transaction, VerificationMethod,
    ZkProof, ZkSystem, ZERO_ADDRESS,
};

// Proof-of-Useful-Work (PoUW) Engine - The 4 Economic Moats
pub use pouw_engine::{
    BondLiquidation,
    ComplianceBond,
    // Moat 2: Compliance Bonds
    ComplianceBondType,
    ComputeOperationRecord,
    // Moat 3: Congestion-Squared Burn
    CongestionMetrics,
    DataCategory,
    DataVerificationLevel,
    FeeDistribution as PoUWFeeDistribution,
    HardwareTier,
    LiquidationReason,
    // Moat 1: Compute-Weighted Multiplier
    NodeComputeStats,
    OracleDataRequest,
    PoUWConfig,
    // Main engine
    PoUWEngine,
    PoUWStats,
    ProviderStats,
    SovereigntyOracle,
    // Moat 4: Sovereignty Premium
    SovereigntyRegion,
    TeeVerificationType,
    BASE_APY_BPS,
    COMPLIANCE_BURN_BPS,
    COMPLIANCE_VICTIM_PAYOUT_BPS,
    MAX_BURN_RATE_BPS as POUW_MAX_BURN_BPS,
    MAX_COMPUTE_MULTIPLIER_BPS,
    MIN_BURN_RATE_BPS as POUW_MIN_BURN_BPS,
    // Constants
    ONE_AETHEL as POUW_ONE_AETHEL,
};

// =============================================================================
// SYSTEM CONTRACT ADDRESSES
// =============================================================================

/// Well-known address for JobRegistry
pub const JOB_REGISTRY_ADDRESS: [u8; 32] = {
    let mut addr = [0u8; 32];
    addr[31] = 0x01;
    addr
};

/// Well-known address for StakingManager
pub const STAKING_MANAGER_ADDRESS: [u8; 32] = {
    let mut addr = [0u8; 32];
    addr[31] = 0x02;
    addr
};

/// Well-known address for ComplianceModule
pub const COMPLIANCE_MODULE_ADDRESS: [u8; 32] = {
    let mut addr = [0u8; 32];
    addr[31] = 0x03;
    addr
};

/// Well-known address for GovernanceModule
pub const GOVERNANCE_MODULE_ADDRESS: [u8; 32] = {
    let mut addr = [0u8; 32];
    addr[31] = 0x04;
    addr
};

/// Well-known address for Treasury
pub const TREASURY_ADDRESS: [u8; 32] = {
    let mut addr = [0u8; 32];
    addr[31] = 0x05;
    addr
};

/// Burn address (tokens sent here are destroyed)
pub const BURN_ADDRESS: [u8; 32] = [0xFF; 32];

// =============================================================================
// SYSTEM KERNEL
// =============================================================================

use parking_lot::RwLock;
use std::sync::Arc;

/// The System Kernel coordinates all native system contracts
pub struct SystemKernel {
    /// Job registry for AI task management
    pub job_registry: Arc<RwLock<JobRegistry>>,

    /// Staking manager for economics
    pub staking: Arc<RwLock<StakingManager>>,

    /// Compliance module for regulatory enforcement
    pub compliance: Arc<RwLock<ComplianceModule>>,

    /// Bank for token operations
    pub bank: Arc<RwLock<Bank>>,

    /// Current block context
    context: RwLock<BlockContext>,
}

/// Block execution context
#[derive(Debug, Clone)]
pub struct BlockContext {
    /// Current block height
    pub height: u64,
    /// Current block timestamp
    pub timestamp: u64,
    /// Current slot
    pub slot: u64,
    /// Block proposer (validator)
    pub proposer: Address,
    /// Gas limit for this block
    pub gas_limit: u64,
    /// Gas used so far
    pub gas_used: u64,
}

impl Default for BlockContext {
    fn default() -> Self {
        Self {
            height: 0,
            timestamp: 0,
            slot: 0,
            proposer: [0u8; 32],
            gas_limit: 30_000_000,
            gas_used: 0,
        }
    }
}

impl SystemKernel {
    /// Create new system kernel with genesis configuration
    pub fn from_genesis(genesis: &GenesisConfig) -> SystemContractResult<Self> {
        // Initialize bank first (other modules depend on it)
        let bank = Arc::new(RwLock::new(Bank::from_genesis(genesis)?));

        // Initialize job registry
        let job_registry = Arc::new(RwLock::new(JobRegistry::new(genesis.job_config.clone())));

        // Initialize staking manager
        let staking = Arc::new(RwLock::new(StakingManager::new(
            genesis.staking_config.clone(),
            bank.clone(),
        )));

        // Initialize compliance module
        let compliance = Arc::new(RwLock::new(ComplianceModule::new(
            genesis.compliance_config.clone(),
        )));

        Ok(Self {
            job_registry,
            staking,
            compliance,
            bank,
            context: RwLock::new(BlockContext::default()),
        })
    }

    /// Begin a new block
    pub fn begin_block(&self, ctx: BlockContext) {
        *self.context.write() = ctx;
    }

    /// End current block (apply rewards, decay, etc.)
    pub fn end_block(&self) -> SystemContractResult<Vec<SystemEvent>> {
        let ctx = self.context.read().clone();
        let mut events = Vec::new();

        // Process expired jobs
        let job_events = self
            .job_registry
            .write()
            .process_expired_jobs(ctx.timestamp)?;
        events.extend(job_events.into_iter().map(SystemEvent::Job));

        // Process staking epoch if needed
        let staking_events = self.staking.write().end_block(&ctx)?;
        events.extend(staking_events.into_iter().map(SystemEvent::Staking));

        // Update network utilization metric
        let utilization = (ctx.gas_used as f64 / ctx.gas_limit as f64 * 100.0) as u8;
        self.staking.write().update_utilization(utilization);

        Ok(events)
    }

    /// Get current block context
    pub fn context(&self) -> BlockContext {
        self.context.read().clone()
    }

    /// Pre-transaction compliance check
    pub fn check_compliance(
        &self,
        requester: &Address,
        data_provider: Option<&Address>,
        required_standards: &[ComplianceStandard],
        jurisdiction: Option<&str>,
        amount: TokenAmount,
        metadata: &std::collections::HashMap<String, String>,
    ) -> SystemContractResult<ComplianceCheckResult> {
        self.compliance.write().enforce(
            requester,
            data_provider,
            required_standards,
            jurisdiction,
            amount,
            metadata,
        )
    }

    /// Execute a system contract call
    pub fn execute(&self, call: SystemCall) -> SystemContractResult<SystemCallResult> {
        let ctx = self.context.read().clone();

        match call {
            // Job Registry calls
            SystemCall::SubmitJob(params) => {
                // Convert ComplianceRequirement to ComplianceStandard
                let required_standards: Vec<ComplianceStandard> = params
                    .required_compliance
                    .iter()
                    .map(|r| ComplianceStandard::from_requirement(*r))
                    .collect();

                // Run compliance check before job submission
                let metadata = std::collections::HashMap::new();
                let compliance_result = self.check_compliance(
                    &params.requester,
                    params.data_provider.as_ref(),
                    &required_standards,
                    params.jurisdiction.as_deref(),
                    params.max_bid,
                    &metadata,
                )?;

                if !compliance_result.passed {
                    return Err(SystemContractError::Compliance(format!(
                        "Compliance check failed: {} violations",
                        compliance_result.violations.len()
                    )));
                }

                let result =
                    self.job_registry
                        .write()
                        .submit_job(params, &ctx, &mut *self.bank.write())?;
                Ok(SystemCallResult::JobSubmitted(result))
            }

            SystemCall::AssignJob(job_id, prover) => {
                let result = self.job_registry.write().assign_job(job_id, prover, &ctx)?;
                Ok(SystemCallResult::JobAssigned(result))
            }

            SystemCall::SubmitProof(params) => {
                let result = self.job_registry.write().submit_proof(
                    params,
                    &ctx,
                    &mut *self.staking.write(),
                    &mut *self.bank.write(),
                )?;
                Ok(SystemCallResult::ProofSubmitted(result))
            }

            SystemCall::CancelJob(job_id, requester) => {
                let result = self.job_registry.write().cancel_job(
                    job_id,
                    requester,
                    &ctx,
                    &mut *self.bank.write(),
                )?;
                Ok(SystemCallResult::JobCancelled(result))
            }

            // Staking calls
            SystemCall::Stake(staker, amount, role) => {
                self.staking
                    .write()
                    .stake(staker, amount, role, &mut *self.bank.write())?;
                Ok(SystemCallResult::Staked { staker, amount })
            }

            SystemCall::Unstake(staker, amount) => {
                self.staking.write().unstake(staker, amount, &ctx)?;
                Ok(SystemCallResult::UnstakeInitiated { staker, amount })
            }

            SystemCall::WithdrawStake(staker) => {
                let amount =
                    self.staking
                        .write()
                        .withdraw(staker, &ctx, &mut *self.bank.write())?;
                Ok(SystemCallResult::Withdrawn { staker, amount })
            }

            // Compliance calls (governance only)
            SystemCall::AddSanctionedAddress(address, list_name) => {
                self.compliance
                    .write()
                    .add_sanctioned_address(address, list_name)?;
                Ok(SystemCallResult::ComplianceUpdated)
            }

            SystemCall::AddCertification(cert) => {
                self.compliance.write().add_certification(cert)?;
                Ok(SystemCallResult::EntityCertified)
            }

            SystemCall::RegisterBaa(covered_entity, business_associate) => {
                self.compliance
                    .write()
                    .register_baa(covered_entity, business_associate)?;
                Ok(SystemCallResult::BaaRegistered)
            }
        }
    }
}

// =============================================================================
// SYSTEM CALL TYPES
// =============================================================================

/// System contract call
#[derive(Debug, Clone)]
pub enum SystemCall {
    // Job Registry
    SubmitJob(SubmitJobParams),
    AssignJob(JobId, Address),
    SubmitProof(SubmitProofParams),
    CancelJob(JobId, Address),

    // Staking
    Stake(Address, TokenAmount, StakeRole),
    Unstake(Address, TokenAmount),
    WithdrawStake(Address),

    // Compliance (governance only)
    AddSanctionedAddress(Address, String),
    AddCertification(Certification),
    RegisterBaa(Address, Address),
}

/// System call result
#[derive(Debug, Clone)]
pub enum SystemCallResult {
    // Job results
    JobSubmitted(JobSubmitResult),
    JobAssigned(JobAssignResult),
    ProofSubmitted(ProofSubmitResult),
    JobCancelled(JobCancelResult),

    // Staking results
    Staked {
        staker: Address,
        amount: TokenAmount,
    },
    UnstakeInitiated {
        staker: Address,
        amount: TokenAmount,
    },
    Withdrawn {
        staker: Address,
        amount: TokenAmount,
    },

    // Compliance results
    ComplianceUpdated,
    EntityCertified,
    BaaRegistered,
}

// =============================================================================
// GENESIS CONFIGURATION
// =============================================================================

use serde::{Deserialize, Serialize};

/// Genesis configuration for system contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Chain ID
    pub chain_id: String,

    /// Launch timestamp
    pub launch_timestamp: u64,

    /// Initial token allocations
    pub allocations: Vec<TokenAllocation>,

    /// Job registry configuration
    pub job_config: JobConfig,

    /// Staking configuration
    pub staking_config: StakingConfig,

    /// Compliance configuration
    pub compliance_config: ComplianceConfig,

    /// Initial parameters
    pub parameters: ChainParameters,
}

/// Initial token allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAllocation {
    pub address: Address,
    pub balance: TokenAmount,
    pub vesting: Option<VestingSchedule>,
}

/// Vesting schedule for token allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Cliff duration in seconds
    pub cliff_duration: u64,
    /// Total vesting duration in seconds
    pub total_duration: u64,
    /// Amount available at TGE
    pub tge_amount: TokenAmount,
}

/// Chain parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainParameters {
    /// Block time in milliseconds
    pub block_time_ms: u64,
    /// Epoch length in blocks
    pub epoch_length: u64,
    /// Maximum gas per block
    pub max_block_gas: u64,
    /// Minimum transaction fee
    pub min_tx_fee: TokenAmount,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl GenesisConfig {
    /// Mainnet genesis configuration
    pub fn mainnet() -> Self {
        Self {
            chain_id: "aethelred-mainnet-1".into(),
            launch_timestamp: 0,
            allocations: vec![TokenAllocation {
                address: TREASURY_ADDRESS,
                balance: 200_000_000_000_000_000_000, // 200M tokens
                vesting: Some(VestingSchedule {
                    cliff_duration: 365 * 24 * 3600,        // 1 year cliff
                    total_duration: 4 * 365 * 24 * 3600,    // 4 year vesting
                    tge_amount: 10_000_000_000_000_000_000, // 10M at TGE
                }),
            }],
            job_config: JobConfig::mainnet(),
            staking_config: StakingConfig::mainnet(),
            compliance_config: ComplianceConfig::mainnet(),
            parameters: ChainParameters {
                block_time_ms: 6000,
                epoch_length: 43200,
                max_block_gas: 30_000_000,
                min_tx_fee: 1_000_000_000_000, // 0.001 AETHEL
            },
        }
    }

    /// Testnet genesis configuration
    pub fn testnet() -> Self {
        Self {
            chain_id: "aethelred-testnet-1".into(),
            launch_timestamp: 0,
            allocations: vec![],
            job_config: JobConfig::testnet(),
            staking_config: StakingConfig::testnet(),
            compliance_config: ComplianceConfig::testnet(),
            parameters: ChainParameters {
                block_time_ms: 3000,
                epoch_length: 21600,
                max_block_gas: 50_000_000,
                min_tx_fee: 100_000_000_000,
            },
        }
    }

    /// Devnet genesis configuration
    pub fn devnet() -> Self {
        Self {
            chain_id: "aethelred-devnet".into(),
            launch_timestamp: 0,
            allocations: vec![],
            job_config: JobConfig::devnet(),
            staking_config: StakingConfig::devnet(),
            compliance_config: ComplianceConfig::devnet(),
            parameters: ChainParameters {
                block_time_ms: 1000,
                epoch_length: 100,
                max_block_gas: 100_000_000,
                min_tx_fee: 0,
            },
        }
    }

    /// Validate genesis configuration
    pub fn validate(&self) -> SystemContractResult<()> {
        if self.chain_id.is_empty() {
            return Err(SystemContractError::InvalidConfig("Empty chain_id".into()));
        }

        if self.parameters.block_time_ms == 0 {
            return Err(SystemContractError::InvalidConfig(
                "Block time cannot be 0".into(),
            ));
        }

        if self.parameters.epoch_length == 0 {
            return Err(SystemContractError::InvalidConfig(
                "Epoch length cannot be 0".into(),
            ));
        }

        self.job_config.validate()?;
        self.staking_config.validate()?;
        self.compliance_config.validate()?;

        Ok(())
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_addresses() {
        assert_eq!(JOB_REGISTRY_ADDRESS[31], 0x01);
        assert_eq!(STAKING_MANAGER_ADDRESS[31], 0x02);
        assert_eq!(COMPLIANCE_MODULE_ADDRESS[31], 0x03);
    }

    #[test]
    fn test_genesis_config_validation() {
        let config = GenesisConfig::devnet();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_kernel_creation() {
        let genesis = GenesisConfig::devnet();
        let kernel = SystemKernel::from_genesis(&genesis).unwrap();
        assert_eq!(kernel.context().height, 0);
    }
}
